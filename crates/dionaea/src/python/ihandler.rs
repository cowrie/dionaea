// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: Python-visible incident handler class for event dispatch.
// ABOUTME: Dispatches to handle_incident_<origin_with_underscores>() or fallback handle_incident().

use pyo3::prelude::*;

use crate::ihandler::{HandlerCallback, IHandler, WildcardPattern};
use crate::python::incident::PyIncident;
use crate::runtime;

/// Incident handler exposed to Python.
///
/// Python ihandler subclasses (logsql, hpfeeds, log_json, etc.) define methods like
/// `handle_incident_dionaea_connection_tcp_accept(self, incident)`. The dispatch
/// logic replaces dots with underscores and looks for a specific method first,
/// falling back to `handle_incident(incident)`.
///
/// Matches the Cython `ihandler` class in binding.pyx.
#[pyclass(subclass)]
pub struct PyIHandler {
    pattern: String,
}

impl PyIHandler {
    /// Create a new handler from Rust (used by tests).
    pub fn empty() -> Self {
        PyIHandler {
            pattern: String::new(),
        }
    }
}

#[pymethods]
impl PyIHandler {
    /// Accept any args/kwargs from Python subclass constructors.
    /// The actual pattern is set in `__init__`.
    #[new]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn new(
        _args: &Bound<'_, pyo3::types::PyTuple>,
        _kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> Self {
        PyIHandler::empty()
    }

    /// Initialize the handler. Python subclasses call `super().__init__(pattern)`.
    ///
    /// Auto-registers this handler in the global IHandlerRegistry if the runtime
    /// is initialized. Matches the C behavior where `ihandler.__init__()` calls
    /// `c_ihandler_new()` to register immediately.
    #[pyo3(signature = (pattern=None))]
    fn __init__(slf: &Bound<'_, Self>, pattern: Option<String>) -> PyResult<()> {
        let pat = pattern.unwrap_or_default();
        slf.borrow_mut().pattern = pat.clone();

        if let Some(state) = runtime::get() {
            let callback = HandlerCallback::Python(slf.clone().into_any().unbind());
            let handler = IHandler {
                pattern: WildcardPattern::new(pat),
                callback,
            };
            state
                .ihandler_registry
                .lock()
                .expect("ihandler registry lock")
                .register(handler);
            tracing::debug!(pattern = %slf.borrow().pattern, "ihandler registered");
        }
        Ok(())
    }

    /// Apply configuration dict to this handler.
    fn apply_config(&self, _config: &Bound<'_, PyAny>) -> PyResult<()> {
        Ok(())
    }

    /// Start the handler. Called after all handlers are registered.
    fn start(&self) -> PyResult<()> {
        Ok(())
    }

    /// Stop the handler. Called during shutdown.
    fn stop(&self) -> PyResult<()> {
        Ok(())
    }

    /// Register this handler with the incident system.
    fn register(&self) -> PyResult<()> {
        Ok(())
    }

    /// Unregister this handler from the incident system.
    fn unregister(&self) -> PyResult<()> {
        Ok(())
    }

    /// Default incident handler. Override in Python subclasses.
    fn handle_incident(&self, _incident: &Bound<'_, PyAny>) -> PyResult<()> {
        Ok(())
    }

    /// The glob pattern this handler matches.
    #[getter]
    fn pattern(&self) -> &str {
        &self.pattern
    }
}

/// Dispatch an incident to a Python ihandler.
///
/// Tries `handle_incident_<origin_with_dots_replaced_by_underscores>(incident)` first.
/// Falls back to `handle_incident(incident)` if the specific method doesn't exist.
///
/// This matches the exact dispatch logic in binding.pyx `c_python_ihandler_cb`.
pub fn dispatch_to_handler(
    py: Python<'_>,
    handler: &Bound<'_, PyAny>,
    incident: &PyIncident,
) -> PyResult<()> {
    let mut new_incident = PyIncident::from_incident(&incident.to_incident());
    for (k, v) in &incident.py_refs {
        new_incident.py_refs.insert(k.clone(), v.clone_ref(py));
    }
    let py_incident = Py::new(py, new_incident)?;
    let origin = incident.to_incident().origin;
    let method_name = format!("handle_incident_{}", origin.replace('.', "_"));

    match handler.getattr(method_name.as_str()) {
        Ok(method) => {
            method.call1((py_incident.bind(py),))?;
        }
        Err(_) => {
            handler.call_method1("handle_incident", (py_incident.bind(py),))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyModule;

    fn register_module(py: Python<'_>, name: &str) {
        let module = PyModule::new(py, name).unwrap();
        module.add_class::<PyIHandler>().unwrap();
        module.add_class::<PyIncident>().unwrap();
        py.import(c"sys")
            .unwrap()
            .getattr("modules")
            .unwrap()
            .set_item(name, module)
            .unwrap();
    }

    #[test]
    fn test_ihandler_basic() {
        Python::attach(|py| {
            let h = Py::new(py, PyIHandler::empty()).unwrap();
            let bound = h.bind(py);
            // Call __init__ through Python to test the Bound<Self> signature
            bound
                .call_method1("__init__", ("dionaea.connection.*",))
                .unwrap();
            let pattern: String = bound.getattr("pattern").unwrap().extract().unwrap();
            assert_eq!(pattern, "dionaea.connection.*");
        });
    }

    #[test]
    fn test_ihandler_dispatch_specific_method() {
        Python::attach(|py| {
            register_module(py, "dionaea_ih_test1");

            py.run(
                c"
from dionaea_ih_test1 import PyIHandler, PyIncident

class TestHandler(PyIHandler):
    def __init__(self):
        super().__init__('dionaea.connection.*')
        self.calls = []

    def handle_incident_dionaea_connection_tcp_accept(self, incident):
        self.calls.append(('specific', incident.origin))

    def handle_incident(self, incident):
        self.calls.append(('generic', incident.origin))
",
                None,
                None,
            )
            .unwrap();

            let handler = py.eval(c"TestHandler()", None, None).unwrap();

            // Create and dispatch an incident that matches the specific method
            let incident = PyIncident::from_incident(
                &crate::incident::Incident::new("dionaea.connection.tcp.accept"),
            );
            dispatch_to_handler(py, &handler, &incident).unwrap();

            let calls: Vec<(String, String)> = handler
                .getattr("calls")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, "specific");
            assert_eq!(calls[0].1, "dionaea.connection.tcp.accept");
        });
    }

    #[test]
    fn test_ihandler_dispatch_fallback() {
        Python::attach(|py| {
            register_module(py, "dionaea_ih_test2");

            py.run(
                c"
from dionaea_ih_test2 import PyIHandler, PyIncident

class FallbackHandler(PyIHandler):
    def __init__(self):
        super().__init__('*')
        self.calls = []

    def handle_incident(self, incident):
        self.calls.append(('generic', incident.origin))
",
                None,
                None,
            )
            .unwrap();

            let handler = py.eval(c"FallbackHandler()", None, None).unwrap();

            // This handler doesn't have a specific method, so it falls back
            let incident = PyIncident::from_incident(
                &crate::incident::Incident::new("dionaea.download.complete.hash"),
            );
            dispatch_to_handler(py, &handler, &incident).unwrap();

            let calls: Vec<(String, String)> = handler
                .getattr("calls")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, "generic");
            assert_eq!(calls[0].1, "dionaea.download.complete.hash");
        });
    }

    #[test]
    fn test_ihandler_dispatch_with_data() {
        Python::attach(|py| {
            register_module(py, "dionaea_ih_test3");

            py.run(
                c"
from dionaea_ih_test3 import PyIHandler, PyIncident

class DataHandler(PyIHandler):
    def __init__(self):
        super().__init__('dionaea.download.*')
        self.received = {}

    def handle_incident_dionaea_download_complete(self, incident):
        self.received['url'] = incident.url
        self.received['size'] = incident.size
",
                None,
                None,
            )
            .unwrap();

            let handler = py.eval(c"DataHandler()", None, None).unwrap();

            let mut rust_incident = crate::incident::Incident::new("dionaea.download.complete");
            rust_incident.set(
                "url",
                crate::incident::OpaqueData::String("http://evil.com/malware.exe".into()),
            );
            rust_incident.set("size", crate::incident::OpaqueData::Int(4096));

            let incident = PyIncident::from_incident(&rust_incident);
            dispatch_to_handler(py, &handler, &incident).unwrap();

            let received = handler.getattr("received").unwrap();
            let url: String = received.get_item("url").unwrap().extract().unwrap();
            assert_eq!(url, "http://evil.com/malware.exe");
            let size: i64 = received.get_item("size").unwrap().extract().unwrap();
            assert_eq!(size, 4096);
        });
    }

    #[test]
    fn test_dispatch_preserves_py_refs() {
        Python::attach(|py| {
            register_module(py, "dionaea_ih_test_pyrefs");

            // Register PyConnection so we can create instances
            let module = PyModule::new(py, "dionaea_ih_test_pyrefs_conn").unwrap();
            module
                .add_class::<crate::python::connection::PyConnection>()
                .unwrap();
            py.import(c"sys")
                .unwrap()
                .getattr("modules")
                .unwrap()
                .set_item("dionaea_ih_test_pyrefs_conn", module)
                .unwrap();

            py.run(
                c"
from dionaea_ih_test_pyrefs import PyIHandler, PyIncident
from dionaea_ih_test_pyrefs_conn import PyConnection

class ConnHandler(PyIHandler):
    def __init__(self):
        super().__init__('dionaea.connection.*')
        self.con_type = None

    def handle_incident_dionaea_connection_tcp_accept(self, incident):
        # This should get the actual connection object, not an int
        self.con_type = type(incident.con).__name__
",
                None,
                None,
            )
            .unwrap();

            let handler = py.eval(c"ConnHandler()", None, None).unwrap();

            // Create a connection object via Python (constructor needs *args, **kwargs)
            let conn: Py<PyAny> = py
                .eval(c"PyConnection('tcp')", None, None)
                .unwrap()
                .unbind();

            let mut incident = PyIncident::new(Some("dionaea.connection.tcp.accept".into()));
            // Simulate what emit_connection_incident does: setattr("con", conn)
            incident
                .py_refs
                .insert("con".to_string(), conn.clone_ref(py));
            incident.data.insert(
                "con".to_string(),
                crate::incident::OpaqueData::ConnectionRef(
                    crate::connection::ConnectionId(1),
                ),
            );

            dispatch_to_handler(py, &handler, &incident).unwrap();

            let con_type: String = handler
                .getattr("con_type")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(con_type, "PyConnection");
        });
    }

    #[test]
    fn test_ihandler_subclass_lifecycle() {
        Python::attach(|py| {
            register_module(py, "dionaea_ih_test4");

            py.run(
                c"
from dionaea_ih_test4 import PyIHandler

class LifecycleHandler(PyIHandler):
    def __init__(self):
        super().__init__('*')
        self.lifecycle = []

    def apply_config(self, config):
        self.lifecycle.append('config')

    def start(self):
        self.lifecycle.append('start')

    def stop(self):
        self.lifecycle.append('stop')
",
                None,
                None,
            )
            .unwrap();

            let handler = py.eval(c"LifecycleHandler()", None, None).unwrap();
            handler.call_method1("apply_config", (py.None(),)).unwrap();
            handler.call_method0("start").unwrap();
            handler.call_method0("stop").unwrap();

            let lifecycle: Vec<String> = handler
                .getattr("lifecycle")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(lifecycle, vec!["config", "start", "stop"]);
        });
    }
}
