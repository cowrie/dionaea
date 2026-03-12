// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: PyO3 bridge between Rust core and Python protocol handlers.
// ABOUTME: Defines #[pyclass] types that Python protocol modules subclass.

/// PyConnection: base class for Python protocol handlers.
pub mod connection;
/// Rust ↔ Python type conversion helpers.
pub mod convert;
/// PyDionaea singleton: config access, getifaddrs, version.
pub mod dionaea;
/// PyIHandler: base class for Python incident handlers.
pub mod ihandler;
/// PyIncident: dynamic key-value container for event data.
pub mod incident;
/// Python module loading: import, new(), start(), stop() lifecycle.
pub mod loader;
/// PyNodeInfo: network endpoint address exposed to Python.
pub mod node_info;
/// PyConnectionTimeouts, PyConnectionSpeed, etc. exposed to Python.
pub mod stats;

use pyo3::prelude::*;
use pyo3_stub_gen::derive::gen_stub_pyfunction;

/// Register all dionaea bridge classes into a Python module.
///
/// Called during Python interpreter initialization to make the Rust types
/// available as `from dionaea_core import connection, ...` (or whatever
/// the module is named).
pub fn register_classes(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<connection::PyConnection>()?;
    module.add_class::<incident::PyIncident>()?;
    module.add_class::<ihandler::PyIHandler>()?;
    module.add_class::<node_info::PyNodeInfo>()?;
    module.add_class::<stats::PyConnectionTimeouts>()?;
    module.add_class::<stats::PyConnectionSpeed>()?;
    module.add_class::<stats::PyConnectionAccounting>()?;
    module.add_class::<stats::PyConnectionStats>()?;
    module.add_class::<dionaea::PyDionaea>()?;

    // Add the g_dionaea singleton
    let g_dionaea = Py::new(module.py(), dionaea::PyDionaea::new())?;
    module.add("g_dionaea", g_dionaea)?;

    // Add connection_new factory function
    module.add_function(wrap_pyfunction!(connection_new, module)?)?;

    // Add dlhfn logging bridge
    module.add_function(wrap_pyfunction!(dlhfn, module)?)?;

    Ok(())
}

/// Bridge Python logging to Rust tracing.
///
/// Called by `dionaea/log.py` as `dlhfn(name, number, path, line, msg)`.
/// Maps Python log levels (DEBUG=10, INFO=20, WARNING=30, ERROR=40, CRITICAL=50)
/// to tracing levels.
#[gen_stub_pyfunction]
#[pyfunction]
fn dlhfn(name: &str, number: i32, path: &str, line: i32, msg: &str) {
    let file = strip_to_relative(path);
    match number {
        50 => tracing::error!(target: "python", logger = name, file = file, line = line, "{msg}"),
        40 => tracing::error!(target: "python", logger = name, file = file, line = line, "{msg}"),
        30 => tracing::warn!(target: "python", logger = name, file = file, line = line, "{msg}"),
        20 => tracing::info!(target: "python", logger = name, file = file, line = line, "{msg}"),
        _ => tracing::debug!(target: "python", logger = name, file = file, line = line, "{msg}"),
    }
}

/// Strip an absolute path to a relative one from the current working directory.
fn strip_to_relative(path: &str) -> &str {
    static CWD: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    let cwd = CWD.get_or_init(|| std::env::current_dir().unwrap_or_default());
    let cwd_str = cwd.to_str().unwrap_or("");
    if !cwd_str.is_empty() {
        if let Some(rel) = path.strip_prefix(cwd_str) {
            return rel.strip_prefix('/').unwrap_or(rel);
        }
    }
    path
}

/// Factory function for creating connections from Python.
#[gen_stub_pyfunction]
#[pyfunction]
fn connection_new(py: Python<'_>, con_type: String) -> PyResult<Py<PyAny>> {
    let empty_tuple = pyo3::types::PyTuple::empty(py);
    let conn = Py::new(py, connection::PyConnection::new(Some(con_type.clone()), &empty_tuple, None))?;
    // Call __init__ to set up the transport
    {
        let mut c = conn.bind(py).cast::<connection::PyConnection>()?.borrow_mut();
        c.__init__(Some(con_type))?;
    }
    // Return a weakref proxy
    let weakref = py.import(c"weakref")?;
    let proxy = weakref.call_method1("proxy", (conn,))?;
    Ok(proxy.unbind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyModule;

    fn setup_module<'py>(py: Python<'py>, name: &str) -> Bound<'py, PyModule> {
        let module = PyModule::new(py, name).unwrap();
        register_classes(&module).unwrap();
        py.import(c"sys")
            .unwrap()
            .getattr("modules")
            .unwrap()
            .set_item(name, &module)
            .unwrap();
        module
    }

    #[test]
    fn test_register_classes() {
        Python::attach(|py| {
            let module = setup_module(py, "dionaea_reg_test");
            // Verify all classes are registered
            assert!(module.getattr("connection").is_ok());
            assert!(module.getattr("incident").is_ok());
            assert!(module.getattr("ihandler").is_ok());
            assert!(module.getattr("node_info").is_ok());
            assert!(module.getattr("connection_timeouts").is_ok());
            assert!(module.getattr("connection_speed").is_ok());
            assert!(module.getattr("connection_accounting").is_ok());
            assert!(module.getattr("connection_stats").is_ok());
            assert!(module.getattr("dionaea").is_ok());
            assert!(module.getattr("g_dionaea").is_ok());
            assert!(module.getattr("connection_new").is_ok());
            assert!(module.getattr("dlhfn").is_ok());
        });
    }

    #[test]
    fn test_dlhfn_does_not_panic() {
        Python::attach(|py| {
            setup_module(py, "dionaea_dlhfn_test");
            // Call dlhfn at each log level to verify it doesn't panic
            py.run(
                c"
from dionaea_dlhfn_test import dlhfn
dlhfn('test.logger', 10, '/tmp/test.py', 42, 'debug message')
dlhfn('test.logger', 20, '/tmp/test.py', 43, 'info message')
dlhfn('test.logger', 30, '/tmp/test.py', 44, 'warning message')
dlhfn('test.logger', 40, '/tmp/test.py', 45, 'error message')
dlhfn('test.logger', 50, '/tmp/test.py', 46, 'critical message')
",
                None,
                None,
            )
            .unwrap();
        });
    }

    #[test]
    fn test_g_dionaea_singleton() {
        Python::attach(|py| {
            setup_module(py, "dionaea_singleton_test");

            let version: String = py
                .eval(
                    c"__import__('dionaea_singleton_test').g_dionaea.version()",
                    None,
                    None,
                )
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(version, super::dionaea::VERSION);
        });
    }

    /// Integration test: define a protocol, create incidents, dispatch to ihandler.
    #[test]
    fn test_full_protocol_incident_ihandler_roundtrip() {
        Python::attach(|py| {
            setup_module(py, "dionaea_integration");

            py.run(
                c"
from dionaea_integration import connection as PyConnection, incident as PyIncident, ihandler as PyIHandler

# Define a simple protocol
class EchoService(PyConnection):
    def __init__(self, proto=None):
        super().__init__(proto)
        self.events = []

    def handle_established(self):
        self.events.append('established')

    def handle_io_in(self, data):
        self.events.append(('io_in', bytes(data)))
        return len(data)

    def handle_disconnect(self):
        self.events.append('disconnect')
        return False

# Define an incident handler
class LogHandler(PyIHandler):
    def __init__(self):
        super().__init__('test.*')
        self.logged = []

    def handle_incident_test_connection_accept(self, incident):
        self.logged.append({
            'origin': incident.origin,
            'port': incident.port,
        })

    def handle_incident(self, incident):
        self.logged.append({
            'origin': incident.origin,
            'fallback': True,
        })

# Create protocol instance
proto = EchoService('tcp')
proto.handle_established()
proto.handle_io_in(b'hello')
proto.handle_disconnect()

# Create ihandler
handler = LogHandler()

# Create and report incidents
inc1 = PyIncident('test.connection.accept')
inc1.port = 445

inc2 = PyIncident('test.download.complete')
inc2.url = 'http://evil.com/malware.exe'
",
                None,
                None,
            )
            .unwrap();

            // Verify protocol events
            let proto = py.eval(c"proto", None, None).unwrap();
            let events: Vec<String> = py
                .eval(
                    c"[str(e) for e in proto.events]",
                    None,
                    None,
                )
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(events.len(), 3);
            assert_eq!(events[0], "established");
            assert!(events[1].contains("io_in"));
            assert_eq!(events[2], "disconnect");

            // Dispatch incidents to handler
            let handler = py.eval(c"handler", None, None).unwrap();
            let inc1 = py.eval(c"inc1", None, None).unwrap();
            let inc1_py = inc1.cast::<incident::PyIncident>().unwrap().borrow();
            ihandler::dispatch_to_handler(py, &handler, &inc1_py).unwrap();

            let inc2 = py.eval(c"inc2", None, None).unwrap();
            let inc2_py = inc2.cast::<incident::PyIncident>().unwrap().borrow();
            ihandler::dispatch_to_handler(py, &handler, &inc2_py).unwrap();

            // Verify handler logged correctly
            let logged_len: usize = py
                .eval(c"len(handler.logged)", None, None)
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(logged_len, 2);

            // First incident: specific handler
            let first_origin: String = py
                .eval(c"handler.logged[0]['origin']", None, None)
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(first_origin, "test.connection.accept");
            let first_port: i64 = py
                .eval(c"handler.logged[0]['port']", None, None)
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(first_port, 445);

            // Second incident: fallback handler
            let second_fallback: bool = py
                .eval(c"handler.logged[1]['fallback']", None, None)
                .unwrap()
                .extract()
                .unwrap();
            assert!(second_fallback);
        });
    }

    /// Test that connection_new returns a weakref proxy.
    #[test]
    fn test_connection_new_returns_weakref() {
        Python::attach(|py| {
            setup_module(py, "dionaea_connew_test");

            py.run(
                c"
import weakref
from dionaea_connew_test import connection_new
conn = connection_new('tcp')
# weakref.proxy objects are instances of weakref.ProxyType
assert isinstance(conn, weakref.ProxyType), f'expected weakref proxy, got {type(conn).__name__}'
",
                None,
                None,
            )
            .unwrap();
        });
    }
}
