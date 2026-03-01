// ABOUTME: PyO3 bridge between Rust core and Python protocol handlers.
// ABOUTME: Defines #[pyclass] types that Python protocol modules subclass.

pub mod connection;
pub mod convert;
pub mod dionaea;
pub mod ihandler;
pub mod incident;
pub mod loader;
pub mod node_info;
pub mod stats;

use pyo3::prelude::*;

/// Register all dionaea bridge classes into a Python module.
///
/// Called during Python interpreter initialization to make the Rust types
/// available as `from dionaea_core import PyConnection, ...` (or whatever
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

    Ok(())
}

/// Factory function for creating connections from Python.
/// Returns a weakref proxy, matching the Cython `connection_new()`.
#[pyfunction]
fn connection_new(py: Python<'_>, con_type: String) -> PyResult<Py<PyAny>> {
    let conn = Py::new(py, connection::PyConnection::new(Some(con_type.clone())))?;
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
            assert!(module.getattr("PyConnection").is_ok());
            assert!(module.getattr("PyIncident").is_ok());
            assert!(module.getattr("PyIHandler").is_ok());
            assert!(module.getattr("PyNodeInfo").is_ok());
            assert!(module.getattr("PyConnectionTimeouts").is_ok());
            assert!(module.getattr("PyConnectionSpeed").is_ok());
            assert!(module.getattr("PyConnectionAccounting").is_ok());
            assert!(module.getattr("PyConnectionStats").is_ok());
            assert!(module.getattr("PyDionaea").is_ok());
            assert!(module.getattr("g_dionaea").is_ok());
            assert!(module.getattr("connection_new").is_ok());
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
            assert_eq!(version, env!("CARGO_PKG_VERSION"));
        });
    }

    /// Integration test: define a protocol, create incidents, dispatch to ihandler.
    #[test]
    fn test_full_protocol_incident_ihandler_roundtrip() {
        Python::attach(|py| {
            setup_module(py, "dionaea_integration");

            py.run(
                c"
from dionaea_integration import PyConnection, PyIncident, PyIHandler

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
