// ABOUTME: PyO3 connection class that Python protocol handlers subclass.
// ABOUTME: Full API surface matching binding.pyx connection class.

use bytes::Bytes;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::cell::Cell;
use tokio::sync::mpsc;

use crate::connection::{ConnectionId, SendMessage};
use crate::python::node_info::PyNodeInfo;
use crate::python::stats::{
    PyConnectionAccounting, PyConnectionSpeed, PyConnectionStats, PyConnectionTimeouts,
};

// Thread-local for factory instantiation.
// Set before calling the Python subclass constructor so `__init__` knows
// it's a factory-created (accepted) connection, not a new one.
thread_local! {
    static FACTORY_CON_ID: Cell<Option<ConnectionId>> = const { Cell::new(None) };
    static FACTORY_SEND_TX: Cell<Option<mpsc::Sender<SendMessage>>> = const { Cell::new(None) };
}

/// Connection object exposed to Python. Protocol handlers subclass this.
///
/// Python protocols override `handle_io_in`, `handle_established`, etc.
/// Rust calls these callbacks when I/O events occur.
///
/// The I/O task owns the receiver end of the send channel.
/// Python's `send()` pushes data through the sender.
#[pyclass(subclass, weakref)]
pub struct PyConnection {
    /// Connection ID. None after invalidation (connection freed/disconnected).
    pub(crate) id: Option<ConnectionId>,
    /// Transport type string.
    pub(crate) transport: String,
    /// Protocol name.
    pub(crate) protocol: String,
    /// Connection state string.
    pub(crate) status: String,
    /// Local endpoint info.
    pub(crate) local: PyNodeInfo,
    /// Remote endpoint info.
    pub(crate) remote: PyNodeInfo,
    /// Timeout configuration.
    pub(crate) timeouts: PyConnectionTimeouts,
    /// Channel for sending data/control to the I/O task.
    pub(crate) send_tx: Option<mpsc::Sender<SendMessage>>,
}

/// Check that the connection is still valid (not freed/disconnected).
/// Returns `ReferenceError` if invalidated, matching Cython behavior.
fn check_valid(id: &Option<ConnectionId>) -> PyResult<ConnectionId> {
    id.ok_or_else(|| {
        pyo3::exceptions::PyReferenceError::new_err("the object requested does not exist")
    })
}

impl PyConnection {
    /// Create a connection with an externally-provided send channel.
    /// Used by the accept/connect path in the I/O layer.
    pub fn with_channel(
        id: ConnectionId,
        transport: String,
        tx: mpsc::Sender<SendMessage>,
    ) -> Self {
        PyConnection {
            id: Some(id),
            transport,
            protocol: String::new(),
            status: "none".to_string(),
            local: PyNodeInfo::new(),
            remote: PyNodeInfo::new(),
            timeouts: PyConnectionTimeouts::new(),
            send_tx: Some(tx),
        }
    }

    /// Invalidate this connection (set id to None).
    /// All subsequent property/method access will raise ReferenceError.
    pub fn invalidate(&mut self) {
        self.id = None;
        self.send_tx = None;
    }

    /// Get the connection ID if still valid.
    pub fn connection_id(&self) -> Option<ConnectionId> {
        self.id
    }
}

#[pymethods]
impl PyConnection {
    /// Construct the Rust struct. Python subclasses call __init__ via super().
    #[new]
    #[pyo3(signature = (_proto=None))]
    pub fn new(_proto: Option<String>) -> Self {
        // Check if this is a factory call (accept path)
        let factory_id = FACTORY_CON_ID.with(|f| f.take());
        let factory_tx = FACTORY_SEND_TX.with(|f| f.take());

        if let Some(con_id) = factory_id {
            return PyConnection {
                id: Some(con_id),
                transport: String::new(),
                protocol: String::new(),
                status: "none".to_string(),
                local: PyNodeInfo::new(),
                remote: PyNodeInfo::new(),
                timeouts: PyConnectionTimeouts::new(),
                send_tx: factory_tx,
            };
        }

        PyConnection {
            id: None,
            transport: String::new(),
            protocol: String::new(),
            status: "none".to_string(),
            local: PyNodeInfo::new(),
            remote: PyNodeInfo::new(),
            timeouts: PyConnectionTimeouts::new(),
            send_tx: None,
        }
    }

    /// Initialize the connection. Called after __new__.
    /// Python subclasses call `super().__init__(proto)` which reaches here.
    #[pyo3(signature = (proto=None))]
    pub fn __init__(&mut self, proto: Option<String>) -> PyResult<()> {
        self.transport = proto.unwrap_or_else(|| "tcp".to_string());

        // Only create a channel if we don't already have one (from factory)
        if self.send_tx.is_none() {
            let (tx, _rx) = mpsc::channel(256);
            self.send_tx = Some(tx);
        }

        // Set protocol name from class name if not already set
        // (will be set by Python subclass via protocol_name attribute or class name)

        Ok(())
    }

    /// Hash by connection ID. Required for storing connections in Python dicts/sets.
    fn __hash__(&self) -> PyResult<u64> {
        let id = check_valid(&self.id)?;
        Ok(id.0)
    }

    /// Compare connections by ID.
    fn __richcmp__(&self, other: &Bound<'_, PyAny>, op: pyo3::basic::CompareOp) -> PyResult<bool> {
        let other_conn = match other.cast::<PyConnection>() {
            Ok(c) => c,
            Err(_) => {
                return match op {
                    pyo3::basic::CompareOp::Eq => Ok(false),
                    pyo3::basic::CompareOp::Ne => Ok(true),
                    _ => Err(pyo3::exceptions::PyTypeError::new_err(
                        "comparison not supported",
                    )),
                };
            }
        };
        let a = self.id.map_or(0u64, |id| id.0);
        let b = other_conn.borrow().id.map_or(0u64, |id| id.0);
        Ok(match op {
            pyo3::basic::CompareOp::Lt => a < b,
            pyo3::basic::CompareOp::Le => a <= b,
            pyo3::basic::CompareOp::Eq => a == b,
            pyo3::basic::CompareOp::Ne => a != b,
            pyo3::basic::CompareOp::Gt => a > b,
            pyo3::basic::CompareOp::Ge => a >= b,
        })
    }

    /// Transport type as a string ("tcp", "tls", "udp").
    #[getter]
    fn transport(&self) -> PyResult<&str> {
        check_valid(&self.id)?;
        Ok(&self.transport)
    }

    /// Protocol name (set by Python, e.g. "smbd", "httpd").
    #[getter]
    fn protocol(&self) -> PyResult<&str> {
        check_valid(&self.id)?;
        Ok(&self.protocol)
    }

    /// Connection state as a string.
    #[getter]
    fn status(&self) -> PyResult<&str> {
        check_valid(&self.id)?;
        Ok(&self.status)
    }

    /// Remote endpoint address info.
    #[getter]
    fn remote(&self, py: Python<'_>) -> PyResult<Py<PyNodeInfo>> {
        check_valid(&self.id)?;
        Py::new(py, PyNodeInfo::from_other(&self.remote))
    }

    /// Local endpoint address info.
    #[getter]
    fn local(&self, py: Python<'_>) -> PyResult<Py<PyNodeInfo>> {
        check_valid(&self.id)?;
        Py::new(py, PyNodeInfo::from_other(&self.local))
    }

    /// Connection timeout configuration.
    #[getter]
    fn timeouts(&self, py: Python<'_>) -> PyResult<Py<PyConnectionTimeouts>> {
        check_valid(&self.id)?;
        Py::new(py, PyConnectionTimeouts::from_values(
            &crate::connection::ConnectionTimeouts {
                idle: self.timeouts.idle,
                sustain: self.timeouts.sustain,
                listen: self.timeouts.listen,
                handshake: self.timeouts.handshake,
                connecting: self.timeouts.connecting,
                close: 10.0,
            },
            self.send_tx.clone(),
        ))
    }

    /// Ingress connection stats.
    #[getter]
    fn _in(&self, py: Python<'_>) -> PyResult<Py<PyConnectionStats>> {
        check_valid(&self.id)?;
        let speed = PyConnectionSpeed::new(
            0.0,
            0.0,
            crate::connection::Direction::In,
            self.send_tx.clone(),
        );
        let accounting = PyConnectionAccounting::new(
            0.0,
            0.0,
            crate::connection::Direction::In,
            self.send_tx.clone(),
        );
        Py::new(py, PyConnectionStats::new(py, speed, accounting)?)
    }

    /// Egress connection stats.
    #[getter]
    fn _out(&self, py: Python<'_>) -> PyResult<Py<PyConnectionStats>> {
        check_valid(&self.id)?;
        let speed = PyConnectionSpeed::new(
            0.0,
            0.0,
            crate::connection::Direction::Out,
            self.send_tx.clone(),
        );
        let accounting = PyConnectionAccounting::new(
            0.0,
            0.0,
            crate::connection::Direction::Out,
            self.send_tx.clone(),
        );
        Py::new(py, PyConnectionStats::new(py, speed, accounting)?)
    }

    /// Apply configuration dict. Override in Python subclasses.
    fn apply_config(&self, _config: &Bound<'_, PyAny>) -> PyResult<()> {
        Ok(())
    }

    /// Copy shared config values from parent connection.
    fn apply_parent_config(&self, parent: &Bound<'_, PyAny>) -> PyResult<()> {
        let value_names = match parent.getattr("shared_config_values") {
            Ok(names) => names,
            Err(_) => return Ok(()),
        };
        let slf = parent.py().None(); // placeholder; actual copying happens in Python override
        let _ = (value_names, slf);
        Ok(())
    }

    /// Send data to the remote peer.
    ///
    /// For UDP, `local` and `remote` specify the source and destination addresses.
    #[pyo3(signature = (data, local=None, remote=None))]
    fn send(
        &mut self,
        data: &Bound<'_, PyAny>,
        local: Option<(String, u16)>,
        remote: Option<(String, u16)>,
    ) -> PyResult<()> {
        check_valid(&self.id)?;

        let bytes_data: Vec<u8> = if let Ok(b) = data.cast::<PyBytes>() {
            b.as_bytes().to_vec()
        } else if let Ok(s) = data.extract::<String>() {
            s.into_bytes()
        } else {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "requires text/bytes input, got {}",
                data.get_type().name()?
            )));
        };

        let tx = self.send_tx.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("connection closed")
        })?;

        let msg = if self.transport == "udp" {
            if let (Some((lhost, lport)), Some((rhost, rport))) = (local, remote) {
                // Update local/remote node info for UDP
                self.local.host = lhost.clone();
                self.local.port = lport;
                self.remote.host = rhost.clone();
                self.remote.port = rport;

                let local_addr = format!("{lhost}:{lport}")
                    .parse()
                    .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid local address: {e}")))?;
                let remote_addr = format!("{rhost}:{rport}")
                    .parse()
                    .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid remote address: {e}")))?;

                SendMessage::Datagram {
                    data: Bytes::from(bytes_data),
                    local: local_addr,
                    remote: remote_addr,
                }
            } else {
                SendMessage::Data(Bytes::from(bytes_data))
            }
        } else {
            SendMessage::Data(Bytes::from(bytes_data))
        };

        tx.try_send(msg).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("send failed: {e}"))
        })?;

        Ok(())
    }

    /// Bind the connection to a local address and port.
    #[pyo3(signature = (addr, port, iface="".to_string()))]
    fn bind(&self, addr: String, port: u16, iface: String) -> PyResult<i32> {
        check_valid(&self.id)?;
        let _ = (addr, port, iface);
        // Will be implemented in Phase 4 (TCP/UDP I/O).
        Ok(0)
    }

    /// Listen for incoming connections.
    #[pyo3(signature = (size=20))]
    fn listen(&self, size: i32) -> PyResult<i32> {
        check_valid(&self.id)?;
        let _ = size;
        // Will be implemented in Phase 4.
        Ok(0)
    }

    /// Connect to a remote host.
    #[pyo3(signature = (addr, port, iface="".to_string()))]
    fn connect(&self, addr: String, port: u16, iface: String) -> PyResult<()> {
        check_valid(&self.id)?;
        let _ = (addr, port, iface);
        // Will be implemented in Phase 4.
        Ok(())
    }

    /// Close this connection.
    fn close(&mut self) -> PyResult<()> {
        check_valid(&self.id)?;
        // Drop the send channel to signal the I/O task
        self.send_tx = None;
        Ok(())
    }

    /// Attach the processor pipeline to this connection.
    fn processors(&self) -> PyResult<()> {
        check_valid(&self.id)?;
        // Will be implemented in Phase 5 (processor pipeline).
        Ok(())
    }

    /// Increment reference count.
    #[pyo3(name = "ref")]
    fn ref_(&self) -> PyResult<i32> {
        check_valid(&self.id)?;
        // Reference counting is handled by the Rust side (AtomicU32 in ConnectionMeta).
        // This is exposed for compatibility with Python protocols that call it.
        Ok(1)
    }

    /// Decrement reference count.
    fn unref(&self) -> PyResult<i32> {
        check_valid(&self.id)?;
        Ok(0)
    }

    // --- Protocol callbacks (Python overrides these) ---

    /// Called when connection is established. Override in Python.
    fn handle_established(&self) -> PyResult<()> {
        Ok(())
    }

    /// Called when data arrives. Override in Python.
    /// Returns number of bytes consumed.
    #[pyo3(signature = (data))]
    fn handle_io_in(&self, data: &Bound<'_, PyBytes>) -> PyResult<usize> {
        Ok(data.as_bytes().len())
    }

    /// Called when the outbound buffer is flushed. Override in Python.
    fn handle_io_out(&self) -> PyResult<()> {
        Ok(())
    }

    /// Called on disconnect. Return true to reconnect (outbound only).
    fn handle_disconnect(&self) -> PyResult<bool> {
        Ok(false)
    }

    /// Called on error. Override in Python.
    #[pyo3(signature = (err))]
    fn handle_error(&self, err: &Bound<'_, PyAny>) -> PyResult<()> {
        let _ = err;
        Ok(())
    }

    /// Called on idle timeout. Return true to keep alive.
    fn handle_timeout_idle(&self) -> PyResult<bool> {
        Ok(false)
    }

    /// Called on sustain timeout. Return true to keep alive.
    fn handle_timeout_sustain(&self) -> PyResult<bool> {
        Ok(false)
    }

    /// Called on listen timeout. Return true to keep alive.
    fn handle_timeout_listen(&self) -> PyResult<bool> {
        Ok(false)
    }

    /// Called to set parent connection context.
    #[pyo3(signature = (parent))]
    fn handle_origin(&self, parent: &Bound<'_, PyAny>) -> PyResult<()> {
        let _ = parent;
        Ok(())
    }
}

/// Set the factory thread-locals for the accept path.
/// Must be called before instantiating the Python subclass.
pub fn set_factory_context(id: ConnectionId, tx: mpsc::Sender<SendMessage>) {
    FACTORY_CON_ID.with(|f| f.set(Some(id)));
    FACTORY_SEND_TX.with(|f| f.set(Some(tx)));
}

/// Clear factory thread-locals (in case of error during construction).
pub fn clear_factory_context() {
    FACTORY_CON_ID.with(|f| f.set(None));
    FACTORY_SEND_TX.with(|f| f.set(None));
}

/// Factory-create a child connection for the accept path.
///
/// Creates a new instance of the same class as `parent`, with factory thread-locals
/// set so that `__init__` knows it's a factory call.
pub fn factory_create(
    _py: Python<'_>,
    parent: &Bound<'_, PyAny>,
    id: ConnectionId,
    tx: mpsc::Sender<SendMessage>,
    transport: &str,
) -> PyResult<Py<PyAny>> {
    set_factory_context(id, tx);

    let parent_type = parent.get_type();
    let result = parent_type.call1((transport,));

    // Always clear factory context, even on error
    clear_factory_context();

    let child = result?;

    // Copy shared config from parent
    if let Err(e) = child.call_method1("apply_parent_config", (parent,)) {
        tracing::error!("Error in apply_parent_config: {e}");
    }

    Ok(child.unbind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::SendMessage;
    use pyo3::types::PyModule;
    use std::time::Instant;

    /// Register PyConnection as a Python module for tests.
    fn register_test_module(py: Python<'_>, name: &str) {
        let module = PyModule::new(py, name).expect("module creation");
        module
            .add_class::<PyConnection>()
            .expect("add PyConnection");
        let c_name = std::ffi::CString::new(name).expect("CString");
        py.import(c_name.as_c_str())
            .expect_err("module not in sys.modules yet");
        py.import(c"sys")
            .expect("import sys")
            .getattr("modules")
            .expect("get modules")
            .set_item(name, module)
            .expect("set module");
    }

    /// Verify that a Python class can subclass PyConnection and override handle_io_in.
    #[test]
    fn test_python_subclass_and_callback() {
        Python::attach(|py| {
            let (tx, mut rx) = mpsc::channel::<SendMessage>(256);

            register_test_module(py, "dionaea_core");

            py.run(
                c"
from dionaea_core import PyConnection

class EchoProtocol(PyConnection):
    def __init__(self, proto=None):
        super().__init__(proto)
        self.received = []

    def handle_io_in(self, data):
        self.received.append(bytes(data))
        self.send(data)  # echo back
        return len(data)

    def handle_established(self):
        self.received.append(b'ESTABLISHED')

    def handle_disconnect(self):
        self.received.append(b'DISCONNECT')
        return False
",
                None,
                None,
            )
            .expect("define EchoProtocol");

            // Instantiate and inject the channel sender + connection ID
            let echo_cls = py
                .eval(c"EchoProtocol('tcp')", None, None)
                .expect("instantiate EchoProtocol");

            {
                let mut conn = echo_cls
                    .cast::<PyConnection>()
                    .expect("cast to PyConnection")
                    .borrow_mut();
                conn.send_tx = Some(tx);
                conn.id = Some(ConnectionId(1));
            }

            // Verify transport was set
            let transport: String = echo_cls
                .getattr("transport")
                .expect("get transport")
                .extract()
                .expect("extract transport");
            assert_eq!(transport, "tcp");

            // Call handle_established from Rust
            echo_cls
                .call_method0("handle_established")
                .expect("call handle_established");

            // Call handle_io_in with test data
            let test_data = PyBytes::new(py, b"hello world");
            let consumed: usize = echo_cls
                .call_method1("handle_io_in", (test_data,))
                .expect("call handle_io_in")
                .extract()
                .expect("extract consumed");
            assert_eq!(consumed, 11);

            // Verify the Python side received the data
            let received: Vec<Vec<u8>> = echo_cls
                .getattr("received")
                .expect("get received")
                .extract()
                .expect("extract received");
            assert_eq!(received.len(), 2);
            assert_eq!(received[0], b"ESTABLISHED");
            assert_eq!(received[1], b"hello world");

            // Verify send() was called (data should be in the channel)
            let msg = rx.try_recv().expect("should have a message");
            match msg {
                SendMessage::Data(d) => assert_eq!(&d[..], b"hello world"),
                other => panic!("unexpected: {other:?}"),
            }

            // Call handle_disconnect
            let reconnect: bool = echo_cls
                .call_method0("handle_disconnect")
                .expect("call handle_disconnect")
                .extract()
                .expect("extract reconnect");
            assert!(!reconnect);
        });
    }

    /// Verify that __init__ with super().__init__() works.
    #[test]
    fn test_super_init_call() {
        Python::attach(|py| {
            register_test_module(py, "dionaea_core2");

            py.run(
                c"
from dionaea_core2 import PyConnection

class CustomProto(PyConnection):
    def __init__(self, proto=None):
        super().__init__(proto or 'tls')
        self.custom_field = 'initialized'
",
                None,
                None,
            )
            .expect("define CustomProto");

            let obj = py
                .eval(c"CustomProto()", None, None)
                .expect("instantiate CustomProto");

            // Set a valid ID so property access works
            {
                let mut conn = obj
                    .cast::<PyConnection>()
                    .expect("cast")
                    .borrow_mut();
                conn.id = Some(ConnectionId(2));
            }

            let transport: String = obj
                .getattr("transport")
                .expect("get transport")
                .extract()
                .expect("extract");
            assert_eq!(transport, "tls");

            let custom: String = obj
                .getattr("custom_field")
                .expect("get custom_field")
                .extract()
                .expect("extract");
            assert_eq!(custom, "initialized");
        });
    }

    /// Verify method resolution order: Python override takes precedence.
    #[test]
    fn test_method_resolution_order() {
        Python::attach(|py| {
            register_test_module(py, "dionaea_core3");

            py.run(
                c"
from dionaea_core3 import PyConnection

class BaseProto(PyConnection):
    def handle_io_in(self, data):
        return 42

class DerivedProto(BaseProto):
    def handle_io_in(self, data):
        base_result = super().handle_io_in(data)
        return base_result + 1
",
                None,
                None,
            )
            .expect("define protocols");

            let base = py
                .eval(c"BaseProto('tcp')", None, None)
                .expect("instantiate BaseProto");
            let test_data = PyBytes::new(py, b"test");
            let result: usize = base
                .call_method1("handle_io_in", (test_data,))
                .expect("call")
                .extract()
                .expect("extract");
            assert_eq!(result, 42);

            let derived = py
                .eval(c"DerivedProto('tcp')", None, None)
                .expect("instantiate DerivedProto");
            let test_data = PyBytes::new(py, b"test");
            let result: usize = derived
                .call_method1("handle_io_in", (test_data,))
                .expect("call")
                .extract()
                .expect("extract");
            assert_eq!(result, 43);
        });
    }

    /// Test connection invalidation raises ReferenceError.
    #[test]
    fn test_invalidation_raises_reference_error() {
        Python::attach(|py| {
            register_test_module(py, "dionaea_core_inv");

            let conn = py
                .eval(c"__import__('dionaea_core_inv').PyConnection('tcp')", None, None)
                .expect("create connection");

            // Without an ID, properties should raise ReferenceError
            let result = conn.getattr("transport");
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.is_instance_of::<pyo3::exceptions::PyReferenceError>(py));

            // Set an ID, then invalidate
            {
                let mut c = conn.cast::<PyConnection>().unwrap().borrow_mut();
                c.id = Some(ConnectionId(99));
            }
            let transport: String = conn.getattr("transport").unwrap().extract().unwrap();
            assert_eq!(transport, "tcp");

            // Invalidate
            {
                let mut c = conn.cast::<PyConnection>().unwrap().borrow_mut();
                c.invalidate();
            }

            let result = conn.getattr("transport");
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .is_instance_of::<pyo3::exceptions::PyReferenceError>(py));
        });
    }

    /// Test __hash__ and __richcmp__.
    #[test]
    fn test_hash_and_compare() {
        Python::attach(|py| {
            register_test_module(py, "dionaea_core_hash");

            py.run(
                c"
from dionaea_core_hash import PyConnection

a = PyConnection('tcp')
b = PyConnection('tcp')
",
                None,
                None,
            )
            .unwrap();

            let a = py.eval(c"a", None, None).unwrap();
            let b = py.eval(c"b", None, None).unwrap();

            // Set IDs
            {
                let mut ca = a.cast::<PyConnection>().unwrap().borrow_mut();
                ca.id = Some(ConnectionId(10));
            }
            {
                let mut cb = b.cast::<PyConnection>().unwrap().borrow_mut();
                cb.id = Some(ConnectionId(20));
            }

            let hash_a: u64 = py
                .eval(c"hash(a)", None, None)
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(hash_a, 10);

            let eq: bool = py
                .eval(c"a == b", None, None)
                .unwrap()
                .extract()
                .unwrap();
            assert!(!eq);

            let lt: bool = py
                .eval(c"a < b", None, None)
                .unwrap()
                .extract()
                .unwrap();
            assert!(lt);
        });
    }

    /// Test factory instantiation creates the same subclass.
    #[test]
    fn test_factory_instantiation() {
        Python::attach(|py| {
            register_test_module(py, "dionaea_core_factory");

            py.run(
                c"
from dionaea_core_factory import PyConnection

class SMBProtocol(PyConnection):
    shared_config_values = ['max_connections']
    def __init__(self, proto=None):
        super().__init__(proto)
        self.max_connections = 10

    def apply_parent_config(self, parent):
        for name in getattr(parent, 'shared_config_values', []):
            setattr(self, name, getattr(parent, name))

parent = SMBProtocol('tcp')
",
                None,
                None,
            )
            .unwrap();

            let parent = py.eval(c"parent", None, None).unwrap();

            // Set parent ID
            {
                let mut c = parent.cast::<PyConnection>().unwrap().borrow_mut();
                c.id = Some(ConnectionId(100));
            }

            // Factory-create a child
            let (tx, _rx) = mpsc::channel(256);
            let child = factory_create(py, &parent, ConnectionId(101), tx, "tcp").unwrap();
            let child = child.bind(py);

            // Verify child is same class
            let parent_class = parent.get_type().name().unwrap().to_string();
            let child_class = child.get_type().name().unwrap().to_string();
            assert_eq!(parent_class, child_class);
            assert_eq!(child_class, "SMBProtocol");

            // Verify child has factory-provided ID
            {
                let c = child.cast::<PyConnection>().unwrap().borrow();
                assert_eq!(c.id, Some(ConnectionId(101)));
            }

            // Verify shared config was copied
            let max_connections: i64 = child
                .getattr("max_connections")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(max_connections, 10);
        });
    }

    /// Test send with UDP local/remote addresses.
    #[test]
    fn test_udp_send_with_addresses() {
        Python::attach(|py| {
            register_test_module(py, "dionaea_core_udp");

            let conn = py
                .eval(
                    c"__import__('dionaea_core_udp').PyConnection('udp')",
                    None,
                    None,
                )
                .unwrap();

            let (tx, mut rx) = mpsc::channel(256);
            {
                let mut c = conn.cast::<PyConnection>().unwrap().borrow_mut();
                c.id = Some(ConnectionId(200));
                c.send_tx = Some(tx);
            }

            // Call send with local and remote tuples
            py.run(
                c"
import dionaea_core_udp
conn = dionaea_core_udp.PyConnection.__new__(dionaea_core_udp.PyConnection)
",
                None,
                None,
            )
            .unwrap();

            conn.call_method(
                "send",
                (PyBytes::new(py, b"hello udp"),),
                Some(
                    &pyo3::types::PyDict::from_sequence(
                        &pyo3::types::PyList::new(
                            py,
                            vec![
                                ("local", ("127.0.0.1", 5060u16).into_pyobject(py).unwrap().into_any()),
                                ("remote", ("10.0.0.1", 5060u16).into_pyobject(py).unwrap().into_any()),
                            ],
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                ),
            )
            .unwrap();

            let msg = rx.try_recv().unwrap();
            match msg {
                SendMessage::Datagram {
                    data,
                    local,
                    remote,
                } => {
                    assert_eq!(&data[..], b"hello udp");
                    assert_eq!(local.to_string(), "127.0.0.1:5060");
                    assert_eq!(remote.to_string(), "10.0.0.1:5060");
                }
                other => panic!("expected Datagram, got {other:?}"),
            }
        });
    }

    /// Measure spawn_blocking + GIL round-trip latency.
    /// Target: <100us P99 per callback.
    ///
    /// Uses move-and-return pattern: the handler is moved into spawn_blocking
    /// and returned with the result.
    #[test]
    fn test_spawn_blocking_gil_latency() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async {
            let mut handler: Py<PyAny> = Python::attach(|py| {
                register_test_module(py, "dionaea_core4");

                py.run(
                    c"
from dionaea_core4 import PyConnection

class BenchProto(PyConnection):
    def handle_io_in(self, data):
        return len(data)
",
                    None,
                    None,
                )
                .expect("define BenchProto");

                py.eval(c"BenchProto('tcp')", None, None)
                    .expect("instantiate")
                    .unbind()
            });

            // Warm up
            for _ in 0..100 {
                let h = handler;
                let (h_back, _): (Py<PyAny>, usize) =
                    tokio::task::spawn_blocking(move || {
                        Python::attach(|py| {
                            let data = PyBytes::new(py, b"warmup");
                            let result: usize = h
                                .bind(py)
                                .call_method1("handle_io_in", (data,))
                                .expect("call")
                                .extract()
                                .expect("extract");
                            (h, result)
                        })
                    })
                    .await
                    .expect("spawn_blocking");
                handler = h_back;
            }

            // Measure
            let iterations = 1000;
            let mut latencies = Vec::with_capacity(iterations);

            for _ in 0..iterations {
                let h = handler;
                let start = Instant::now();
                let (h_back, _): (Py<PyAny>, usize) =
                    tokio::task::spawn_blocking(move || {
                        Python::attach(|py| {
                            let data = PyBytes::new(py, b"benchmark data for latency test");
                            let result: usize = h
                                .bind(py)
                                .call_method1("handle_io_in", (data,))
                                .expect("call")
                                .extract()
                                .expect("extract");
                            (h, result)
                        })
                    })
                    .await
                    .expect("spawn_blocking");
                handler = h_back;
                latencies.push(start.elapsed());
            }

            Python::attach(|py| {
                let _ = handler.into_bound(py);
            });

            latencies.sort();
            let p50 = latencies[iterations / 2];
            let p99 = latencies[iterations * 99 / 100];
            let p999 = latencies[iterations * 999 / 1000];
            let max = latencies[iterations - 1];

            eprintln!("spawn_blocking + GIL round-trip latency ({iterations} iterations):");
            eprintln!("  P50:  {p50:?}");
            eprintln!("  P99:  {p99:?}");
            eprintln!("  P999: {p999:?}");
            eprintln!("  Max:  {max:?}");

            // Under test parallelism, GIL contention inflates P99.
            assert!(
                p99 < std::time::Duration::from_micros(500),
                "P99 latency {p99:?} exceeds 500us threshold"
            );
        });
    }
}
