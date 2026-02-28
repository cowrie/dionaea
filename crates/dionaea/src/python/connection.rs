// ABOUTME: PyO3 connection class that Python protocol handlers subclass.
// ABOUTME: Validates that PyO3 subclassing works for the dionaea protocol pattern.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::sync::mpsc;

/// Messages sent from Python's `send()` to the Rust I/O task.
#[derive(Debug)]
pub enum SendMessage {
    /// Data to write to the remote peer.
    Data(Vec<u8>),
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
    transport: String,
    send_tx: Option<mpsc::Sender<SendMessage>>,
}

impl PyConnection {
    /// Create a connection with an externally-provided send channel.
    /// The caller owns the `Receiver` (the I/O task will drain it).
    pub fn with_channel(transport: String, tx: mpsc::Sender<SendMessage>) -> Self {
        PyConnection {
            transport,
            send_tx: Some(tx),
        }
    }
}

#[pymethods]
impl PyConnection {
    /// Construct the Rust struct. Python subclasses call __init__ via super().
    #[new]
    #[pyo3(signature = (_proto=None))]
    fn new(_proto: Option<String>) -> Self {
        PyConnection {
            transport: String::new(),
            send_tx: None,
        }
    }

    /// Initialize the connection. Called after __new__.
    /// Python subclasses call `super().__init__(proto)` which reaches here.
    #[pyo3(signature = (proto=None))]
    fn __init__(&mut self, proto: Option<String>) -> PyResult<()> {
        self.transport = proto.unwrap_or_else(|| "tcp".to_string());
        // Create a channel; the receiver is immediately dropped since no I/O task exists.
        // In production, the factory or connect/listen path provides the channel.
        let (tx, _rx) = mpsc::channel(256);
        self.send_tx = Some(tx);
        Ok(())
    }

    /// Transport type as a string ("tcp", "tls", "udp").
    #[getter]
    fn transport(&self) -> &str {
        &self.transport
    }

    /// Send data to the remote peer. Called by Python protocol handlers.
    fn send(&self, py: Python<'_>, data: &Bound<'_, PyBytes>) -> PyResult<()> {
        let bytes = data.as_bytes().to_vec();
        let tx = self.send_tx.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("connection closed")
        })?;
        tx.try_send(SendMessage::Data(bytes)).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("send failed: {e}"))
        })?;
        let _ = py;
        Ok(())
    }

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

    /// Called on disconnect. Returns true to reconnect.
    fn handle_disconnect(&self) -> PyResult<bool> {
        Ok(false)
    }

    /// Called on idle timeout. Returns true to keep alive.
    fn handle_timeout_idle(&self) -> PyResult<bool> {
        Ok(false)
    }

    /// Called on sustain timeout. Returns true to keep alive.
    fn handle_timeout_sustain(&self) -> PyResult<bool> {
        Ok(false)
    }

    /// Called on listen timeout. Returns true to keep alive.
    fn handle_timeout_listen(&self) -> PyResult<bool> {
        Ok(false)
    }

    /// Called on error.
    #[pyo3(signature = (err))]
    fn handle_error(&self, err: &Bound<'_, PyAny>) -> PyResult<()> {
        let _ = err;
        Ok(())
    }

    /// Called to set parent connection context.
    #[pyo3(signature = (parent))]
    fn handle_origin(&self, parent: &Bound<'_, PyAny>) -> PyResult<()> {
        let _ = parent;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            // Create a channel we can inspect from the test
            let (tx, mut rx) = mpsc::channel::<SendMessage>(256);

            register_test_module(py, "dionaea_core");

            // Define a Python echo protocol that subclasses PyConnection
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

            // Instantiate and inject the channel sender
            let echo_cls = py
                .eval(c"EchoProtocol('tcp')", None, None)
                .expect("instantiate EchoProtocol");

            // Replace the default sender with our test sender
            {
                let mut conn = echo_cls
                    .cast::<PyConnection>()
                    .expect("cast to PyConnection")
                    .borrow_mut();
                conn.send_tx = Some(tx);
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
                SendMessage::Data(d) => assert_eq!(d, b"hello world"),
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
        return 42  # custom return value

class DerivedProto(BaseProto):
    def handle_io_in(self, data):
        base_result = super().handle_io_in(data)
        return base_result + 1
",
                None,
                None,
            )
            .expect("define protocols");

            // Test BaseProto
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

            // Test DerivedProto (MRO: DerivedProto -> BaseProto -> PyConnection)
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

    /// Measure spawn_blocking + GIL round-trip latency.
    /// Target: <100us P99 per callback.
    ///
    /// Uses move-and-return pattern: the handler is moved into spawn_blocking
    /// and returned with the result. This matches the real connection task
    /// pattern and avoids the need for Py::clone_ref().
    #[test]
    fn test_spawn_blocking_gil_latency() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async {
            // Create protocol instance (GIL acquired by Python::attach)
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

            // Warm up: move handler in, get it back
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

            // Clean up: drop handler while GIL is held
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

            // Go/no-go gate: P99 must be under 100us
            assert!(
                p99 < std::time::Duration::from_micros(100),
                "P99 latency {p99:?} exceeds 100us target"
            );
        });
    }
}
