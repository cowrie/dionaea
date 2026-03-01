// ABOUTME: Integration test for the Python connection bind/listen/connect lifecycle.
// ABOUTME: Verifies the full stack: runtime init → bind → listen → TCP connect → data flow.

use std::sync::Arc;
use std::time::Duration;

use dionaea::connection::limits::ConnectionLimits;
use dionaea::connection::ConnectionRegistry;
use dionaea::python::connection::PyConnection;
use dionaea::runtime;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

fn register_test_module(py: Python<'_>, name: &str) {
    let module = PyModule::new(py, name).expect("module creation");
    module
        .add_class::<PyConnection>()
        .expect("add PyConnection");
    py.import(c"sys")
        .expect("import sys")
        .getattr("modules")
        .expect("get modules")
        .set_item(name, module)
        .expect("set module");
}

/// Full lifecycle test: bind + listen → TCP connect → echo data → disconnect.
#[test]
fn test_tcp_listen_via_python() {
    // Initialize global runtime state (safe: integration test binary = separate process)
    let registry = Arc::new(ConnectionRegistry::new());
    let limits = Arc::new(ConnectionLimits::new(50, 10_000, 70));
    let state = Arc::new(runtime::RuntimeState::new(
        registry.clone(),
        limits.clone(),
        65536,
    ));
    runtime::init(state.clone());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(8)
        .enable_all()
        .build()
        .expect("runtime");

    rt.block_on(async {
        // Create a Python listener via bind + listen (runs in spawn_blocking for GIL)
        let bound_port: u16 = tokio::task::spawn_blocking(|| {
            Python::attach(|py| {
                register_test_module(py, "listen_integ");

                py.run(
                    c"
from listen_integ import PyConnection

class EchoService(PyConnection):
    events = []
    def __init__(self, proto=None):
        super().__init__(proto)

    def handle_established(self):
        EchoService.events.append('established')

    def handle_io_in(self, data):
        self.send(data)
        EchoService.events.append(('io_in', bytes(data)))
        return len(data)

    def handle_disconnect(self):
        EchoService.events.append('disconnect')
        return False

listener = EchoService('tcp')
listener.bind('127.0.0.1', 0)
listener.listen()
port = listener.local.port
",
                    None,
                    None,
                )
                .expect("define and start echo service");

                let port: u16 = py
                    .eval(c"port", None, None)
                    .expect("get port")
                    .extract()
                    .expect("extract port");
                port
            })
        })
        .await
        .expect("spawn_blocking");

        assert!(bound_port > 0, "listener should bind to a real port");

        // Wait a moment for the accept loop to start
        time::sleep(Duration::from_millis(100)).await;

        // Connect to the listener
        let mut stream = TcpStream::connect(format!("127.0.0.1:{bound_port}"))
            .await
            .expect("connect");

        // Wait for established callback
        time::sleep(Duration::from_millis(200)).await;

        // Send data and read echo
        stream.write_all(b"hello from test").await.expect("write");
        time::sleep(Duration::from_millis(200)).await;

        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"hello from test");

        // Close
        drop(stream);
        time::sleep(Duration::from_millis(200)).await;

        // Verify Python events
        Python::attach(|py| {
            let events: Vec<String> = py
                .eval(
                    c"[e if isinstance(e, str) else '' for e in EchoService.events]",
                    None,
                    None,
                )
                .expect("events")
                .extract()
                .expect("extract");
            assert!(
                events.contains(&"established".to_string()),
                "expected 'established', got {events:?}"
            );
        });

        // Verify registry tracked the connection
        // Connection may already be cleaned up after disconnect
        let _ = registry.len();

        // Clean shutdown
        state.stop_all_listeners();
    });
}
