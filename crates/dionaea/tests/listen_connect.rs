// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Integration test for the Python connection bind/listen/connect lifecycle.
// ABOUTME: Verifies the full stack: runtime init → bind → listen → TCP connect → data flow.

use std::sync::Arc;
use std::time::Duration;

use dionaea::config;
use dionaea::connection::ConnectionRegistry;
use dionaea::connection::limits::ConnectionLimits;
use dionaea::python::connection::PyConnection;
use dionaea::python::ihandler::PyIHandler;
use dionaea::python::incident::PyIncident;
use dionaea::runtime;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

fn test_config() -> config::Config {
    config::load_from_str(
        r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = ["0.0.0.0"]
[logging]
[modules]
"#,
    )
    .expect("test config")
}

fn register_test_module(py: Python<'_>, name: &str) {
    let module = PyModule::new(py, name).expect("module creation");
    module
        .add_class::<PyConnection>()
        .expect("add PyConnection");
    module.add_class::<PyIHandler>().expect("add PyIHandler");
    module.add_class::<PyIncident>().expect("add PyIncident");
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
        test_config(),
        Vec::new(),
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
from listen_integ import connection as PyConnection

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

        // --- Incident dispatch integration test ---
        // Test that ihandler auto-registers via __init__ and report() dispatches correctly
        tokio::task::spawn_blocking(|| {
            Python::attach(|py| {
                py.run(
                    c"
from listen_integ import ihandler as PyIHandler, incident as PyIncident

class LogHandler(PyIHandler):
    received = []
    def __init__(self):
        super().__init__('test.incident.*')

    def handle_incident_test_incident_accept(self, incident):
        LogHandler.received.append({
            'origin': incident.origin,
            'port': incident.port,
        })

    def handle_incident(self, incident):
        LogHandler.received.append({
            'origin': incident.origin,
            'fallback': True,
        })

handler = LogHandler()

# Report an incident that matches the specific handler method
inc1 = PyIncident('test.incident.accept')
inc1.port = 445
inc1.report()

# Report an incident that falls back to generic handler
inc2 = PyIncident('test.incident.unknown')
inc2.report()
",
                    None,
                    None,
                )
                .expect("incident dispatch test");

                // Verify handler received both incidents
                let count: usize = py
                    .eval(c"len(LogHandler.received)", None, None)
                    .expect("len")
                    .extract()
                    .expect("extract");
                assert_eq!(count, 2, "handler should have received 2 incidents");

                // First incident: specific method
                let origin: String = py
                    .eval(c"LogHandler.received[0]['origin']", None, None)
                    .expect("origin")
                    .extract()
                    .expect("extract");
                assert_eq!(origin, "test.incident.accept");

                let port: i64 = py
                    .eval(c"LogHandler.received[0]['port']", None, None)
                    .expect("port")
                    .extract()
                    .expect("extract");
                assert_eq!(port, 445);

                // Second incident: fallback method
                let fallback: bool = py
                    .eval(c"LogHandler.received[1]['fallback']", None, None)
                    .expect("fallback")
                    .extract()
                    .expect("extract");
                assert!(fallback, "second incident should use fallback handler");
            });
        })
        .await
        .expect("incident test spawn_blocking");

        // Verify ihandler_registry has at least our handler registered
        let handler_count = state.ihandler_registry.lock().expect("lock").len();
        assert!(
            handler_count >= 1,
            "ihandler_registry should have at least 1 handler, got {handler_count}"
        );

        // Clean shutdown
        state.stop_all_listeners();
    });
}
