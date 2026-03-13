// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Integration test verifying accepted connections have correct addresses.
// ABOUTME: Ensures the Python handler's local/remote fields reflect actual socket endpoints.

use std::sync::Arc;
use std::time::Duration;

use dionaea::config;
use dionaea::connection::limits::ConnectionLimits;
use dionaea::connection::ConnectionRegistry;
use dionaea::runtime;
use pyo3::prelude::*;
use tokio::io::AsyncWriteExt;
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

/// Verify that accepted connections have non-zero addresses on the Python handler.
///
/// A custom ihandler captures the connection object from the tcp.accept incident
/// and records its local/remote host and port. After connecting and disconnecting,
/// we check that the addresses are correct (not 0.0.0.0:0).
#[test]
fn test_accepted_connection_has_correct_addresses() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

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
        let python_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../modules/python")
            .canonicalize()
            .expect("modules/python/ should exist");

        let bound_port: u16 = tokio::task::spawn_blocking(move || {
            Python::attach(|py| {
                dionaea::python::loader::load(
                    py,
                    &config::PythonModuleConfig { python_path: Some(python_path), ..Default::default() },
                )
                .expect("loader init");

                py.run(
                    c"
from dionaea.core import ihandler, incident

# Ihandler that captures connection addresses from tcp.accept incidents
class AddressCapture(ihandler):
    captured = []
    def __init__(self):
        ihandler.__init__(self, 'dionaea.connection.tcp.accept')
    def handle_incident(self, icd):
        con = icd.con
        AddressCapture.captured.append({
            'local_host': con.local.host,
            'local_port': con.local.port,
            'remote_host': con.remote.host,
            'remote_port': con.remote.port,
        })

addr_handler = AddressCapture()

from dionaea.echo import echo
e = echo(proto='tcp')
e.bind('127.0.0.1', 0)
e.listen()
port = e.local.port
",
                    None,
                    None,
                )
                .expect("setup");

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

        assert!(bound_port > 0);
        time::sleep(Duration::from_millis(100)).await;

        // Connect and disconnect
        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{bound_port}"))
                .await
                .expect("connect");
            time::sleep(Duration::from_millis(300)).await;
            stream.shutdown().await.ok();
        }
        time::sleep(Duration::from_millis(500)).await;

        // Check captured addresses
        let (local_host, local_port, remote_host, remote_port) =
            tokio::task::spawn_blocking(move || {
                Python::attach(|py| {
                    let captured: Vec<(String, u16, String, u16)> = py
                        .eval(
                            c"[(c['local_host'], c['local_port'], c['remote_host'], c['remote_port']) for c in AddressCapture.captured]",
                            None,
                            None,
                        )
                        .expect("captured")
                        .extract()
                        .expect("extract");

                    assert!(
                        !captured.is_empty(),
                        "AddressCapture should have captured at least one incident"
                    );
                    captured[0].clone()
                })
            })
            .await
            .expect("check");

        eprintln!("Captured: local={local_host}:{local_port} remote={remote_host}:{remote_port}");

        assert_eq!(local_host, "127.0.0.1", "local host should be 127.0.0.1");
        assert_eq!(local_port, bound_port, "local port should match listener");
        assert_eq!(remote_host, "127.0.0.1", "remote host should be 127.0.0.1");
        assert!(remote_port > 0, "remote port should be non-zero");

        state.stop_all_listeners();
    });
}
