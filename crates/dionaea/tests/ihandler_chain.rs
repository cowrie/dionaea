// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Integration test for the ihandler loading and dispatch chain.
// ABOUTME: Verifies that incidents flow from connections through to ihandler callbacks.

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
level = "debug"
[modules]
"#,
    )
    .expect("test config")
}

/// Test the full ihandler chain:
/// 1. A custom ihandler records all incidents matching `dionaea.connection.*`
/// 2. A real LogJsonHandler writes incidents to a JSON file
/// 3. An echo protocol generates connection lifecycle incidents
/// 4. Verify both handlers receive the incidents
#[test]
fn test_ihandler_chain_with_log_json() {
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

    let tmp_dir = std::env::temp_dir().join("dionaea_ihandler_test");
    let _ = std::fs::create_dir_all(&tmp_dir);
    let log_file = tmp_dir.join("incidents.json");
    let _ = std::fs::remove_file(&log_file);
    let log_file_str = log_file.to_string_lossy().to_string();

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

        let bound_port: u16 = tokio::task::spawn_blocking({
            let log_path = log_file_str.clone();
            move || {
                Python::attach(|py| {
                    dionaea::python::loader::load(
                        py,
                        &config::PythonModuleConfig { python_path: Some(python_path), ..Default::default() },
                    )
                    .expect("loader init");

                    let code = format!(
                        r#"
from dionaea.core import ihandler, incident

# Custom ihandler that records incident origins
class TestIHandler(ihandler):
    received = []
    def __init__(self):
        ihandler.__init__(self, "dionaea.connection.*")
    def handle_incident(self, icd):
        TestIHandler.received.append(icd.origin)

test_handler = TestIHandler()

# Real LogJsonHandler writing to a file
from dionaea.log_incident import LogJsonHandler
json_handler = LogJsonHandler("*", config={{
    "handlers": ["file://{log_path}"],
}})

# Echo protocol to generate connection incidents
from dionaea.echo import echo
e = echo()
e.bind('127.0.0.1', 0)
e.listen()
port = e.local.port
"#
                    );
                    let c_code = std::ffi::CString::new(code).expect("CString");
                    py.run(c_code.as_c_str(), None, None)
                        .expect("ihandler chain setup");

                    let port: u16 = py
                        .eval(c"port", None, None)
                        .expect("get port")
                        .extract()
                        .expect("extract port");
                    port
                })
            }
        })
        .await
        .expect("spawn_blocking");

        assert!(bound_port > 0, "echo listener should bind to a real port");
        time::sleep(Duration::from_millis(100)).await;

        // Connect and disconnect to trigger incidents
        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{bound_port}"))
                .await
                .expect("connect");
            time::sleep(Duration::from_millis(200)).await;
            stream.shutdown().await.ok();
        }
        time::sleep(Duration::from_millis(500)).await;

        // Verify the custom ihandler received incidents
        let (has_accept, has_free) = tokio::task::spawn_blocking(move || {
            Python::attach(|py| {
                let received: Vec<String> = py
                    .eval(c"TestIHandler.received", None, None)
                    .expect("received")
                    .extract()
                    .expect("extract");
                eprintln!("TestIHandler received: {received:?}");
                (
                    received.iter().any(|o| o == "dionaea.connection.tcp.accept"),
                    received.iter().any(|o| o == "dionaea.connection.free"),
                )
            })
        })
        .await
        .expect("check");

        assert!(has_accept, "ihandler should receive dionaea.connection.tcp.accept");
        assert!(has_free, "ihandler should receive dionaea.connection.free");

        // Verify the LogJsonHandler wrote incidents to the file
        let contents = std::fs::read_to_string(&log_file)
            .expect("read incident log file");

        assert!(!contents.is_empty(), "incident log file should not be empty");

        let has_accept_json = contents.lines().any(|l| l.contains("dionaea.connection.tcp.accept"));
        let has_free_json = contents.lines().any(|l| l.contains("dionaea.connection.free"));
        assert!(has_accept_json, "JSON log should contain tcp.accept: {contents}");
        assert!(has_free_json, "JSON log should contain connection.free: {contents}");

        // Verify each line is valid JSON with expected fields
        for line in contents.lines() {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("each line should be valid JSON");
            assert!(parsed.get("origin").is_some(), "JSON should have 'origin'");
            assert!(parsed.get("timestamp").is_some(), "JSON should have 'timestamp'");
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);
        state.stop_all_listeners();
    });
}
