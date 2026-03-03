// ABOUTME: Integration test loading the real http.py Python protocol module.
// ABOUTME: Verifies HTTP GET against a temp directory with a static HTML file.

use std::sync::Arc;
use std::time::Duration;

use dionaea::config;
use dionaea::connection::limits::ConnectionLimits;
use dionaea::connection::ConnectionRegistry;
use dionaea::runtime;
use pyo3::prelude::*;
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
level = "debug"
[modules]
"#,
    )
    .expect("test config")
}

/// Load the real http.py protocol, serve a static HTML file, verify HTTP GET response.
#[test]
fn test_real_http_get() {
    let registry = Arc::new(ConnectionRegistry::new());
    let limits = Arc::new(ConnectionLimits::new(50, 10_000, 70));
    let state = Arc::new(runtime::RuntimeState::new(
        registry.clone(),
        limits.clone(),
        65536,
        test_config(),
    ));
    runtime::init(state.clone());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(8)
        .enable_all()
        .build()
        .expect("runtime");

    rt.block_on(async {
        // Create a temp directory with a simple HTML file
        let tmp_dir = std::env::temp_dir().join("dionaea_http_test");
        let _ = std::fs::create_dir_all(&tmp_dir);
        std::fs::write(
            tmp_dir.join("index.html"),
            "<html><body>Hello from Dionaea!</body></html>",
        )
        .expect("write index.html");

        let python_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../modules/python")
            .canonicalize()
            .expect("modules/python/ should exist");

        let tmp_dir_str = tmp_dir.to_string_lossy().to_string();

        let bound_port: u16 = tokio::task::spawn_blocking(move || {
            Python::attach(|py| {
                // Register dionaea.core
                dionaea::python::loader::load(
                    py,
                    &config::PythonModuleConfig {
                        imports: vec![],
                        service_configs: vec![],
                        ihandler_configs: vec![],
                        python_path: Some(python_path),
                    },
                )
                .expect("loader init");

                // Import and instantiate HTTP protocol
                let code = format!(
                    r#"
from dionaea.http import httpd

h = httpd(proto='tcp')
h.root = '{}'
h.bind('127.0.0.1', 0)
h.listen()
port = h.local.port
"#,
                    tmp_dir_str.replace('\\', "\\\\").replace('\'', "\\'")
                );
                let c_code = std::ffi::CString::new(code).expect("CString");
                py.run(c_code.as_c_str(), None, None)
                    .expect("httpd setup");

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

        assert!(bound_port > 0, "HTTP listener should bind to a real port");

        // Wait for accept loop
        time::sleep(Duration::from_millis(100)).await;

        // Connect and send HTTP GET
        let mut stream = TcpStream::connect(format!("127.0.0.1:{bound_port}"))
            .await
            .expect("connect to httpd");

        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write GET");

        // Read response
        let mut response = Vec::new();
        let mut buf = vec![0u8; 4096];

        // Read until connection closes or timeout
        loop {
            match time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
                Ok(Ok(0)) => break,           // Connection closed
                Ok(Ok(n)) => response.extend_from_slice(&buf[..n]),
                Ok(Err(_)) => break,          // Read error
                Err(_) => break,              // Timeout
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.contains("HTTP/1.1 200"),
            "expected 200 OK, got: {response_str}"
        );
        assert!(
            response_str.contains("Hello from Dionaea!"),
            "expected HTML body in response, got: {response_str}"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);
        state.stop_all_listeners();
    });
}
