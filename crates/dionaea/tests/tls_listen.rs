// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: Integration test for TLS listen from Python.
// ABOUTME: Verifies that httpd with proto='tls' can accept HTTPS connections.

use std::sync::Arc;
use std::time::Duration;

use dionaea::config;
use dionaea::connection::limits::ConnectionLimits;
use dionaea::connection::ConnectionRegistry;
use dionaea::runtime;
use pyo3::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// Test that a Python protocol with transport "tls" can listen and serve HTTPS.
#[test]
fn test_tls_listen_via_python() {
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

        // Create temp HTTP root
        let tmp_dir = std::env::temp_dir().join("dionaea_tls_listen_test");
        let _ = std::fs::create_dir_all(&tmp_dir);
        std::fs::write(
            tmp_dir.join("index.html"),
            "<html><body>TLS works!</body></html>",
        )
        .expect("write index.html");

        let tmp_dir_str = tmp_dir.to_string_lossy().to_string();

        let bound_port: u16 = tokio::task::spawn_blocking(move || {
            Python::attach(|py| {
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

                let code = format!(
                    r#"
from dionaea.http import httpd

h = httpd(proto='tls')
h.root = '{}'
h.bind('127.0.0.1', 0)
h.listen()
port = h.local.port
"#,
                    tmp_dir_str.replace('\\', "\\\\").replace('\'', "\\'")
                );
                let c_code = std::ffi::CString::new(code).expect("CString");
                py.run(c_code.as_c_str(), None, None)
                    .expect("httpd tls setup");

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

        assert!(bound_port > 0, "TLS listener should bind to a real port");
        time::sleep(Duration::from_millis(100)).await;

        // Connect with a TLS client (skip cert verification — self-signed)
        let tcp_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{bound_port}"))
            .await
            .expect("tcp connect");

        let mut connector_builder =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).expect("connector");
        connector_builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
        let connector = connector_builder.build();

        let ssl = connector
            .configure()
            .expect("configure")
            .into_ssl("localhost")
            .expect("ssl");
        let mut tls_stream =
            tokio_openssl::SslStream::new(ssl, tcp_stream).expect("ssl stream");

        let pinned = std::pin::Pin::new(&mut tls_stream);
        pinned.connect().await.expect("tls connect");

        time::sleep(Duration::from_millis(100)).await;

        // Send HTTP GET over TLS
        tls_stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write GET");

        // Read response
        let mut response = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            match time::timeout(Duration::from_secs(3), tls_stream.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => response.extend_from_slice(&buf[..n]),
                Ok(Err(_)) | Err(_) => break,
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.contains("HTTP/1.1 200"),
            "expected 200 OK over TLS, got: {response_str}"
        );
        assert!(
            response_str.contains("TLS works!"),
            "expected HTML body over TLS, got: {response_str}"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);
        state.stop_all_listeners();
    });
}
