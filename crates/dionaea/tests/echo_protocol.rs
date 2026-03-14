// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Integration test loading the real echo.py Python protocol module.
// ABOUTME: Verifies the full stack: runtime → loader → echo.py → TCP connect → data flow.

use std::sync::Arc;
use std::time::Duration;

use dionaea::config;
use dionaea::connection::ConnectionRegistry;
use dionaea::connection::limits::ConnectionLimits;
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
[modules]
"#,
    )
    .expect("test config")
}

/// Load the real echo.py protocol, bind/listen, connect, and verify behavior.
///
/// echo.py sends "welcome to reverse world!\n" on connect, then echoes
/// reversed data (minus first byte) + newline on each input.
#[test]
fn test_real_echo_protocol() {
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
        // Determine the path to modules/python/ relative to the project root
        let python_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../modules/python")
            .canonicalize()
            .expect("modules/python/ should exist");

        // Load dionaea.core, set sys.path, import echo.py, bind, listen
        let bound_port: u16 = tokio::task::block_in_place(|| {
            Python::attach(|py| {
                // Register dionaea.core in sys.modules
                dionaea::python::loader::load(
                    py,
                    &config::PythonModuleConfig {
                        python_path: Some(python_path),
                        ..Default::default()
                    },
                )
                .expect("loader init");

                // Import and instantiate echo protocol
                py.run(
                    c"
from dionaea.echo import echo

e = echo(proto='tcp')
e.bind('127.0.0.1', 0)
e.listen()
port = e.local.port
",
                    None,
                    None,
                )
                .expect("echo setup");

                let port: u16 = py
                    .eval(c"port", None, None)
                    .expect("get port")
                    .extract()
                    .expect("extract port");
                port
            })
        });

        assert!(bound_port > 0, "echo listener should bind to a real port");

        // Wait for accept loop to start
        time::sleep(Duration::from_millis(100)).await;

        // Connect to the echo server
        let mut stream = TcpStream::connect(format!("127.0.0.1:{bound_port}"))
            .await
            .expect("connect to echo");

        // Read the welcome message
        let mut buf = vec![0u8; 256];
        let n = time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("welcome timeout")
            .expect("welcome read");
        let welcome = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(
            welcome, "welcome to reverse world!\n",
            "expected welcome message, got: {welcome:?}"
        );

        // Send "hello\n" and read reversed response
        stream.write_all(b"hello\n").await.expect("write hello");
        time::sleep(Duration::from_millis(200)).await;

        let n = time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("echo timeout")
            .expect("echo read");
        let response = String::from_utf8_lossy(&buf[..n]);
        // echo.py: data[::-1][1:] + b'\n'
        // "hello\n" reversed = "\nolle h", [1:] = "olleh", + "\n" = "olleh\n"
        // Wait, let me re-check: "hello\n" as bytes reversed is b"\nolleh"
        // [1:] = b"olleh", + b"\n" = b"olleh\n"
        assert_eq!(
            response, "olleh\n",
            "expected reversed data, got: {response:?}"
        );

        // Verify connection was tracked
        assert!(registry.len() >= 1, "connection should be in registry");

        // Clean disconnect
        drop(stream);
        time::sleep(Duration::from_millis(300)).await;

        // Clean shutdown
        state.stop_all_listeners();
    });
}
