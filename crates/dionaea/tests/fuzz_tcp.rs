// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Fuzz test sending random bytes to TCP read path.
// ABOUTME: Verifies no panics or crashes from arbitrary input data.

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
[modules]
"#,
    )
    .expect("test config")
}

#[test]
fn test_random_bytes_no_panic() {
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
        .expect("tokio runtime");

    rt.block_on(async {
        // Load a minimal protocol that accepts all data (simplest handler to fuzz)
        let python_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../modules/python")
            .canonicalize()
            .expect("modules/python/ should exist");

        let port: u16 = tokio::task::spawn_blocking(move || {
            Python::attach(|py| {
                dionaea::python::loader::load(
                    py,
                    &config::PythonModuleConfig { python_path: Some(python_path), ..Default::default() },
                )
                .expect("loader init");

                py.run(
                    c"
from dionaea.core import connection
class FuzzTarget(connection):
    protocol_name = 'fuzz'
    def handle_established(self):
        pass
    def handle_io_in(self, data):
        return len(data)
    def handle_disconnect(self):
        return False
    def handle_timeout_idle(self):
        return False
daemon = FuzzTarget('tcp')
daemon.bind('127.0.0.1', 0)
daemon.listen()
port = daemon.local.port
",
                    None,
                    None,
                )
                .expect("setup fuzz target");

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

        // Use a fixed seed for reproducibility but cover diverse patterns
        let test_payloads: Vec<Vec<u8>> = vec![
            // Empty
            vec![],
            // Single byte — all 256 values
            (0..=255u8).collect(),
            // All zeros
            vec![0u8; 4096],
            // All 0xFF
            vec![0xFFu8; 4096],
            // Null bytes mixed with printable
            b"GET / HTTP/1.1\x00\x00\x00\r\n\r\n".to_vec(),
            // Very long line
            vec![b'A'; 65536],
            // Random-looking binary data (deterministic)
            (0..8192u32).map(|i| (i.wrapping_mul(7919) % 256) as u8).collect(),
            // SMB-like header
            vec![0x00, 0x00, 0x00, 0x45, 0xFF, 0x53, 0x4D, 0x42],
            // MySQL-like packet
            vec![0x01, 0x00, 0x00, 0x01, 0x85],
            // FTP-like commands
            b"USER \xff\xfe\xfd\r\nPASS \x00\x01\x02\r\nQUIT\r\n".to_vec(),
            // HTTP with binary body
            b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09".to_vec(),
            // Repeated CRLF
            b"\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n".to_vec(),
            // UTF-8 multibyte sequences (some invalid)
            vec![0xC0, 0xAF, 0xE0, 0x80, 0x80, 0xF4, 0x90, 0x80, 0x80],
            // Large random payload
            (0..32768u64).map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8).collect(),
        ];

        for (i, payload) in test_payloads.iter().enumerate() {
            let result = time::timeout(Duration::from_secs(3), async {
                match TcpStream::connect(("127.0.0.1", port)).await {
                    Ok(mut stream) => {
                        if !payload.is_empty() {
                            let _ = stream.write_all(payload).await;
                        }
                        // Give the server time to process
                        time::sleep(Duration::from_millis(50)).await;
                        // Try to read any response
                        let mut buf = vec![0u8; 4096];
                        let _ = time::timeout(
                            Duration::from_millis(200),
                            stream.read(&mut buf),
                        )
                        .await;
                        // Graceful close
                        let _ = stream.shutdown().await;
                    }
                    Err(e) => {
                        panic!("Failed to connect for payload {}: {}", i, e);
                    }
                }
            })
            .await;

            assert!(
                result.is_ok(),
                "Payload {} ({} bytes) caused a timeout — possible hang",
                i,
                payload.len()
            );
        }

        // Verify the server is still alive after all fuzz payloads
        let alive_check = TcpStream::connect(("127.0.0.1", port)).await;
        assert!(alive_check.is_ok(), "Server should still accept connections after fuzz");

        state.stop_all_listeners();
    });
}
