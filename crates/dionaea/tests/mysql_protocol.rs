// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: Integration test for the MySQL protocol.
// ABOUTME: Verifies the server greeting packet on connect.

use std::sync::Arc;
use std::time::Duration;

use dionaea::config;
use dionaea::connection::limits::ConnectionLimits;
use dionaea::connection::ConnectionRegistry;
use dionaea::runtime;
use pyo3::prelude::*;
use tokio::io::AsyncReadExt;
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

/// Test MySQL protocol: connect, verify server greeting packet.
#[test]
fn test_mysql_greeting() {
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
                    &config::PythonModuleConfig {
                        imports: vec![],
                        service_configs: vec![],
                        ihandler_configs: vec![],
                        python_path: Some(python_path),
                    },
                )
                .expect("loader init");

                let code = r#"
from dionaea.mysql import mysqld

d = mysqld()
d.apply_config({
    "databases": {
        "information_schema": {"path": ":memory:"},
    },
})
d.bind('127.0.0.1', 0)
d.listen()
port = d.local.port
"#;
                let c_code = std::ffi::CString::new(code).expect("CString");
                py.run(c_code.as_c_str(), None, None).expect("MySQL setup");

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

        assert!(bound_port > 0, "MySQL listener should bind to a real port");
        time::sleep(Duration::from_millis(100)).await;

        // Connect and read the server greeting
        let mut stream = TcpStream::connect(format!("127.0.0.1:{bound_port}"))
            .await
            .expect("connect to MySQL");

        let mut buf = vec![0u8; 4096];
        let n = time::timeout(Duration::from_secs(3), stream.read(&mut buf))
            .await
            .expect("greeting timeout")
            .expect("greeting read");

        // MySQL packet: 3-byte length (LE 24-bit) + 1-byte number + payload
        assert!(n >= 4, "expected at least packet header, got {n}");

        let pkt_len = buf[0] as u32 | (buf[1] as u32) << 8 | (buf[2] as u32) << 16;
        let pkt_num = buf[3];
        assert_eq!(pkt_num, 0, "greeting should be packet number 0");
        assert!(
            pkt_len > 20,
            "greeting payload should be at least 20 bytes, got {pkt_len}"
        );
        assert!(
            n as u32 >= pkt_len + 4,
            "should receive full packet: need {}, got {n}",
            pkt_len + 4
        );

        // Payload starts at byte 4
        let payload = &buf[4..4 + pkt_len as usize];

        // Protocol version = 0x0a (10)
        assert_eq!(payload[0], 0x0a, "MySQL protocol version should be 10");

        // Server version string (null-terminated)
        let nul_pos = payload[1..]
            .iter()
            .position(|&b| b == 0)
            .expect("version string should be null-terminated");
        let version = std::str::from_utf8(&payload[1..1 + nul_pos]).expect("valid UTF-8 version");
        assert!(
            !version.is_empty(),
            "version string should not be empty"
        );

        // After version string: 4-byte thread ID + 8-byte scramble + 1-byte filler(0x00)
        let after_version = 1 + nul_pos + 1; // skip protocol_version + version + null
        assert!(
            payload.len() > after_version + 13,
            "payload too short for thread ID + scramble"
        );

        // Filler byte after scramble should be 0x00
        let filler_offset = after_version + 4 + 8; // thread_id(4) + scramble(8)
        assert_eq!(
            payload[filler_offset], 0x00,
            "filler byte after scramble should be 0x00"
        );

        state.stop_all_listeners();
    });
}
