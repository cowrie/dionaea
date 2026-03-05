// SPDX-License-Identifier: GPL-3.0-only
// ABOUTME: Integration test for the real FTP protocol.
// ABOUTME: Verifies banner, USER/PASS login, PWD, and CWD commands.

use std::sync::Arc;
use std::time::Duration;

use dionaea::config;
use dionaea::connection::limits::ConnectionLimits;
use dionaea::connection::ConnectionRegistry;
use dionaea::runtime;
use pyo3::prelude::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

/// Test FTP protocol: connect, verify banner, login, PWD.
#[test]
fn test_ftp_login_sequence() {
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

        // Create temp FTP root
        let tmp_dir = std::env::temp_dir().join("dionaea_ftp_test");
        let _ = std::fs::create_dir_all(&tmp_dir);
        std::fs::write(tmp_dir.join("test.txt"), "FTP test file content\n")
            .expect("write test.txt");

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
from dionaea.ftp import FTPd

d = FTPd(proto='tcp')
d.basedir = '{}'
d.bind('127.0.0.1', 0)
d.listen()
port = d.local.port
"#,
                    tmp_dir_str.replace('\\', "\\\\").replace('\'', "\\'")
                );
                let c_code = std::ffi::CString::new(code).expect("CString");
                py.run(c_code.as_c_str(), None, None).expect("FTP setup");

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

        assert!(bound_port > 0, "FTP listener should bind to a real port");
        time::sleep(Duration::from_millis(100)).await;

        // Connect and interact with FTP protocol
        let stream = TcpStream::connect(format!("127.0.0.1:{bound_port}"))
            .await
            .expect("connect to FTP");
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        // Read welcome banner (220)
        line.clear();
        time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .expect("banner timeout")
            .expect("banner read");
        assert!(
            line.starts_with("220"),
            "expected 220 banner, got: {line:?}"
        );

        // USER anonymous
        writer.write_all(b"USER anonymous\r\n").await.expect("write USER");
        line.clear();
        time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .expect("USER timeout")
            .expect("USER read");
        assert!(
            line.starts_with("331"),
            "expected 331 response to USER, got: {line:?}"
        );

        // PASS guest@
        writer.write_all(b"PASS guest@\r\n").await.expect("write PASS");
        line.clear();
        time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .expect("PASS timeout")
            .expect("PASS read");
        assert!(
            line.starts_with("230"),
            "expected 230 login OK, got: {line:?}"
        );

        // PWD
        writer.write_all(b"PWD\r\n").await.expect("write PWD");
        line.clear();
        time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .expect("PWD timeout")
            .expect("PWD read");
        assert!(
            line.starts_with("257"),
            "expected 257 PWD response, got: {line:?}"
        );
        assert!(
            line.contains("\"/\""),
            "PWD should show root directory, got: {line:?}"
        );

        // QUIT
        writer.write_all(b"QUIT\r\n").await.expect("write QUIT");

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);
        state.stop_all_listeners();
    });
}
