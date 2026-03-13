// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Integration test for the full service loading chain.
// ABOUTME: Loads dionaea + services modules, starts blackhole + HTTP services via ServiceLoader.

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

/// Full service loading chain: config → loader → services.new() → services.start().
///
/// Uses the blackhole service (simplest ServiceLoader) on a random port.
/// Verifies: Python modules import, submodule discovery, service config loading,
/// ServiceLoader dispatch, bind/listen, TCP accept.
#[test]
fn test_full_service_loading_chain() {
    let python_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../modules/python")
        .canonicalize()
        .expect("modules/python/ should exist");

    // Create temp dirs for service configs and HTTP root
    let tmp_dir = std::env::temp_dir().join("dionaea_service_test");
    let http_root = tmp_dir.join("www");
    let _ = std::fs::create_dir_all(&http_root);
    std::fs::write(
        http_root.join("index.html"),
        "<html><body>ServiceLoader HTTP works!</body></html>",
    )
    .expect("write index.html");

    // Blackhole service config
    std::fs::write(
        tmp_dir.join("blackhole.toml"),
        r#"
name = "blackhole"

[[config.services]]
port = 0
protocol = "tcp"
"#,
    )
    .expect("write blackhole.toml");

    // HTTP service config
    let http_config = format!(
        r#"
name = "http"

[config]
root = "{root}"
ports = [0]
"#,
        root = http_root.to_string_lossy().replace('\\', "\\\\"),
    );
    std::fs::write(tmp_dir.join("http.toml"), http_config).expect("write http.toml");

    let svc_glob = tmp_dir.join("*.toml").to_string_lossy().to_string();

    // Build config with service_configs pointing to our temp dir
    let config_str = format!(
        r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = ["127.0.0.1"]
[dionaea.admin]
listen = "127.0.0.2"
[logging]
[modules]
[modules.python]
imports = ["dionaea", "dionaea.services", "dionaea.ihandlers"]
service_configs = ["{svc_glob}"]
ihandler_configs = []
python_path = "{python_path}"
"#,
        svc_glob = svc_glob.replace('\\', "\\\\"),
        python_path = python_path.to_string_lossy().replace('\\', "\\\\"),
    );

    let cfg = config::load_from_str(&config_str).expect("parse config");

    let registry = Arc::new(ConnectionRegistry::new());
    let limits = Arc::new(ConnectionLimits::new(50, 10_000, 70));
    let state = Arc::new(runtime::RuntimeState::new(
        registry.clone(),
        limits.clone(),
        65536,
        cfg,
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
        // Load Python modules via the full chain
        let python_config = &state.config.modules.python;
        let imports = python_config.imports.clone();
        let service_configs = python_config.service_configs.clone();
        let ihandler_configs = python_config.ihandler_configs.clone();
        let python_path = python_config.python_path.clone();

        let load_result = tokio::task::spawn_blocking(move || {
            Python::attach(|py| {
                let config = config::PythonModuleConfig {
                    imports,
                    service_configs,
                    ihandler_configs,
                    python_path,
                    ..Default::default()
                };
                dionaea::python::loader::load(py, &config)
            })
        })
        .await
        .expect("spawn_blocking join");

        if let Err(e) = load_result {
            panic!("Python module loading failed: {e}");
        }

        // Give listeners time to start (services.start() binds/listens)
        time::sleep(Duration::from_millis(500)).await;

        // Discover bound ports from Python's g_slave
        let (blackhole_port, http_port) = tokio::task::spawn_blocking(|| {
            Python::attach(|py| {
                py.run(
                    c"
from dionaea.services import g_slave
from dionaea.blackhole import BlackholeService
from dionaea.http import HTTPService
_blackhole_port = 0
_http_port = 0
if g_slave and hasattr(g_slave, 'daemons'):
    for _addr, _services in g_slave.daemons.items():
        for _svc, _daemons in _services.items():
            for _d in _daemons:
                if _d.local.port > 0:
                    if _svc is BlackholeService:
                        _blackhole_port = _d.local.port
                    elif _svc is HTTPService:
                        _http_port = _d.local.port
",
                    None,
                    None,
                )
                .expect("find ports");
                let bp: u16 = py
                    .eval(c"_blackhole_port", None, None)
                    .expect("bp")
                    .extract()
                    .unwrap_or(0);
                let hp: u16 = py
                    .eval(c"_http_port", None, None)
                    .expect("hp")
                    .extract()
                    .unwrap_or(0);
                (bp, hp)
            })
        })
        .await
        .expect("get ports");

        assert!(
            blackhole_port > 0,
            "blackhole service should have started on a port"
        );
        assert!(http_port > 0, "http service should have started on a port");

        // --- Test blackhole: accepts and discards data ---
        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{blackhole_port}"))
                .await
                .expect("connect to blackhole");
            stream.write_all(b"test data").await.expect("write");
            time::sleep(Duration::from_millis(200)).await;
            assert!(
                registry.len() >= 1,
                "blackhole connection should be in registry"
            );
            drop(stream);
            time::sleep(Duration::from_millis(200)).await;
        }

        // --- Test HTTP: GET / returns 200 OK with index.html content ---
        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{http_port}"))
                .await
                .expect("connect to http");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("write GET");

            let mut response = Vec::new();
            let mut buf = vec![0u8; 4096];
            loop {
                match time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => response.extend_from_slice(&buf[..n]),
                    Ok(Err(_)) | Err(_) => break,
                }
            }
            let response_str = String::from_utf8_lossy(&response);
            assert!(
                response_str.contains("HTTP/1.1 200"),
                "expected 200 OK from HTTP service, got: {response_str}"
            );
            assert!(
                response_str.contains("ServiceLoader HTTP works!"),
                "expected HTML body from HTTP service, got: {response_str}"
            );
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);
        state.stop_all_listeners();
    });
}
