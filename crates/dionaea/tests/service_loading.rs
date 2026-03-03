// ABOUTME: Integration test for the full service loading chain.
// ABOUTME: Loads dionaea + services modules, starts blackhole service, verifies TCP accept.

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

    // Create a temp service config for blackhole on port 0 (random)
    let tmp_dir = std::env::temp_dir().join("dionaea_service_test");
    let _ = std::fs::create_dir_all(&tmp_dir);
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
level = "debug"
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

        // Blackhole uses port 0, so we need to find what port it bound to.
        // Check the registry for any listening connections, or try to discover
        // from Python.
        let bound_port: u16 = tokio::task::spawn_blocking(|| {
            Python::attach(|py| {
                py.run(
                    c"
from dionaea.services import g_slave
_found_port = 0
if g_slave and hasattr(g_slave, 'daemons'):
    for _addr, _services in g_slave.daemons.items():
        for _svc, _daemons in _services.items():
            for _d in _daemons:
                if _d.local.port > 0:
                    _found_port = _d.local.port
",
                    None,
                    None,
                )
                .expect("find port");
                let val = py.eval(c"_found_port", None, None).expect("read port");
                val.extract::<u16>().unwrap_or(0)
            })
        })
        .await
        .expect("get port");

        if bound_port == 0 {
            // port 0 means the blackhole service didn't start.
            // This could be because services.py couldn't find 127.0.0.1 via
            // getifaddrs in manual mode. Let's check what services.py saw.
            let debug = tokio::task::spawn_blocking(|| {
                Python::attach(|py| {
                    py.run(
                        c"
from dionaea.services import g_slave
_debug_parts = []
_debug_parts.append('type=' + type(g_slave).__name__)
if g_slave and hasattr(g_slave, 'addresses'):
    _debug_parts.append('addrs=' + str(g_slave.addresses))
if g_slave and hasattr(g_slave, 'daemons'):
    _debug_parts.append('daemons=' + str(g_slave.daemons))
_debug_info = ', '.join(_debug_parts)
",
                        None,
                        None,
                    )
                    .ok();
                    match py.eval(c"_debug_info", None, None) {
                        Ok(val) => val.extract::<String>().unwrap_or_default(),
                        Err(e) => format!("error: {e}"),
                    }
                })
            })
            .await
            .expect("debug");
            panic!("Blackhole service didn't start (port=0). Debug: {debug}");
        }

        // Connect to the blackhole service
        let mut stream = TcpStream::connect(format!("127.0.0.1:{bound_port}"))
            .await
            .expect("connect to blackhole");

        // Blackhole accepts and discards data
        stream.write_all(b"test data").await.expect("write");
        time::sleep(Duration::from_millis(200)).await;

        // Verify connection was tracked
        assert!(
            registry.len() >= 1,
            "blackhole connection should be in registry"
        );

        drop(stream);
        time::sleep(Duration::from_millis(200)).await;

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);
        state.stop_all_listeners();
    });
}
