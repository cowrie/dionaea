// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: Integration test for Rust-native ihandler dispatch.
// ABOUTME: Verifies that PyIncident::report() calls HandlerCallback::Rust handlers.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dionaea::config;
use dionaea::connection::limits::ConnectionLimits;
use dionaea::connection::ConnectionRegistry;
use dionaea::ihandler::{HandlerCallback, IHandler, WildcardPattern};
use dionaea::runtime;
use pyo3::prelude::*;

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

/// Verify that PyIncident::report() dispatches to Rust-native handlers.
#[test]
fn test_rust_handler_dispatch_via_report() {
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

    // Register a Rust-native handler for download incidents
    let call_count = Arc::new(AtomicU32::new(0));
    let received_url = Arc::new(std::sync::Mutex::new(String::new()));

    {
        let call_count = call_count.clone();
        let received_url = received_url.clone();
        let mut reg = state.ihandler_registry.lock().expect("lock");
        reg.register(IHandler {
            pattern: WildcardPattern::new("dionaea.download.*"),
            callback: HandlerCallback::Rust(Arc::new(move |incident| {
                call_count.fetch_add(1, Ordering::SeqCst);
                if let Some(dionaea::incident::OpaqueData::String(url)) = incident.get("url") {
                    *received_url.lock().unwrap() = url.clone();
                }
            })),
        });
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    rt.block_on(async {
        // Report a download.offer incident from Python
        tokio::task::spawn_blocking(move || {
            Python::attach(|py| {
                let python_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../modules/python")
                    .canonicalize()
                    .expect("modules/python/ should exist");

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

                py.run(
                    c"
from dionaea.core import incident
i = incident('dionaea.download.offer')
i.url = 'http://evil.com/malware.exe'
i.report()
",
                    None,
                    None,
                )
                .expect("report incident");
            });
        })
        .await
        .expect("spawn_blocking");
    });

    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "Rust handler should be called exactly once"
    );
    assert_eq!(
        *received_url.lock().unwrap(),
        "http://evil.com/malware.exe",
        "Rust handler should receive the URL from the incident"
    );
}
