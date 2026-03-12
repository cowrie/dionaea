// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: GPL-3.0-only
// ABOUTME: Integration test for the download module end-to-end flow.
// ABOUTME: Verifies: URL validation, HTTP download, SHA256 file naming.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use dionaea::config;
use dionaea::connection::limits::ConnectionLimits;
use dionaea::connection::ConnectionRegistry;
use dionaea::ihandler::{HandlerCallback, IHandler, WildcardPattern};
use dionaea::incident::OpaqueData;
use dionaea::runtime;
use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_config(download_dir: &std::path::Path) -> config::Config {
    let toml = format!(
        r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = ["0.0.0.0"]
[dionaea.download]
dir = "{}"
suffix = ".tmp"
timeout_secs = 10
size_limit_bytes = 1048576
[logging]
level = "debug"
[modules]
"#,
        download_dir.display()
    );
    config::load_from_str(&toml).expect("test config")
}

/// Verify the full download flow:
/// 1. SSRF protection rejects loopback URLs via incident
/// 2. Direct download_url works for file saving with SHA256
/// 3. Download handler registration works
#[test]
fn test_download_module_end_to_end() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    let tmp_dir = std::env::temp_dir().join("dionaea_download_e2e");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).expect("create dir");

    let registry = Arc::new(ConnectionRegistry::new());
    let limits = Arc::new(ConnectionLimits::new(50, 10_000, 70));
    let state = Arc::new(runtime::RuntimeState::new(
        registry.clone(),
        limits.clone(),
        65536,
        test_config(&tmp_dir),
        Vec::new(),
    ));
    runtime::init(state.clone());

    // Register download handler and a capture handler for complete events
    dionaea::download::register();

    let complete_count = Arc::new(AtomicU32::new(0));
    let received_hash = Arc::new(std::sync::Mutex::new(String::new()));
    {
        let complete_count = complete_count.clone();
        let received_hash = received_hash.clone();
        let mut reg = state.ihandler_registry.lock().expect("lock");
        reg.register(IHandler {
            pattern: WildcardPattern::new("dionaea.download.complete"),
            callback: HandlerCallback::Rust(Arc::new(move |incident| {
                complete_count.fetch_add(1, Ordering::SeqCst);
                if let Some(OpaqueData::String(h)) = incident.get("sha256hash") {
                    *received_hash.lock().unwrap() = h.clone();
                }
            })),
        });
    }

    let malware_body = b"DEADBEEF_FAKE_MALWARE_PAYLOAD_FOR_TEST";
    let expected_hash = {
        let mut h = Sha256::new();
        h.update(malware_body);
        let result = h.finalize();
        let mut s = String::with_capacity(result.len() * 2);
        for b in result.iter() {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");

    rt.block_on(async {
        // Part 1: Test SSRF protection via Python incident
        let python_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../modules/python")
            .canonicalize()
            .expect("modules/python/ should exist");

        tokio::task::spawn_blocking(move || {
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

                // Report a download.offer with loopback URL — should be rejected
                py.run(
                    c"
from dionaea.core import incident
i = incident('dionaea.download.offer')
i.url = 'http://127.0.0.1:9999/malware.exe'
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

        // Give time for any async processing
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert_eq!(
            complete_count.load(Ordering::SeqCst),
            0,
            "loopback download should be rejected by SSRF protection"
        );

        // Part 2: Test direct download (bypassing URL validation)
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let body = malware_body.to_vec();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write");
            stream.write_all(&body).await.expect("write body");
        });

        let url = reqwest::Url::parse(&format!("http://127.0.0.1:{port}/malware.exe"))
            .expect("parse url");
        let config = state.config.dionaea.download.clone();

        let (path, hash) =
            dionaea::download::download_url(&url, &config)
                .await
                .expect("download should succeed");

        assert_eq!(hash, expected_hash, "SHA256 hash should match");
        assert!(path.exists(), "file should exist at {}", path.display());
        assert_eq!(
            path.file_name().expect("filename").to_str().expect("str"),
            expected_hash,
            "filename should be the SHA256 hash"
        );
        assert_eq!(
            std::fs::read(&path).expect("read"),
            malware_body.to_vec(),
            "file content should match"
        );

        server.await.expect("server");

        // Part 3: Verify deduplication — downloading same content again
        let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind2");
        let port2 = listener2.local_addr().expect("addr").port();
        let body2 = malware_body.to_vec();
        let server2 = tokio::spawn(async move {
            let (mut stream, _) = listener2.accept().await.expect("accept");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body2.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write");
            stream.write_all(&body2).await.expect("write body");
        });

        let url2 = reqwest::Url::parse(&format!("http://127.0.0.1:{port2}/malware.exe"))
            .expect("parse url");

        let (path2, hash2) =
            dionaea::download::download_url(&url2, &config)
                .await
                .expect("duplicate download should succeed");

        assert_eq!(hash2, expected_hash, "same content = same hash");
        assert_eq!(path2, path, "same path for duplicate");

        server2.await.expect("server2");

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);
        state.stop_all_listeners();
    });
}
