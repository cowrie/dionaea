// SPDX-License-Identifier: GPL-3.0-only
// ABOUTME: HTTP download module for capturing malware binaries.
// ABOUTME: Listens for dionaea.download.offer incidents and fetches URLs via reqwest.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::config::DownloadConfig;
use crate::ihandler::{HandlerCallback, IHandler, WildcardPattern};
use crate::incident::{Incident, OpaqueData};
use crate::runtime;

/// Validate that a URL is safe to download.
/// Only http:// and https:// schemes are allowed.
fn validate_url(url: &str) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("unsupported scheme: {scheme}")),
    }

    // Reject private/loopback IPs to prevent SSRF.
    // host_str() returns brackets for IPv6 (e.g. "[::1]"), strip them for parsing.
    if let Some(host) = parsed.host_str() {
        let host_bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host_bare.parse::<std::net::IpAddr>() {
            if ip.is_loopback() {
                return Err(format!("loopback address rejected: {ip}"));
            }
            match ip {
                std::net::IpAddr::V4(v4) => {
                    if v4.is_private() || v4.is_link_local() {
                        return Err(format!("private address rejected: {ip}"));
                    }
                }
                std::net::IpAddr::V6(v6) => {
                    // fe80::/10 link-local
                    if v6.segments()[0] & 0xffc0 == 0xfe80 {
                        return Err(format!("link-local address rejected: {ip}"));
                    }
                }
            }
        }
    }

    Ok(parsed)
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Download a URL to the download directory.
///
/// Returns the final path (named by SHA256 hash) and the hex hash string.
/// Public for integration testing — callers bypass URL validation.
pub async fn download_url(
    url: &reqwest::Url,
    config: &DownloadConfig,
) -> Result<(PathBuf, String), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let mut response = client
        .get(url.as_str())
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }

    // Create download directory if needed
    tokio::fs::create_dir_all(&config.dir)
        .await
        .map_err(|e| format!("failed to create download dir: {e}"))?;

    // Save to temp file with unique name
    let temp_name = format!(
        "download_{}_{}{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        config.suffix
    );
    let temp_path = config.dir.join(&temp_name);
    let mut file = tokio::fs::File::create(&temp_path)
        .await
        .map_err(|e| format!("failed to create temp file: {e}"))?;

    let mut hasher = Sha256::new();
    let mut total_bytes: u64 = 0;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("download stream error: {e}"))?
    {
        total_bytes += chunk.len() as u64;
        if config.size_limit_bytes > 0 && total_bytes > config.size_limit_bytes {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(format!(
                "download exceeds size limit ({total_bytes} > {})",
                config.size_limit_bytes
            ));
        }

        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|e| format!("write error: {e}"))?;
    }

    file.flush().await.map_err(|e| format!("flush error: {e}"))?;
    drop(file);

    let hash = hex_encode(&hasher.finalize());
    let final_path = config.dir.join(&hash);

    // Rename temp to final (content-addressable, deduplicates)
    if final_path.exists() {
        // Already have this file, remove temp
        let _ = tokio::fs::remove_file(&temp_path).await;
    } else {
        tokio::fs::rename(&temp_path, &final_path)
            .await
            .map_err(|e| format!("rename error: {e}"))?;
    }

    tracing::info!(
        url = %url,
        hash = %hash,
        bytes = total_bytes,
        path = %final_path.display(),
        "download complete"
    );

    Ok((final_path, hash))
}

/// Emit a `dionaea.download.complete` incident.
fn emit_download_complete(path: &Path, url: &str, hash: &str) {
    let path_str = path.to_string_lossy().to_string();
    let url = url.to_string();
    let hash = hash.to_string();

    // Need the GIL to create and report the incident.
    let _ = std::thread::spawn(move || {
        pyo3::Python::attach(|py| {
            use pyo3::types::PyAnyMethods;

            let inc = pyo3::Py::new(
                py,
                crate::python::incident::PyIncident::new(Some(
                    "dionaea.download.complete".to_string(),
                )),
            );
            let Ok(inc) = inc else {
                tracing::error!("failed to create download.complete incident");
                return;
            };
            let bound = inc.into_bound(py).into_any();
            let _ = bound.setattr("path", &path_str);
            let _ = bound.setattr("url", &url);
            let _ = bound.setattr("sha256hash", &hash);
            if let Err(e) = bound.call_method0("report") {
                tracing::error!(error = %e, "failed to report download.complete");
            }
        });
    })
    .join();
}

/// Handle a `dionaea.download.offer` incident.
fn handle_download_offer(incident: &Incident) {
    let url_str = match incident.get("url") {
        Some(OpaqueData::String(s)) => s.clone(),
        Some(OpaqueData::Bytes(b)) => String::from_utf8_lossy(b).to_string(),
        _ => {
            tracing::warn!(origin = %incident.origin, "download.offer missing 'url' field");
            return;
        }
    };

    let url = match validate_url(&url_str) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(url = %url_str, error = %e, "rejecting download URL");
            return;
        }
    };

    let Some(state) = runtime::get() else {
        tracing::warn!("no runtime for download");
        return;
    };

    let config = state.config.dionaea.download.clone();

    // Spawn the async download on the tokio runtime
    match tokio::runtime::Handle::try_current() {
        Ok(h) => {
            let url_string = url_str.clone();
            h.spawn(async move {
                match download_url(&url, &config).await {
                    Ok((path, hash)) => {
                        emit_download_complete(&path, &url_string, &hash);
                    }
                    Err(e) => {
                        tracing::error!(url = %url_string, error = %e, "download failed");
                    }
                }
            });
        }
        Err(_) => {
            tracing::error!("no tokio runtime available for download");
        }
    }
}

/// Register the download handler with the incident system.
///
/// Call this during startup if `modules.download` is enabled.
pub fn register() {
    let Some(state) = runtime::get() else {
        tracing::warn!("cannot register download handler: no runtime");
        return;
    };

    let handler = IHandler {
        pattern: WildcardPattern::new("dionaea.download.offer"),
        callback: HandlerCallback::Rust(Arc::new(handle_download_offer)),
    };

    state
        .ihandler_registry
        .lock()
        .expect("registry lock")
        .register(handler);

    tracing::info!("download handler registered");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url_http() {
        assert!(validate_url("http://evil.com/malware.exe").is_ok());
    }

    #[test]
    fn test_validate_url_https() {
        assert!(validate_url("https://evil.com/malware.exe").is_ok());
    }

    #[test]
    fn test_validate_url_rejects_ftp() {
        let err = validate_url("ftp://evil.com/file").unwrap_err();
        assert!(err.contains("unsupported scheme"));
    }

    #[test]
    fn test_validate_url_rejects_file() {
        let err = validate_url("file:///etc/passwd").unwrap_err();
        assert!(err.contains("unsupported scheme"));
    }

    #[test]
    fn test_validate_url_rejects_loopback() {
        let err = validate_url("http://127.0.0.1/malware").unwrap_err();
        assert!(err.contains("loopback"));
    }

    #[test]
    fn test_validate_url_rejects_private_10() {
        let err = validate_url("http://10.0.0.1/malware").unwrap_err();
        assert!(err.contains("private"));
    }

    #[test]
    fn test_validate_url_rejects_private_192() {
        let err = validate_url("http://192.168.1.1/malware").unwrap_err();
        assert!(err.contains("private"));
    }

    #[test]
    fn test_validate_url_rejects_private_172() {
        let err = validate_url("http://172.16.0.1/malware").unwrap_err();
        assert!(err.contains("private"));
    }

    #[test]
    fn test_validate_url_rejects_link_local() {
        let err = validate_url("http://169.254.1.1/malware").unwrap_err();
        assert!(err.contains("link-local") || err.contains("private"));
    }

    #[test]
    fn test_validate_url_rejects_ipv6_loopback() {
        let err = validate_url("http://[::1]/malware").unwrap_err();
        assert!(err.contains("loopback"));
    }

    #[test]
    fn test_validate_url_allows_hostname() {
        // Hostnames are allowed (DNS resolution happens at download time)
        assert!(validate_url("http://evil.com/malware.exe").is_ok());
    }

    #[test]
    fn test_validate_url_rejects_invalid() {
        let err = validate_url("not a url").unwrap_err();
        assert!(err.contains("invalid URL"));
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[tokio::test]
    async fn test_download_url_to_file() {
        // Create a temp directory for downloads
        let tmp_dir = std::env::temp_dir().join("dionaea_download_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).expect("create temp dir");

        // Start a simple HTTP server
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let body = b"this is fake malware content for testing";
        let expected_hash = {
            let mut h = Sha256::new();
            h.update(body);
            hex_encode(&h.finalize())
        };

        // Spawn HTTP server
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            use tokio::io::{AsyncReadExt, AsyncWriteExt as _};

            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.expect("write header");
            stream.write_all(body).await.expect("write body");
        });

        let config = DownloadConfig {
            dir: tmp_dir.clone(),
            suffix: ".tmp".to_string(),
            timeout_secs: 5,
            size_limit_bytes: 1024 * 1024,
        };

        // validate_url rejects 127.0.0.1, so parse directly for testing
        let url = reqwest::Url::parse(&format!("http://127.0.0.1:{port}/malware.exe"))
            .expect("parse url");

        let (path, hash) = download_url(&url, &config).await.expect("download");

        assert_eq!(hash, expected_hash);
        assert!(path.exists(), "downloaded file should exist");
        assert_eq!(
            std::fs::read(&path).expect("read file"),
            body.to_vec()
        );
        assert_eq!(
            path.file_name().expect("filename").to_str().expect("str"),
            expected_hash
        );

        server.await.expect("server");
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn test_download_size_limit() {
        let tmp_dir = std::env::temp_dir().join("dionaea_download_size_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).expect("create temp dir");

        // Start HTTP server that sends a large body
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let big_body = vec![0x41u8; 2048]; // 2KB
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            use tokio::io::{AsyncReadExt, AsyncWriteExt as _};

            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                big_body.len()
            );
            stream.write_all(response.as_bytes()).await.expect("write header");
            stream.write_all(&big_body).await.expect("write body");
        });

        let config = DownloadConfig {
            dir: tmp_dir.clone(),
            suffix: ".tmp".to_string(),
            timeout_secs: 5,
            size_limit_bytes: 1024, // 1KB limit
        };

        let url = reqwest::Url::parse(&format!("http://127.0.0.1:{port}/big.bin"))
            .expect("parse url");

        let result = download_url(&url, &config).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("size limit"));

        server.await.expect("server");
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
