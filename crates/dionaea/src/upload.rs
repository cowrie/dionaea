// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: HTTP multipart upload module for submitting captured data to external services.
// ABOUTME: Handles dionaea.upload.request incidents from Python ihandlers (virustotal, hpfeeds, etc).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::ihandler::{HandlerCallback, IHandler, WildcardPattern};
use crate::incident::{Incident, OpaqueData};
use crate::runtime;

/// Default upload timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Extract string fields from an incident, classifying them by type.
///
/// Returns `(url, callback, userdata, user, pass, file_fields, text_fields, content_types)`.
fn extract_fields(
    incident: &Incident,
) -> (
    Option<String>,                            // _url
    Option<String>,                            // _callback
    Option<String>,                            // _userdata
    Option<String>,                            // user
    Option<String>,                            // pass
    Vec<(String, String)>,                     // file fields: (field_name, file_path)
    Vec<(String, String)>,                     // text fields: (field_name, value)
    std::collections::HashMap<String, String>, // content_types: field_name -> ct
) {
    let mut url = None;
    let mut callback = None;
    let mut userdata = None;
    let mut user = None;
    let mut pass = None;
    let mut file_fields = Vec::new();
    let mut text_fields = Vec::new();
    let mut content_types = std::collections::HashMap::new();

    for (key, value) in &incident.data {
        let val_str = match value {
            OpaqueData::String(s) => s.clone(),
            OpaqueData::Bytes(b) => String::from_utf8_lossy(b).to_string(),
            _ => continue, // skip non-string fields (matching C behavior)
        };

        match key.as_str() {
            "_url" => url = Some(val_str),
            "_callback" => callback = Some(val_str),
            "_userdata" => userdata = Some(val_str),
            "user" => user = Some(val_str),
            "pass" => pass = Some(val_str),
            k if k.starts_with("file://") => {
                let field_name = k[7..].to_string();
                file_fields.push((field_name, val_str));
            }
            k if k.ends_with("_ct") => {
                let field_name = k[..k.len() - 3].to_string();
                content_types.insert(field_name, val_str);
            }
            _ => {
                text_fields.push((key.clone(), val_str));
            }
        }
    }

    (
        url,
        callback,
        userdata,
        user,
        pass,
        file_fields,
        text_fields,
        content_types,
    )
}

/// Execute the multipart POST upload.
async fn upload_multipart(
    url: &str,
    user: Option<&str>,
    pass: Option<&str>,
    file_fields: Vec<(String, String)>,
    text_fields: Vec<(String, String)>,
    content_types: &std::collections::HashMap<String, String>,
    callback: Option<&str>,
    userdata: Option<&str>,
    timeout_secs: u64,
) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(true) // matching C: SSL_VERIFYPEER=0
        .user_agent("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)")
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let mut form = reqwest::multipart::Form::new();

    // Add text fields
    for (name, value) in &text_fields {
        let mut part = reqwest::multipart::Part::text(value.clone());
        if let Some(ct) = content_types.get(name) {
            part = part
                .mime_str(ct)
                .map_err(|e| format!("invalid mime type: {e}"))?;
        }
        form = form.part(name.clone(), part);
    }

    // Add file fields (validate paths are within allowed directories)
    let allowed_dir = runtime::get()
        .map(|s| s.config.dionaea.download.dir.clone())
        .unwrap_or_else(|| std::env::temp_dir());
    let allowed_canonical = allowed_dir.canonicalize().unwrap_or(allowed_dir);

    for (name, path) in &file_fields {
        let file_path = Path::new(path);
        if let Ok(canonical) = file_path.canonicalize() {
            if !canonical.starts_with(&allowed_canonical) {
                return Err(format!("file path outside allowed directory: {path}"));
            }
        } else {
            return Err(format!("cannot resolve file path: {path}"));
        }

        let data = tokio::fs::read(path)
            .await
            .map_err(|e| format!("failed to read file {path}: {e}"))?;

        let file_name = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("upload")
            .to_string();

        let mut part = reqwest::multipart::Part::bytes(data).file_name(file_name);
        if let Some(ct) = content_types.get(&*name) {
            part = part
                .mime_str(ct)
                .map_err(|e| format!("invalid mime type: {e}"))?;
        }
        form = form.part(name.clone(), part);
    }

    let mut request = client.post(url).multipart(form);

    // HTTP Basic Auth
    if let Some(u) = user {
        request = request.basic_auth(u, pass);
    }

    // Suppress Expect: 100-continue (matching C behavior)
    request = request.header("Expect", "");

    let response = request
        .send()
        .await
        .map_err(|e| format!("upload request failed: {e}"))?;

    tracing::info!(
        url = %url,
        status = %response.status(),
        "upload complete"
    );

    // If callback specified, save response body to temp file and emit callback incident
    if let Some(cb_origin) = callback {
        let body = response
            .bytes()
            .await
            .map_err(|e| format!("failed to read response body: {e}"))?;

        // Write response to temp file
        let tmp_dir = std::env::temp_dir();
        let tmp_name = format!(
            "httpupload-{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        let tmp_path = tmp_dir.join(&tmp_name);
        tokio::fs::write(&tmp_path, &body)
            .await
            .map_err(|e| format!("failed to write response temp file: {e}"))?;

        let path_str = tmp_path.to_string_lossy().to_string();
        let cb = cb_origin.to_string();
        let ud = userdata.map(String::from);

        emit_upload_callback(&cb, &path_str, ud.as_deref());

        // Clean up temp file
        let _ = tokio::fs::remove_file(&tmp_path).await;
    }

    Ok(())
}

/// Emit a callback incident with the response file path and userdata.
fn emit_upload_callback(origin: &str, path: &str, userdata: Option<&str>) {
    let origin = origin.to_string();
    let path = path.to_string();
    let userdata = userdata.map(String::from);

    let _ = std::thread::spawn(move || {
        pyo3::Python::attach(|py| {
            use pyo3::types::PyAnyMethods;

            let inc = pyo3::Py::new(
                py,
                crate::python::incident::PyIncident::new(Some(origin.clone())),
            );
            let Ok(inc) = inc else {
                tracing::error!(origin = %origin, "failed to create upload callback incident");
                return;
            };
            let bound = inc.into_bound(py).into_any();
            let _ = bound.setattr("path", &path);
            if let Some(ref ud) = userdata {
                let _ = bound.setattr("_userdata", ud);
            }
            if let Err(e) = bound.call_method0("report") {
                tracing::error!(origin = %origin, error = %e, "failed to report upload callback");
            }
        });
    })
    .join();
}

/// Handle a `dionaea.upload.request` incident.
fn handle_upload_request(incident: &Incident) {
    let (url, callback, userdata, user, pass, file_fields, text_fields, content_types) =
        extract_fields(incident);

    let Some(url_str) = url else {
        tracing::warn!(origin = %incident.origin, "upload.request missing '_url' field");
        return;
    };

    // Spawn the async upload on the tokio runtime
    let Some(h) = tokio::runtime::Handle::try_current().ok() else {
        tracing::error!("no tokio runtime available for upload");
        return;
    };

    let timeout = runtime::get()
        .map(|s| s.config.dionaea.download.timeout_secs)
        .unwrap_or(DEFAULT_TIMEOUT_SECS);

    h.spawn(async move {
        let result = upload_multipart(
            &url_str,
            user.as_deref(),
            pass.as_deref(),
            file_fields,
            text_fields,
            &content_types,
            callback.as_deref(),
            userdata.as_deref(),
            timeout,
        )
        .await;

        if let Err(e) = result {
            tracing::error!(url = %url_str, error = %e, "upload failed");
        }
    });
}

/// Register the upload handler with the incident system.
///
/// Call this during startup if `modules.upload` is enabled.
pub fn register() {
    let Some(state) = runtime::get() else {
        tracing::warn!("cannot register upload handler: no runtime");
        return;
    };

    let handler = IHandler {
        pattern: WildcardPattern::new("dionaea.upload.request"),
        callback: HandlerCallback::Rust(Arc::new(handle_upload_request)),
    };

    state
        .ihandler_registry
        .lock()
        .expect("registry lock")
        .register(handler);

    tracing::info!("upload handler registered");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::Incident;

    fn make_incident(fields: Vec<(&str, &str)>) -> Incident {
        let mut inc = Incident::new("dionaea.upload.request");
        for (k, v) in fields {
            inc.set(k, OpaqueData::String(v.to_string()));
        }
        inc
    }

    #[test]
    fn test_extract_fields_url() {
        let inc = make_incident(vec![("_url", "http://example.com/upload")]);
        let (url, callback, userdata, user, pass, files, texts, cts) = extract_fields(&inc);
        assert_eq!(url.as_deref(), Some("http://example.com/upload"));
        assert!(callback.is_none());
        assert!(userdata.is_none());
        assert!(user.is_none());
        assert!(pass.is_none());
        assert!(files.is_empty());
        assert!(texts.is_empty());
        assert!(cts.is_empty());
    }

    #[test]
    fn test_extract_fields_callback_and_userdata() {
        let inc = make_incident(vec![
            ("_url", "http://example.com"),
            ("_callback", "my.callback"),
            ("_userdata", "cookie123"),
        ]);
        let (_, callback, userdata, _, _, _, _, _) = extract_fields(&inc);
        assert_eq!(callback.as_deref(), Some("my.callback"));
        assert_eq!(userdata.as_deref(), Some("cookie123"));
    }

    #[test]
    fn test_extract_fields_auth() {
        let inc = make_incident(vec![
            ("_url", "http://example.com"),
            ("user", "admin"),
            ("pass", "secret"),
        ]);
        let (_, _, _, user, pass, _, _, _) = extract_fields(&inc);
        assert_eq!(user.as_deref(), Some("admin"));
        assert_eq!(pass.as_deref(), Some("secret"));
    }

    #[test]
    fn test_extract_fields_file_prefix() {
        let inc = make_incident(vec![
            ("_url", "http://example.com"),
            ("file://data", "/tmp/malware.bin"),
            ("file://attachment", "/tmp/info.txt"),
        ]);
        let (_, _, _, _, _, files, _, _) = extract_fields(&inc);
        assert_eq!(files.len(), 2);
        assert!(
            files
                .iter()
                .any(|(n, p)| n == "data" && p == "/tmp/malware.bin")
        );
        assert!(
            files
                .iter()
                .any(|(n, p)| n == "attachment" && p == "/tmp/info.txt")
        );
    }

    #[test]
    fn test_extract_fields_content_type() {
        let inc = make_incident(vec![
            ("_url", "http://example.com"),
            ("comment", "hello"),
            ("comment_ct", "text/plain"),
        ]);
        let (_, _, _, _, _, _, texts, cts) = extract_fields(&inc);
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0], ("comment".to_string(), "hello".to_string()));
        assert_eq!(cts.get("comment").map(|s| s.as_str()), Some("text/plain"));
    }

    #[test]
    fn test_extract_fields_regular_text() {
        let inc = make_incident(vec![
            ("_url", "http://example.com"),
            ("apikey", "abc123"),
            ("resource", "deadbeef"),
        ]);
        let (_, _, _, _, _, _, texts, _) = extract_fields(&inc);
        assert_eq!(texts.len(), 2);
        assert!(texts.iter().any(|(k, v)| k == "apikey" && v == "abc123"));
        assert!(
            texts
                .iter()
                .any(|(k, v)| k == "resource" && v == "deadbeef")
        );
    }

    #[test]
    fn test_extract_fields_skips_non_string() {
        let mut inc = Incident::new("dionaea.upload.request");
        inc.set("_url", OpaqueData::String("http://example.com".to_string()));
        inc.set("count", OpaqueData::Int(42));
        let (url, _, _, _, _, _, texts, _) = extract_fields(&inc);
        assert!(url.is_some());
        assert!(texts.is_empty()); // integer field skipped
    }

    #[test]
    fn test_missing_url_logged() {
        let inc = make_incident(vec![("apikey", "abc123")]);
        let (url, _, _, _, _, _, _, _) = extract_fields(&inc);
        assert!(url.is_none());
    }

    #[tokio::test]
    async fn test_upload_to_local_server() {
        // Start a local HTTP server that captures the multipart POST
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();

        // Create a temp file to upload
        let tmp_dir = std::env::temp_dir().join("dionaea_upload_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).expect("create dir");
        let test_file = tmp_dir.join("test_data.bin");
        std::fs::write(&test_file, b"malware content").expect("write test file");

        // Spawn HTTP server that reads the full request
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // Read request headers + body (may arrive in multiple reads)
            let mut all = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                all.extend_from_slice(&buf[..n]);
                // Check if we've received the full request (look for closing boundary)
                let s = String::from_utf8_lossy(&all);
                if s.contains("--") && s.ends_with("--\r\n") {
                    break;
                }
                // Also break if we have a reasonable amount of data
                if all.len() > 2048 {
                    break;
                }
            }

            let request = String::from_utf8_lossy(&all).to_string();
            let request_lower = request.to_lowercase();

            // Verify it's a multipart POST with our fields
            assert!(
                request.starts_with("POST /upload"),
                "should be POST: {request}"
            );
            assert!(
                request_lower.contains("content-type: multipart/form-data"),
                "should be multipart: {request}"
            );
            assert!(request.contains("apikey"), "should contain apikey field");
            assert!(request.contains("abc123"), "should contain apikey value");
            assert!(
                request.contains("malware content"),
                "should contain file data"
            );

            // Send response
            let body = b"upload accepted";
            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            stream.write_all(response.as_bytes()).await.expect("write");
            stream.write_all(body).await.expect("write body");
        });

        let content_types = std::collections::HashMap::new();
        let result = upload_multipart(
            &format!("http://127.0.0.1:{port}/upload"),
            None,
            None,
            vec![("file".to_string(), test_file.to_string_lossy().to_string())],
            vec![("apikey".to_string(), "abc123".to_string())],
            &content_types,
            None,
            None,
            5,
        )
        .await;

        assert!(result.is_ok(), "upload should succeed: {result:?}");

        server.await.expect("server");
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
