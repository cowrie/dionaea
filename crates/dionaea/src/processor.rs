// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: GPL-3.0-only
// ABOUTME: Processor pipeline for intercepting connection I/O.
// ABOUTME: Supports filtering, bistream recording, and shellcode detection.

use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::bistream::BiStream;
use crate::config::ProcessorConfig;
use crate::connection::Direction;

/// A processor that can observe and act on connection I/O data.
///
/// Processors are stored in a global template tree. Per-connection
/// instances are created by calling `new_ctx()` for each accepted connection.
pub trait Processor: Send + Sync {
    /// Name of this processor (for logging/config).
    fn name(&self) -> &str;

    /// Whether this processor applies to a connection with the given
    /// protocol name and connection type ("accept", "connect", "listen").
    fn accepts(&self, _protocol: &str, _conn_type: &str) -> bool {
        true
    }

    /// Called when data is received from the remote.
    fn io_in(&self, _ctx: &mut dyn ProcessorCtx, _data: &[u8]) {}

    /// Called when data is sent to the remote.
    fn io_out(&self, _ctx: &mut dyn ProcessorCtx, _data: &[u8]) {}

    /// Create per-connection state for this processor.
    fn new_ctx(&self) -> Box<dyn ProcessorCtx>;
}

/// Per-connection state held by a processor instance.
pub trait ProcessorCtx: Send {
    /// Downcast to concrete type.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// A node in the processor template tree (built from config, shared globally).
pub struct ProcessorNode {
    /// The processor implementation.
    pub processor: Arc<dyn Processor>,
    /// Child processors that run after this one.
    pub children: Vec<ProcessorNode>,
}

/// Per-connection instantiation of the processor tree after filtering.
pub struct ProcessorPipeline {
    nodes: Vec<ActiveNode>,
    bistream: Arc<BiStream>,
}

impl std::fmt::Debug for ProcessorPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessorPipeline")
            .field("node_count", &self.nodes.len())
            .finish()
    }
}

/// A filtered, instantiated processor node with per-connection context.
struct ActiveNode {
    processor: Arc<dyn Processor>,
    ctx: Box<dyn ProcessorCtx>,
    children: Vec<ActiveNode>,
}

impl ProcessorPipeline {
    /// Build a pipeline by walking the template tree and filtering out
    /// processors that don't accept this connection's protocol/type.
    pub fn from_tree(
        tree: &[ProcessorNode],
        protocol: &str,
        conn_type: &str,
    ) -> Self {
        let mut nodes = Vec::new();
        for template in tree {
            if let Some(active) = Self::instantiate(template, protocol, conn_type) {
                nodes.push(active);
            }
        }
        ProcessorPipeline {
            nodes,
            bistream: Arc::new(BiStream::new()),
        }
    }

    fn instantiate(
        template: &ProcessorNode,
        protocol: &str,
        conn_type: &str,
    ) -> Option<ActiveNode> {
        if !template.processor.accepts(protocol, conn_type) {
            return None;
        }

        let ctx = template.processor.new_ctx();
        let mut children = Vec::new();
        for child_template in &template.children {
            if let Some(child) = Self::instantiate(child_template, protocol, conn_type) {
                children.push(child);
            }
        }

        Some(ActiveNode {
            processor: Arc::clone(&template.processor),
            ctx,
            children,
        })
    }

    /// Feed incoming data through the pipeline.
    pub fn io_in(&mut self, data: &[u8]) {
        self.bistream
            .push(Direction::In, bytes::Bytes::copy_from_slice(data));
        for node in &mut self.nodes {
            Self::dispatch_in(node, data);
        }
    }

    /// Feed outgoing data through the pipeline.
    pub fn io_out(&mut self, data: &[u8]) {
        self.bistream
            .push(Direction::Out, bytes::Bytes::copy_from_slice(data));
        for node in &mut self.nodes {
            Self::dispatch_out(node, data);
        }
    }

    fn dispatch_in(node: &mut ActiveNode, data: &[u8]) {
        node.processor.io_in(&mut *node.ctx, data);
        for child in &mut node.children {
            Self::dispatch_in(child, data);
        }
    }

    fn dispatch_out(node: &mut ActiveNode, data: &[u8]) {
        node.processor.io_out(&mut *node.ctx, data);
        for child in &mut node.children {
            Self::dispatch_out(child, data);
        }
    }

    /// Access the bistream for this connection.
    pub fn bistream(&self) -> &Arc<BiStream> {
        &self.bistream
    }

    /// Whether the pipeline has any active processors.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

// --- Config → Tree Builder ---

/// Build a processor node tree from config entries.
///
/// Each config entry has a `label` (unique name) and `next` (labels of children).
/// Root nodes are entries not referenced by any other entry's `next`.
pub fn build_tree(
    configs: &[ProcessorConfig],
    download_dir: &Path,
) -> Vec<ProcessorNode> {
    // Build processor instances indexed by label
    let mut processors: HashMap<&str, Arc<dyn Processor>> = HashMap::new();

    for cfg in configs {
        let processor: Arc<dyn Processor> = match cfg.name.as_str() {
            "filter" => {
                let allow: Vec<(Vec<String>, Vec<String>)> = cfg
                    .allow
                    .iter()
                    .map(|r| (r.protocols.clone(), r.types.clone()))
                    .collect();
                let deny: Vec<(Vec<String>, Vec<String>)> = cfg
                    .deny
                    .iter()
                    .map(|r| (r.protocols.clone(), r.types.clone()))
                    .collect();
                Arc::new(FilterProcessor::new(cfg.label.clone(), allow, deny))
            }
            "streamdumper" => {
                let path = cfg
                    .path
                    .clone()
                    .unwrap_or_else(|| "var/lib/dionaea/bistreams/%Y-%m-%d/".into());
                Arc::new(StreamDumper::new(path))
            }
            "shellcode" => Arc::new(ShellcodeProcessor::new(download_dir.to_path_buf())),
            other => {
                tracing::warn!(name = other, label = %cfg.label, "unknown processor type, skipping");
                continue;
            }
        };
        processors.insert(&cfg.label, processor);
    }

    // Build adjacency: label → children labels
    let mut children_map: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut referenced: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for cfg in configs {
        for next_label in &cfg.next {
            children_map
                .entry(cfg.label.as_str())
                .or_default()
                .push(next_label.as_str());
            referenced.insert(next_label.as_str());
        }
    }

    // Root nodes = those not referenced by any `next`
    let roots: Vec<&str> = configs
        .iter()
        .map(|c| c.label.as_str())
        .filter(|label| !referenced.contains(label))
        .collect();

    // Recursive tree builder
    fn build_node(
        label: &str,
        processors: &HashMap<&str, Arc<dyn Processor>>,
        children_map: &HashMap<&str, Vec<&str>>,
    ) -> Option<ProcessorNode> {
        let processor = processors.get(label)?.clone();
        let children = children_map
            .get(label)
            .map(|child_labels| {
                child_labels
                    .iter()
                    .filter_map(|child| build_node(child, processors, children_map))
                    .collect()
            })
            .unwrap_or_default();

        Some(ProcessorNode {
            processor,
            children,
        })
    }

    roots
        .into_iter()
        .filter_map(|label| build_node(label, &processors, &children_map))
        .collect()
}

// --- Filter Processor ---

/// A rule matching connection protocol and/or type.
#[derive(Debug, Clone)]
struct FilterRule {
    /// Protocol names to match (empty = any).
    protocols: Vec<String>,
    /// Connection types to match (empty = any). Values: "accept", "connect", "listen".
    conn_types: Vec<String>,
}

impl FilterRule {
    /// Check if this rule matches a given protocol and connection type.
    fn matches(&self, protocol: &str, conn_type: &str) -> bool {
        let proto_ok = self.protocols.is_empty() || self.protocols.iter().any(|p| p == protocol);
        let type_ok = self.conn_types.is_empty() || self.conn_types.iter().any(|t| t == conn_type);
        proto_ok && type_ok
    }
}

/// Processor that filters which connections pass through to its children.
///
/// Must match at least one allow rule AND zero deny rules.
pub struct FilterProcessor {
    label: String,
    allow: Vec<FilterRule>,
    deny: Vec<FilterRule>,
}

impl FilterProcessor {
    /// Create a new filter processor.
    pub fn new(label: String, allow: Vec<(Vec<String>, Vec<String>)>, deny: Vec<(Vec<String>, Vec<String>)>) -> Self {
        FilterProcessor {
            label,
            allow: allow
                .into_iter()
                .map(|(protocols, conn_types)| FilterRule {
                    protocols,
                    conn_types,
                })
                .collect(),
            deny: deny
                .into_iter()
                .map(|(protocols, conn_types)| FilterRule {
                    protocols,
                    conn_types,
                })
                .collect(),
        }
    }
}

impl Processor for FilterProcessor {
    fn name(&self) -> &str {
        &self.label
    }

    fn accepts(&self, protocol: &str, conn_type: &str) -> bool {
        // Must match at least one allow rule (if any exist)
        let allowed = self.allow.is_empty()
            || self.allow.iter().any(|r| r.matches(protocol, conn_type));
        // Must not match any deny rule
        let denied = self.deny.iter().any(|r| r.matches(protocol, conn_type));
        allowed && !denied
    }

    fn io_in(&self, _ctx: &mut dyn ProcessorCtx, _data: &[u8]) {
        // Filters don't process data, they only gate children
    }

    fn io_out(&self, _ctx: &mut dyn ProcessorCtx, _data: &[u8]) {}

    fn new_ctx(&self) -> Box<dyn ProcessorCtx> {
        Box::new(EmptyCtx)
    }
}

/// No-op per-connection context for processors that don't need state.
struct EmptyCtx;

impl ProcessorCtx for EmptyCtx {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// --- StreamDumper Processor ---

/// Records bidirectional I/O to disk in Python-eval-compatible format.
///
/// Output format (one per connection):
/// ```python
/// stream = [('in', b'GET / HTTP/1.1\r\n'), ('out', b'HTTP/1.1 200 OK\r\n')]
/// ```
///
/// Files are written to a directory derived from the configured path pattern,
/// which supports strftime-style `%Y`, `%m`, `%d` substitution.
pub struct StreamDumper {
    path_pattern: String,
}

impl StreamDumper {
    /// Create a new stream dumper with the given path pattern.
    pub fn new(path_pattern: String) -> Self {
        StreamDumper { path_pattern }
    }
}

impl Processor for StreamDumper {
    fn name(&self) -> &str {
        "streamdumper"
    }

    fn new_ctx(&self) -> Box<dyn ProcessorCtx> {
        let dir = expand_strftime(&self.path_pattern);
        let dir_path = PathBuf::from(&dir);
        // Reject path patterns that contain traversal sequences after expansion
        if dir.contains("..") {
            tracing::error!(path = %dir, "streamdumper path contains traversal, refusing");
            return Box::new(StreamDumperCtx {
                dir: PathBuf::new(),
                file: None,
                chunk_count: 0,
                disabled: true,
            });
        }
        Box::new(StreamDumperCtx {
            dir: dir_path,
            file: None,
            chunk_count: 0,
            disabled: false,
        })
    }

    fn io_in(&self, ctx: &mut dyn ProcessorCtx, data: &[u8]) {
        let ctx = ctx
            .as_any_mut()
            .downcast_mut::<StreamDumperCtx>()
            .expect("StreamDumperCtx");
        ctx.write_chunk("in", data);
    }

    fn io_out(&self, ctx: &mut dyn ProcessorCtx, data: &[u8]) {
        let ctx = ctx
            .as_any_mut()
            .downcast_mut::<StreamDumperCtx>()
            .expect("StreamDumperCtx");
        ctx.write_chunk("out", data);
    }
}

/// Per-connection state for the stream dumper.
struct StreamDumperCtx {
    dir: PathBuf,
    file: Option<fs::File>,
    chunk_count: usize,
    disabled: bool,
}

impl StreamDumperCtx {
    fn write_chunk(&mut self, direction: &str, data: &[u8]) {
        if self.disabled {
            return;
        }
        if let Err(e) = self.write_chunk_inner(direction, data) {
            tracing::warn!(err = %e, "streamdumper write failed");
        }
    }

    fn write_chunk_inner(
        &mut self,
        direction: &str,
        data: &[u8],
    ) -> std::io::Result<()> {
        let file = match &mut self.file {
            Some(f) => f,
            None => {
                fs::create_dir_all(&self.dir)?;
                let path = self.dir.join(format!(
                    "{}-{}.bistream",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                ));
                let f = fs::File::create(&path)?;
                tracing::debug!(path = %path.display(), "opened bistream file");
                self.file = Some(f);
                self.file.as_mut().expect("just created")
            }
        };

        // Write Python-compatible format
        if self.chunk_count == 0 {
            write!(file, "stream = [(")?;
        } else {
            write!(file, ", (")?;
        }
        write!(file, "'{direction}', ")?;
        write_python_bytes(file, data)?;
        write!(file, ")")?;
        self.chunk_count += 1;
        Ok(())
    }
}

impl Drop for StreamDumperCtx {
    fn drop(&mut self) {
        if let Some(ref mut file) = self.file {
            // Close the Python list
            let _ = writeln!(file, "]");
        }
    }
}

impl ProcessorCtx for StreamDumperCtx {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Write bytes as a Python bytes literal (b'...') with proper escaping.
fn write_python_bytes(w: &mut impl Write, data: &[u8]) -> std::io::Result<()> {
    w.write_all(b"b'")?;
    for &byte in data {
        match byte {
            b'\\' => w.write_all(b"\\\\")?,
            b'\'' => w.write_all(b"\\'")?,
            b'\n' => w.write_all(b"\\n")?,
            b'\r' => w.write_all(b"\\r")?,
            b'\t' => w.write_all(b"\\t")?,
            0x20..=0x7E => w.write_all(&[byte])?,
            _ => write!(w, "\\x{byte:02x}")?,
        }
    }
    w.write_all(b"'")?;
    Ok(())
}

// --- Shellcode Processor ---

/// Detects shellcode in incoming data using GetPC pattern scanning.
///
/// On detection: saves shellcode bytes to a file (content-addressable by SHA256)
/// and emits a `dionaea.shellcode.detected` incident.
pub struct ShellcodeProcessor {
    download_dir: PathBuf,
}

impl ShellcodeProcessor {
    /// Create a new shellcode processor that saves detections to the given directory.
    pub fn new(download_dir: PathBuf) -> Self {
        ShellcodeProcessor { download_dir }
    }
}

impl Processor for ShellcodeProcessor {
    fn name(&self) -> &str {
        "shellcode"
    }

    fn new_ctx(&self) -> Box<dyn ProcessorCtx> {
        Box::new(ShellcodeCtx {
            scan_offset: 0,
            download_dir: self.download_dir.clone(),
        })
    }

    fn io_in(&self, ctx: &mut dyn ProcessorCtx, data: &[u8]) {
        let ctx = ctx
            .as_any_mut()
            .downcast_mut::<ShellcodeCtx>()
            .expect("ShellcodeCtx");
        ctx.scan(data);
    }

    fn io_out(&self, _ctx: &mut dyn ProcessorCtx, _data: &[u8]) {
        // Only scan incoming data (attacker → honeypot)
    }
}

/// Per-connection state for the shellcode detector.
struct ShellcodeCtx {
    scan_offset: usize,
    download_dir: PathBuf,
}

impl ShellcodeCtx {
    fn scan(&mut self, data: &[u8]) {
        // Only scan new data (after scan_offset within this chunk)
        if let Some(det) = shell_detect::detect(data) {
            let hash = {
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            };

            let path = self.download_dir.join(format!("shellcode-{hash}.bin"));

            // Content-addressable: skip if already exists
            if !path.exists() {
                if let Err(e) = fs::create_dir_all(&self.download_dir) {
                    tracing::warn!(err = %e, "failed to create shellcode dir");
                    return;
                }
                if let Err(e) = fs::write(&path, data) {
                    tracing::warn!(err = %e, "failed to write shellcode");
                    return;
                }
            }

            let global_offset = self.scan_offset + det.offset;
            tracing::info!(
                arch = %det.arch,
                offset = global_offset,
                hash = %hash,
                path = %path.display(),
                "shellcode detected"
            );

            // Emit incident (requires GIL — spawn a thread)
            emit_shellcode_incident(
                det.arch.to_string(),
                global_offset,
                hash,
                path.to_string_lossy().to_string(),
            );
        }

        self.scan_offset += data.len();
    }
}

impl ProcessorCtx for ShellcodeCtx {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Emit a `dionaea.shellcode.detected` incident via Python's incident system.
fn emit_shellcode_incident(arch: String, offset: usize, hash: String, path: String) {
    let _ = std::thread::spawn(move || {
        pyo3::Python::attach(|py| {
            use pyo3::types::PyAnyMethods;

            let inc = pyo3::Py::new(
                py,
                crate::python::incident::PyIncident::new(Some(
                    "dionaea.shellcode.detected".to_string(),
                )),
            );
            let Ok(inc) = inc else {
                tracing::error!("failed to create shellcode.detected incident");
                return;
            };
            let bound = inc.into_bound(py).into_any();
            let _ = bound.setattr("arch", &arch);
            let _ = bound.setattr("offset", offset);
            let _ = bound.setattr("sha256hash", &hash);
            let _ = bound.setattr("path", &path);
            if let Err(e) = bound.call_method0("report") {
                tracing::error!(error = %e, "failed to report shellcode.detected");
            }
        });
    })
    .join();
}

/// Expand strftime-style patterns in a path string.
/// Supports: %Y (year), %m (month), %d (day), %H (hour), %M (minute), %S (second).
pub fn expand_strftime(pattern: &str) -> String {
    use std::time::SystemTime;

    let secs = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    expand_strftime_with_epoch(pattern, secs)
}

/// Expand strftime patterns using a specific epoch timestamp (for testing).
fn expand_strftime_with_epoch(pattern: &str, epoch_secs: u64) -> String {
    // Convert epoch seconds to date components
    // Algorithm from Howard Hinnant's civil_from_days
    let days = (epoch_secs / 86400) as i64;
    let time_of_day = epoch_secs % 86400;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    pattern
        .replace("%Y", &format!("{y:04}"))
        .replace("%m", &format!("{m:02}"))
        .replace("%d", &format!("{d:02}"))
        .replace("%H", &format!("{hour:02}"))
        .replace("%M", &format!("{minute:02}"))
        .replace("%S", &format!("{second:02}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Filter tests ---

    #[test]
    fn filter_allow_all() {
        let filter = FilterProcessor::new("test".into(), vec![], vec![]);
        assert!(filter.accepts("httpd", "accept"));
        assert!(filter.accepts("smbd", "connect"));
    }

    #[test]
    fn filter_allow_by_type() {
        let filter = FilterProcessor::new(
            "test".into(),
            vec![(vec![], vec!["accept".into()])],
            vec![],
        );
        assert!(filter.accepts("httpd", "accept"));
        assert!(!filter.accepts("httpd", "connect"));
    }

    #[test]
    fn filter_allow_by_protocol() {
        let filter = FilterProcessor::new(
            "test".into(),
            vec![(vec!["httpd".into(), "smbd".into()], vec![])],
            vec![],
        );
        assert!(filter.accepts("httpd", "accept"));
        assert!(filter.accepts("smbd", "connect"));
        assert!(!filter.accepts("ftpd", "accept"));
    }

    #[test]
    fn filter_deny_overrides_allow() {
        let filter = FilterProcessor::new(
            "test".into(),
            vec![(vec![], vec!["accept".into()])],
            vec![(vec!["ftpdata".into()], vec![])],
        );
        assert!(filter.accepts("httpd", "accept"));
        assert!(!filter.accepts("ftpdata", "accept")); // denied
    }

    #[test]
    fn filter_multiple_allow_rules() {
        let filter = FilterProcessor::new(
            "test".into(),
            vec![
                (vec![], vec!["accept".into()]),
                (vec!["ftpctrl".into()], vec!["connect".into()]),
            ],
            vec![],
        );
        assert!(filter.accepts("httpd", "accept"));
        assert!(filter.accepts("ftpctrl", "connect"));
        assert!(!filter.accepts("httpd", "connect")); // not accepted
    }

    // --- Pipeline tests ---

    /// Simple counting processor for testing.
    struct CountingProcessor {
        name: String,
    }
    struct CountingCtx {
        in_count: usize,
        out_count: usize,
    }
    impl ProcessorCtx for CountingCtx {
        fn as_any_mut(&mut self) -> &mut dyn Any { self }
    }
    impl Processor for CountingProcessor {
        fn name(&self) -> &str { &self.name }
        fn new_ctx(&self) -> Box<dyn ProcessorCtx> {
            Box::new(CountingCtx { in_count: 0, out_count: 0 })
        }
        fn io_in(&self, ctx: &mut dyn ProcessorCtx, _data: &[u8]) {
            let ctx = ctx.as_any_mut().downcast_mut::<CountingCtx>().unwrap();
            ctx.in_count += 1;
        }
        fn io_out(&self, ctx: &mut dyn ProcessorCtx, _data: &[u8]) {
            let ctx = ctx.as_any_mut().downcast_mut::<CountingCtx>().unwrap();
            ctx.out_count += 1;
        }
    }

    #[test]
    fn pipeline_from_empty_tree() {
        let pipeline = ProcessorPipeline::from_tree(&[], "httpd", "accept");
        assert!(pipeline.is_empty());
    }

    #[test]
    fn pipeline_dispatches_io() {
        let tree = vec![ProcessorNode {
            processor: Arc::new(CountingProcessor { name: "counter".into() }),
            children: vec![],
        }];
        let mut pipeline = ProcessorPipeline::from_tree(&tree, "httpd", "accept");
        assert!(!pipeline.is_empty());

        pipeline.io_in(b"hello");
        pipeline.io_in(b"world");
        pipeline.io_out(b"response");

        // Verify bistream recorded everything
        assert_eq!(pipeline.bistream().len(), 3);
        assert_eq!(pipeline.bistream().total_bytes(Direction::In), 10);
        assert_eq!(pipeline.bistream().total_bytes(Direction::Out), 8);
    }

    #[test]
    fn pipeline_filters_by_protocol() {
        let filter = Arc::new(FilterProcessor::new(
            "filter".into(),
            vec![(vec!["smbd".into()], vec![])],
            vec![],
        ));
        let counter: Arc<dyn Processor> = Arc::new(CountingProcessor { name: "counter".into() });

        let tree = vec![ProcessorNode {
            processor: filter,
            children: vec![ProcessorNode {
                processor: counter,
                children: vec![],
            }],
        }];

        // smbd should pass the filter
        let pipeline = ProcessorPipeline::from_tree(&tree, "smbd", "accept");
        assert!(!pipeline.is_empty());

        // httpd should be filtered out
        let pipeline = ProcessorPipeline::from_tree(&tree, "httpd", "accept");
        assert!(pipeline.is_empty());
    }

    // --- StreamDumper tests ---

    #[test]
    fn streamdumper_writes_bistream_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let dumper = StreamDumper::new(dir.path().to_str().unwrap().to_string());

        let tree = vec![ProcessorNode {
            processor: Arc::new(dumper),
            children: vec![],
        }];

        let mut pipeline = ProcessorPipeline::from_tree(&tree, "httpd", "accept");
        pipeline.io_in(b"GET / HTTP/1.1\r\n");
        pipeline.io_out(b"HTTP/1.1 200 OK\r\n");

        // Drop pipeline to close the file
        drop(pipeline);

        // Find the bistream file
        let entries: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);

        let content = fs::read_to_string(entries[0].path()).expect("read file");
        assert!(content.starts_with("stream = [("));
        assert!(content.contains("'in'"));
        assert!(content.contains("'out'"));
        assert!(content.contains("GET / HTTP/1.1"));
        assert!(content.contains("HTTP/1.1 200 OK"));
        assert!(content.ends_with("]\n"));
    }

    #[test]
    fn python_bytes_escaping() {
        let mut buf = Vec::new();
        write_python_bytes(&mut buf, b"hello\r\n\t\\world'").expect("write");
        let s = String::from_utf8(buf).expect("utf8");
        assert_eq!(s, r"b'hello\r\n\t\\world\''");
    }

    #[test]
    fn python_bytes_non_printable() {
        let mut buf = Vec::new();
        write_python_bytes(&mut buf, &[0x00, 0x01, 0xFF, 0x41]).expect("write");
        let s = String::from_utf8(buf).expect("utf8");
        assert_eq!(s, r"b'\x00\x01\xffA'");
    }

    #[test]
    fn strftime_expansion() {
        // 2024-01-15 12:30:45 UTC = epoch 1705318245
        let result = expand_strftime_with_epoch("var/lib/%Y-%m-%d/bistreams", 1_705_318_245);
        assert_eq!(result, "var/lib/2024-01-15/bistreams");
    }

    #[test]
    fn strftime_time_components() {
        // 2024-01-15 11:30:45 UTC = epoch 1705318245
        let result = expand_strftime_with_epoch("%H-%M-%S", 1_705_318_245);
        assert_eq!(result, "11-30-45");
    }

    // --- build_tree tests ---

    #[test]
    fn build_tree_empty_config() {
        let tree = build_tree(&[], Path::new("/tmp"));
        assert!(tree.is_empty());
    }

    #[test]
    fn build_tree_filter_with_child() {
        let configs = vec![
            ProcessorConfig {
                name: "filter".into(),
                label: "filter_sd".into(),
                next: vec!["sd".into()],
                allow: vec![crate::config::FilterRuleConfig {
                    types: vec!["accept".into()],
                    protocols: vec![],
                }],
                deny: vec![],
                path: None,
            },
            ProcessorConfig {
                name: "streamdumper".into(),
                label: "sd".into(),
                next: vec![],
                allow: vec![],
                deny: vec![],
                path: Some("/tmp/bistreams/%Y-%m-%d/".into()),
            },
        ];

        let tree = build_tree(&configs, Path::new("/tmp"));
        // Only filter_sd should be a root (sd is referenced by next)
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].processor.name(), "filter_sd");
        assert_eq!(tree[0].children.len(), 1);
        assert_eq!(tree[0].children[0].processor.name(), "streamdumper");
    }

    #[test]
    fn build_tree_two_independent_roots() {
        let configs = vec![
            ProcessorConfig {
                name: "streamdumper".into(),
                label: "sd".into(),
                next: vec![],
                allow: vec![],
                deny: vec![],
                path: Some("/tmp/bs/".into()),
            },
            ProcessorConfig {
                name: "shellcode".into(),
                label: "sc".into(),
                next: vec![],
                allow: vec![],
                deny: vec![],
                path: None,
            },
        ];

        let tree = build_tree(&configs, Path::new("/tmp"));
        assert_eq!(tree.len(), 2);
    }

    // --- ShellcodeProcessor tests ---

    #[test]
    fn shellcode_saves_detection() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let detector = ShellcodeProcessor::new(dir.path().to_path_buf());

        let tree = vec![ProcessorNode {
            processor: Arc::new(detector),
            children: vec![],
        }];

        let mut pipeline = ProcessorPipeline::from_tree(&tree, "smbd", "accept");

        // Send x86 call+pop shellcode
        let shellcode = vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x90, 0x90];
        pipeline.io_in(&shellcode);

        // Check that a shellcode file was written
        let entries: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);

        let name = entries[0].file_name();
        let name_str = name.to_str().expect("filename");
        assert!(name_str.starts_with("shellcode-"));
        assert!(name_str.ends_with(".bin"));

        // Verify contents match the shellcode
        let saved = fs::read(entries[0].path()).expect("read shellcode");
        assert_eq!(saved, shellcode);
    }

    #[test]
    fn shellcode_deduplication() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let detector = ShellcodeProcessor::new(dir.path().to_path_buf());

        let tree = vec![ProcessorNode {
            processor: Arc::new(detector),
            children: vec![],
        }];

        let mut pipeline = ProcessorPipeline::from_tree(&tree, "smbd", "accept");

        // Send same shellcode twice
        let shellcode = vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x90];
        pipeline.io_in(&shellcode);
        pipeline.io_in(&shellcode);

        // Should only have one file (content-addressable)
        let entries: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn shellcode_no_detection_on_clean_data() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let detector = ShellcodeProcessor::new(dir.path().to_path_buf());

        let tree = vec![ProcessorNode {
            processor: Arc::new(detector),
            children: vec![],
        }];

        let mut pipeline = ProcessorPipeline::from_tree(&tree, "httpd", "accept");
        pipeline.io_in(b"GET / HTTP/1.1\r\n");

        // No shellcode files
        let entries: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn shellcode_scan_offset_tracking() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let detector = ShellcodeProcessor::new(dir.path().to_path_buf());
        let mut ctx = detector.new_ctx();

        let ctx = ctx.as_any_mut().downcast_mut::<ShellcodeCtx>().unwrap();

        // First chunk: clean data (100 bytes)
        let clean_data = vec![0x41u8; 100];
        ctx.scan(&clean_data);
        assert_eq!(ctx.scan_offset, 100);

        // Second chunk: more clean data
        ctx.scan(&clean_data);
        assert_eq!(ctx.scan_offset, 200);
    }

    // --- Pipeline tests ---

    #[test]
    fn pipeline_nested_dispatch() {
        let parent: Arc<dyn Processor> = Arc::new(CountingProcessor { name: "parent".into() });
        let child: Arc<dyn Processor> = Arc::new(CountingProcessor { name: "child".into() });

        let tree = vec![ProcessorNode {
            processor: parent,
            children: vec![ProcessorNode {
                processor: child,
                children: vec![],
            }],
        }];

        let mut pipeline = ProcessorPipeline::from_tree(&tree, "httpd", "accept");
        pipeline.io_in(b"data");

        // Both parent and child should have been called (verified via bistream)
        assert_eq!(pipeline.bistream().len(), 1);
    }
}
