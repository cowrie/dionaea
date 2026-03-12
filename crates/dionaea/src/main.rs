// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: Entry point for the dionaea honeypot daemon.
// ABOUTME: Initializes config, logging, Python, tokio runtime, and signal handlers.

//! Dionaea honeypot daemon entry point.

use dionaea::config;
use dionaea::processor;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// File writer that supports reopening (for SIGHUP-based log rotation).
///
/// Holds a shared file handle behind a mutex so that the tracing layer and
/// the SIGHUP handler both refer to the same underlying file.
#[derive(Clone)]
struct ReopenableWriter {
    file: Arc<Mutex<File>>,
    path: PathBuf,
}

impl ReopenableWriter {
    fn new(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(ReopenableWriter {
            file: Arc::new(Mutex::new(file)),
            path: path.to_path_buf(),
        })
    }

    fn reopen(&self) -> io::Result<()> {
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut guard = self.file.lock().expect("log file lock");
        *guard = new_file;
        Ok(())
    }
}

impl io::Write for ReopenableWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.lock().expect("log file lock").write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.lock().expect("log file lock").flush()
    }
}

/// Guard returned by `MakeWriter` that holds the mutex for one log event.
struct WriterGuard<'a>(std::sync::MutexGuard<'a, File>);

impl io::Write for WriterGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ReopenableWriter {
    type Writer = WriterGuard<'a>;
    fn make_writer(&'a self) -> Self::Writer {
        WriterGuard(self.file.lock().expect("log file lock"))
    }
}

/// Holds references to file-based log writers for SIGHUP reopening.
struct LogState {
    file_writers: Vec<ReopenableWriter>,
}

impl LogState {
    fn reopen_all(&self) {
        for writer in &self.file_writers {
            if let Err(e) = writer.reopen() {
                eprintln!("failed to reopen log file {}: {e}", writer.path.display());
            }
        }
    }
}

/// Timestamp formatter that produces RFC 3339 with `Z` suffix instead of `+00:00`.
struct Rfc3339Utc;

impl tracing_subscriber::fmt::time::FormatTime for Rfc3339Utc {
    fn format_time(
        &self,
        w: &mut tracing_subscriber::fmt::format::Writer<'_>,
    ) -> std::fmt::Result {
        write!(w, "{}", chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
    }
}

fn main() {
    // Parse CLI args
    let config_path = parse_args();

    // Load config
    let config = match config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fatal: {e}");
            std::process::exit(1);
        }
    };

    // Initialize tracing (logging)
    let log_state = init_tracing(&config.logging);

    tracing::info!(
        version = dionaea::python::dionaea::VERSION,
        config = %config_path.display(),
        "dionaea starting"
    );

    // Ignore SIGPIPE (broken pipe on network writes)
    #[cfg(unix)]
    ignore_sigpipe();

    // Initialize Python interpreter
    tracing::info!("initializing Python interpreter");
    pyo3::Python::attach(|py| {
        use pyo3::prelude::*;
        let version: String = py
            .import(c"sys")
            .expect("import sys")
            .getattr("version")
            .expect("sys.version")
            .extract()
            .expect("version string");
        tracing::info!(python_version = %version, "Python initialized");
    });

    // Build and start tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_workers())
        .max_blocking_threads(64)
        .enable_all()
        .thread_name("dionaea-worker")
        .build()
        .expect("tokio runtime");

    rt.block_on(async_main(config, log_state));

    tracing::info!("dionaea shut down");
}

/// Async entry point running inside the tokio runtime.
async fn async_main(config: config::Config, log_state: LogState) {
    use std::sync::Arc;
    use dionaea::connection::limits::ConnectionLimits;
    use dionaea::connection::ConnectionRegistry;
    use dionaea::runtime;

    // Create shared connection infrastructure
    let registry = Arc::new(ConnectionRegistry::new());
    let limits = Arc::new(ConnectionLimits::new(
        config.dionaea.limits.max_connections_per_ip,
        config.dionaea.limits.max_connections_total,
        config.dionaea.limits.max_fds_pct,
    ));
    let processor_tree = processor::build_tree(
        &config.processors,
        &config.dionaea.download.dir,
    );
    let state = Arc::new(runtime::RuntimeState::new(
        registry.clone(),
        limits,
        config.dionaea.limits.recv_buffer_size,
        config,
        processor_tree,
    ));
    runtime::init(state.clone());

    tracing::info!(
        listen_mode = %state.config.dionaea.listen.mode,
        max_connections = state.config.dionaea.limits.max_connections_total,
        "daemon ready"
    );

    // Load Python modules (must run with GIL via spawn_blocking)
    {
        let python_config = &state.config.modules.python;
        // Clone what we need to move into the blocking task
        let imports = python_config.imports.clone();
        let service_configs = python_config.service_configs.clone();
        let ihandler_configs = python_config.ihandler_configs.clone();
        let python_path = python_config.python_path.clone();
        let load_result = tokio::task::spawn_blocking(move || {
            pyo3::Python::attach(|py| {
                let config = dionaea::config::PythonModuleConfig {
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
            tracing::error!(error = %e, "failed to load Python modules");
            std::process::exit(1);
        }
    }

    // Register built-in Rust modules
    #[cfg(feature = "download")]
    if state.config.modules.download {
        dionaea::download::register();
    }
    #[cfg(feature = "upload")]
    if state.config.modules.upload {
        dionaea::upload::register();
    }

    // Start pcap capture threads (before privilege drop — needs raw socket access).
    #[cfg(feature = "pcap")]
    let pcap_shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    #[cfg(feature = "pcap")]
    let pcap_threads = if let Some(ref pcap_config) = state.config.modules.pcap {
        Some(dionaea::pcap::start(pcap_config, &pcap_shutdown))
    } else {
        None
    };

    // Drop privileges after all ports are bound
    {
        if let Err(e) = dionaea::privileges::raise_nofile_limit() {
            tracing::warn!(error = %e, "failed to raise RLIMIT_NOFILE");
        }

        if let (Some(user), Some(group)) = (&state.config.dionaea.user, &state.config.dionaea.group) {
            match (
                dionaea::privileges::resolve_user(user),
                dionaea::privileges::resolve_group(group),
            ) {
                (Ok(uid), Ok(gid)) => {
                    if let Err(e) = dionaea::privileges::drop_privileges(uid, gid) {
                        tracing::error!(error = %e, "failed to drop privileges");
                        std::process::exit(1);
                    }
                }
                (Err(e), _) => {
                    tracing::error!(error = %e, user = %user, "failed to resolve user");
                    std::process::exit(1);
                }
                (_, Err(e)) => {
                    tracing::error!(error = %e, group = %group, "failed to resolve group");
                    std::process::exit(1);
                }
            }
        } else {
            tracing::info!("no user/group configured, skipping privilege drop");
        }
    }

    // Wait for shutdown signal. SIGHUP reopens logs without shutting down.
    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler");
        let mut sigint =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .expect("SIGINT handler");
        let mut sighup =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("SIGHUP handler");

        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    tracing::info!("received SIGTERM, shutting down");
                    break;
                }
                _ = sigint.recv() => {
                    tracing::info!("received SIGINT, shutting down");
                    break;
                }
                _ = sighup.recv() => {
                    tracing::info!("received SIGHUP, reopening logs");
                    log_state.reopen_all();
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.expect("ctrl-c handler");
        tracing::info!("received Ctrl-C, shutting down");
    }

    // Graceful shutdown with timeout. A second SIGINT forces immediate exit.
    graceful_shutdown(state, registry, #[cfg(feature = "pcap")] pcap_threads, #[cfg(feature = "pcap")] pcap_shutdown).await;
}

/// Shutdown timeout in seconds.
const SHUTDOWN_TIMEOUT_SECS: u64 = 5;

async fn graceful_shutdown(
    state: Arc<dionaea::runtime::RuntimeState>,
    registry: Arc<dionaea::connection::ConnectionRegistry>,
    #[cfg(feature = "pcap")] pcap_threads: Option<Vec<std::thread::JoinHandle<()>>>,
    #[cfg(feature = "pcap")] pcap_shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    // Second SIGINT forces immediate exit.
    #[cfg(unix)]
    let mut force_sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("SIGINT handler");

    let shutdown_work = async {
        state.stop_all_listeners();
        tracing::debug!("listeners stopped");

        // Signal pcap threads to stop. Don't join — pcap_next_packet blocks
        // indefinitely on macOS despite the configured timeout. The threads
        // will exit on their own or be cleaned up at process exit.
        #[cfg(feature = "pcap")]
        {
            pcap_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
            drop(pcap_threads);
            tracing::debug!("pcap signaled");
        }

        tracing::info!(
            active_connections = registry.len(),
            "draining connections"
        );

        // Call Python module stop() functions
        {
            let imports = state.config.modules.python.imports.clone();
            let service_configs = state.config.modules.python.service_configs.clone();
            let ihandler_configs = state.config.modules.python.ihandler_configs.clone();
            let python_path = state.config.modules.python.python_path.clone();
            let _ = tokio::task::spawn_blocking(move || {
                pyo3::Python::attach(|py| {
                    let config = dionaea::config::PythonModuleConfig {
                        imports,
                        service_configs,
                        ihandler_configs,
                        python_path,
                    };
                    dionaea::python::loader::shutdown(py, &config);
                });
            })
            .await;
            tracing::debug!("python modules stopped");
        }

        // Clear ihandler registry
        state
            .ihandler_registry
            .lock()
            .expect("registry lock")
            .clear();

        tracing::info!("shutdown complete");
    };

    tokio::select! {
        result = tokio::time::timeout(
            std::time::Duration::from_secs(SHUTDOWN_TIMEOUT_SECS),
            shutdown_work,
        ) => {
            if result.is_err() {
                tracing::warn!("shutdown timed out after {SHUTDOWN_TIMEOUT_SECS}s, forcing exit");
                std::process::exit(1);
            }
        }
        _ = async {
            #[cfg(unix)]
            force_sigint.recv().await;
            #[cfg(not(unix))]
            tokio::signal::ctrl_c().await.ok();
        } => {
            tracing::warn!("forced shutdown (second signal)");
            std::process::exit(1);
        }
    }
}

/// Parse command-line arguments. Returns config file path.
fn parse_args() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = PathBuf::from("/etc/dionaea/dionaea.toml");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if i < args.len() {
                    config_path = PathBuf::from(&args[i]);
                } else {
                    eprintln!("error: -c/--config requires an argument");
                    std::process::exit(1);
                }
            }
            "-V" | "--version" => {
                println!("dionaea {}", dionaea::python::dionaea::VERSION);
                std::process::exit(0);
            }
            "-h" | "--help" => {
                println!("dionaea {} - low-interaction honeypot", dionaea::python::dionaea::VERSION);
                println!();
                println!("Usage: dionaea [OPTIONS]");
                println!();
                println!("Options:");
                println!("  -c, --config <PATH>  Config file [default: /etc/dionaea/dionaea.toml]");
                println!("  -V, --version        Print version");
                println!("  -h, --help           Print help");
                std::process::exit(0);
            }
            other => {
                eprintln!("error: unknown argument '{other}'");
                eprintln!("Try 'dionaea --help' for usage");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    config_path
}

/// Initialize tracing subscriber with configured targets.
///
/// Returns `LogState` holding file writers so SIGHUP can reopen them.
fn init_tracing(logging_config: &config::LoggingConfig) -> LogState {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&logging_config.level));

    let mut log_state = LogState {
        file_writers: Vec::new(),
    };

    // If no targets configured, default to stdout text
    if logging_config.targets.is_empty() {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_timer(Rfc3339Utc)
                    .with_target(true),
            )
            .init();
        return log_state;
    }

    let layers = build_log_layers(&logging_config.targets, &mut log_state);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(layers)
        .init();

    log_state
}

/// Parse a `levels` config string into a tracing `LevelFilter`.
///
/// Accepts comma-separated level names: `"warning,error,critical"`.
/// Maps to the most permissive (lowest) level in the list.
/// Supports dionaea-style names: "critical" → ERROR, "warning" → WARN.
fn parse_level_filter(levels: &str) -> tracing_subscriber::filter::LevelFilter {
    use tracing_subscriber::filter::LevelFilter;

    let mut most_permissive = LevelFilter::OFF;

    for level in levels.split(',') {
        let l = match level.trim().to_lowercase().as_str() {
            "trace" => LevelFilter::TRACE,
            "debug" => LevelFilter::DEBUG,
            "info" => LevelFilter::INFO,
            "warn" | "warning" => LevelFilter::WARN,
            "error" | "critical" => LevelFilter::ERROR,
            s if s.starts_with("all") => LevelFilter::TRACE,
            _ => continue,
        };
        if l > most_permissive {
            most_permissive = l;
        }
    }

    most_permissive
}

/// Build tracing layers for each configured log target.
fn build_log_layers<S>(
    targets: &[config::LogTarget],
    state: &mut LogState,
) -> Vec<Box<dyn tracing_subscriber::Layer<S> + Send + Sync>>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::fmt;

    let mut layers: Vec<Box<dyn tracing_subscriber::Layer<S> + Send + Sync>> = Vec::new();

    for target in targets {
        let level_filter = parse_level_filter(&target.levels);

        match target.target_type.as_str() {
            "stdout" => {
                if target.format == "json" {
                    layers.push(Box::new(
                        fmt::layer()
                            .json()
                            .with_timer(Rfc3339Utc)
                            .with_target(true)
                            .with_filter(level_filter),
                    ));
                } else {
                    layers.push(Box::new(
                        fmt::layer()
                            .with_timer(Rfc3339Utc)
                            .with_target(true)
                            .with_filter(level_filter),
                    ));
                }
            }
            "file" => {
                let Some(path) = &target.path else {
                    eprintln!("log target of type 'file' has no path, skipping");
                    continue;
                };

                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() && !parent.exists() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            eprintln!(
                                "failed to create log directory {}: {e}",
                                parent.display()
                            );
                            continue;
                        }
                    }
                }

                let writer = match ReopenableWriter::new(path) {
                    Ok(w) => w,
                    Err(e) => {
                        eprintln!("failed to open log file {}: {e}", path.display());
                        continue;
                    }
                };

                state.file_writers.push(writer.clone());

                if target.format == "json" {
                    layers.push(Box::new(
                        fmt::layer()
                            .json()
                            .with_timer(Rfc3339Utc)
                            .with_target(true)
                            .with_writer(writer)
                            .with_filter(level_filter),
                    ));
                } else {
                    layers.push(Box::new(
                        fmt::layer()
                            .with_timer(Rfc3339Utc)
                            .with_target(true)
                            .with_ansi(false)
                            .with_writer(writer)
                            .with_filter(level_filter),
                    ));
                }
            }
            other => {
                eprintln!("unknown log target type: {other}, skipping");
            }
        }
    }

    // If no valid targets were built, add default stdout text
    if layers.is_empty() {
        layers.push(Box::new(
            fmt::layer().with_timer(Rfc3339Utc).with_target(true),
        ));
    }

    layers
}

/// Ignore SIGPIPE to prevent crashes on broken network connections.
#[cfg(unix)]
fn ignore_sigpipe() {
    use nix::sys::signal::{signal, SigHandler, Signal};

    // SAFETY: SIG_IGN is safe — it just tells the kernel to discard SIGPIPE.
    // This is standard practice for network daemons.
    #[allow(unsafe_code)]
    unsafe {
        signal(Signal::SIGPIPE, SigHandler::SigIgn).expect("ignore SIGPIPE");
    }
}

/// Number of tokio worker threads: at least 2, up to CPU count.
fn num_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().max(2))
        .unwrap_or(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reopenable_writer_creates_file() {
        let dir = std::env::temp_dir().join("dionaea_rw_test_create");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let path = dir.join("test.log");
        let writer = ReopenableWriter::new(&path).expect("new writer");

        use io::Write;
        let mut w = writer.clone();
        w.write_all(b"hello\n").expect("write");
        w.flush().expect("flush");

        let content = std::fs::read_to_string(&path).expect("read");
        assert!(content.contains("hello"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reopenable_writer_reopen_after_rename() {
        let dir = std::env::temp_dir().join("dionaea_rw_test_reopen");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let path = dir.join("test.log");
        let writer = ReopenableWriter::new(&path).expect("new writer");

        use io::Write;
        let mut w = writer.clone();
        w.write_all(b"before\n").expect("write");
        w.flush().expect("flush");

        // Simulate logrotate: rename the file
        let rotated = dir.join("test.log.1");
        std::fs::rename(&path, &rotated).expect("rename");

        // Reopen — creates a new file at the original path
        writer.reopen().expect("reopen");

        let mut w = writer.clone();
        w.write_all(b"after\n").expect("write");
        w.flush().expect("flush");

        // New file should have "after" but not "before"
        let new_content = std::fs::read_to_string(&path).expect("read new");
        assert!(new_content.contains("after"));
        assert!(!new_content.contains("before"));

        // Rotated file should have "before"
        let old_content = std::fs::read_to_string(&rotated).expect("read old");
        assert!(old_content.contains("before"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_log_state_reopen_all() {
        let dir = std::env::temp_dir().join("dionaea_rw_test_reopen_all");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let path1 = dir.join("a.log");
        let path2 = dir.join("b.log");
        let w1 = ReopenableWriter::new(&path1).expect("w1");
        let w2 = ReopenableWriter::new(&path2).expect("w2");

        use io::Write;
        w1.clone().write_all(b"a1\n").expect("write a1");
        w1.clone().flush().expect("flush a1");
        w2.clone().write_all(b"b1\n").expect("write b1");
        w2.clone().flush().expect("flush b1");

        // Rename both
        std::fs::rename(&path1, dir.join("a.log.1")).expect("rename a");
        std::fs::rename(&path2, dir.join("b.log.1")).expect("rename b");

        let state = LogState {
            file_writers: vec![w1.clone(), w2.clone()],
        };
        state.reopen_all();

        w1.clone().write_all(b"a2\n").expect("write a2");
        w1.clone().flush().expect("flush a2");
        w2.clone().write_all(b"b2\n").expect("write b2");
        w2.clone().flush().expect("flush b2");

        let a_new = std::fs::read_to_string(&path1).expect("read a new");
        assert!(a_new.contains("a2"));
        assert!(!a_new.contains("a1"));

        let b_new = std::fs::read_to_string(&path2).expect("read b new");
        assert!(b_new.contains("b2"));
        assert!(!b_new.contains("b1"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_level_filter_error_only() {
        use tracing_subscriber::filter::LevelFilter;
        assert_eq!(parse_level_filter("error,critical"), LevelFilter::ERROR);
    }

    #[test]
    fn test_parse_level_filter_info_and_above() {
        use tracing_subscriber::filter::LevelFilter;
        assert_eq!(
            parse_level_filter("info,warning,error,critical"),
            LevelFilter::INFO
        );
    }

    #[test]
    fn test_parse_level_filter_debug() {
        use tracing_subscriber::filter::LevelFilter;
        assert_eq!(
            parse_level_filter("debug,info,warning,error,critical"),
            LevelFilter::DEBUG
        );
    }

    #[test]
    fn test_parse_level_filter_all() {
        use tracing_subscriber::filter::LevelFilter;
        assert_eq!(parse_level_filter("all,-debug"), LevelFilter::TRACE);
    }

    #[test]
    fn test_parse_level_filter_empty() {
        use tracing_subscriber::filter::LevelFilter;
        assert_eq!(parse_level_filter(""), LevelFilter::OFF);
    }
}
