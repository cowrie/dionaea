// SPDX-License-Identifier: GPL-3.0-only
// ABOUTME: Entry point for the dionaea honeypot daemon.
// ABOUTME: Initializes config, logging, Python, tokio runtime, and signal handlers.

//! Dionaea honeypot daemon entry point.

use dionaea::config;
use dionaea::processor;
use std::path::PathBuf;

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
    init_tracing(&config.logging);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
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

    rt.block_on(async_main(config));

    tracing::info!("dionaea shut down");
}

/// Async entry point running inside the tokio runtime.
async fn async_main(config: config::Config) {
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
                    // File-based log targets would reopen their handles here.
                    // Currently all logging goes to stdout, so this is a no-op.
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.expect("ctrl-c handler");
        tracing::info!("received Ctrl-C, shutting down");
    }

    // Graceful shutdown
    state.stop_all_listeners();
    tracing::info!(
        active_connections = registry.len(),
        "listeners stopped, draining connections"
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
    }

    // Clear ihandler registry
    state
        .ihandler_registry
        .lock()
        .expect("registry lock")
        .clear();

    tracing::info!("shutdown complete");
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
                println!("dionaea {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => {
                println!("dionaea {} - low-interaction honeypot", env!("CARGO_PKG_VERSION"));
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
fn init_tracing(logging_config: &config::LoggingConfig) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&logging_config.level));

    let registry = tracing_subscriber::registry().with(env_filter);

    // If no targets configured, default to stdout text
    if logging_config.targets.is_empty() {
        registry
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .init();
        return;
    }

    // Check if any target is stdout
    let has_stdout = logging_config
        .targets
        .iter()
        .any(|t| t.target_type == "stdout");

    if has_stdout {
        // Find the stdout target to check format
        let stdout_target = logging_config
            .targets
            .iter()
            .find(|t| t.target_type == "stdout")
            .expect("just checked");

        if stdout_target.format == "json" {
            registry
                .with(tracing_subscriber::fmt::layer().json().with_target(true))
                .init();
        } else {
            registry
                .with(tracing_subscriber::fmt::layer().with_target(true))
                .init();
        }
    } else {
        // No stdout target, init with default (no output layer — file logging handled separately)
        registry
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .init();
    }
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
