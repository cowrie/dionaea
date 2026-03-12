// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Global runtime state shared between main.rs and Python-initiated listeners.
// ABOUTME: Holds the connection registry, limits, and tracks listener abort handles.

use std::sync::{Arc, Mutex, OnceLock};

use crate::config::Config;
use crate::connection::limits::ConnectionLimits;
use crate::connection::ConnectionRegistry;
use crate::ihandler::IHandlerRegistry;
use crate::processor::ProcessorNode;

/// Global runtime state, initialized by `async_main`.
static RUNTIME: OnceLock<Arc<RuntimeState>> = OnceLock::new();

/// Shared runtime state for the honeypot daemon.
///
/// Created by `async_main` from config, then accessed by Python's
/// `connection.listen()` to start new listeners with the correct registry/limits.
pub struct RuntimeState {
    /// Connection metadata registry (shared across all listeners).
    pub registry: Arc<ConnectionRegistry>,
    /// Connection limits (per-IP, total, FD budget).
    pub limits: Arc<ConnectionLimits>,
    /// Receive buffer size for handler tasks.
    pub recv_buffer_size: usize,
    /// Incident handler registry (lock before use, release before Python callbacks).
    pub ihandler_registry: Mutex<IHandlerRegistry>,
    /// Parsed configuration (read-only after init).
    pub config: Config,
    /// Processor template tree (built from config at startup).
    pub processor_tree: Vec<ProcessorNode>,
    /// Abort handles for all active listeners. Stopped on shutdown.
    listeners: Mutex<Vec<tokio::task::AbortHandle>>,
}

impl RuntimeState {
    /// Create a new runtime state.
    pub fn new(
        registry: Arc<ConnectionRegistry>,
        limits: Arc<ConnectionLimits>,
        recv_buffer_size: usize,
        config: Config,
        processor_tree: Vec<ProcessorNode>,
    ) -> Self {
        RuntimeState {
            registry,
            limits,
            recv_buffer_size,
            ihandler_registry: Mutex::new(IHandlerRegistry::new()),
            config,
            processor_tree,
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Register a listener's abort handle for shutdown tracking.
    pub fn track_listener(&self, abort: tokio::task::AbortHandle) {
        self.listeners.lock().expect("lock").push(abort);
    }

    /// Stop all tracked listeners.
    pub fn stop_all_listeners(&self) {
        let handles = self.listeners.lock().expect("lock");
        for h in handles.iter() {
            h.abort();
        }
    }
}

impl std::fmt::Debug for RuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.listeners.lock().map(|v| v.len()).unwrap_or(0);
        f.debug_struct("RuntimeState")
            .field("recv_buffer_size", &self.recv_buffer_size)
            .field("listener_count", &count)
            .finish()
    }
}

/// Initialize the global runtime state. Called once by `async_main`.
///
/// Panics if called more than once.
pub fn init(state: Arc<RuntimeState>) {
    RUNTIME
        .set(state)
        .expect("runtime state already initialized");
}

/// Get the global runtime state. Returns None if not yet initialized.
pub fn get() -> Option<Arc<RuntimeState>> {
    RUNTIME.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn test_config() -> Config {
        config::load_from_str(
            r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = ["0.0.0.0"]
[logging]
level = "info"
[modules]
"#,
        )
        .expect("test config")
    }

    // Note: Cannot test init/get here because OnceLock is process-global
    // and tests run in parallel. The integration test covers this.

    #[test]
    fn test_runtime_state_track_and_stop() {
        let reg = Arc::new(ConnectionRegistry::new());
        let lim = Arc::new(ConnectionLimits::new(50, 10_000, 70));
        let state = RuntimeState::new(reg, lim, 65536, test_config(), Vec::new());

        // Create a dummy task to get an abort handle
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let handle = rt.spawn(async { tokio::time::sleep(std::time::Duration::from_secs(3600)).await });
        state.track_listener(handle.abort_handle());

        assert_eq!(state.listeners.lock().unwrap().len(), 1);
        state.stop_all_listeners();
        // After abort, the task should be cancelled
        rt.block_on(async {
            assert!(handle.await.unwrap_err().is_cancelled());
        });
    }
}
