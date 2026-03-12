// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: GPL-3.0-only
// ABOUTME: Dionaea honeypot core library.
// ABOUTME: Re-exports public types for integration tests and the binary.

//! Dionaea honeypot core: connection management, Python bridge, and incident system.

/// Bidirectional stream recording for protocol analysis.
pub mod bistream;
/// TOML configuration parsing and env var overrides.
pub mod config;
/// Connection lifecycle, registry, and I/O loops.
pub mod connection;
/// HTTP/HTTPS download capture module.
#[cfg(feature = "download")]
pub mod download;
/// HTTP multipart upload module (virustotal, hpfeeds, submit_http).
#[cfg(feature = "upload")]
pub mod upload;
/// Passive pcap capture for TCP RST rejection detection.
#[cfg(feature = "pcap")]
pub mod pcap;
/// Error types for the dionaea crate.
pub mod error;
/// Incident handler dispatch (Rust-side handlers).
pub mod ihandler;
/// Incident creation, attribute storage, and dispatch to handlers.
pub mod incident;
/// Network endpoint address info (host, port, hostname).
pub mod node_info;
/// Unix privilege dropping (setuid/setgid) and RLIMIT management.
pub mod privileges;
/// Per-connection processor pipeline (stream dumping, shellcode detection).
pub mod processor;
/// PyO3 bridge types exposed to Python protocol handlers.
pub mod python;
/// Global runtime state (registry, limits, config) shared across tasks.
pub mod runtime;
