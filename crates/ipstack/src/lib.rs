// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Custom userspace TCP/IP stack with nmap OS fingerprint personality simulation.
// ABOUTME: Operates on a TUN device to bypass the kernel stack, enabling honeyd-style OS emulation.

// Network protocol code intentionally uses casts between integer sizes (u32→u16, u16→u8)
// for fields with well-known widths defined by RFCs. The struct has multiple bool fields
// because TCP/IP headers inherently have many boolean flags.
#![allow(
    clippy::cast_possible_truncation,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::match_same_arms,
    clippy::redundant_closure_for_method_calls,
    clippy::redundant_closure,
    clippy::too_many_arguments,
    clippy::unnecessary_map_or,
    clippy::needless_range_loop,
    clippy::derivable_impls,
    clippy::map_unwrap_or,
    clippy::explicit_iter_loop,
    clippy::unused_async
)]

//! # dionaea-ipstack
//!
//! A custom userspace TCP/IP stack that operates on raw IP packets via a TUN device,
//! integrated with Tokio for async I/O. The stack supports honeyd-style OS personality
//! simulation by loading nmap fingerprint definitions and crafting TCP/IP responses
//! that match specific operating system signatures.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐     ┌──────────────┐     ┌────────────────┐
//! │  TUN Device  │────▶│  IP Demuxer  │────▶│  TCP Engine    │
//! │  (raw pkts)  │◀────│  (IPv4/v6)   │◀────│  (per-conn SM) │
//! └─────────────┘     │              │     └────────────────┘
//!                     │              │────▶│  UDP Handler   │
//!                     │              │◀────│  (stateless)   │
//!                     │              │     └────────────────┘
//!                     │              │────▶│  ICMP Handler  │
//!                     │              │◀────│  (echo/unreach)│
//!                     └──────────────┘     └────────────────┘
//!                            │
//!                     ┌──────────────┐
//!                     │  Personality  │  ← nmap-os-db fingerprints
//!                     │  Engine       │  ← controls: TTL, window, ISN,
//!                     │              │    DF, options, ICMP quirks
//!                     └──────────────┘
//! ```

/// Configuration types for the IP stack.
pub mod config;
/// IP packet demuxer — routes packets to TCP/UDP/ICMP handlers.
pub mod demux;
/// Nmap OS fingerprint database parser and data model.
pub mod fingerprint;
/// ICMP echo and unreachable response handler (nmap IE test).
pub mod icmp;
/// Raw packet construction utilities.
pub mod packet;
/// TCP/IP personality engine — maps fingerprint fields to packet parameters.
pub mod personality;
/// Custom TCP state machine with personality-driven response crafting.
pub mod tcp;
/// TUN device integration with Tokio.
pub mod tun;
/// UDP probe response handler (nmap U1 test).
pub mod udp;
