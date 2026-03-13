// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: TUN device creation and async I/O wrapper for Tokio integration.
// ABOUTME: Provides raw IP packet read/write over a virtual network interface.

//! TUN device integration with Tokio.
//!
//! Creates a TUN device (Layer 3, IP packets only) and provides an async
//! interface for reading and writing raw IP packets. The TUN device bypasses
//! the kernel TCP/IP stack, allowing our custom personality-driven stack to
//! handle all traffic.

use std::net::Ipv4Addr;

/// Configuration for the TUN device.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Name of the TUN device (e.g. "honeypot0"). Empty for auto-assign.
    pub name: String,
    /// IPv4 address to assign to the TUN device.
    pub address: Ipv4Addr,
    /// Network mask (e.g. "255.255.255.0").
    pub netmask: Ipv4Addr,
    /// MTU (Maximum Transmission Unit). Default: 1500.
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        TunConfig {
            name: String::new(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1500,
        }
    }
}

/// Async TUN device wrapper.
///
/// Split into a reader and writer half for concurrent access from the
/// packet demuxer (read) and response senders (write).
pub struct TunDevice {
    device: tun_rs::AsyncDevice,
}

impl TunDevice {
    /// Create and configure a new TUN device.
    pub fn create(config: &TunConfig) -> Result<Self, TunError> {
        let mut builder = tun_rs::DeviceBuilder::new();

        if !config.name.is_empty() {
            builder = builder.name(&config.name);
        }

        builder = builder
            .ipv4(config.address, config.netmask, None)
            .mtu(config.mtu)
            .layer(tun_rs::Layer::L3);

        let device = builder
            .build_async()
            .map_err(|e| TunError::Create(format!("failed to create TUN device: {e}")))?;

        tracing::info!(
            name = %config.name,
            address = %config.address,
            netmask = %config.netmask,
            mtu = config.mtu,
            "TUN device created"
        );

        Ok(TunDevice { device })
    }

    /// Read a raw IP packet from the TUN device.
    ///
    /// Returns the number of bytes read into `buf`.
    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        self.device
            .recv(buf)
            .await
            .map_err(|e| TunError::Read(format!("TUN read failed: {e}")))
    }

    /// Write a raw IP packet to the TUN device.
    pub async fn write_packet(&self, packet: &[u8]) -> Result<(), TunError> {
        self.device
            .send(packet)
            .await
            .map_err(|e| TunError::Write(format!("TUN write failed: {e}")))?;
        Ok(())
    }
}

/// Errors from TUN device operations.
#[derive(Debug)]
pub enum TunError {
    /// Failed to create the TUN device.
    Create(String),
    /// Read error.
    Read(String),
    /// Write error.
    Write(String),
}

impl std::fmt::Display for TunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunError::Create(msg) => write!(f, "TUN create: {msg}"),
            TunError::Read(msg) => write!(f, "TUN read: {msg}"),
            TunError::Write(msg) => write!(f, "TUN write: {msg}"),
        }
    }
}

impl std::error::Error for TunError {}
