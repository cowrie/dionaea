// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: IP packet demuxer that routes incoming packets to TCP/UDP/ICMP handlers.
// ABOUTME: Main packet processing loop integrating TUN device with protocol handlers.

//! IP packet demuxer.
//!
//! Reads raw IP packets from the TUN device, parses the IP header, and routes
//! them to the appropriate protocol handler (TCP, UDP, ICMP). Response packets
//! are written back to the TUN device.
//!
//! The demuxer also provides a channel-based API for sending application data
//! back through established TCP connections.

use std::sync::Arc;
use tokio::sync::mpsc;

use crate::config::IpStackConfig;
use crate::fingerprint::FingerprintDb;
use crate::icmp::IcmpHandler;
use crate::packet::{ParsedIcmp, ParsedIpv4, ParsedTcp, ParsedUdp, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use crate::personality::Personality;
use crate::tcp::{TcpEngine, TcpEvent};
use crate::tun::{TunConfig, TunDevice};
use crate::udp::{UdpEvent, UdpHandler};

/// Commands from the application layer to the IP stack.
#[derive(Debug)]
pub enum StackCommand {
    /// Send data on an established TCP connection.
    TcpSend {
        /// Connection 4-tuple.
        conn_id: crate::tcp::TcpConnId,
        /// Data to send.
        data: Vec<u8>,
    },
    /// Close a TCP connection.
    TcpClose {
        /// Connection 4-tuple.
        conn_id: crate::tcp::TcpConnId,
    },
    /// Open a TCP port for listening.
    OpenTcpPort(u16),
    /// Close a TCP port.
    CloseTcpPort(u16),
    /// Open a UDP port.
    OpenUdpPort(u16),
    /// Close a UDP port.
    CloseUdpPort(u16),
    /// Shutdown the stack.
    Shutdown,
}

/// Events from the IP stack to the application layer.
#[derive(Debug)]
pub enum StackEvent {
    /// TCP event (connection established, data received, closed).
    Tcp(TcpEvent),
    /// UDP event (datagram received on open port).
    Udp(UdpEvent),
}

/// Handle to the running IP stack. Used by the application layer to send commands.
#[derive(Clone)]
pub struct StackHandle {
    cmd_tx: mpsc::Sender<StackCommand>,
}

impl StackHandle {
    /// Send data on a TCP connection.
    pub async fn tcp_send(&self, conn_id: crate::tcp::TcpConnId, data: Vec<u8>) -> Result<(), StackError> {
        self.cmd_tx
            .send(StackCommand::TcpSend { conn_id, data })
            .await
            .map_err(|_| StackError::ChannelClosed)
    }

    /// Close a TCP connection.
    pub async fn tcp_close(&self, conn_id: crate::tcp::TcpConnId) -> Result<(), StackError> {
        self.cmd_tx
            .send(StackCommand::TcpClose { conn_id })
            .await
            .map_err(|_| StackError::ChannelClosed)
    }

    /// Open a TCP port.
    pub async fn open_tcp_port(&self, port: u16) -> Result<(), StackError> {
        self.cmd_tx
            .send(StackCommand::OpenTcpPort(port))
            .await
            .map_err(|_| StackError::ChannelClosed)
    }

    /// Shutdown the stack.
    pub async fn shutdown(&self) -> Result<(), StackError> {
        self.cmd_tx
            .send(StackCommand::Shutdown)
            .await
            .map_err(|_| StackError::ChannelClosed)
    }
}

/// Errors from stack operations.
#[derive(Debug)]
pub enum StackError {
    /// TUN device error.
    Tun(String),
    /// Fingerprint database error.
    Fingerprint(String),
    /// Personality not found.
    PersonalityNotFound(String),
    /// Command channel closed.
    ChannelClosed,
}

impl std::fmt::Display for StackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StackError::Tun(msg) => write!(f, "TUN error: {msg}"),
            StackError::Fingerprint(msg) => write!(f, "fingerprint error: {msg}"),
            StackError::PersonalityNotFound(name) => {
                write!(f, "personality not found in nmap-os-db: {name}")
            }
            StackError::ChannelClosed => write!(f, "stack command channel closed"),
        }
    }
}

impl std::error::Error for StackError {}

/// Start the custom IP stack. Returns a handle for sending commands and a receiver for events.
///
/// This spawns a Tokio task that runs the packet processing loop.
pub async fn start(
    config: &IpStackConfig,
) -> Result<(StackHandle, mpsc::Receiver<StackEvent>), StackError> {
    // Load fingerprint database
    let db = FingerprintDb::load(&config.personality.nmap_os_db).map_err(|e| {
        StackError::Fingerprint(format!("{e}"))
    })?;

    // Find the requested personality
    let fp = db.find_by_name(&config.personality.name).ok_or_else(|| {
        StackError::PersonalityNotFound(config.personality.name.clone())
    })?;
    let personality = Personality::from_fingerprint(fp);

    tracing::info!(
        personality = %personality.name,
        ttl = personality.ttl,
        df = personality.df,
        window = personality.window_sizes[0],
        "loaded OS personality"
    );

    // Create TUN device
    let tun_config = TunConfig {
        name: config.tun.name.clone(),
        address: config.tun.address,
        netmask: config.tun.netmask,
        mtu: config.tun.mtu,
    };
    let tun = TunDevice::create(&tun_config).map_err(|e| StackError::Tun(format!("{e}")))?;
    let tun = Arc::new(tun);

    // Create protocol handlers
    let mut tcp_engine = TcpEngine::new(personality.clone());
    for &port in &config.tcp_ports {
        tcp_engine.open_port(port);
        tracing::info!(port, "TCP port open");
    }

    let mut udp_handler = UdpHandler::new(personality.clone());
    for &port in &config.udp_ports {
        udp_handler.open_port(port);
        tracing::info!(port, "UDP port open");
    }

    let icmp_handler = IcmpHandler::new(personality);

    // Channels
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<StackCommand>(256);
    let (event_tx, event_rx) = mpsc::channel::<StackEvent>(1024);

    let handle = StackHandle { cmd_tx };
    let tun_writer = tun.clone();

    // Spawn the packet processing loop
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];

        loop {
            tokio::select! {
                // Read from TUN device
                result = tun.read_packet(&mut buf) => {
                    match result {
                        Ok(n) => {
                            let packet = &buf[..n];
                            process_packet(
                                packet,
                                &mut tcp_engine,
                                &udp_handler,
                                &icmp_handler,
                                &tun_writer,
                                &event_tx,
                            ).await;
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "TUN read error");
                        }
                    }
                }

                // Process commands from application
                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else { break; };
                    match cmd {
                        StackCommand::TcpSend { conn_id, data } => {
                            if let Some(pkt) = tcp_engine.send_data(&conn_id, &data) {
                                if let Err(e) = tun_writer.write_packet(&pkt).await {
                                    tracing::error!(error = %e, "TUN write error");
                                }
                            }
                        }
                        StackCommand::TcpClose { conn_id } => {
                            if let Some(pkt) = tcp_engine.close_connection(&conn_id) {
                                if let Err(e) = tun_writer.write_packet(&pkt).await {
                                    tracing::error!(error = %e, "TUN write error");
                                }
                            }
                        }
                        StackCommand::OpenTcpPort(port) => {
                            tcp_engine.open_port(port);
                            tracing::info!(port, "TCP port opened");
                        }
                        StackCommand::CloseTcpPort(port) => {
                            tcp_engine.close_port(port);
                            tracing::info!(port, "TCP port closed");
                        }
                        StackCommand::OpenUdpPort(port) => {
                            udp_handler.open_port(port);
                            tracing::info!(port, "UDP port opened");
                        }
                        StackCommand::CloseUdpPort(port) => {
                            udp_handler.close_port(port);
                            tracing::info!(port, "UDP port closed");
                        }
                        StackCommand::Shutdown => {
                            tracing::info!("IP stack shutting down");
                            break;
                        }
                    }
                }
            }
        }

        tracing::info!(
            tcp_connections = tcp_engine.connection_count(),
            "IP stack stopped"
        );
    });

    Ok((handle, event_rx))
}

/// Process a single raw IP packet from the TUN device.
async fn process_packet(
    packet: &[u8],
    tcp_engine: &mut TcpEngine,
    udp_handler: &UdpHandler,
    icmp_handler: &IcmpHandler,
    tun: &TunDevice,
    event_tx: &mpsc::Sender<StackEvent>,
) {
    let Some(ip) = ParsedIpv4::parse(packet) else {
        return;
    };

    let payload = ip.payload(packet);

    match ip.protocol {
        PROTO_TCP => {
            let Some(tcp) = ParsedTcp::parse(payload) else {
                return;
            };

            let (out_packets, events) = tcp_engine.handle_packet(&ip, &tcp, payload);

            for pkt in out_packets {
                if let Err(e) = tun.write_packet(&pkt).await {
                    tracing::error!(error = %e, "TUN write error (TCP response)");
                }
            }

            for event in events {
                let _ = event_tx.try_send(StackEvent::Tcp(event));
            }
        }
        PROTO_UDP => {
            let Some(udp) = ParsedUdp::parse(payload) else {
                return;
            };

            let (resp, events) = udp_handler.handle_packet(&ip, &udp, packet);

            if let Some(pkt) = resp {
                if let Err(e) = tun.write_packet(&pkt).await {
                    tracing::error!(error = %e, "TUN write error (UDP ICMP response)");
                }
            }

            for event in events {
                let _ = event_tx.try_send(StackEvent::Udp(event));
            }
        }
        PROTO_ICMP => {
            let Some(icmp) = ParsedIcmp::parse(payload) else {
                return;
            };

            if let Some(pkt) = icmp_handler.handle_packet(&ip, &icmp, payload) {
                if let Err(e) = tun.write_packet(&pkt).await {
                    tracing::error!(error = %e, "TUN write error (ICMP response)");
                }
            }
        }
        _ => {
            tracing::trace!(protocol = ip.protocol, "ignoring unknown IP protocol");
        }
    }
}
