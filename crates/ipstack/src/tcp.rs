// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: Custom TCP state machine with personality-driven response crafting.
// ABOUTME: Manages per-connection state and generates packets matching the OS fingerprint.

//! Custom TCP state machine.
//!
//! Implements a minimal TCP stack that operates at the IP packet level rather
//! than using kernel sockets. Each connection tracks sequence numbers, state
//! transitions, and crafts response packets using the loaded OS personality.
//!
//! The state machine supports:
//! - SYN → SYN-ACK (with personality-matched window, options, ISN)
//! - Established data transfer (ACK, PSH+ACK)
//! - FIN handshake (graceful close)
//! - RST for closed ports (with personality-matched behavior)
//!
//! Application data is delivered to a callback for protocol emulation.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::packet::{self, ParsedIpv4, ParsedTcp};
use crate::personality::{
    AckBehavior, IsnGenerator, Personality, SeqBehavior, TcpFlags, TProbeResponse,
};

/// TCP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// Listening for SYN.
    Listen,
    /// SYN-ACK sent, waiting for ACK.
    SynReceived,
    /// Three-way handshake complete. Data can flow.
    Established,
    /// FIN sent, waiting for ACK.
    FinWait1,
    /// FIN sent and ACKed, waiting for peer FIN.
    FinWait2,
    /// Peer FIN received in ESTABLISHED, sent ACK. Waiting for app close.
    CloseWait,
    /// FIN sent from CloseWait, waiting for ACK.
    LastAck,
    /// Both FINs exchanged.
    TimeWait,
    /// Connection closed/reset.
    Closed,
}

/// Identifier for a TCP connection (4-tuple).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpConnId {
    /// Local IP.
    pub local_ip: Ipv4Addr,
    /// Local port.
    pub local_port: u16,
    /// Remote IP.
    pub remote_ip: Ipv4Addr,
    /// Remote port.
    pub remote_port: u16,
}

/// Per-connection TCP state.
#[derive(Debug)]
pub struct TcpConnection {
    /// Connection identifier.
    pub id: TcpConnId,
    /// Current state.
    pub state: TcpState,
    /// Our send sequence number (SND.NXT).
    pub snd_nxt: u32,
    /// Our send unacknowledged (SND.UNA).
    pub snd_una: u32,
    /// Initial send sequence number (our ISN).
    pub iss: u32,
    /// Receive next expected sequence number (RCV.NXT).
    pub rcv_nxt: u32,
    /// Initial receive sequence number (their ISN).
    pub irs: u32,
    /// Probe index counter for window/options selection.
    pub probe_idx: usize,
}

impl TcpConnection {
    fn new(id: TcpConnId, isn: u32) -> Self {
        TcpConnection {
            id,
            state: TcpState::Listen,
            snd_nxt: isn,
            snd_una: isn,
            iss: isn,
            rcv_nxt: 0,
            irs: 0,
            probe_idx: 0,
        }
    }
}

/// Events emitted by the TCP engine for the application layer.
#[derive(Debug)]
pub enum TcpEvent {
    /// A new connection has been established. Application should prepare protocol handler.
    Connected {
        /// Connection identifier.
        conn_id: TcpConnId,
    },
    /// Data received from the remote on an established connection.
    DataReceived {
        /// Connection identifier.
        conn_id: TcpConnId,
        /// The received payload bytes.
        data: Vec<u8>,
    },
    /// Connection was closed (by either side or RST).
    Closed {
        /// Connection identifier.
        conn_id: TcpConnId,
    },
}

/// The TCP engine manages all active TCP connections.
pub struct TcpEngine {
    /// Active connections indexed by 4-tuple.
    connections: HashMap<TcpConnId, TcpConnection>,
    /// Open ports that accept new connections.
    open_ports: Vec<u16>,
    /// ISN generator.
    isn_gen: IsnGenerator,
    /// Personality driving packet crafting.
    personality: Personality,
}

impl TcpEngine {
    /// Create a new TCP engine with the given personality.
    pub fn new(personality: Personality) -> Self {
        let isn_gen = IsnGenerator::new(personality.isn_params.clone());
        TcpEngine {
            connections: HashMap::new(),
            open_ports: Vec::new(),
            isn_gen,
            personality,
        }
    }

    /// Mark a port as open (will accept SYN with SYN-ACK).
    pub fn open_port(&mut self, port: u16) {
        if !self.open_ports.contains(&port) {
            self.open_ports.push(port);
        }
    }

    /// Mark a port as closed.
    pub fn close_port(&mut self, port: u16) {
        self.open_ports.retain(|&p| p != port);
    }

    /// Check if a port is open.
    pub fn is_port_open(&self, port: u16) -> bool {
        self.open_ports.contains(&port)
    }

    /// Process an incoming TCP segment. Returns response packets and events.
    pub fn handle_packet(
        &mut self,
        ip: &ParsedIpv4,
        tcp: &ParsedTcp,
        tcp_data: &[u8],
    ) -> (Vec<Vec<u8>>, Vec<TcpEvent>) {
        let conn_id = TcpConnId {
            local_ip: Ipv4Addr::from(ip.dst_ip),
            local_port: tcp.dst_port,
            remote_ip: Ipv4Addr::from(ip.src_ip),
            remote_port: tcp.src_port,
        };

        let mut out_packets = Vec::new();
        let mut events = Vec::new();

        // Handle SYN to closed port — send RST per personality
        if tcp.is_syn_only() && !self.is_port_open(tcp.dst_port) {
            if let Some(t_resp) = self.get_closed_port_response() {
                if t_resp.responds {
                    let (seq, ack) = compute_seq_ack(
                        t_resp,
                        tcp.seq_num,
                        tcp.ack_num,
                        self.isn_gen.next_isn(),
                    );
                    let pkt = packet::build_tcp_packet(
                        ip.dst_ip,
                        ip.src_ip,
                        tcp.dst_port,
                        tcp.src_port,
                        seq,
                        ack,
                        t_resp.window,
                        t_resp.flags,
                        &[],
                        &[],
                        t_resp.ttl,
                        t_resp.df,
                        self.isn_gen.next_ip_id(),
                    );
                    out_packets.push(pkt);
                }
            }
            return (out_packets, events);
        }

        // Look up or create connection
        if tcp.is_syn_only() && self.is_port_open(tcp.dst_port) {
            // New connection
            let isn = self.isn_gen.next_isn();
            let mut conn = TcpConnection::new(conn_id, isn);
            conn.irs = tcp.seq_num;
            conn.rcv_nxt = tcp.seq_num.wrapping_add(1);
            conn.snd_nxt = isn.wrapping_add(1);

            // Send SYN-ACK
            let pkt = packet::build_tcp_synack(
                ip.dst_ip,
                ip.src_ip,
                tcp.dst_port,
                tcp.src_port,
                isn,
                conn.rcv_nxt,
                &self.personality,
                &self.isn_gen,
                conn.probe_idx % 6,
            );
            conn.probe_idx += 1;
            conn.state = TcpState::SynReceived;
            out_packets.push(pkt);
            self.connections.insert(conn_id, conn);
            return (out_packets, events);
        }

        // Process packet for existing connection
        let Some(conn) = self.connections.get_mut(&conn_id) else {
            // No connection and not a SYN — send RST
            if !tcp.is_rst() {
                let pkt = packet::build_tcp_rst(
                    ip.dst_ip,
                    ip.src_ip,
                    tcp.dst_port,
                    tcp.src_port,
                    tcp.ack_num,
                    tcp.seq_num.wrapping_add(1),
                    &self.personality,
                    &self.isn_gen,
                );
                out_packets.push(pkt);
            }
            return (out_packets, events);
        };

        // RST received — tear down
        if tcp.is_rst() {
            conn.state = TcpState::Closed;
            events.push(TcpEvent::Closed { conn_id });
            self.connections.remove(&conn_id);
            return (out_packets, events);
        }

        match conn.state {
            TcpState::SynReceived => {
                if tcp.is_ack() {
                    conn.state = TcpState::Established;
                    events.push(TcpEvent::Connected { conn_id });
                }
            }
            TcpState::Established => {
                let payload = tcp.payload(tcp_data);

                if !payload.is_empty() {
                    conn.rcv_nxt = conn
                        .rcv_nxt
                        .wrapping_add(payload.len() as u32);

                    events.push(TcpEvent::DataReceived {
                        conn_id,
                        data: payload.to_vec(),
                    });

                    // Send ACK
                    let ack_pkt = packet::build_tcp_packet(
                        ip.dst_ip,
                        ip.src_ip,
                        tcp.dst_port,
                        tcp.src_port,
                        conn.snd_nxt,
                        conn.rcv_nxt,
                        self.personality.window_for_probe(conn.probe_idx % 6),
                        TcpFlags {
                            syn: false,
                            ack: true,
                            rst: false,
                            fin: false,
                            psh: false,
                            urg: false,
                            ece: false,
                            cwr: false,
                        },
                        &[],
                        &[],
                        self.personality.ttl,
                        self.personality.df,
                        self.isn_gen.next_ip_id(),
                    );
                    out_packets.push(ack_pkt);
                }

                if tcp.is_fin() {
                    conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                    conn.state = TcpState::CloseWait;

                    // ACK the FIN
                    let ack_pkt = packet::build_tcp_packet(
                        ip.dst_ip,
                        ip.src_ip,
                        tcp.dst_port,
                        tcp.src_port,
                        conn.snd_nxt,
                        conn.rcv_nxt,
                        self.personality.window_for_probe(conn.probe_idx % 6),
                        TcpFlags {
                            syn: false,
                            ack: true,
                            rst: false,
                            fin: false,
                            psh: false,
                            urg: false,
                            ece: false,
                            cwr: false,
                        },
                        &[],
                        &[],
                        self.personality.ttl,
                        self.personality.df,
                        self.isn_gen.next_ip_id(),
                    );
                    out_packets.push(ack_pkt);

                    events.push(TcpEvent::Closed { conn_id });
                }
            }
            TcpState::FinWait1 => {
                if tcp.is_ack() && tcp.is_fin() {
                    conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                    conn.state = TcpState::TimeWait;
                    // ACK the FIN
                    let ack_pkt = packet::build_tcp_packet(
                        ip.dst_ip,
                        ip.src_ip,
                        tcp.dst_port,
                        tcp.src_port,
                        conn.snd_nxt,
                        conn.rcv_nxt,
                        0,
                        TcpFlags {
                            syn: false,
                            ack: true,
                            rst: false,
                            fin: false,
                            psh: false,
                            urg: false,
                            ece: false,
                            cwr: false,
                        },
                        &[],
                        &[],
                        self.personality.ttl,
                        self.personality.df,
                        self.isn_gen.next_ip_id(),
                    );
                    out_packets.push(ack_pkt);
                    events.push(TcpEvent::Closed { conn_id });
                } else if tcp.is_ack() {
                    conn.state = TcpState::FinWait2;
                } else if tcp.is_fin() {
                    conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                    conn.state = TcpState::TimeWait;
                    let ack_pkt = packet::build_tcp_packet(
                        ip.dst_ip,
                        ip.src_ip,
                        tcp.dst_port,
                        tcp.src_port,
                        conn.snd_nxt,
                        conn.rcv_nxt,
                        0,
                        TcpFlags {
                            syn: false,
                            ack: true,
                            rst: false,
                            fin: false,
                            psh: false,
                            urg: false,
                            ece: false,
                            cwr: false,
                        },
                        &[],
                        &[],
                        self.personality.ttl,
                        self.personality.df,
                        self.isn_gen.next_ip_id(),
                    );
                    out_packets.push(ack_pkt);
                    events.push(TcpEvent::Closed { conn_id });
                }
            }
            TcpState::FinWait2 => {
                if tcp.is_fin() {
                    conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                    conn.state = TcpState::TimeWait;
                    let ack_pkt = packet::build_tcp_packet(
                        ip.dst_ip,
                        ip.src_ip,
                        tcp.dst_port,
                        tcp.src_port,
                        conn.snd_nxt,
                        conn.rcv_nxt,
                        0,
                        TcpFlags {
                            syn: false,
                            ack: true,
                            rst: false,
                            fin: false,
                            psh: false,
                            urg: false,
                            ece: false,
                            cwr: false,
                        },
                        &[],
                        &[],
                        self.personality.ttl,
                        self.personality.df,
                        self.isn_gen.next_ip_id(),
                    );
                    out_packets.push(ack_pkt);
                    events.push(TcpEvent::Closed { conn_id });
                }
            }
            TcpState::LastAck => {
                if tcp.is_ack() {
                    conn.state = TcpState::Closed;
                    events.push(TcpEvent::Closed { conn_id });
                    self.connections.remove(&conn_id);
                }
            }
            _ => {}
        }

        // Clean up TIME_WAIT and Closed connections
        if let Some(conn) = self.connections.get(&conn_id) {
            if conn.state == TcpState::TimeWait || conn.state == TcpState::Closed {
                self.connections.remove(&conn_id);
            }
        }

        (out_packets, events)
    }

    /// Send data on an established connection. Returns the packet to transmit.
    pub fn send_data(&mut self, conn_id: &TcpConnId, data: &[u8]) -> Option<Vec<u8>> {
        let conn = self.connections.get_mut(conn_id)?;
        if conn.state != TcpState::Established {
            return None;
        }

        let pkt = packet::build_tcp_packet(
            conn.id.local_ip.octets(),
            conn.id.remote_ip.octets(),
            conn.id.local_port,
            conn.id.remote_port,
            conn.snd_nxt,
            conn.rcv_nxt,
            self.personality.window_for_probe(conn.probe_idx % 6),
            TcpFlags {
                syn: false,
                ack: true,
                rst: false,
                fin: false,
                psh: true,
                urg: false,
                ece: false,
                cwr: false,
            },
            &[],
            data,
            self.personality.ttl,
            self.personality.df,
            self.isn_gen.next_ip_id(),
        );

        conn.snd_nxt = conn.snd_nxt.wrapping_add(data.len() as u32);
        Some(pkt)
    }

    /// Initiate a graceful close. Returns the FIN packet to transmit.
    pub fn close_connection(&mut self, conn_id: &TcpConnId) -> Option<Vec<u8>> {
        let conn = self.connections.get_mut(conn_id)?;
        if conn.state != TcpState::Established && conn.state != TcpState::CloseWait {
            return None;
        }

        let pkt = packet::build_tcp_packet(
            conn.id.local_ip.octets(),
            conn.id.remote_ip.octets(),
            conn.id.local_port,
            conn.id.remote_port,
            conn.snd_nxt,
            conn.rcv_nxt,
            0,
            TcpFlags {
                syn: false,
                ack: true,
                rst: false,
                fin: true,
                psh: false,
                urg: false,
                ece: false,
                cwr: false,
            },
            &[],
            &[],
            self.personality.ttl,
            self.personality.df,
            self.isn_gen.next_ip_id(),
        );

        conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
        conn.state = if conn.state == TcpState::Established {
            TcpState::FinWait1
        } else {
            TcpState::LastAck
        };

        Some(pkt)
    }

    /// Number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get the T5 probe response (SYN to closed port) from the personality.
    fn get_closed_port_response(&self) -> Option<&TProbeResponse> {
        // T5 = SYN to closed port
        self.personality.t_responses[4].as_ref()
    }
}

/// Compute sequence and acknowledgment numbers based on probe response behavior.
fn compute_seq_ack(
    t_resp: &TProbeResponse,
    probe_seq: u32,
    probe_ack: u32,
    isn: u32,
) -> (u32, u32) {
    let seq = match t_resp.seq_behavior {
        SeqBehavior::Zero => 0,
        SeqBehavior::EchoAck => probe_ack,
        SeqBehavior::EchoAckPlus => probe_ack.wrapping_add(1),
        SeqBehavior::Other => isn,
    };

    let ack = match t_resp.ack_behavior {
        AckBehavior::Zero => 0,
        AckBehavior::EchoSeq => probe_seq,
        AckBehavior::EchoSeqPlus => probe_seq.wrapping_add(1),
        AckBehavior::Other => 0,
    };

    (seq, ack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::FingerprintDb;

    fn make_engine() -> TcpEngine {
        let db = FingerprintDb::parse(
            r#"
Fingerprint Linux 3.2 - 4.9
Class Linux | Linux | 3.X | general purpose
SEQ(SP=F9%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%T=40%TG=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%TG=40%W=0%S=A%A=Z%F=R%RD=0%Q=)
T5(R=Y%DF=Y%T=40%TG=40%W=0%S=Z%A=S+%F=AR%RD=0%Q=)
T6(R=Y%DF=Y%T=40%TG=40%W=0%S=A%A=Z%F=R%RD=0%Q=)
T7(R=Y%DF=Y%T=40%TG=40%W=0%S=Z%A=S+%F=AR%RD=0%Q=)
U1(R=Y%DF=N%T=40%TG=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%TG=40%CD=S)
"#,
        )
        .expect("parse");
        let fp = db.find_by_name("Linux").expect("found");
        let p = Personality::from_fingerprint(fp);
        TcpEngine::new(p)
    }

    fn make_syn_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        // Minimal IP + TCP SYN packet
        let flags = TcpFlags {
            syn: true,
            ack: false,
            rst: false,
            fin: false,
            psh: false,
            urg: false,
            ece: false,
            cwr: false,
        };
        packet::build_tcp_packet(
            src_ip, dst_ip, src_port, dst_port, 1000, 0, 65535, flags, &[], &[], 64, true, 1,
        )
    }

    #[test]
    fn test_syn_to_open_port_returns_synack() {
        let mut engine = make_engine();
        engine.open_port(80);

        let pkt = make_syn_packet([10, 0, 0, 2], [10, 0, 0, 1], 12345, 80);
        let ip = ParsedIpv4::parse(&pkt).expect("ip");
        let tcp_data = ip.payload(&pkt);
        let tcp = ParsedTcp::parse(tcp_data).expect("tcp");

        let (out, events) = engine.handle_packet(&ip, &tcp, tcp_data);
        assert_eq!(out.len(), 1, "should send SYN-ACK");
        assert!(events.is_empty(), "no events yet");

        // Verify SYN-ACK
        let resp_ip = ParsedIpv4::parse(&out[0]).expect("resp ip");
        let resp_tcp = ParsedTcp::parse(resp_ip.payload(&out[0])).expect("resp tcp");
        assert!(resp_tcp.is_syn());
        assert!(resp_tcp.is_ack());
        assert_eq!(resp_tcp.window, 0xFE88); // Linux personality window
        assert_eq!(resp_ip.ttl, 64); // Linux TTL
    }

    #[test]
    fn test_syn_to_closed_port_returns_rst() {
        let mut engine = make_engine();
        // Port 80 is NOT open

        let pkt = make_syn_packet([10, 0, 0, 2], [10, 0, 0, 1], 12345, 80);
        let ip = ParsedIpv4::parse(&pkt).expect("ip");
        let tcp_data = ip.payload(&pkt);
        let tcp = ParsedTcp::parse(tcp_data).expect("tcp");

        let (out, _) = engine.handle_packet(&ip, &tcp, tcp_data);
        assert_eq!(out.len(), 1, "should send RST");

        let resp_ip = ParsedIpv4::parse(&out[0]).expect("resp ip");
        let resp_tcp = ParsedTcp::parse(resp_ip.payload(&out[0])).expect("resp tcp");
        assert!(resp_tcp.is_rst());
        assert!(resp_tcp.is_ack());
        // T5: W=0, S=Z (seq should be 0), A=S+ (ack should be probe_seq + 1)
        assert_eq!(resp_tcp.window, 0);
        assert_eq!(resp_tcp.seq_num, 0); // S=Z
        assert_eq!(resp_tcp.ack_num, 1001); // A=S+ (1000+1)
    }

    #[test]
    fn test_three_way_handshake() {
        let mut engine = make_engine();
        engine.open_port(22);

        // SYN
        let syn = make_syn_packet([10, 0, 0, 2], [10, 0, 0, 1], 50000, 22);
        let ip = ParsedIpv4::parse(&syn).expect("ip");
        let tcp_data = ip.payload(&syn);
        let tcp = ParsedTcp::parse(tcp_data).expect("tcp");
        let (out, events) = engine.handle_packet(&ip, &tcp, tcp_data);
        assert_eq!(out.len(), 1);
        assert!(events.is_empty());
        assert_eq!(engine.connection_count(), 1);

        // Extract SYN-ACK seq/ack for the ACK
        let sa_ip = ParsedIpv4::parse(&out[0]).expect("sa ip");
        let sa_tcp = ParsedTcp::parse(sa_ip.payload(&out[0])).expect("sa tcp");
        let server_isn = sa_tcp.seq_num;

        // ACK
        let ack_flags = TcpFlags {
            syn: false,
            ack: true,
            rst: false,
            fin: false,
            psh: false,
            urg: false,
            ece: false,
            cwr: false,
        };
        let ack_pkt = packet::build_tcp_packet(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            50000,
            22,
            1001,                        // client seq (ISN + 1)
            server_isn.wrapping_add(1),  // ack the server ISN
            65535,
            ack_flags,
            &[],
            &[],
            64,
            true,
            2,
        );
        let ip = ParsedIpv4::parse(&ack_pkt).expect("ip");
        let tcp_data = ip.payload(&ack_pkt);
        let tcp = ParsedTcp::parse(tcp_data).expect("tcp");
        let (out, events) = engine.handle_packet(&ip, &tcp, tcp_data);
        assert!(out.is_empty());
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], TcpEvent::Connected { .. }));
    }

    #[test]
    fn test_send_data() {
        let mut engine = make_engine();
        engine.open_port(80);

        // Do handshake (abbreviated)
        let syn = make_syn_packet([10, 0, 0, 2], [10, 0, 0, 1], 50000, 80);
        let ip = ParsedIpv4::parse(&syn).expect("ip");
        let tcp_data = ip.payload(&syn);
        let tcp = ParsedTcp::parse(tcp_data).expect("tcp");
        let (out, _) = engine.handle_packet(&ip, &tcp, tcp_data);

        let sa_ip = ParsedIpv4::parse(&out[0]).expect("sa ip");
        let sa_tcp = ParsedTcp::parse(sa_ip.payload(&out[0])).expect("sa tcp");
        let server_isn = sa_tcp.seq_num;

        // Send ACK to complete handshake
        let ack_pkt = packet::build_tcp_packet(
            [10, 0, 0, 2], [10, 0, 0, 1], 50000, 80,
            1001, server_isn.wrapping_add(1), 65535,
            TcpFlags { syn: false, ack: true, rst: false, fin: false, psh: false, urg: false, ece: false, cwr: false },
            &[], &[], 64, true, 2,
        );
        let ip = ParsedIpv4::parse(&ack_pkt).expect("ip");
        let tcp_data = ip.payload(&ack_pkt);
        let tcp = ParsedTcp::parse(tcp_data).expect("tcp");
        engine.handle_packet(&ip, &tcp, tcp_data);

        // Now send data
        let conn_id = TcpConnId {
            local_ip: Ipv4Addr::new(10, 0, 0, 1),
            local_port: 80,
            remote_ip: Ipv4Addr::new(10, 0, 0, 2),
            remote_port: 50000,
        };
        let data_pkt = engine.send_data(&conn_id, b"HTTP/1.0 200 OK\r\n");
        assert!(data_pkt.is_some());

        let pkt = data_pkt.expect("packet");
        let resp_ip = ParsedIpv4::parse(&pkt).expect("ip");
        let resp_tcp_data = resp_ip.payload(&pkt);
        let resp_tcp = ParsedTcp::parse(resp_tcp_data).expect("tcp");
        assert!(resp_tcp.is_ack());
        assert!(resp_tcp.is_psh());

        let payload = resp_tcp.payload(resp_tcp_data);
        assert_eq!(payload, b"HTTP/1.0 200 OK\r\n");
    }
}
