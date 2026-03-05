// ABOUTME: Connection lifecycle state machine and metadata registry.
// ABOUTME: Owns ConnectionMeta (shared via DashMap) and defines state transitions.

pub mod callback;
pub mod limits;
pub mod tcp;
pub mod throttle;
#[cfg(feature = "tls")]
pub mod tls;
pub mod udp;

use crate::error::Error;
use crate::node_info::NodeInfo;
use crate::processor::ProcessorPipeline;
use bytes::Bytes;
use dashmap::DashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::mpsc;

/// Monotonically increasing connection identifier. Never recycled.
///
/// Python holds copies of this to reference connections by ID rather
/// than holding direct references to I/O state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Global counter for assigning unique connection IDs.
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a new unique connection ID.
pub fn next_id() -> ConnectionId {
    ConnectionId(NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed))
}

/// Network transport layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Plain TCP.
    Tcp,
    /// TLS over TCP.
    Tls,
    /// UDP.
    Udp,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Transport::Tcp => write!(f, "tcp"),
            Transport::Tls => write!(f, "tls"),
            Transport::Udp => write!(f, "udp"),
        }
    }
}

impl Transport {
    /// Parse from a protocol string (as used by Python protocols).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(Transport::Tcp),
            "tls" => Some(Transport::Tls),
            "udp" => Some(Transport::Udp),
            _ => None,
        }
    }
}

/// How this connection was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Accepted from a listener.
    Accept,
    /// Listening for incoming connections.
    Listen,
    /// Outbound connect() initiated.
    Connect,
}

/// Connection lifecycle state.
///
/// Drives which operations are valid and which Python callbacks fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state. No I/O task yet.
    None,
    /// DNS resolution in progress (outbound connect).
    Resolve,
    /// TCP connect in progress.
    Connecting,
    /// TLS handshake in progress.
    Handshake,
    /// Connection is live. Data can flow.
    Established,
    /// Graceful shutdown initiated.
    Shutdown,
    /// Connection closed. Pending cleanup.
    Close,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionState::None => write!(f, "none"),
            ConnectionState::Resolve => write!(f, "resolve"),
            ConnectionState::Connecting => write!(f, "connecting"),
            ConnectionState::Handshake => write!(f, "handshake"),
            ConnectionState::Established => write!(f, "established"),
            ConnectionState::Shutdown => write!(f, "shutdown"),
            ConnectionState::Close => write!(f, "close"),
        }
    }
}

/// Validate a state transition. Returns error if invalid.
pub fn validate_transition(from: ConnectionState, to: ConnectionState) -> Result<(), Error> {
    use ConnectionState::*;
    let valid = matches!(
        (from, to),
        (None, Resolve)
            | (None, Connecting)
            | (None, Handshake)
            | (None, Established)
            | (None, Close)
            | (Resolve, Connecting)
            | (Resolve, Close)
            | (Connecting, Handshake)
            | (Connecting, Established)
            | (Connecting, Close)
            | (Handshake, Established)
            | (Handshake, Close)
            | (Established, Shutdown)
            | (Established, Close)
            | (Shutdown, Close)
    );
    if valid {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "invalid connection state transition: {from} -> {to}"
        )))
    }
}

/// Per-connection transfer statistics.
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Bytes received.
    pub bytes_in: u64,
    /// Bytes sent.
    pub bytes_out: u64,
    /// When the connection was created.
    pub created_at: Instant,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        ConnectionStats {
            bytes_in: 0,
            bytes_out: 0,
            created_at: Instant::now(),
        }
    }
}

/// Configurable timeout values per connection (seconds, 0 = disabled).
#[derive(Debug, Clone)]
pub struct ConnectionTimeouts {
    /// No data for this many seconds → fire timeout.
    pub idle: f64,
    /// Connection open longer than this → fire timeout.
    pub sustain: f64,
    /// Listening socket timeout.
    pub listen: f64,
    /// TLS handshake timeout.
    pub handshake: f64,
    /// Outbound TCP connect timeout.
    pub connecting: f64,
    /// Graceful close timeout.
    pub close: f64,
}

impl Default for ConnectionTimeouts {
    fn default() -> Self {
        ConnectionTimeouts {
            idle: 120.0,
            sustain: 300.0,
            listen: 0.0,
            handshake: 10.0,
            connecting: 5.0,
            close: 10.0,
        }
    }
}

/// Metadata visible to Python and the incident system.
///
/// Stored in `ConnectionRegistry` (`DashMap<ConnectionId, ConnectionMeta>`).
/// The tokio task owns the I/O state separately (socket, buffers, timeouts).
pub struct ConnectionMeta {
    /// Unique identifier. Never recycled.
    pub id: ConnectionId,
    /// Network transport.
    pub transport: Transport,
    /// How this connection was created.
    pub connection_type: ConnectionType,
    /// Current lifecycle state.
    pub state: ConnectionState,
    /// Local endpoint address.
    pub local: NodeInfo,
    /// Remote endpoint address.
    pub remote: NodeInfo,
    /// Protocol name (set by Python, e.g. "smbd", "httpd").
    pub protocol: String,
    /// Transfer statistics.
    pub stats: ConnectionStats,
    /// Timeout configuration.
    pub timeouts: ConnectionTimeouts,
    /// Reference count for preventing premature cleanup.
    pub refcount: AtomicU32,
}

impl ConnectionMeta {
    /// Create metadata for a new connection.
    pub fn new(
        id: ConnectionId,
        transport: Transport,
        connection_type: ConnectionType,
    ) -> Self {
        ConnectionMeta {
            id,
            transport,
            connection_type,
            state: ConnectionState::None,
            local: NodeInfo::unset(),
            remote: NodeInfo::unset(),
            protocol: String::new(),
            stats: ConnectionStats::default(),
            timeouts: ConnectionTimeouts::default(),
            refcount: AtomicU32::new(1),
        }
    }

    /// Increment reference count. Returns new count.
    pub fn ref_inc(&self) -> u32 {
        self.refcount.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Decrement reference count. Returns new count.
    pub fn ref_dec(&self) -> u32 {
        self.refcount.fetch_sub(1, Ordering::Relaxed) - 1
    }

    /// Current reference count.
    pub fn ref_count(&self) -> u32 {
        self.refcount.load(Ordering::Relaxed)
    }
}

/// Messages sent from Python's `send()` to the connection's I/O task.
#[derive(Debug)]
pub enum SendMessage {
    /// TCP/TLS: send data to the remote.
    Data(Bytes),
    /// UDP: send datagram to a specific remote from a specific local address.
    Datagram {
        /// Datagram payload.
        data: Bytes,
        /// Local address to send from.
        local: SocketAddr,
        /// Remote address to send to.
        remote: SocketAddr,
    },
    /// Update a timeout value.
    SetTimeout {
        /// Which timeout to update.
        which: TimeoutKind,
        /// New value in seconds.
        value: f64,
    },
    /// Update throttle speed limit.
    SetThrottle {
        /// Ingress or egress.
        direction: Direction,
        /// Bytes per second (0 = unlimited).
        limit: f64,
    },
    /// Update accounting byte limit.
    SetAccountingLimit {
        /// Ingress or egress.
        direction: Direction,
        /// Max bytes (0 = unlimited).
        limit: u64,
    },
    /// Attach a processor pipeline (streamdumper, shellcode, etc.) to this connection.
    AttachProcessors(ProcessorPipeline),
    /// Graceful close requested by Python's `close()`.
    Close,
}

/// Which timeout to configure.
#[derive(Debug, Clone, Copy)]
pub enum TimeoutKind {
    /// Idle timeout.
    Idle,
    /// Sustain timeout.
    Sustain,
    /// Listen timeout.
    Listen,
    /// Handshake timeout.
    Handshake,
    /// Connecting timeout.
    Connecting,
    /// Close timeout.
    Close,
}

/// Data transfer direction.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    /// Ingress (data coming in).
    In,
    /// Egress (data going out).
    Out,
}

/// Global registry of active connections.
///
/// Python reads metadata through `PyConnection`, which holds a `ConnectionId`
/// and looks up the entry here on each property access.
pub struct ConnectionRegistry {
    connections: DashMap<ConnectionId, ConnectionMeta>,
}

impl ConnectionRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        ConnectionRegistry {
            connections: DashMap::new(),
        }
    }

    /// Register a new connection. Returns the send channel sender.
    pub fn register(
        &self,
        transport: Transport,
        connection_type: ConnectionType,
    ) -> (ConnectionId, mpsc::Sender<SendMessage>, mpsc::Receiver<SendMessage>) {
        let id = next_id();
        let meta = ConnectionMeta::new(id, transport, connection_type);
        let (tx, rx) = mpsc::channel(256);
        self.connections.insert(id, meta);
        (id, tx, rx)
    }

    /// Look up connection metadata. Returns None if the connection doesn't exist.
    pub fn get(
        &self,
        id: ConnectionId,
    ) -> Option<dashmap::mapref::one::Ref<'_, ConnectionId, ConnectionMeta>> {
        self.connections.get(&id)
    }

    /// Look up connection metadata for mutation.
    pub fn get_mut(
        &self,
        id: ConnectionId,
    ) -> Option<dashmap::mapref::one::RefMut<'_, ConnectionId, ConnectionMeta>> {
        self.connections.get_mut(&id)
    }

    /// Remove a connection from the registry.
    pub fn remove(&self, id: ConnectionId) -> Option<ConnectionMeta> {
        self.connections.remove(&id).map(|(_, meta)| meta)
    }

    /// Number of active connections.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Iterate over all connection IDs. Used for finding connections in tests.
    pub fn iter_ids(&self) -> impl Iterator<Item = ConnectionId> + '_ {
        self.connections.iter().map(|entry| *entry.key())
    }
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id_uniqueness() {
        let id1 = next_id();
        let id2 = next_id();
        let id3 = next_id();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert!(id2.0 > id1.0);
        assert!(id3.0 > id2.0);
    }

    #[test]
    fn test_state_transitions_valid() {
        use ConnectionState::*;
        assert!(validate_transition(None, Established).is_ok());
        assert!(validate_transition(None, Connecting).is_ok());
        assert!(validate_transition(Connecting, Established).is_ok());
        assert!(validate_transition(Established, Close).is_ok());
        assert!(validate_transition(Established, Shutdown).is_ok());
        assert!(validate_transition(Shutdown, Close).is_ok());
        assert!(validate_transition(Handshake, Established).is_ok());
        assert!(validate_transition(Handshake, Close).is_ok());
    }

    #[test]
    fn test_state_transitions_invalid() {
        use ConnectionState::*;
        assert!(validate_transition(Close, Established).is_err());
        assert!(validate_transition(Established, None).is_err());
        assert!(validate_transition(Close, None).is_err());
        assert!(validate_transition(Shutdown, Established).is_err());
    }

    #[test]
    fn test_registry_register_and_lookup() {
        let registry = ConnectionRegistry::new();
        let (id, _tx, _rx) = registry.register(Transport::Tcp, ConnectionType::Accept);

        assert_eq!(registry.len(), 1);
        let meta = registry.get(id).expect("should exist");
        assert_eq!(meta.transport, Transport::Tcp);
        assert_eq!(meta.state, ConnectionState::None);
    }

    #[test]
    fn test_registry_remove() {
        let registry = ConnectionRegistry::new();
        let (id, _tx, _rx) = registry.register(Transport::Tls, ConnectionType::Connect);
        assert_eq!(registry.len(), 1);

        let removed = registry.remove(id);
        assert!(removed.is_some());
        assert_eq!(registry.len(), 0);
        assert!(registry.get(id).is_none());
    }

    #[test]
    fn test_refcount() {
        let meta = ConnectionMeta::new(
            ConnectionId(1),
            Transport::Tcp,
            ConnectionType::Accept,
        );
        assert_eq!(meta.ref_count(), 1);
        assert_eq!(meta.ref_inc(), 2);
        assert_eq!(meta.ref_count(), 2);
        assert_eq!(meta.ref_dec(), 1);
        assert_eq!(meta.ref_count(), 1);
    }

    #[test]
    fn test_transport_display() {
        assert_eq!(Transport::Tcp.to_string(), "tcp");
        assert_eq!(Transport::Tls.to_string(), "tls");
        assert_eq!(Transport::Udp.to_string(), "udp");
    }

    #[test]
    fn test_transport_from_str() {
        assert_eq!(Transport::from_str_loose("tcp"), Some(Transport::Tcp));
        assert_eq!(Transport::from_str_loose("TLS"), Some(Transport::Tls));
        assert_eq!(Transport::from_str_loose("UDP"), Some(Transport::Udp));
        assert_eq!(Transport::from_str_loose("invalid"), None);
    }

    #[test]
    fn test_state_display() {
        assert_eq!(ConnectionState::None.to_string(), "none");
        assert_eq!(ConnectionState::Established.to_string(), "established");
        assert_eq!(ConnectionState::Close.to_string(), "close");
    }

    #[test]
    fn test_registry_mutation() {
        let registry = ConnectionRegistry::new();
        let (id, _tx, _rx) = registry.register(Transport::Tcp, ConnectionType::Accept);

        {
            let mut meta = registry.get_mut(id).expect("should exist");
            meta.state = ConnectionState::Established;
            meta.protocol = "httpd".to_string();
        }

        let meta = registry.get(id).expect("should exist");
        assert_eq!(meta.state, ConnectionState::Established);
        assert_eq!(meta.protocol, "httpd");
    }
}
