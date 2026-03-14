// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: UDP listener with per-peer connection multiplexing via peer table.
// ABOUTME: Single socket, per-peer Python handlers, idle timeout sweep for cleanup.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use pyo3::prelude::*;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{self, Duration, Instant};

use crate::connection::callback::{self, PostCallback};
use crate::connection::limits::ConnectionLimits;
use crate::connection::tcp::{cleanup_connection, get_fd_soft_limit, invalidate_handler};
use crate::connection::{
    ConnectionId, ConnectionRegistry, ConnectionState, ConnectionType, SendMessage, Transport,
};
use crate::python::connection::{PyConnection, factory_create};

/// Handle for a running UDP listener.
pub struct UdpListenerHandle {
    /// Abort handle for the recv loop task.
    abort: tokio::task::AbortHandle,
    /// The address the listener is bound to.
    pub addr: SocketAddr,
}

impl UdpListenerHandle {
    /// Stop the listener.
    pub fn stop(&self) {
        self.abort.abort();
    }

    /// Get the abort handle for external tracking (e.g., shutdown manager).
    pub fn abort_handle(&self) -> tokio::task::AbortHandle {
        self.abort.clone()
    }
}

/// Hard cap on UDP peer table size to prevent memory exhaustion from IP spoofing.
const MAX_UDP_PEERS: usize = 10_000;

/// Per-peer state in the UDP peer table.
struct UdpPeer {
    /// Connection ID in the registry.
    id: ConnectionId,
    /// Python protocol handler.
    handler: Py<PyAny>,
    /// Per-peer channel receiver for send messages (Data, Datagram, control).
    rx: mpsc::Receiver<SendMessage>,
    /// When this peer last sent or received data.
    last_activity: Instant,
    /// Idle timeout duration. Peers are removed when idle longer than this.
    idle_timeout: Duration,
}

/// Start a UDP listener on the given address.
///
/// Returns a handle that can be used to stop the listener.
/// The recv loop dispatches datagrams to per-peer Python handlers.
pub async fn udp_listen(
    addr: SocketAddr,
    registry: Arc<ConnectionRegistry>,
    limits: Arc<ConnectionLimits>,
    protocol_factory: Py<PyAny>,
    recv_buffer_size: usize,
    idle_timeout_secs: f64,
) -> std::io::Result<UdpListenerHandle> {
    let socket = UdpSocket::bind(addr).await?;
    let bound_addr = socket.local_addr()?;
    tracing::debug!(%bound_addr, "UDP listener bound");

    let idle_timeout = if idle_timeout_secs <= 0.0 {
        Duration::from_secs(86400 * 365) // effectively disabled
    } else {
        Duration::from_secs_f64(idle_timeout_secs)
    };

    let task = tokio::spawn(udp_recv_loop(
        socket,
        registry,
        limits,
        protocol_factory,
        recv_buffer_size,
        idle_timeout,
    ));

    Ok(UdpListenerHandle {
        abort: task.abort_handle(),
        addr: bound_addr,
    })
}

/// UDP recv loop: receive datagrams, dispatch to per-peer handlers, send replies.
///
/// Manages a peer table (`HashMap<SocketAddr, UdpPeer>`) and sweeps for idle
/// peers every second. Python callbacks run via `block_in_place` + GIL.
#[allow(clippy::too_many_lines)]
async fn udp_recv_loop(
    socket: UdpSocket,
    registry: Arc<ConnectionRegistry>,
    limits: Arc<ConnectionLimits>,
    protocol_factory: Py<PyAny>,
    recv_buffer_size: usize,
    default_idle_timeout: Duration,
) {
    let socket = Arc::new(socket);
    let local_addr = socket
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

    let mut peers: HashMap<SocketAddr, UdpPeer> = HashMap::new();
    let mut buf = vec![0u8; recv_buffer_size];

    // Shared send channel: peers push datagrams here, we send_to from the socket.
    // Also used for control messages (timeout changes).
    let (_outgoing_tx, mut outgoing_rx) = mpsc::channel::<(Bytes, SocketAddr)>(256);

    let sweep_interval = Duration::from_secs(1);

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, remote_addr)) => {
                        let data = buf[..n].to_vec();
                        let remote_ip = remote_addr.ip();

                        if let Some(peer) = peers.get_mut(&remote_addr) {
                            // Existing peer: call handle_io_in
                            peer.last_activity = Instant::now();

                            // Drain any pending send messages from this peer
                            drain_peer_sends(&mut peer.rx, &socket, remote_addr).await;

                            let post = tokio::task::block_in_place(|| {
                                Python::attach(|py| {
                                    let (result, _consumed) =
                                        callback::call_handle_io_in(peer.handler.bind(py), &data);
                                    result
                                })
                            });

                            if post != PostCallback::Continue {
                                remove_peer(&mut peers, &remote_addr, &registry, &limits);
                                continue;
                            }
                        } else {
                            // New peer: check peer table cap and limits
                            if peers.len() >= MAX_UDP_PEERS {
                                tracing::warn!(%remote_addr, peers = peers.len(), "UDP peer table full, rejecting");
                                continue;
                            }

                            let fd_count = registry.len() as u64;
                            let fd_soft_limit = get_fd_soft_limit();

                            if let Err(reason) = limits.check(
                                remote_ip,
                                #[allow(clippy::cast_possible_truncation)]
                                (registry.len() as u32),
                                fd_count,
                                fd_soft_limit,
                            ) {
                                tracing::debug!(%remote_addr, %reason, "rejecting UDP peer");
                                continue;
                            }

                            let (id, tx, rx) = registry.register(Transport::Udp, ConnectionType::Accept);
                            limits.increment(remote_ip);

                            if let Some(mut meta) = registry.get_mut(id) {
                                meta.local = crate::node_info::NodeInfo::from_socket_addr(local_addr);
                                meta.remote = crate::node_info::NodeInfo::from_socket_addr(remote_addr);
                                meta.state = ConnectionState::Established;
                            }

                            tracing::debug!(connection_id = %id, %remote_addr, "new UDP peer");

                            let handler_tx = tx;

                            let child_result = tokio::task::block_in_place(|| {
                                Python::attach(|py| {
                                    let parent = protocol_factory.bind(py);
                                    factory_create(
                                        py, parent, id, handler_tx, "udp",
                                        Some(registry.clone()), Some(limits.clone()), recv_buffer_size,
                                    )
                                })
                            });

                            let handler = match child_result {
                                Ok(h) => h,
                                Err(e) => {
                                    tracing::error!(connection_id = %id, err = %e, "factory_create failed");
                                    cleanup_connection(&registry, &limits, id, remote_ip);
                                    continue;
                                }
                            };

                            let post = tokio::task::block_in_place(|| {
                                Python::attach(|py| {
                                    if let Ok(conn) = handler.bind(py).cast::<PyConnection>() {
                                        let mut c = conn.borrow_mut();
                                        c.local.host = local_addr.ip().to_string();
                                        c.local.port = local_addr.port();
                                        c.remote.host = remote_addr.ip().to_string();
                                        c.remote.port = remote_addr.port();
                                        c.status = "established".to_string();
                                    }
                                    callback::call_handle_established(handler.bind(py))
                                })
                            });

                            if post != PostCallback::Continue {
                                invalidate_handler(&handler);
                                cleanup_connection(&registry, &limits, id, remote_ip);
                                continue;
                            }

                            peers.insert(remote_addr, UdpPeer {
                                id,
                                handler,
                                rx,
                                last_activity: Instant::now(),
                                idle_timeout: default_idle_timeout,
                            });

                            let peer = peers.get_mut(&remote_addr).expect("just inserted");
                            let post = tokio::task::block_in_place(|| {
                                Python::attach(|py| {
                                    let (result, _consumed) =
                                        callback::call_handle_io_in(peer.handler.bind(py), &data);
                                    result
                                })
                            });

                            if post != PostCallback::Continue {
                                remove_peer(&mut peers, &remote_addr, &registry, &limits);
                                continue;
                            }
                        }

                        // After processing, drain any sends queued during callbacks
                        if let Some(peer) = peers.get_mut(&remote_addr) {
                            drain_peer_sends(&mut peer.rx, &socket, remote_addr).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(err = %e, "UDP recv_from failed");
                    }
                }
            }

            msg = outgoing_rx.recv() => {
                if let Some((data, remote)) = msg {
                    if let Err(e) = socket.send_to(&data, remote).await {
                        tracing::debug!(err = %e, %remote, "UDP send_to failed");
                    }
                }
            }

            () = time::sleep(sweep_interval) => {
                sweep_idle_peers(&mut peers, &registry, &limits);
            }
        }
    }
}

/// Drain pending send messages from a peer's channel and send them via the socket.
///
/// `peer_addr` is the known remote address for this peer, used as the
/// destination when a `Data` message arrives without explicit addresses
/// (e.g. from Python `self.send(bytes)` without local/remote kwargs).
async fn drain_peer_sends(
    rx: &mut mpsc::Receiver<SendMessage>,
    socket: &UdpSocket,
    peer_addr: SocketAddr,
) {
    while let Ok(msg) = rx.try_recv() {
        match msg {
            SendMessage::Datagram { data, remote, .. } => {
                if let Err(e) = socket.send_to(&data, remote).await {
                    tracing::debug!(err = %e, %remote, "UDP send_to failed");
                }
            }
            SendMessage::Data(data) => {
                if let Err(e) = socket.send_to(&data, peer_addr).await {
                    tracing::debug!(err = %e, %peer_addr, "UDP send_to failed");
                }
            }
            _ => {
                // Control messages (SetTimeout etc.) — could update peer state
                // For now, ignored (timeouts managed by sweep)
            }
        }
    }
}

/// Remove idle peers from the table, cleaning up their connections.
fn sweep_idle_peers(
    peers: &mut HashMap<SocketAddr, UdpPeer>,
    registry: &ConnectionRegistry,
    limits: &ConnectionLimits,
) {
    let now = Instant::now();
    let expired: Vec<SocketAddr> = peers
        .iter()
        .filter(|(_, peer)| now.duration_since(peer.last_activity) > peer.idle_timeout)
        .map(|(addr, _)| *addr)
        .collect();

    for addr in expired {
        tracing::debug!(%addr, "UDP peer idle timeout");
        remove_peer(peers, &addr, registry, limits);
    }
}

/// Remove a peer from the table and clean up its connection.
fn remove_peer(
    peers: &mut HashMap<SocketAddr, UdpPeer>,
    addr: &SocketAddr,
    registry: &ConnectionRegistry,
    limits: &ConnectionLimits,
) {
    if let Some(peer) = peers.remove(addr) {
        tokio::task::block_in_place(|| {
            Python::attach(|py| {
                let _ = peer.handler.bind(py).call_method0("handle_disconnect");
                if let Ok(conn) = peer.handler.bind(py).cast::<PyConnection>() {
                    conn.borrow_mut().invalidate();
                }
            });
        });
        cleanup_connection(registry, limits, peer.id, addr.ip());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::python::connection::PyConnection;
    use pyo3::types::PyModule;
    use std::time::Duration;

    fn register_test_module(py: Python<'_>, name: &str) {
        let module = PyModule::new(py, name).expect("module creation");
        module
            .add_class::<PyConnection>()
            .expect("add PyConnection");
        py.import(c"sys")
            .expect("import sys")
            .getattr("modules")
            .expect("get modules")
            .set_item(name, module)
            .expect("set module");
    }

    fn create_udp_echo_factory(py: Python<'_>, module_name: &str) -> Py<PyAny> {
        register_test_module(py, module_name);
        let code = format!(
            "
from {module_name} import connection as PyConnection
class UdpEchoProtocol(PyConnection):
    events = []
    def __init__(self, proto=None):
        super().__init__(proto)
    def handle_established(self):
        UdpEchoProtocol.events.append('established')
    def handle_io_in(self, data):
        self.send(data, local=(self.local.host, self.local.port), remote=(self.remote.host, self.remote.port))
        UdpEchoProtocol.events.append(('io_in', bytes(data)))
        return len(data)
    def handle_disconnect(self):
        UdpEchoProtocol.events.append('disconnect')
        return False
factory = UdpEchoProtocol('udp')
"
        );
        let c_code = std::ffi::CString::new(code).expect("CString");
        py.run(c_code.as_c_str(), None, None).expect("define echo");
        let factory = py.eval(c"factory", None, None).expect("factory");
        {
            let mut c = factory.cast::<PyConnection>().expect("cast").borrow_mut();
            c.id = Some(ConnectionId(0));
        }
        factory.unbind()
    }

    #[test]
    fn test_udp_echo_roundtrip() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let reg = Arc::new(ConnectionRegistry::new());
            let lim = Arc::new(ConnectionLimits::new(50, 10_000, 70));
            let factory = Python::attach(|py| create_udp_echo_factory(py, "udp_echo_t"));

            let handle = udp_listen(
                "127.0.0.1:0".parse().expect("addr"),
                reg.clone(),
                lim.clone(),
                factory,
                65536,
                120.0,
            )
            .await
            .expect("udp_listen");

            time::sleep(Duration::from_millis(50)).await;

            // Send a UDP datagram
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
            client
                .send_to(b"hello udp", handle.addr)
                .await
                .expect("send");

            // Wait for processing
            time::sleep(Duration::from_millis(500)).await;

            // Read echo response
            let mut resp = vec![0u8; 64];
            let recv_result =
                tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut resp)).await;
            let (n, _from) = recv_result.expect("timeout").expect("recv");
            assert_eq!(&resp[..n], b"hello udp");

            // Verify peer was created
            assert!(reg.len() >= 1);

            // Verify Python events
            Python::attach(|py| {
                let events: Vec<String> = py
                    .eval(
                        c"[e if isinstance(e, str) else '' for e in UdpEchoProtocol.events]",
                        None,
                        None,
                    )
                    .expect("events")
                    .extract()
                    .expect("extract");
                assert!(
                    events.contains(&"established".to_string()),
                    "expected 'established', got {events:?}"
                );
            });

            handle.stop();
        });
    }

    #[test]
    fn test_udp_peer_idle_timeout() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let reg = Arc::new(ConnectionRegistry::new());
            let lim = Arc::new(ConnectionLimits::new(50, 10_000, 70));
            let factory = Python::attach(|py| {
                register_test_module(py, "udp_idle_t");
                let code = "
from udp_idle_t import connection as PyConnection
class UdpIdleProto(PyConnection):
    events = []
    def __init__(self, proto=None):
        super().__init__(proto)
    def handle_established(self):
        UdpIdleProto.events.append('established')
    def handle_io_in(self, data):
        return len(data)
    def handle_disconnect(self):
        UdpIdleProto.events.append('disconnect')
        return False
factory = UdpIdleProto('udp')
";
                let c_code = std::ffi::CString::new(code).expect("CString");
                py.run(c_code.as_c_str(), None, None).expect("define");
                let factory = py.eval(c"factory", None, None).expect("factory");
                {
                    factory
                        .cast::<PyConnection>()
                        .expect("cast")
                        .borrow_mut()
                        .id = Some(ConnectionId(0));
                }
                factory.unbind()
            });

            // Short idle timeout for testing
            let handle = udp_listen(
                "127.0.0.1:0".parse().expect("addr"),
                reg.clone(),
                lim.clone(),
                factory,
                65536,
                0.5, // 500ms idle timeout
            )
            .await
            .expect("udp_listen");

            time::sleep(Duration::from_millis(50)).await;

            // Send a datagram to create a peer
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
            client.send_to(b"ping", handle.addr).await.expect("send");
            time::sleep(Duration::from_millis(300)).await;

            // Peer should exist
            assert_eq!(reg.len(), 1, "peer should be registered");

            // Wait for idle timeout (0.5s + sweep interval 1s + margin)
            time::sleep(Duration::from_millis(2000)).await;

            // Peer should be cleaned up
            assert_eq!(reg.len(), 0, "peer should be removed after idle timeout");

            // Verify disconnect was called
            Python::attach(|py| {
                let events: Vec<String> = py
                    .eval(c"UdpIdleProto.events", None, None)
                    .expect("events")
                    .extract()
                    .expect("extract");
                assert!(
                    events.contains(&"disconnect".to_string()),
                    "expected 'disconnect', got {events:?}"
                );
            });

            handle.stop();
        });
    }
}
