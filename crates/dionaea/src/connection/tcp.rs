// ABOUTME: TCP listener, accept loop, and per-connection I/O handler task.
// ABOUTME: Wires Python protocol callbacks to live sockets via spawn_blocking + GIL.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use pyo3::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{self, Duration, Instant, Sleep};

use crate::connection::callback::{self, PostCallback};
use crate::connection::limits::ConnectionLimits;
use crate::connection::throttle::{Accounting, Throttle};
use crate::connection::{
    ConnectionId, ConnectionRegistry, ConnectionState, ConnectionType, Direction, SendMessage,
    TimeoutKind, Transport,
};
use crate::python::connection::{factory_create, PyConnection};

/// Handle for a running TCP listener, used for shutdown.
pub struct TcpListenerHandle {
    /// Abort handle for the accept loop task.
    abort: tokio::task::AbortHandle,
    /// The address the listener is bound to.
    pub addr: SocketAddr,
}

impl TcpListenerHandle {
    /// Stop the listener (cancels the accept loop).
    pub fn stop(&self) {
        self.abort.abort();
    }
}

/// Start a TCP listener on the given address.
///
/// `protocol_factory` is the Python connection (listener) used as a template
/// for factory-creating accepted child connections.
pub async fn tcp_listen(
    addr: SocketAddr,
    registry: Arc<ConnectionRegistry>,
    limits: Arc<ConnectionLimits>,
    protocol_factory: Py<PyAny>,
    recv_buffer_size: usize,
) -> std::io::Result<TcpListenerHandle> {
    let listener = TcpListener::bind(addr).await?;
    let bound_addr = listener.local_addr()?;
    tracing::info!(%bound_addr, "TCP listener bound");

    let task = tokio::spawn(accept_loop(
        listener,
        registry,
        limits,
        protocol_factory,
        recv_buffer_size,
    ));

    Ok(TcpListenerHandle {
        abort: task.abort_handle(),
        addr: bound_addr,
    })
}

/// Accept loop: accepts connections, checks limits, spawns handler tasks.
async fn accept_loop(
    listener: TcpListener,
    registry: Arc<ConnectionRegistry>,
    limits: Arc<ConnectionLimits>,
    protocol_factory: Py<PyAny>,
    recv_buffer_size: usize,
) {
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(err = %e, "TCP accept failed");
                continue;
            }
        };

        let peer_ip = peer_addr.ip();
        let local_addr = stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

        // Check limits
        let fd_count = registry.len() as u64;
        let fd_soft_limit = get_fd_soft_limit();

        if let Err(reason) = limits.check(peer_ip, registry.len() as u32, fd_count, fd_soft_limit)
        {
            tracing::debug!(%peer_addr, %reason, "rejecting connection");
            drop(stream);
            continue;
        }

        // Register connection
        let (id, tx, rx) = registry.register(Transport::Tcp, ConnectionType::Accept);
        limits.increment(peer_ip);

        if let Some(mut meta) = registry.get_mut(id) {
            meta.local = crate::node_info::NodeInfo::from_socket_addr(local_addr);
            meta.remote = crate::node_info::NodeInfo::from_socket_addr(peer_addr);
            meta.state = ConnectionState::Established;
        }

        tracing::debug!(connection_id = %id, %peer_addr, "accepted TCP connection");

        // Clone factory inside GIL scope (PyO3 0.28: Py::clone requires GIL)
        // This is an atomic incref (~1μs), safe to do briefly on a worker thread.
        let factory_clone = Python::attach(|py| protocol_factory.clone_ref(py));

        let reg = registry.clone();
        let lim = limits.clone();

        tokio::spawn(async move {
            let handler_tx = tx.clone();
            let child_result = tokio::task::spawn_blocking(move || {
                Python::attach(|py| {
                    let parent = factory_clone.bind(py);
                    factory_create(py, &parent, id, handler_tx, "tcp")
                })
            })
            .await;

            let handler = match child_result {
                Ok(Ok(h)) => h,
                Ok(Err(e)) => {
                    tracing::error!(connection_id = %id, err = %e, "factory_create failed");
                    cleanup_connection(&reg, &lim, id, peer_ip);
                    return;
                }
                Err(e) => {
                    tracing::error!(connection_id = %id, err = %e, "factory panicked");
                    cleanup_connection(&reg, &lim, id, peer_ip);
                    return;
                }
            };

            handle_connection(stream, handler, id, rx, reg.clone(), recv_buffer_size).await;
            cleanup_connection(&reg, &lim, id, peer_ip);
        });
    }
}

/// Per-connection I/O handler task.
///
/// Runs a `select!` loop reading from the socket and the send channel.
/// Python callbacks are invoked via `spawn_blocking` + GIL.
/// Sequential callback guarantee: each callback completes before the next I/O event.
#[allow(clippy::too_many_lines)]
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    handler: Py<PyAny>,
    id: ConnectionId,
    mut rx: mpsc::Receiver<SendMessage>,
    registry: Arc<ConnectionRegistry>,
    recv_buffer_size: usize,
) {
    let mut buf = BytesMut::zeroed(recv_buffer_size);
    let mut partial_buf: Vec<u8> = Vec::new();

    let mut in_throttle = Throttle::unlimited();
    let mut out_throttle = Throttle::unlimited();
    let mut in_accounting = Accounting::unlimited();
    let mut out_accounting = Accounting::unlimited();

    // Call handle_established (move-and-return pattern for GIL)
    let h = handler;
    let post = tokio::task::spawn_blocking(move || {
        Python::attach(|py| {
            let result = callback::call_handle_established(h.bind(py));
            (h, result)
        })
    })
    .await;

    let mut handler = match post {
        Ok((h, PostCallback::Continue)) => h,
        Ok((h, _)) => {
            invalidate_handler(h);
            return;
        }
        Err(e) => {
            tracing::error!(connection_id = %id, err = %e, "handle_established panicked");
            return;
        }
    };

    // Drain any SetTimeout messages sent during handle_established
    // (Python protocol may set timeouts in handle_established)
    drain_control_messages(
        &mut rx,
        &registry,
        id,
        &mut in_throttle,
        &mut out_throttle,
        &mut in_accounting,
        &mut out_accounting,
    );

    // Initialize timeouts (pinned for select!)
    let idle_timeout = make_timeout(get_timeout_secs(&registry, id, TimeoutKind::Idle));
    let sustain_timeout = make_timeout(get_timeout_secs(&registry, id, TimeoutKind::Sustain));
    tokio::pin!(idle_timeout);
    tokio::pin!(sustain_timeout);

    loop {
        let read_limit = if in_throttle.is_unlimited() {
            recv_buffer_size
        } else {
            let avail = in_throttle.available();
            if avail == 0 {
                if let Err(wait) = in_throttle.try_consume(1) {
                    time::sleep(wait).await;
                }
                continue;
            }
            avail.min(recv_buffer_size)
        };

        tokio::select! {
            result = stream.read(&mut buf[..read_limit]) => {
                match result {
                    Ok(0) => {
                        handler = call_disconnect(handler, id).await;
                        invalidate_handler(handler);
                        return;
                    }
                    Ok(n) => {
                        // Reset idle timeout on data
                        let secs = get_timeout_secs(&registry, id, TimeoutKind::Idle);
                        idle_timeout.as_mut().reset(Instant::now() + secs_to_duration(secs));

                        let _ = in_throttle.try_consume(n);

                        if in_accounting.add(n as u64) {
                            tracing::debug!(connection_id = %id, "accounting limit, closing");
                            handler = call_disconnect(handler, id).await;
                            invalidate_handler(handler);
                            return;
                        }

                        if let Some(mut meta) = registry.get_mut(id) {
                            meta.stats.bytes_in += n as u64;
                        }

                        let data = if partial_buf.is_empty() {
                            buf[..n].to_vec()
                        } else {
                            let mut combined = std::mem::take(&mut partial_buf);
                            combined.extend_from_slice(&buf[..n]);
                            combined
                        };

                        let h = handler;
                        let post = tokio::task::spawn_blocking(move || {
                            Python::attach(|py| {
                                let (result, consumed) =
                                    callback::call_handle_io_in(h.bind(py), &data);
                                (h, result, consumed, data)
                            })
                        })
                        .await;

                        match post {
                            Ok((h, PostCallback::Continue, consumed, io_data)) => {
                                handler = h;
                                if consumed < io_data.len() {
                                    partial_buf = io_data[consumed..].to_vec();
                                }
                            }
                            Ok((h, _, _, _)) => {
                                invalidate_handler(h);
                                return;
                            }
                            Err(e) => {
                                tracing::error!(connection_id = %id, err = %e, "io_in panicked");
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(connection_id = %id, err = %e, "TCP read error");
                        handler = call_disconnect(handler, id).await;
                        invalidate_handler(handler);
                        return;
                    }
                }
            }

            msg = rx.recv() => {
                match msg {
                    Some(SendMessage::Data(data)) => {
                        if !out_throttle.is_unlimited() {
                            if let Err(wait) = out_throttle.try_consume(data.len()) {
                                time::sleep(wait).await;
                            }
                        }

                        if out_accounting.add(data.len() as u64) {
                            tracing::debug!(connection_id = %id, "outbound accounting limit");
                            handler = call_disconnect(handler, id).await;
                            invalidate_handler(handler);
                            return;
                        }

                        if let Err(e) = stream.write_all(&data).await {
                            tracing::debug!(connection_id = %id, err = %e, "TCP write error");
                            handler = call_disconnect(handler, id).await;
                            invalidate_handler(handler);
                            return;
                        }

                        if let Some(mut meta) = registry.get_mut(id) {
                            meta.stats.bytes_out += data.len() as u64;
                        }
                    }
                    Some(SendMessage::SetTimeout { which, value }) => {
                        update_timeout(&registry, id, which, value);
                        match which {
                            TimeoutKind::Idle => {
                                idle_timeout.as_mut().reset(
                                    Instant::now() + secs_to_duration(value),
                                );
                            }
                            TimeoutKind::Sustain => {
                                sustain_timeout.as_mut().reset(
                                    Instant::now() + secs_to_duration(value),
                                );
                            }
                            _ => {}
                        }
                    }
                    Some(SendMessage::SetThrottle { direction, limit }) => {
                        match direction {
                            Direction::In => in_throttle.set_rate(limit),
                            Direction::Out => out_throttle.set_rate(limit),
                        }
                    }
                    Some(SendMessage::SetAccountingLimit { direction, limit }) => {
                        match direction {
                            Direction::In => in_accounting.set_limit(limit),
                            Direction::Out => out_accounting.set_limit(limit),
                        }
                    }
                    Some(SendMessage::Datagram { .. }) => {}
                    None => {
                        tracing::debug!(connection_id = %id, "send channel closed");
                        handler = call_disconnect(handler, id).await;
                        invalidate_handler(handler);
                        return;
                    }
                }
            }

            () = &mut idle_timeout => {
                tracing::debug!(connection_id = %id, "idle timeout");
                let h = handler;
                let post = tokio::task::spawn_blocking(move || {
                    Python::attach(|py| {
                        let result = callback::call_handle_timeout_idle(h.bind(py));
                        (h, result)
                    })
                })
                .await;

                match post {
                    Ok((h, PostCallback::Continue)) => {
                        handler = h;
                        let secs = get_timeout_secs(&registry, id, TimeoutKind::Idle);
                        idle_timeout.as_mut().reset(
                            Instant::now() + secs_to_duration(secs),
                        );
                    }
                    Ok((h, _)) => {
                        invalidate_handler(h);
                        return;
                    }
                    Err(e) => {
                        tracing::error!(connection_id = %id, err = %e, "timeout_idle panicked");
                        return;
                    }
                }
            }

            () = &mut sustain_timeout => {
                tracing::debug!(connection_id = %id, "sustain timeout");
                let h = handler;
                let post = tokio::task::spawn_blocking(move || {
                    Python::attach(|py| {
                        let result = callback::call_handle_timeout_sustain(h.bind(py));
                        (h, result)
                    })
                })
                .await;

                match post {
                    Ok((h, PostCallback::Continue)) => {
                        handler = h;
                        let secs = get_timeout_secs(&registry, id, TimeoutKind::Sustain);
                        sustain_timeout.as_mut().reset(
                            Instant::now() + secs_to_duration(secs),
                        );
                    }
                    Ok((h, _)) => {
                        invalidate_handler(h);
                        return;
                    }
                    Err(e) => {
                        tracing::error!(connection_id = %id, err = %e, "timeout_sustain panicked");
                        return;
                    }
                }
            }
        }
    }
}

/// Drain pending control messages from the channel (non-blocking).
/// Called after handle_established to pick up timeouts set by the protocol.
fn drain_control_messages(
    rx: &mut mpsc::Receiver<SendMessage>,
    registry: &ConnectionRegistry,
    id: ConnectionId,
    in_throttle: &mut Throttle,
    out_throttle: &mut Throttle,
    in_accounting: &mut Accounting,
    out_accounting: &mut Accounting,
) {
    while let Ok(msg) = rx.try_recv() {
        match msg {
            SendMessage::SetTimeout { which, value } => {
                update_timeout(registry, id, which, value);
            }
            SendMessage::SetThrottle { direction, limit } => match direction {
                Direction::In => in_throttle.set_rate(limit),
                Direction::Out => out_throttle.set_rate(limit),
            },
            SendMessage::SetAccountingLimit { direction, limit } => match direction {
                Direction::In => in_accounting.set_limit(limit),
                Direction::Out => out_accounting.set_limit(limit),
            },
            _ => {} // Data messages before select! loop are unusual, skip
        }
    }
}

/// Update a timeout value in the registry.
fn update_timeout(
    registry: &ConnectionRegistry,
    id: ConnectionId,
    which: TimeoutKind,
    value: f64,
) {
    if let Some(mut meta) = registry.get_mut(id) {
        match which {
            TimeoutKind::Idle => meta.timeouts.idle = value,
            TimeoutKind::Sustain => meta.timeouts.sustain = value,
            TimeoutKind::Listen => meta.timeouts.listen = value,
            TimeoutKind::Handshake => meta.timeouts.handshake = value,
            TimeoutKind::Connecting => meta.timeouts.connecting = value,
            TimeoutKind::Close => meta.timeouts.close = value,
        }
    }
}

/// Call handle_disconnect via spawn_blocking, returning the handler.
async fn call_disconnect(handler: Py<PyAny>, id: ConnectionId) -> Py<PyAny> {
    match tokio::task::spawn_blocking(move || {
        Python::attach(|py| {
            callback::call_handle_disconnect(handler.bind(py));
            handler
        })
    })
    .await
    {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(connection_id = %id, err = %e, "handle_disconnect panicked");
            Python::attach(|py| py.None().into())
        }
    }
}

/// Get timeout seconds from the registry.
fn get_timeout_secs(registry: &ConnectionRegistry, id: ConnectionId, kind: TimeoutKind) -> f64 {
    registry.get(id).map_or(0.0, |meta| match kind {
        TimeoutKind::Idle => meta.timeouts.idle,
        TimeoutKind::Sustain => meta.timeouts.sustain,
        TimeoutKind::Listen => meta.timeouts.listen,
        TimeoutKind::Handshake => meta.timeouts.handshake,
        TimeoutKind::Connecting => meta.timeouts.connecting,
        TimeoutKind::Close => meta.timeouts.close,
    })
}

/// Convert seconds to Duration, treating <= 0 as "far future" (effectively disabled).
fn secs_to_duration(secs: f64) -> Duration {
    if secs <= 0.0 {
        Duration::from_secs(86400 * 365)
    } else {
        Duration::from_secs_f64(secs)
    }
}

/// Create a sleep future. 0.0 means "far future" (effectively disabled).
fn make_timeout(secs: f64) -> Sleep {
    time::sleep(secs_to_duration(secs))
}

/// Clean up after a connection closes.
fn cleanup_connection(
    registry: &ConnectionRegistry,
    limits: &ConnectionLimits,
    id: ConnectionId,
    peer_ip: std::net::IpAddr,
) {
    if let Some(mut meta) = registry.get_mut(id) {
        meta.state = ConnectionState::Close;
    }
    registry.remove(id);
    limits.decrement(peer_ip);
    tracing::debug!(connection_id = %id, "connection cleaned up");
}

/// Invalidate the Python handler (set id to None, drop channel).
fn invalidate_handler(handler: Py<PyAny>) {
    Python::attach(|py| {
        let bound = handler.bind(py);
        if let Ok(conn) = bound.cast::<PyConnection>() {
            conn.borrow_mut().invalidate();
        }
    });
}

/// Get the RLIMIT_NOFILE soft limit.
#[cfg(unix)]
fn get_fd_soft_limit() -> u64 {
    use nix::sys::resource::{getrlimit, Resource};
    match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok((soft, _hard)) => soft,
        Err(_) => 1024,
    }
}

#[cfg(not(unix))]
fn get_fd_soft_limit() -> u64 {
    1024
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::python::connection::PyConnection;
    use pyo3::types::PyModule;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    fn create_echo_factory(py: Python<'_>, module_name: &str) -> Py<PyAny> {
        register_test_module(py, module_name);
        let code = format!(
            "
from {module_name} import PyConnection
class EchoProtocol(PyConnection):
    def __init__(self, proto=None):
        super().__init__(proto)
    def handle_established(self):
        pass
    def handle_io_in(self, data):
        self.send(data)
        return len(data)
    def handle_disconnect(self):
        return False
factory = EchoProtocol('tcp')
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

    async fn start_listener(
        registry: &Arc<ConnectionRegistry>,
        limits: &Arc<ConnectionLimits>,
        factory: Py<PyAny>,
    ) -> TcpListenerHandle {
        tcp_listen(
            "127.0.0.1:0".parse().expect("addr"),
            registry.clone(),
            limits.clone(),
            factory,
            65536,
        )
        .await
        .expect("tcp_listen")
    }

    #[test]
    fn test_tcp_bind_succeeds() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let reg = Arc::new(ConnectionRegistry::new());
            let lim = Arc::new(ConnectionLimits::new(50, 10_000, 70));
            let factory = Python::attach(|py| create_echo_factory(py, "tcp_bind_t"));
            let handle = start_listener(&reg, &lim, factory).await;
            assert_ne!(handle.addr.port(), 0);
            handle.stop();
        });
    }

    #[test]
    fn test_tcp_echo_roundtrip() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let reg = Arc::new(ConnectionRegistry::new());
            let lim = Arc::new(ConnectionLimits::new(50, 10_000, 70));
            let factory = Python::attach(|py| create_echo_factory(py, "tcp_echo_t"));
            let handle = start_listener(&reg, &lim, factory).await;
            time::sleep(Duration::from_millis(50)).await;

            let mut client =
                tokio::net::TcpStream::connect(handle.addr).await.expect("connect");
            time::sleep(Duration::from_millis(100)).await;

            client.write_all(b"hello dionaea").await.expect("write");

            let mut resp = vec![0u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut resp))
                .await
                .expect("timeout")
                .expect("read");
            assert_eq!(&resp[..n], b"hello dionaea");
            assert!(reg.len() >= 1);

            drop(client);
            time::sleep(Duration::from_millis(100)).await;
            handle.stop();
        });
    }

    #[test]
    fn test_established_and_disconnect_fire() {
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
                register_test_module(py, "tcp_evt_t");
                py.run(c"
from tcp_evt_t import PyConnection
class EventProto(PyConnection):
    events = []
    def __init__(self, proto=None):
        super().__init__(proto)
    def handle_established(self):
        EventProto.events.append('established')
    def handle_io_in(self, data):
        return len(data)
    def handle_disconnect(self):
        EventProto.events.append('disconnect')
        return False
factory = EventProto('tcp')
", None, None).expect("define");
                let f = py.eval(c"factory", None, None).expect("f");
                { f.cast::<PyConnection>().expect("c").borrow_mut().id = Some(ConnectionId(0)); }
                f.unbind()
            });

            let handle = start_listener(&reg, &lim, factory).await;
            time::sleep(Duration::from_millis(50)).await;

            let client = tokio::net::TcpStream::connect(handle.addr).await.expect("connect");
            time::sleep(Duration::from_millis(200)).await;
            drop(client);
            time::sleep(Duration::from_millis(300)).await;

            Python::attach(|py| {
                let events: Vec<String> = py
                    .eval(c"EventProto.events", None, None)
                    .expect("events")
                    .extract()
                    .expect("extract");
                assert!(events.contains(&"established".to_string()));
                assert!(events.contains(&"disconnect".to_string()));
            });
            handle.stop();
        });
    }

    #[test]
    fn test_per_ip_limit_rejects() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let reg = Arc::new(ConnectionRegistry::new());
            let lim = Arc::new(ConnectionLimits::new(1, 10_000, 70));
            let factory = Python::attach(|py| create_echo_factory(py, "tcp_lim_t"));
            let handle = start_listener(&reg, &lim, factory).await;
            time::sleep(Duration::from_millis(50)).await;

            let _c1 = tokio::net::TcpStream::connect(handle.addr).await.expect("c1");
            time::sleep(Duration::from_millis(200)).await;
            let ip: std::net::IpAddr = "127.0.0.1".parse().expect("ip");
            assert_eq!(lim.ip_count(ip), 1);

            let _c2 = tokio::net::TcpStream::connect(handle.addr).await.expect("c2");
            time::sleep(Duration::from_millis(200)).await;
            assert_eq!(lim.ip_count(ip), 1); // Second rejected

            handle.stop();
        });
    }

    #[test]
    fn test_idle_timeout_fires() {
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
                register_test_module(py, "tcp_idle_t");
                py.run(c"
from tcp_idle_t import PyConnection
class IdleProto(PyConnection):
    idle_fired = False
    def __init__(self, proto=None):
        super().__init__(proto)
    def handle_established(self):
        self.timeouts.idle = 0.3  # short idle for test
    def handle_io_in(self, data):
        return len(data)
    def handle_timeout_idle(self):
        IdleProto.idle_fired = True
        return False
    def handle_disconnect(self):
        return False
factory = IdleProto('tcp')
", None, None).expect("define");
                let f = py.eval(c"factory", None, None).expect("f");
                { f.cast::<PyConnection>().expect("c").borrow_mut().id = Some(ConnectionId(0)); }
                f.unbind()
            });

            let handle = start_listener(&reg, &lim, factory).await;
            time::sleep(Duration::from_millis(50)).await;

            let _client = tokio::net::TcpStream::connect(handle.addr).await.expect("connect");
            // Wait for idle timeout (0.3s) + some margin
            time::sleep(Duration::from_millis(800)).await;

            Python::attach(|py| {
                let fired: bool = py
                    .eval(c"IdleProto.idle_fired", None, None)
                    .expect("fired")
                    .extract()
                    .expect("extract");
                assert!(fired, "handle_timeout_idle should have fired");
            });
            handle.stop();
        });
    }

    #[test]
    fn test_exception_in_io_in_closes() {
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
                register_test_module(py, "tcp_exc_t");
                py.run(c"
from tcp_exc_t import PyConnection
class FailProto(PyConnection):
    def __init__(self, proto=None):
        super().__init__(proto)
    def handle_established(self):
        pass
    def handle_io_in(self, data):
        raise RuntimeError('boom')
    def handle_disconnect(self):
        return False
factory = FailProto('tcp')
", None, None).expect("define");
                let f = py.eval(c"factory", None, None).expect("f");
                { f.cast::<PyConnection>().expect("c").borrow_mut().id = Some(ConnectionId(0)); }
                f.unbind()
            });

            let handle = start_listener(&reg, &lim, factory).await;
            time::sleep(Duration::from_millis(50)).await;

            let mut client = tokio::net::TcpStream::connect(handle.addr).await.expect("connect");
            time::sleep(Duration::from_millis(100)).await;

            client.write_all(b"trigger error").await.expect("write");
            time::sleep(Duration::from_millis(300)).await;

            // Connection should have been closed after the exception
            let ip: std::net::IpAddr = "127.0.0.1".parse().expect("ip");
            assert_eq!(lim.ip_count(ip), 0, "connection should be cleaned up");
            handle.stop();
        });
    }
}
