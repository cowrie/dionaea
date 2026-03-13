// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: TCP listener, accept loop, and per-connection I/O handler task.
// ABOUTME: Wires Python protocol callbacks to live sockets via spawn_blocking + GIL.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
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

/// What to do when a connection is rejected (limits exceeded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectStrategy {
    /// Drop immediately (TCP RST). Fast but attackers may detect it.
    Rst,
    /// Accept the connection, then hold it open silently until it times out.
    /// Looks like a slow/unresponsive service rather than a rate limit.
    AcceptSilence,
}

/// Configuration for connection rejection behavior.
#[derive(Debug, Clone)]
pub struct RejectConfig {
    /// Which strategy to use when rejecting connections.
    pub strategy: RejectStrategy,
    /// How long to hold silent connections open (seconds). Default: 30.
    pub silence_timeout_secs: f64,
    /// Maximum number of concurrent silent connections. Default: 100.
    pub silence_cap: usize,
}

impl Default for RejectConfig {
    fn default() -> Self {
        RejectConfig {
            strategy: RejectStrategy::AcceptSilence,
            silence_timeout_secs: 30.0,
            silence_cap: 100,
        }
    }
}

/// Tracks concurrent silent (rejected) connections.
#[derive(Debug)]
pub struct SilentConnectionTracker {
    /// Current number of active silent connections.
    active: AtomicUsize,
    /// Maximum allowed.
    cap: usize,
}

impl SilentConnectionTracker {
    /// Create a tracker with the given cap.
    pub fn new(cap: usize) -> Self {
        SilentConnectionTracker {
            active: AtomicUsize::new(0),
            cap,
        }
    }

    /// Try to acquire a slot. Returns true if under cap.
    pub fn try_acquire(&self) -> bool {
        self.active
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                if current < self.cap {
                    Some(current + 1)
                } else {
                    None
                }
            })
            .is_ok()
    }

    /// Release a slot.
    pub fn release(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }

    /// Current count.
    pub fn count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

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

    /// Get the abort handle for external tracking (e.g., shutdown manager).
    pub fn abort_handle(&self) -> tokio::task::AbortHandle {
        self.abort.clone()
    }
}

/// Opaque TLS acceptor for STARTTLS upgrades.
///
/// Type-erased so `tcp_listen` doesn't depend on the `tls` feature at the type
/// level. Wraps an `openssl::ssl::SslAcceptor` when the `tls` feature is enabled.
pub type StarttlsAcceptor = Arc<dyn std::any::Any + Send + Sync>;

/// Start a TCP listener on the given address.
///
/// `protocol_factory` is the Python connection (listener) used as a template
/// for factory-creating accepted child connections.
///
/// `starttls_acceptor` enables STARTTLS: if a protocol handler requests a TLS
/// upgrade mid-connection, this acceptor is used for the handshake.
pub async fn tcp_listen(
    addr: SocketAddr,
    registry: Arc<ConnectionRegistry>,
    limits: Arc<ConnectionLimits>,
    protocol_factory: Py<PyAny>,
    recv_buffer_size: usize,
    reject_config: RejectConfig,
    starttls_acceptor: Option<StarttlsAcceptor>,
) -> std::io::Result<TcpListenerHandle> {
    let listener = TcpListener::bind(addr).await?;
    let bound_addr = listener.local_addr()?;
    tracing::debug!(%bound_addr, "TCP listener bound");

    let silent_tracker = Arc::new(SilentConnectionTracker::new(reject_config.silence_cap));

    let task = tokio::spawn(accept_loop(
        listener,
        registry,
        limits,
        protocol_factory,
        recv_buffer_size,
        reject_config,
        silent_tracker,
        starttls_acceptor,
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
    reject_config: RejectConfig,
    silent_tracker: Arc<SilentConnectionTracker>,
    starttls_acceptor: Option<StarttlsAcceptor>,
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
            reject_connection(stream, &reject_config, &silent_tracker);
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

        tracing::debug!(connection_id = %id, %peer_addr, %local_addr, "accepted TCP connection");

        // Clone factory inside GIL scope (PyO3 0.28: Py::clone requires GIL)
        // This is an atomic incref (~1μs), safe to do briefly on a worker thread.
        let factory_clone = Python::attach(|py| protocol_factory.clone_ref(py));

        let reg = registry.clone();
        let lim = limits.clone();
        let starttls = starttls_acceptor.clone();

        tokio::spawn(async move {
            let handler_tx = tx.clone();
            let reg_for_factory = reg.clone();
            let lim_for_factory = lim.clone();
            let child_result = tokio::task::spawn_blocking(move || {
                Python::attach(|py| {
                    let parent = factory_clone.bind(py);
                    let child = factory_create(
                        py, &parent, id, handler_tx, "tcp",
                        Some(reg_for_factory), Some(lim_for_factory), recv_buffer_size,
                    )?;

                    // Set socket addresses and status on the child handler
                    if let Ok(conn) = child.bind(py).cast::<PyConnection>() {
                        let mut c = conn.borrow_mut();
                        c.remote.host = peer_addr.ip().to_string();
                        c.remote.port = peer_addr.port();
                        c.local.host = local_addr.ip().to_string();
                        c.local.port = local_addr.port();
                        c.status = "established".to_string();
                    }

                    PyResult::Ok(child)
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

            let (tcp_stream, h, rx, post, pipeline) =
                handle_connection(stream, handler, id, rx, reg.clone(), recv_buffer_size, "tcp", false, None).await;

            let h = handle_starttls_or_finish(
                post, tcp_stream, h, rx, id, reg.clone(), recv_buffer_size, &starttls, pipeline,
            ).await;
            let h = emit_connection_free(h).await;
            invalidate_handler(h);
            cleanup_connection(&reg, &lim, id, peer_ip);
        });
    }
}

/// Perform a mid-connection TLS upgrade (STARTTLS) if requested, or return the handler.
///
/// Called after `handle_connection` returns. If the post-callback is `StartTls` and
/// an SSL acceptor is available, wraps the TCP stream in TLS and re-enters the I/O
/// loop. Otherwise returns the handler as-is.
async fn handle_starttls_or_finish(
    post: PostCallback,
    tcp_stream: tokio::net::TcpStream,
    handler: Py<PyAny>,
    rx: mpsc::Receiver<SendMessage>,
    id: ConnectionId,
    registry: Arc<ConnectionRegistry>,
    recv_buffer_size: usize,
    starttls_acceptor: &Option<StarttlsAcceptor>,
    pipeline: Option<crate::processor::ProcessorPipeline>,
) -> Py<PyAny> {
    if post != PostCallback::StartTls {
        return handler;
    }

    #[cfg(not(feature = "tls"))]
    {
        tracing::warn!(connection_id = %id, "STARTTLS requested but TLS support not compiled");
        return handler;
    }

    #[cfg(feature = "tls")]
    {
        let acceptor = match starttls_acceptor {
            Some(ctx) => match ctx.downcast_ref::<openssl::ssl::SslAcceptor>() {
                Some(a) => a,
                None => {
                    tracing::error!(connection_id = %id, "STARTTLS context is not an SslAcceptor");
                    return handler;
                }
            },
            None => {
                tracing::warn!(connection_id = %id, "STARTTLS requested but no SSL acceptor configured");
                return handler;
            }
        };

        let ssl = match openssl::ssl::Ssl::new(acceptor.context()) {
            Ok(ssl) => ssl,
            Err(e) => {
                tracing::warn!(connection_id = %id, err = %e, "STARTTLS SSL object creation failed");
                return handler;
            }
        };

        let mut tls_stream = match tokio_openssl::SslStream::new(ssl, tcp_stream) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(connection_id = %id, err = %e, "STARTTLS stream creation failed");
                return handler;
            }
        };

        // Perform TLS handshake with timeout from registry
        let hs_timeout = get_timeout_secs(&registry, id, TimeoutKind::Handshake);
        let handshake_result = time::timeout(secs_to_duration(hs_timeout), async {
            std::pin::Pin::new(&mut tls_stream).accept().await
        })
        .await;

        match handshake_result {
            Ok(Ok(())) => {
                // Update transport in registry
                if let Some(mut meta) = registry.get_mut(id) {
                    meta.transport = Transport::Tls;
                    meta.state = ConnectionState::Established;
                }
                tracing::debug!(connection_id = %id, "STARTTLS handshake completed");

                let (_stream, h, _rx, _post, _pipeline) = handle_connection(
                    tls_stream, handler, id, rx, registry.clone(), recv_buffer_size, "tls", true,
                    pipeline,
                )
                .await;
                h
            }
            Ok(Err(e)) => {
                tracing::debug!(connection_id = %id, err = %e, "STARTTLS handshake failed");
                handler
            }
            Err(_) => {
                tracing::debug!(connection_id = %id, "STARTTLS handshake timed out");
                handler
            }
        }
    }
}

/// Async task for outbound TCP connections with reconnect support.
///
/// DNS-resolves the target, connects with a timeout, updates the Python handler's
/// address fields, then runs the standard I/O handler loop. If the Python handler
/// requests reconnection (returning True from `handle_disconnect` or `handle_error`),
/// the task sleeps for `timeouts.reconnect` seconds and tries again with a new socket.
pub async fn tcp_connect_task(
    mut handler: Py<PyAny>,
    id: ConnectionId,
    addr: String,
    port: u16,
    mut rx: mpsc::Receiver<SendMessage>,
    registry: Arc<ConnectionRegistry>,
    recv_buffer_size: usize,
) {
    loop {
        let connecting_timeout = get_timeout_secs(&registry, id, TimeoutKind::Connecting);
        let timeout_dur = secs_to_duration(connecting_timeout);

        let connect_result = time::timeout(timeout_dur, async {
            let addr_str = format!("{addr}:{port}");
            tokio::net::TcpStream::connect(&addr_str).await
        })
        .await;

        match connect_result {
            Ok(Ok(stream)) => {
                let peer_addr = stream.peer_addr().ok();
                let local_addr = stream.local_addr().ok();

                // Update registry metadata
                if let Some(mut meta) = registry.get_mut(id) {
                    if let Some(pa) = peer_addr {
                        meta.remote = crate::node_info::NodeInfo::from_socket_addr(pa);
                    }
                    if let Some(la) = local_addr {
                        meta.local = crate::node_info::NodeInfo::from_socket_addr(la);
                    }
                    meta.state = ConnectionState::Established;
                }

                // Update the Python handler's address fields before handle_established
                handler = {
                    let h = handler;
                    match tokio::task::spawn_blocking(move || {
                        Python::attach(|py| {
                            if let Ok(conn) = h.bind(py).cast::<PyConnection>() {
                                let mut c = conn.borrow_mut();
                                if let Some(pa) = peer_addr {
                                    c.remote.host = pa.ip().to_string();
                                    c.remote.port = pa.port();
                                }
                                if let Some(la) = local_addr {
                                    c.local.host = la.ip().to_string();
                                    c.local.port = la.port();
                                }
                                c.status = "established".to_string();
                            }
                            h
                        })
                    })
                    .await
                    {
                        Ok(h) => h,
                        Err(e) => {
                            tracing::error!(connection_id = %id, err = %e, "address update panicked");
                            break;
                        }
                    }
                };

                tracing::debug!(connection_id = %id, ?peer_addr, "outbound TCP connected");

                let post;
                let _stream;
                let _pipeline;
                (_stream, handler, rx, post, _pipeline) = handle_connection(
                    stream, handler, id, rx, registry.clone(), recv_buffer_size, "tcp", false, None,
                )
                .await;

                if post != PostCallback::Reconnect {
                    handler = emit_connection_free(handler).await;
                    invalidate_handler(handler);
                    break;
                }
            }
            Ok(Err(e)) => {
                tracing::debug!(connection_id = %id, err = %e, %addr, port, "outbound TCP connect failed");
                let post;
                (handler, post) = call_handle_error(handler, id, &format!("connect failed: {e}")).await;
                if post != PostCallback::Reconnect {
                    handler = emit_connection_free(handler).await;
                    invalidate_handler(handler);
                    break;
                }
            }
            Err(_) => {
                tracing::debug!(connection_id = %id, %addr, port, "outbound TCP connect timed out");
                let post;
                (handler, post) = call_handle_error(handler, id, "connect timed out").await;
                if post != PostCallback::Reconnect {
                    handler = emit_connection_free(handler).await;
                    invalidate_handler(handler);
                    break;
                }
            }
        }

        // Reconnect: read delay from handler's timeouts.reconnect, then retry
        let reconnect_delay = {
            let h = handler;
            match tokio::task::spawn_blocking(move || {
                Python::attach(|py| {
                    let delay = if let Ok(conn) = h.bind(py).cast::<PyConnection>() {
                        conn.borrow().timeouts.reconnect
                    } else {
                        5.0
                    };
                    (h, delay)
                })
            })
            .await
            {
                Ok((h, delay)) => {
                    handler = h;
                    delay
                }
                Err(e) => {
                    tracing::error!(connection_id = %id, err = %e, "reconnect delay read panicked");
                    break;
                }
            }
        };

        tracing::info!(
            connection_id = %id,
            delay_secs = reconnect_delay,
            %addr,
            port,
            "reconnecting"
        );
        time::sleep(secs_to_duration(reconnect_delay)).await;

        // Reset connection state for the next attempt
        if let Some(mut meta) = registry.get_mut(id) {
            meta.state = ConnectionState::Connecting;
        }
    }

    registry.remove(id);
}

/// Call `handle_error` on the Python handler via spawn_blocking.
///
/// Returns the handler and post-callback so the reconnect loop can decide
/// whether to retry or give up.
async fn call_handle_error(
    handler: Py<PyAny>,
    id: ConnectionId,
    msg: &str,
) -> (Py<PyAny>, PostCallback) {
    let err_msg = msg.to_string();
    match tokio::task::spawn_blocking(move || {
        Python::attach(|py| {
            let err = pyo3::exceptions::PyOSError::new_err(err_msg);
            let post = callback::call_handle_error(handler.bind(py), &err.value(py).to_string());
            (handler, post)
        })
    })
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(connection_id = %id, err = %e, "handle_error panicked");
            let h = Python::attach(|py| py.None().into());
            (h, PostCallback::Close)
        }
    }
}

/// Per-connection I/O handler task.
///
/// Runs a `select!` loop reading from the socket and the send channel.
/// Python callbacks are invoked via `spawn_blocking` + GIL.
/// Sequential callback guarantee: each callback completes before the next I/O event.
///
/// Generic over the stream type so it works with both plain TCP and TLS.
///
/// Returns `(stream, handler, rx, post_callback)` so that callers can reuse
/// the Python handler and channel across reconnections or TLS upgrades.
///
/// When `skip_established` is true (e.g. after STARTTLS), the accept incident
/// and `handle_established` callback are not fired (the connection is already live).
#[allow(clippy::too_many_lines)]
pub(crate) async fn handle_connection<S>(
    mut stream: S,
    handler: Py<PyAny>,
    id: ConnectionId,
    mut rx: mpsc::Receiver<SendMessage>,
    registry: Arc<ConnectionRegistry>,
    recv_buffer_size: usize,
    transport: &str,
    skip_established: bool,
    initial_pipeline: Option<crate::processor::ProcessorPipeline>,
) -> (S, Py<PyAny>, mpsc::Receiver<SendMessage>, PostCallback, Option<crate::processor::ProcessorPipeline>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Cap on partial_buf to prevent memory exhaustion from slow protocol handlers.
    const MAX_PARTIAL_BUF: usize = 10 * 1024 * 1024; // 10 MB

    let mut buf = BytesMut::zeroed(recv_buffer_size);
    let mut partial_buf: Vec<u8> = Vec::new();
    let mut processor_pipeline = initial_pipeline;

    let mut in_throttle = Throttle::unlimited();
    let mut out_throttle = Throttle::unlimited();
    let mut in_accounting = Accounting::unlimited();
    let mut out_accounting = Accounting::unlimited();

    // Helper: return tuple for error exits where handler was lost (panics).
    macro_rules! error_exit {
        ($stream:expr, $rx:expr) => {{
            let h = Python::attach(|py| py.None().into());
            return ($stream, h, $rx, PostCallback::Close, None);
        }};
    }

    // Emit connection accept/connect incident and call handle_established
    // (skipped after STARTTLS — the connection is already live)
    let mut handler = if skip_established {
        handler
    } else {
        let transport_str = transport.to_string();
        let h = handler;
        let post = tokio::task::spawn_blocking(move || {
            Python::attach(|py| {
                let accept_origin = format!("dionaea.connection.{transport_str}.accept");
                callback::emit_connection_incident(py, h.bind(py), &accept_origin);
                let result = callback::call_handle_established(h.bind(py));
                (h, result)
            })
        })
        .await;

        match post {
            Ok((h, PostCallback::Continue)) => h,
            Ok((h, _)) => {
                let (h, _post) = call_disconnect(h, id).await;
                return (stream, h, rx, PostCallback::Close, processor_pipeline);
            }
            Err(e) => {
                tracing::error!(connection_id = %id, err = %e, "handle_established panicked");
                error_exit!(stream, rx);
            }
        }
    };

    if !skip_established {
        // Drain any control messages sent during handle_established
        // (Python protocol may set timeouts, send welcome banners, or attach processors)
        let (pending_data, drained_pipeline) = drain_control_messages(
            &mut rx,
            &registry,
            id,
            &mut in_throttle,
            &mut out_throttle,
            &mut in_accounting,
            &mut out_accounting,
        );
        if drained_pipeline.is_some() {
            processor_pipeline = drained_pipeline;
        }

        // Flush any data sent during handle_established (e.g. welcome banners)
        for data in pending_data {
            if let Err(e) = stream.write_all(&data).await {
                tracing::debug!(connection_id = %id, err = %e, "write error flushing established data");
                let (h, _post) = call_disconnect(handler, id).await;
                return (stream, h, rx, PostCallback::Close, processor_pipeline);
            }
            if let Some(mut meta) = registry.get_mut(id) {
                meta.stats.bytes_out += data.len() as u64;
            }
        }
    }

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
                        tracing::debug!(connection_id = %id, "peer closed connection");
                        let (h, post) = call_disconnect(handler, id).await;
                        return (stream, h, rx, post, processor_pipeline);
                    }
                    Ok(n) => {
                        // Reset idle timeout on data
                        let secs = get_timeout_secs(&registry, id, TimeoutKind::Idle);
                        idle_timeout.as_mut().reset(Instant::now() + secs_to_duration(secs));

                        let _ = in_throttle.try_consume(n);

                        if in_accounting.add(n as u64) {
                            tracing::debug!(connection_id = %id, "accounting limit, closing");
                            let (h, post) = call_disconnect(handler, id).await;
                            return (stream, h, rx, post, processor_pipeline);
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

                        if let Some(ref mut pipeline) = processor_pipeline {
                            pipeline.io_in(&data);
                        }

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
                                    let remaining = io_data.len() - consumed;
                                    if remaining > MAX_PARTIAL_BUF {
                                        tracing::warn!(connection_id = %id, remaining, "partial buffer exceeded limit, closing");
                                        let (h, post) = call_disconnect(handler, id).await;
                                        return (stream, h, rx, post, processor_pipeline);
                                    }
                                    partial_buf = io_data[consumed..].to_vec();
                                }
                            }
                            Ok((h, _, _, _)) => {
                                let (h, _post) = call_disconnect(h, id).await;
                                return (stream, h, rx, PostCallback::Close, processor_pipeline);
                            }
                            Err(e) => {
                                tracing::error!(connection_id = %id, err = %e, "io_in panicked");
                                error_exit!(stream, rx);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(connection_id = %id, err = %e, "TCP read error");
                        let (h, post) = call_disconnect(handler, id).await;
                        return (stream, h, rx, post, processor_pipeline);
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
                            let (h, post) = call_disconnect(handler, id).await;
                            return (stream, h, rx, post, processor_pipeline);
                        }

                        if let Err(e) = stream.write_all(&data).await {
                            tracing::debug!(connection_id = %id, err = %e, "TCP write error");
                            let (h, post) = call_disconnect(handler, id).await;
                            return (stream, h, rx, post, processor_pipeline);
                        }

                        if let Some(mut meta) = registry.get_mut(id) {
                            meta.stats.bytes_out += data.len() as u64;
                        }

                        if let Some(ref mut pipeline) = processor_pipeline {
                            pipeline.io_out(&data);
                        }

                        // Notify Python that data was written (enables chunked transfers).
                        // handle_io_out may call self.send() to queue more data.
                        let h = handler;
                        let post = tokio::task::spawn_blocking(move || {
                            Python::attach(|py| {
                                let result = callback::call_handle_io_out(h.bind(py));
                                (h, result)
                            })
                        })
                        .await;

                        match post {
                            Ok((h, PostCallback::Continue)) => {
                                handler = h;
                            }
                            Ok((h, _)) => {
                                let (h, _post) = call_disconnect(h, id).await;
                                return (stream, h, rx, PostCallback::Close, processor_pipeline);
                            }
                            Err(e) => {
                                tracing::error!(connection_id = %id, err = %e, "io_out panicked");
                                error_exit!(stream, rx);
                            }
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
                    Some(SendMessage::AttachProcessors(pipeline)) => {
                        processor_pipeline = Some(pipeline);
                    }
                    Some(SendMessage::StartTls) => {
                        tracing::debug!(connection_id = %id, "STARTTLS requested");
                        // Flush any pending writes before handing stream to TLS
                        if let Err(e) = stream.flush().await {
                            tracing::warn!(connection_id = %id, err = %e, "flush before STARTTLS failed");
                            let (h, post) = call_disconnect(handler, id).await;
                            return (stream, h, rx, post, processor_pipeline);
                        }
                        return (stream, handler, rx, PostCallback::StartTls, processor_pipeline);
                    }
                    Some(SendMessage::Close) => {
                        tracing::debug!(connection_id = %id, "close requested");
                        let (h, post) = call_disconnect(handler, id).await;
                        return (stream, h, rx, post, processor_pipeline);
                    }
                    None => {
                        tracing::debug!(connection_id = %id, "send channel closed");
                        let (h, post) = call_disconnect(handler, id).await;
                        return (stream, h, rx, post, processor_pipeline);
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
                        let (h, _post) = call_disconnect(h, id).await;
                        return (stream, h, rx, PostCallback::Close, processor_pipeline);
                    }
                    Err(e) => {
                        tracing::error!(connection_id = %id, err = %e, "timeout_idle panicked");
                        error_exit!(stream, rx);
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
                        let (h, _post) = call_disconnect(h, id).await;
                        return (stream, h, rx, PostCallback::Close, processor_pipeline);
                    }
                    Err(e) => {
                        tracing::error!(connection_id = %id, err = %e, "timeout_sustain panicked");
                        error_exit!(stream, rx);
                    }
                }
            }
        }
    }
}

/// Drain pending control messages from the channel (non-blocking).
/// Called after handle_established to pick up timeouts set by the protocol.
/// Drain pending control messages from the channel.
///
/// Returns any Data messages (e.g. welcome banners) and an optional
/// processor pipeline if `processors()` was called during handle_established.
fn drain_control_messages(
    rx: &mut mpsc::Receiver<SendMessage>,
    registry: &ConnectionRegistry,
    id: ConnectionId,
    in_throttle: &mut Throttle,
    out_throttle: &mut Throttle,
    in_accounting: &mut Accounting,
    out_accounting: &mut Accounting,
) -> (Vec<Bytes>, Option<crate::processor::ProcessorPipeline>) {
    let mut pending_data = Vec::new();
    let mut pipeline = None;
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
            SendMessage::Data(data) => pending_data.push(data),
            SendMessage::Datagram { .. } => {}
            SendMessage::AttachProcessors(p) => {
                pipeline = Some(p);
            }
            SendMessage::StartTls | SendMessage::Close => {
                // Will be handled after pending data is flushed
                break;
            }
        }
    }
    (pending_data, pipeline)
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

/// Call handle_disconnect via spawn_blocking, returning the handler and post-callback.
///
/// Does NOT emit `dionaea.connection.free` — the caller decides when to emit it
/// (accept-type connections always emit; connect-type only on final close).
async fn call_disconnect(handler: Py<PyAny>, id: ConnectionId) -> (Py<PyAny>, PostCallback) {
    match tokio::task::spawn_blocking(move || {
        Python::attach(|py| {
            let post = callback::call_handle_disconnect(handler.bind(py));
            (handler, post)
        })
    })
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(connection_id = %id, err = %e, "handle_disconnect panicked");
            let h = Python::attach(|py| py.None().into());
            (h, PostCallback::Close)
        }
    }
}

/// Emit `dionaea.connection.free` via spawn_blocking.
pub(crate) async fn emit_connection_free(handler: Py<PyAny>) -> Py<PyAny> {
    match tokio::task::spawn_blocking(move || {
        Python::attach(|py| {
            callback::emit_connection_incident(py, handler.bind(py), "dionaea.connection.free");
            handler
        })
    })
    .await
    {
        Ok(h) => h,
        Err(_) => Python::attach(|py| py.None().into()),
    }
}

/// Get timeout seconds from the registry.
pub(crate) fn get_timeout_secs(registry: &ConnectionRegistry, id: ConnectionId, kind: TimeoutKind) -> f64 {
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
pub(crate) fn secs_to_duration(secs: f64) -> Duration {
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
pub(crate) fn cleanup_connection(
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
    tracing::debug!(connection_id = %id, %peer_ip, "connection cleaned up");
}

/// Invalidate the Python handler (set id to None, drop channel).
pub(crate) fn invalidate_handler(handler: Py<PyAny>) {
    Python::attach(|py| {
        let bound = handler.bind(py);
        if let Ok(conn) = bound.cast::<PyConnection>() {
            conn.borrow_mut().invalidate();
        }
    });
}

/// Apply the configured rejection strategy to a connection that failed limit checks.
pub(crate) fn reject_connection(
    stream: tokio::net::TcpStream,
    config: &RejectConfig,
    tracker: &Arc<SilentConnectionTracker>,
) {
    match config.strategy {
        RejectStrategy::Rst => {
            drop(stream);
        }
        RejectStrategy::AcceptSilence => {
            if tracker.try_acquire() {
                let tracker = tracker.clone();
                let timeout = config.silence_timeout_secs;
                tokio::spawn(async move {
                    time::sleep(secs_to_duration(timeout)).await;
                    drop(stream);
                    tracker.release();
                });
            } else {
                // Silent cap reached, fall back to RST
                drop(stream);
            }
        }
    }
}

/// Get the RLIMIT_NOFILE soft limit.
#[cfg(unix)]
pub(crate) fn get_fd_soft_limit() -> u64 {
    use nix::sys::resource::{getrlimit, Resource};
    match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok((soft, _hard)) => soft,
        Err(_) => 1024,
    }
}

#[cfg(not(unix))]
pub(crate) fn get_fd_soft_limit() -> u64 {
    1024
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::python::connection::PyConnection;
    use pyo3::types::{PyBytes, PyModule};
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
from {module_name} import connection as PyConnection
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
            RejectConfig::default(),
            None,
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
from tcp_evt_t import connection as PyConnection
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
from tcp_idle_t import connection as PyConnection
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
from tcp_exc_t import connection as PyConnection
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

    #[test]
    fn test_tcp_outbound_connect() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let reg = Arc::new(ConnectionRegistry::new());
            let lim = Arc::new(ConnectionLimits::new(50, 10_000, 70));

            // Start a simple echo TCP server
            let echo_server = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind echo server");
            let echo_addr = echo_server.local_addr().expect("echo addr");

            tokio::spawn(async move {
                if let Ok((mut stream, _)) = echo_server.accept().await {
                    let mut buf = [0u8; 1024];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                stream.write_all(&buf[..n]).await.ok();
                            }
                            Err(_) => break,
                        }
                    }
                }
            });

            // Create a Python protocol with connect context
            let proto = Python::attach(|py| {
                register_test_module(py, "tcp_outconn_t");
                py.run(
                    c"
from tcp_outconn_t import connection as PyConnection
class OutProto(PyConnection):
    events = []
    def __init__(self, proto=None):
        super().__init__(proto)
    def handle_established(self):
        OutProto.events.append('established')
    def handle_io_in(self, data):
        OutProto.events.append(('io_in', bytes(data)))
        return len(data)
    def handle_disconnect(self):
        OutProto.events.append('disconnect')
        return False
    def handle_error(self, err):
        OutProto.events.append(('error', str(err)))
proto = OutProto('tcp')
",
                    None,
                    None,
                )
                .expect("define");

                let proto = py.eval(c"proto", None, None).expect("proto");
                {
                    let mut c = proto
                        .cast::<PyConnection>()
                        .expect("cast")
                        .borrow_mut();
                    c.registry = Some(reg.clone());
                    c.limits = Some(lim.clone());
                    c.recv_buffer_size = 65536;
                }

                // Call connect
                proto
                    .call_method1(
                        "connect",
                        (echo_addr.ip().to_string(), echo_addr.port()),
                    )
                    .expect("connect");

                proto.unbind()
            });

            // Wait for async connect + handle_established
            time::sleep(Duration::from_millis(500)).await;

            // Verify handle_established fired
            Python::attach(|py| {
                let events: Vec<String> = py
                    .eval(
                        c"[e if isinstance(e, str) else '' for e in OutProto.events]",
                        None,
                        None,
                    )
                    .expect("events")
                    .extract()
                    .expect("extract");
                assert!(
                    events.contains(&"established".to_string()),
                    "expected 'established' in events, got {events:?}"
                );
            });

            // Send data through the connection
            Python::attach(|py| {
                let p = proto.bind(py);
                p.call_method1("send", (PyBytes::new(py, b"hello outbound"),))
                    .expect("send");
            });

            // Wait for echo
            time::sleep(Duration::from_millis(300)).await;

            // Verify io_in received the echo
            Python::attach(|py| {
                let event_count: usize = py
                    .eval(c"len(OutProto.events)", None, None)
                    .expect("len")
                    .extract()
                    .expect("extract");
                assert!(
                    event_count >= 2,
                    "expected at least 2 events (established + io_in), got {event_count}"
                );
                // Check the io_in data
                let io_data: Vec<u8> = py
                    .eval(
                        c"next(d for e in OutProto.events if isinstance(e, tuple) for t, d in [e] if t == 'io_in')",
                        None,
                        None,
                    )
                    .expect("io_in data")
                    .extract()
                    .expect("extract");
                assert_eq!(io_data, b"hello outbound");
            });

            // Close and verify disconnect
            Python::attach(|py| {
                proto.bind(py).call_method0("close").expect("close");
            });
            time::sleep(Duration::from_millis(300)).await;

            Python::attach(|py| {
                let events: Vec<String> = py
                    .eval(
                        c"[e if isinstance(e, str) else '' for e in OutProto.events]",
                        None,
                        None,
                    )
                    .expect("events")
                    .extract()
                    .expect("extract");
                assert!(
                    events.contains(&"disconnect".to_string()),
                    "expected 'disconnect' in events, got {events:?}"
                );
            });
        });
    }

    #[test]
    fn test_tcp_connect_failure_calls_handle_error() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let reg = Arc::new(ConnectionRegistry::new());
            let lim = Arc::new(ConnectionLimits::new(50, 10_000, 70));

            Python::attach(|py| {
                register_test_module(py, "tcp_cfail_t");
                py.run(
                    c"
from tcp_cfail_t import connection as PyConnection
class FailProto(PyConnection):
    events = []
    def __init__(self, proto=None):
        super().__init__(proto)
    def handle_established(self):
        FailProto.events.append('established')
    def handle_error(self, err):
        FailProto.events.append(('error', str(err)))
    def handle_disconnect(self):
        FailProto.events.append('disconnect')
        return False
proto = FailProto('tcp')
",
                    None,
                    None,
                )
                .expect("define");

                let proto = py.eval(c"proto", None, None).expect("proto");
                {
                    let mut c = proto
                        .cast::<PyConnection>()
                        .expect("cast")
                        .borrow_mut();
                    c.registry = Some(reg.clone());
                    c.limits = Some(lim.clone());
                    c.recv_buffer_size = 65536;
                }

                // Connect to a port that nothing is listening on
                proto
                    .call_method1("connect", ("127.0.0.1", 1u16))
                    .expect("connect");
            });

            // Wait for the connect attempt to fail
            time::sleep(Duration::from_millis(500)).await;

            Python::attach(|py| {
                let has_error: bool = py
                    .eval(
                        c"any(isinstance(e, tuple) and e[0] == 'error' for e in FailProto.events)",
                        None,
                        None,
                    )
                    .expect("check")
                    .extract()
                    .expect("extract");
                assert!(has_error, "expected handle_error to be called");

                let no_established: bool = py
                    .eval(
                        c"'established' not in FailProto.events",
                        None,
                        None,
                    )
                    .expect("check")
                    .extract()
                    .expect("extract");
                assert!(no_established, "handle_established should NOT fire on failure");
            });

            // Registry should be cleaned up
            assert_eq!(reg.len(), 0, "connection should be removed from registry");
        });
    }

    #[test]
    fn test_tcp_connect_timeout_calls_handle_error() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let reg = Arc::new(ConnectionRegistry::new());
            let lim = Arc::new(ConnectionLimits::new(50, 10_000, 70));

            Python::attach(|py| {
                register_test_module(py, "tcp_ctmo_t");
                py.run(
                    c"
from tcp_ctmo_t import connection as PyConnection
class TmoProto(PyConnection):
    events = []
    def __init__(self, proto=None):
        super().__init__(proto)
    def handle_established(self):
        TmoProto.events.append('established')
    def handle_error(self, err):
        TmoProto.events.append(('error', str(err)))
    def handle_disconnect(self):
        TmoProto.events.append('disconnect')
        return False
proto = TmoProto('tcp')
",
                    None,
                    None,
                )
                .expect("define");

                let proto = py.eval(c"proto", None, None).expect("proto");
                {
                    let mut c = proto
                        .cast::<PyConnection>()
                        .expect("cast")
                        .borrow_mut();
                    c.registry = Some(reg.clone());
                    c.limits = Some(lim.clone());
                    c.recv_buffer_size = 65536;
                    // Short connecting timeout (generous enough for GIL contention)
                    c.timeouts.connecting = 0.3;
                }

                // Connect to a non-routable address (will hang until timeout)
                proto
                    .call_method1("connect", ("192.0.2.1", 9999u16))
                    .expect("connect");
            });

            // Timeout is propagated from Python object → registry by connect()
            // Wait for timeout (0.3s + margin for GIL contention under parallel load)
            time::sleep(Duration::from_millis(1500)).await;

            Python::attach(|py| {
                let has_error: bool = py
                    .eval(
                        c"any(isinstance(e, tuple) and e[0] == 'error' for e in TmoProto.events)",
                        None,
                        None,
                    )
                    .expect("check")
                    .extract()
                    .expect("extract");
                assert!(has_error, "expected handle_error on timeout");

                // Check the error message mentions timeout
                let err_msg: String = py
                    .eval(
                        c"next(e[1] for e in TmoProto.events if isinstance(e, tuple) and e[0] == 'error')",
                        None,
                        None,
                    )
                    .expect("msg")
                    .extract()
                    .expect("extract");
                assert!(
                    err_msg.contains("timed out"),
                    "error should mention timeout, got: {err_msg}"
                );
            });

            assert_eq!(reg.len(), 0, "connection should be removed from registry");
        });
    }

    #[test]
    fn test_silent_tracker_cap() {
        let tracker = SilentConnectionTracker::new(2);
        assert_eq!(tracker.count(), 0);

        assert!(tracker.try_acquire(), "first acquire under cap");
        assert_eq!(tracker.count(), 1);

        assert!(tracker.try_acquire(), "second acquire at cap-1");
        assert_eq!(tracker.count(), 2);

        assert!(!tracker.try_acquire(), "third acquire should fail at cap");
        assert_eq!(tracker.count(), 2);

        tracker.release();
        assert_eq!(tracker.count(), 1);

        assert!(tracker.try_acquire(), "should succeed after release");
        assert_eq!(tracker.count(), 2);
    }

    #[test]
    fn test_accept_silence_holds_connection() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let reg = Arc::new(ConnectionRegistry::new());
            // Per-IP limit of 1 so the second connection gets rejected
            let lim = Arc::new(ConnectionLimits::new(1, 10_000, 70));
            let factory = Python::attach(|py| create_echo_factory(py, "tcp_silence_t"));

            let reject_cfg = RejectConfig {
                strategy: RejectStrategy::AcceptSilence,
                silence_timeout_secs: 0.5,
                silence_cap: 10,
            };
            let handle = tcp_listen(
                "127.0.0.1:0".parse().expect("addr"),
                reg.clone(),
                lim.clone(),
                factory,
                65536,
                reject_cfg,
                None,
            )
            .await
            .expect("tcp_listen");

            time::sleep(Duration::from_millis(50)).await;

            // First connection is accepted normally
            let _c1 = tokio::net::TcpStream::connect(handle.addr).await.expect("c1");
            time::sleep(Duration::from_millis(200)).await;

            // Second connection exceeds per-IP limit → rejected via silence
            let mut c2 = tokio::net::TcpStream::connect(handle.addr).await.expect("c2");
            time::sleep(Duration::from_millis(100)).await;

            // c2 should still be "connected" (TCP-level) — it was accepted then held open
            // Try writing to it - should succeed since the socket is open
            let write_result = c2.write_all(b"test").await;
            assert!(write_result.is_ok(), "silent connection should still be open");

            // Wait for the silence timeout (0.5s + margin)
            time::sleep(Duration::from_millis(700)).await;

            // Now the silent connection should be dropped — reads should return EOF or error
            let mut buf = [0u8; 16];
            let read_result = tokio::time::timeout(
                Duration::from_millis(500),
                c2.read(&mut buf),
            )
            .await;
            match read_result {
                Ok(Ok(0)) => {} // EOF — expected
                Ok(Err(_)) => {} // connection reset — also acceptable
                other => panic!("expected EOF or error after silence timeout, got {other:?}"),
            }

            handle.stop();
        });
    }

    #[test]
    fn test_silent_cap_fallback_to_rst() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let reg = Arc::new(ConnectionRegistry::new());
            // Per-IP limit of 1 → second+ connections rejected
            let lim = Arc::new(ConnectionLimits::new(1, 10_000, 70));
            let factory = Python::attach(|py| create_echo_factory(py, "tcp_silcap_t"));

            // Cap of 1 silent connection, long timeout so it won't expire during test
            let reject_cfg = RejectConfig {
                strategy: RejectStrategy::AcceptSilence,
                silence_timeout_secs: 30.0,
                silence_cap: 1,
            };
            let handle = tcp_listen(
                "127.0.0.1:0".parse().expect("addr"),
                reg.clone(),
                lim.clone(),
                factory,
                65536,
                reject_cfg,
                None,
            )
            .await
            .expect("tcp_listen");

            time::sleep(Duration::from_millis(50)).await;

            // c1: accepted normally
            let _c1 = tokio::net::TcpStream::connect(handle.addr).await.expect("c1");
            time::sleep(Duration::from_millis(200)).await;

            // c2: rejected → held silent (fills cap=1)
            let _c2 = tokio::net::TcpStream::connect(handle.addr).await.expect("c2");
            time::sleep(Duration::from_millis(100)).await;

            // c3: rejected → cap full, falls back to RST (drop)
            let mut c3 = tokio::net::TcpStream::connect(handle.addr).await.expect("c3");
            time::sleep(Duration::from_millis(100)).await;

            // c3 should be closed quickly (RST fallback) — read returns EOF or error
            let mut buf = [0u8; 16];
            let read_result = tokio::time::timeout(
                Duration::from_millis(500),
                c3.read(&mut buf),
            )
            .await;
            match read_result {
                Ok(Ok(0)) => {} // EOF
                Ok(Err(_)) => {} // connection reset
                other => panic!("expected RST-like close for c3 (cap exceeded), got {other:?}"),
            }

            handle.stop();
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_starttls_upgrade() {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
        use std::io::{Read, Write};

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let reg = Arc::new(ConnectionRegistry::new());
            let lim = Arc::new(ConnectionLimits::new(50, 10_000, 70));

            // Create a protocol that upgrades to TLS on command
            let factory = Python::attach(|py| {
                register_test_module(py, "tcp_starttls_t");
                py.run(c"
from tcp_starttls_t import connection as PyConnection
class StarttlsProto(PyConnection):
    events = []
    def __init__(self, proto=None):
        super().__init__(proto)
        self._upgrading = False
    def handle_established(self):
        self.send(b'READY\\n')
    def handle_io_in(self, data):
        if data == b'STARTTLS\\n':
            self.send(b'OK\\n')
            self.start_tls()
            return len(data)
        # After TLS: echo
        self.send(data)
        StarttlsProto.events.append(('echo', bytes(data)))
        return len(data)
    def handle_disconnect(self):
        StarttlsProto.events.append('disconnect')
        return False
factory = StarttlsProto('tcp')
", None, None).expect("define");
                let f = py.eval(c"factory", None, None).expect("f");
                { f.cast::<PyConnection>().expect("c").borrow_mut().id = Some(ConnectionId(0)); }
                f.unbind()
            });

            // Create SSL acceptor for STARTTLS
            let tls_config = crate::connection::tls::TlsConfig::default();
            let (pkey, cert) = crate::connection::tls::generate_self_signed_cert(&tls_config)
                .expect("cert gen");
            let acceptor = crate::connection::tls::build_ssl_acceptor(&pkey, &cert, None)
                .expect("acceptor");
            let starttls_ctx: StarttlsAcceptor = Arc::new(acceptor);

            let handle = tcp_listen(
                "127.0.0.1:0".parse().expect("addr"),
                reg.clone(),
                lim.clone(),
                factory,
                65536,
                RejectConfig::default(),
                Some(starttls_ctx),
            )
            .await
            .expect("tcp_listen");
            time::sleep(Duration::from_millis(50)).await;

            // Phase 1: plain TCP
            let tcp_stream = std::net::TcpStream::connect(handle.addr).expect("connect");
            tcp_stream.set_nonblocking(false).expect("blocking");
            tcp_stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok();

            // Read "READY\n"
            let mut buf = [0u8; 64];
            let n = (&tcp_stream).read(&mut buf).expect("read ready");
            assert_eq!(&buf[..n], b"READY\n");

            // Send STARTTLS command
            (&tcp_stream).write_all(b"STARTTLS\n").expect("write starttls");

            // Read "OK\n"
            let n = (&tcp_stream).read(&mut buf).expect("read ok");
            assert_eq!(&buf[..n], b"OK\n");

            // Phase 2: TLS upgrade (client side)
            let mut ssl_connector = SslConnector::builder(SslMethod::tls()).expect("connector");
            ssl_connector.set_verify(SslVerifyMode::NONE);
            let connector = ssl_connector.build();
            let mut tls_stream = connector
                .connect("localhost", tcp_stream)
                .expect("tls connect");

            // Send data over TLS
            tls_stream.write_all(b"hello tls").expect("tls write");
            tls_stream.flush().expect("tls flush");

            // Read echo over TLS
            let n = tls_stream.read(&mut buf).expect("tls read");
            assert_eq!(&buf[..n], b"hello tls");

            // Verify echo event was recorded
            Python::attach(|py| {
                let has_echo: bool = py
                    .eval(
                        c"any(isinstance(e, tuple) and e[0] == 'echo' and e[1] == b'hello tls' for e in StarttlsProto.events)",
                        None,
                        None,
                    )
                    .expect("check")
                    .extract()
                    .expect("extract");
                assert!(has_echo, "expected echo event with TLS data");
            });

            drop(tls_stream);
            time::sleep(Duration::from_millis(200)).await;
            handle.stop();
        });
    }
}
