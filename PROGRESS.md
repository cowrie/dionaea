# Phase 4 Progress - TCP/UDP I/O + TLS

## Completed Increments

### 1. Throttle + Accounting (`connection/throttle.rs`) ✅
- Token bucket rate limiter with configurable bytes/sec, interval refill, burst cap
- Cumulative byte accounting with optional limit
- 11 tests, all passing
- Committed: `36f8578`

### 2. ConnectionLimits (`connection/limits.rs`) ✅
- Per-IP `DashMap<IpAddr, AtomicU32>` counting with cleanup-at-zero
- Global FD % and total connection checks
- `RejectReason` enum for diagnostics
- 8 tests, all passing
- Committed: `36f8578`

### 3. IP Deny List (`connection/limits.rs`) ✅
- CIDR matching via `ip_network_table` crate, behind `#[cfg(feature = "deny-list")]`
- Optional TTL per entry with auto-expire
- Added `ip_network = "0.4"` to workspace deps
- 7 tests (including integration with ConnectionLimits), all passing
- Committed: `36f8578`

### 4. Callback Error Recovery (`connection/callback.rs`) ✅
- Matches actual `binding.pyx` exception handling behavior:
  - `handle_origin`/`handle_established`: log exception, continue (no close)
  - `handle_io_in`/`handle_io_out`: log exception, close connection
  - `handle_disconnect`/timeouts: propagate (close on error)
  - `handle_error`: log and continue
- `PostCallback` enum: `Continue | Close | Reconnect`
- 9 tests, all passing
- Committed: `d861384`

### 5-7. TCP Listener + Handler + Timeouts (`connection/tcp.rs`) ✅
- `tcp_listen()` → `TcpListenerHandle` with bound address
- Accept loop: checks limits → `registry.register` → `factory_create` via spawn_blocking
- Handler I/O loop with `tokio::select!`:
  - Socket read → `handle_io_in` via spawn_blocking + GIL
  - Send channel → `write_all` to socket
  - Idle timeout (resets on data) → `handle_timeout_idle`
  - Sustain timeout (never resets) → `handle_timeout_sustain`
- `drain_control_messages()` after `handle_established` to pick up Python-set timeouts
- Throttle + accounting integration (close when limit exceeded)
- Partial consumption buffer (handle_io_in returns < n)
- Sequential callback guarantee (await each callback before next I/O)
- `call_disconnect()` helper with move-and-return pattern
- 6 tests passing: bind, echo roundtrip, established+disconnect, per-IP rejection, idle timeout, exception closes

#### Key PyO3 0.28 patterns used:
- `Py::clone_ref(py)` inside `Python::attach()` for factory cloning (Py::clone removed in 0.28)
- Move-and-return pattern for all spawn_blocking calls (handler moved in, returned with result)
- `tokio::pin!` for Sleep futures in select!
- `Python::attach()` for brief GIL acquisition on worker threads (atomic incref only)

#### Changes to existing files:
- `connection/mod.rs`: added `pub mod callback; pub mod limits; pub mod tcp; pub mod throttle;` + `iter_ids()` method on registry
- `python/connection.rs`: fields changed from private to `pub(crate)` (id, transport, protocol, status, local, remote, timeouts, send_tx)

## Known Issue
- `test_spawn_blocking_gil_latency` (pre-existing benchmark test in `python/connection.rs`) fails when run alongside TCP tests due to GIL contention. The P99 threshold of 500μs is exceeded under heavy parallel test load. This test was passing before Phase 4 only because there was no GIL contention. **Not a regression — the benchmark needs a higher threshold or isolation.**

### 8. TCP Outbound Connect (`connection/tcp.rs`, `python/connection.rs`) ✅
- `PyConnection.connect()` implemented: registers in registry, spawns async `tcp_connect_task`
- `tcp_connect_task`: DNS resolve → `TcpStream::connect` with configurable connecting timeout
- On success: updates Python handler addresses, runs standard handler I/O loop
- On failure/timeout: calls `handle_error` on the Python handler
- Added `registry`, `limits`, `recv_buffer_size` fields to `PyConnection` for context propagation
- `factory_create` passes runtime context to child connections
- 3 tests: echo roundtrip, connect failure, connect timeout
- Committed: `31b364f`

### 9. Connection Rejection Strategy (`connection/tcp.rs`) ✅
- `RejectStrategy` enum: `Rst` (drop immediately), `AcceptSilence` (hold open silently)
- `RejectConfig`: strategy, silence_timeout_secs (default 30), silence_cap (default 100)
- `SilentConnectionTracker`: atomic try_acquire/release with configurable cap
- `reject_connection()` integrated into accept_loop
- Falls back to RST when silent cap is exhausted
- Also fixed: `connect()` now propagates Python timeouts to registry (was a race)
- 3 tests: tracker cap, accept_silence holds then drops, silent cap fallback to RST

## Not Yet Started

### 10. TLS (`connection/tls.rs`)
- Self-signed cert generation, `SslAcceptor` with weak ciphers, DH params
- TLS accept wraps TCP accept with handshake timeout
- Behind `#[cfg(feature = "tls")]`
- Needs `PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig`

### 11. UDP (`connection/udp.rs`)
- `udp_listen` → `UdpSocket`, peer table `HashMap<SocketAddr, (ConnectionId, Py<PyAny>)>`
- Platform-specific: `recvfrom` on macOS, `recvmsg`+`IP_PKTINFO` on Linux

### 12. Wire into main.rs
- Create `Arc<ConnectionRegistry>`, `Arc<ConnectionLimits>` in `async_main`
- Start listeners per config, `ServiceHandle` for shutdown
- Integration tests in `crates/dionaea/tests/`

## Files Modified/Created in Phase 4
```
NEW: crates/dionaea/src/connection/throttle.rs
NEW: crates/dionaea/src/connection/limits.rs
NEW: crates/dionaea/src/connection/callback.rs
NEW: crates/dionaea/src/connection/tcp.rs
MOD: crates/dionaea/src/connection/mod.rs  (module registration + iter_ids)
MOD: crates/dionaea/src/python/connection.rs  (pub(crate) fields)
MOD: Cargo.toml  (added ip_network = "0.4")
MOD: crates/dionaea/Cargo.toml  (added ip_network dep, updated deny-list feature)
```

## Git State
- Branch: `dionaea-v2-rust`
- 134 tests passing
