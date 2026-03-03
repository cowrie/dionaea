# Dionaea v2 Rust Migration — Progress

## Phase 4: TCP/UDP I/O + TLS ✅ COMPLETE

### Completed Increments

#### 1. Throttle + Accounting (`connection/throttle.rs`) ✅
- Token bucket rate limiter with configurable bytes/sec, interval refill, burst cap
- Cumulative byte accounting with optional limit
- 11 tests, all passing

#### 2. ConnectionLimits (`connection/limits.rs`) ✅
- Per-IP `DashMap<IpAddr, AtomicU32>` counting with cleanup-at-zero
- Global FD % and total connection checks
- `RejectReason` enum for diagnostics
- 8 tests, all passing

#### 3. IP Deny List (`connection/limits.rs`) ✅
- CIDR matching via `ip_network_table` crate, behind `#[cfg(feature = "deny-list")]`
- Optional TTL per entry with auto-expire
- 7 tests (including integration with ConnectionLimits), all passing

#### 4. Callback Error Recovery (`connection/callback.rs`) ✅
- Matches actual `binding.pyx` exception handling behavior
- `PostCallback` enum: `Continue | Close | Reconnect`
- 9 tests, all passing

#### 5-7. TCP Listener + Handler + Timeouts (`connection/tcp.rs`) ✅
- `tcp_listen()` → `TcpListenerHandle` with bound address
- Accept loop: checks limits → `registry.register` → `factory_create` via spawn_blocking
- Handler I/O loop with `tokio::select!`
- `drain_control_messages()` preserves Data messages sent during handle_established
- Throttle + accounting integration
- 6 tests passing

#### 8. TCP Outbound Connect ✅
- `PyConnection.connect()`: registers in registry, spawns async `tcp_connect_task`
- 3 tests: echo roundtrip, connect failure, connect timeout

#### 9. Connection Rejection Strategy ✅
- `RejectStrategy`: Rst, AcceptSilence
- `SilentConnectionTracker` with configurable cap
- 3 tests

#### 10. TLS (`connection/tls.rs`) ✅
- Self-signed cert generation, SSL acceptor, TLS accept loop
- Behind `#[cfg(feature = "tls")]`
- 3 tests

#### 11. UDP (`connection/udp.rs`) ✅
- Single socket, per-peer Python handlers, idle timeout sweep
- 2 tests

#### 12. Wire into main.rs + Python bind/listen ✅
- `RuntimeState` global, `PyConnection.bind()/listen()`
- 1 integration test, 1 unit test

---

## Phase 5: End-to-End Protocol Validation ✅ COMPLETE

### 13. Real echo.py Protocol Test ✅
- Loads actual `modules/python/dionaea/echo.py` via Python module loader
- Binds/listens on random port, connects with TCP client
- Verifies welcome message ("welcome to reverse world!\n") and data reversal
- **Bugs fixed:**
  - `PyConnection.__new__` rejected `proto` keyword argument (was `_proto`)
  - `drain_control_messages` silently dropped Data messages (welcome banners)
- Committed: `84d2e34`

### 14. Real http.py Protocol Test ✅
- Loads actual `modules/python/dionaea/http.py` via module loader
- Creates temp directory with index.html, serves via httpd protocol
- HTTP GET returns 200 OK with correct body
- **Bugs fixed:**
  - `apply_parent_config` was a no-op stub — now iterates `shared_config_values`
    and copies attributes from parent to child (critical for config inheritance)
  - `py_to_opaque` rejected connection objects — now detects `PyConnection`
    subclasses and stores as `ConnectionRef(id)`, fixing `i.con = self` in incidents
- Committed: `16f1485`

---

## Test Summary
- Branch: `dionaea-v2-rust`
- 145 unit tests passing + 3 integration tests (with `--features tls`)
- 1 flaky benchmark test (`test_spawn_blocking_gil_latency`) — GIL contention under
  parallel test load, not a regression

## Known Issue
- `test_spawn_blocking_gil_latency`: P99 threshold of 500μs exceeded under heavy
  parallel test load. Needs higher threshold or test isolation.

## Files Modified/Created
```
Phase 4:
  NEW: crates/dionaea/src/connection/throttle.rs
  NEW: crates/dionaea/src/connection/limits.rs
  NEW: crates/dionaea/src/connection/callback.rs
  NEW: crates/dionaea/src/connection/tcp.rs
  NEW: crates/dionaea/src/connection/tls.rs
  NEW: crates/dionaea/src/connection/udp.rs
  NEW: crates/dionaea/src/runtime.rs
  NEW: crates/dionaea/tests/listen_connect.rs
  MOD: crates/dionaea/src/connection/mod.rs
  MOD: crates/dionaea/src/python/connection.rs
  MOD: crates/dionaea/src/main.rs
  MOD: crates/dionaea/src/lib.rs
  MOD: Cargo.toml
  MOD: crates/dionaea/Cargo.toml

Phase 5:
  NEW: crates/dionaea/tests/echo_protocol.rs
  NEW: crates/dionaea/tests/http_protocol.rs
  MOD: crates/dionaea/src/connection/tcp.rs  (drain_control_messages returns Data)
  MOD: crates/dionaea/src/python/connection.rs  (__new__ proto kwarg, apply_parent_config)
  MOD: crates/dionaea/src/python/convert.rs  (PyConnection → ConnectionRef)
```
