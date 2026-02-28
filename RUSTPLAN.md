# Dionaea v2: Rust Migration Implementation Plan

## Context

Dionaea is a C+Python honeypot (~10K C core, ~35K Python protocols). The C core handles
event-driven networking (TCP/TLS/UDP), module loading, incident dispatch, and stream
processing. Python handles all protocol emulation and logging. We're rewriting the C core
in Rust with PyO3, keeping all Python protocols unchanged.

**Decisions made:**
- Language: Rust (PyO3 for Python bridge)
- Shellcode: Drop libemu entirely. Port GetPC detection (~300 lines) to Rust.
  Keep Python Speakeasy handler for Windows API emulation (IOC extraction).
  No unicorn-engine dependency in Rust core — Speakeasy already uses unicorn
  internally via Python.
- Config: TOML for Rust core. Python service/ihandler configs stay YAML (avoids touching
  every protocol module's config loading code).
- Privileges: Linux capabilities (CAP_NET_BIND_SERVICE), no pchild fork
- Modules: Compile-time Cargo features, no dynamic loading
- TLS: openssl crate (mandatory for weak cipher honeypot support)
- DTLS: Drop entirely. Zero Python protocols or configs reference it. Dead code in C.
- Remote management: Internal management API with two poll-based transports
  (JSON/HTTPS and DNS). Transport choice deferred; hooks designed now.

---

## Dependencies

```toml
[workspace.dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# TLS (must use openssl for weak cipher honeypot support)
openssl = "0.10"
tokio-openssl = "0.6"

# Python embedding
pyo3 = { version = "0.23", features = ["auto-initialize"] }  # verify latest stable on crates.io

# Logging + observability
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tracing-appender = "0.2"
metrics = "0.24"
metrics-exporter-prometheus = "0.18"

# Error handling
thiserror = "2"

# Config
serde = { version = "1", features = ["derive"] }
toml = "1"

# Data structures
bytes = "1"            # BytesMut for zero-copy send buffers
dashmap = "6"          # Concurrent HashMap for per-IP tracking

# Crypto
sha2 = "0.10"          # SHA256 for download/shellcode file naming

# DNS
hickory-resolver = { version = "0.25", features = ["tokio-runtime"] }

# HTTP client (replaces curl module)
reqwest = { version = "0.13", default-features = false, features = ["native-tls"] }

# System/privileges
nix = { version = "0.31", features = ["socket", "uio", "user", "process", "fs", "net", "resource"] }
caps = "0.5"           # Linux-only, behind cfg

# Platform-specific (Linux only, behind cfg)
pcap = "2"             # libpcap bindings
nfq = "0.2"            # netfilter queue (pure Rust, MIT)
rtnetlink = "0.20"     # netlink interface monitoring

[workspace.dev-dependencies]
proptest = "1"

[workspace.lints.rust]
unsafe_code = "deny"
missing_docs = "warn"

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
must_use_candidate = "allow"
```

**Version verification:** Before creating `Cargo.toml`, verify all crate versions against
crates.io. Versions above are best estimates — run `cargo check` in Phase 1 to catch
incompatibilities early. In particular: `pyo3`, `reqwest`, `metrics`, and `nfq` versions
should be pinned to actual latest stable releases.

No unicorn-engine dependency in Rust — Speakeasy uses unicorn internally via Python.
GetPC pattern detection is pure Rust (no external deps needed — it's byte pattern scanning).
Drop libemu and the vendor/unicorn-libemu-shim entirely.

---

## Cross-Cutting Concerns

These apply to every phase, not just one.

### Error Handling Strategy

```rust
// crates/dionaea/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] openssl::error::ErrorStack),

    #[error("config error: {0}")]
    Config(String),

    #[error("Python error: {0}")]
    Python(String),  // Converted from PyErr at the boundary

    #[error("DNS resolution failed for {host}: {source}")]
    Dns { host: String, source: hickory_resolver::error::ResolveError },
}

// Python ↔ Rust boundary: PyErr → Error::Python, Error → PyErr
// PyO3 handles this via From<PyErr> and Into<PyErr> impls.
```

**Panic policy:** `panic = "unwind"` in release. Use `std::panic::catch_unwind` at every
Python callback boundary and every tokio task entry point. A panic in one connection handler
must not take down the process. Log the panic, close that connection, continue.

**Graceful degradation:** If a service fails to start (port in use, config error), log the
error and continue starting other services. Only abort if zero services start successfully.

### Python GIL Strategy

The GIL is the single hardest integration problem. Rules:

1. **Never hold the GIL on a tokio worker thread.** All Python calls go through
   `tokio::task::spawn_blocking`, which runs on a dedicated thread pool.

2. **Release the GIL during Rust I/O.** When Python calls `connection.send()` or similar,
   the PyO3 method acquires the connection lock, queues data, and returns. The actual I/O
   happens on tokio threads without the GIL.

3. **Callback pattern:** When Rust needs to call Python (handle_io_in, handle_established, etc.):
   ```rust
   let result = tokio::task::spawn_blocking(move || {
       Python::with_gil(|py| {
           let handler = py_protocol.bind(py);
           handler.call_method1("handle_io_in", (data,))
       })
   }).await?;
   ```

4. **Batch Python calls.** When dispatching an incident to multiple Python handlers,
   acquire the GIL once, call all handlers, then release.

5. **Python async is out of scope.** All Python protocol code is synchronous (as it is
   today with libev). We don't need `pyo3-asyncio`.

6. **Per-connection callback ordering is guaranteed.** The connection task must `await`
   each Python callback to completion before processing the next I/O event. This preserves
   the C behavior where callbacks for a single connection are strictly ordered:
   `established → io_in → io_in → ... → disconnect`. Without this, a race between
   `handle_io_in` and `handle_disconnect` can deliver callbacks out of order.
   The connection task loop enforces this:
   ```rust
   loop {
       tokio::select! {
           result = socket.read(&mut buf) => {
               let data = result?;
               // MUST await before next loop iteration — no concurrent callbacks
               let consumed = call_python_io_in(&py_handler, &data).await?;
           }
           _ = &mut idle_timeout => {
               call_python_timeout_idle(&py_handler).await?;
           }
       }
   }
   ```

### Testing Strategy

Testing is continuous, not a phase. Every phase includes its own tests.

**Unit tests:** Every module has `#[cfg(test)] mod tests` with tests for its core logic.
State machines, pattern matching, config parsing, type conversions — all unit-tested.

**Integration tests:** `tests/` directory in workspace root. Tests that start a listener,
connect a client, and verify behavior. Run against the real Rust binary with real Python.

**Existing pytest suite:** The current `tests/` directory has pytest-based integration tests
for TFTP, FTP, SMB, HTTP, MySQL, EPMAP, NBNS, SNMP. These run against a live daemon via
network connections. They are the primary acceptance test — if they pass against the Rust
binary, we have feature parity.

**Fuzz testing:** `cargo-fuzz` targets for every parser that handles untrusted input:
- Shellcode detection (GetPC byte scanning)
- TLS handshake parsing (via openssl, but our framing around it)
- Protocol framing (connection read → buffer → io_in callback length)
- Config file parsing

**Property-based testing:** `proptest` for:
- OpaqueData round-trips through Python conversion (Rust → PyObject → Rust)
- Config serialization round-trips (struct → TOML → struct)
- NodeInfo formatting (any valid IP address formats correctly)

**CI pipeline (GitHub Actions):**
```yaml
# Runs on every push/PR
- cargo fmt --check
- cargo clippy -- -D warnings
- cargo test
- cargo audit          # vulnerability scanning
- cargo deny check     # license + dependency policy
# Integration (after build):
- Start Rust binary as daemon
- Run existing pytest suite against it
- Compare logs against expected incident patterns
```

### Linting & Formatting

**rustfmt:** Enforce consistent formatting across the workspace. `rustfmt.toml` at workspace
root:

```toml
# rustfmt.toml
edition = "2024"
```

`cargo fmt --check` runs in CI and blocks merge on formatting violations. No exceptions —
formatting is never a review discussion.

**clippy:** Workspace-level lint configuration in `Cargo.toml`:

```toml
[workspace.lints.rust]
unsafe_code = "deny"
missing_docs = "warn"

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
# Pedantic overrides (too noisy for our codebase):
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
must_use_candidate = "allow"
```

`cargo clippy -- -D warnings` runs in CI.

**Workspace lint inheritance:** Each crate's `Cargo.toml` inherits workspace lints:

```toml
# crates/dionaea/Cargo.toml
[lints]
workspace = true
```

### Documentation Strategy

The codebase will be maintained and extended by LLMs as well as humans. Documentation
is optimized for both: concise enough for humans, explicit enough for LLMs that lack
project-wide context.

**Every file starts with a 2-line ABOUTME comment:**

```rust
// ABOUTME: Manages the connection lifecycle state machine (None → Established → Close).
// ABOUTME: Owns the socket, protocol handler reference, and per-connection rate limits.
```

This gives an LLM (or human) instant context about what a file does without reading
the whole thing. `ABOUTME` is greppable across the project.

**Every public type and function gets a doc comment** explaining:
1. *What* it does (one sentence)
2. *Why* it exists / when to use it (one sentence, if not obvious)
3. *Relationship* to other components (if it's part of a larger flow)

```rust
/// Connection metadata visible to Python and the incident system.
///
/// Stored in `ConnectionRegistry` (a `DashMap<ConnectionId, ConnectionMeta>`).
/// The tokio task owns the I/O state separately (socket, buffers, timeouts).
/// Python reads metadata through `PyConnection`, which holds a `ConnectionId`
/// and looks up the entry in the registry on each property access.
pub struct ConnectionMeta {
    /// Monotonically increasing, never recycled. Python holds copies of this.
    pub id: ConnectionId,
    /// Current lifecycle state. Drives which operations are valid.
    pub state: ConnectionState,
    // ...
}

/// Transition the connection to a new state.
///
/// Returns `Err` if the transition is invalid (e.g., `Close` → `Established`).
/// On success, fires the appropriate Python callback (e.g., `handle_established`)
/// via `spawn_blocking`.
pub async fn transition(&mut self, new_state: ConnectionState) -> Result<(), Error> {
```

**Non-obvious fields get inline comments:**

```rust
pub struct Throttle {
    /// Bytes allowed per second. 0 means unlimited.
    max_bytes_per_second: f64,
    /// Bytes consumed in the current interval. Resets when interval elapses.
    interval_bytes: f64,
    /// When the current interval started. Used to calculate remaining allowance.
    interval_start: Instant,
}
```

**Module-level doc comments** describe the module's role in the system and point to
related modules:

```rust
//! Connection rate limiting and resource management.
//!
//! Implements 8 layers of protection (see RUSTPLAN.md "Rate Limiting & Resource
//! Management" for the full design):
//! - Layer 1: Global FD limit (`limits.rs`)
//! - Layer 2: Per-IP connection limit (`limits.rs`)
//! - Layer 3: Bandwidth throttle (`throttle.rs`)
//! - Layers 4-8: See individual structs.
//!
//! Used by `connection::tcp` and `connection::tls` during accept and I/O.
```

**Enforce in CI:** Add `warn(missing_docs)` to the workspace lints. This produces
warnings (not errors) for undocumented public items — a reminder without blocking PRs
during rapid development. Promote to `deny` once the codebase stabilizes.

```toml
[workspace.lints.rust]
unsafe_code = "deny"
missing_docs = "warn"
```

**What NOT to document:**
- Don't restate the type signature in prose ("takes a `String` and returns a `bool`")
- Don't document private helper functions unless the logic is non-obvious
- Don't write "This struct represents..." — just say what it is
- Don't add historical context ("added in v2", "replaces the old...")

### Observability

**Structured logging:** All log output is structured JSON by default (for SIEM ingestion),
with optional human-readable format for development. Uses `tracing` with `tracing-subscriber`
JSON layer.

```rust
// Every connection gets a tracing span
let span = tracing::info_span!("connection",
    id = %con_id,
    remote = %remote_addr,
    transport = %transport,
    protocol = %protocol_name,
);
// All events within this span automatically include connection context
```

**Log multiplexer:** Replicate the current C behavior — multiple log targets (file, stdout),
each with independent domain glob patterns and level filters. Use `tracing-subscriber::Layer`
composition.

**Metrics (Prometheus):** Exposed on a configurable HTTP port (default: off).
```
dionaea_connections_total{transport="tcp",protocol="smb",state="established"} counter
dionaea_connections_active{transport="tcp"} gauge
dionaea_connections_rejected_total{reason="fd_limit|per_ip_limit|deny_list"} counter
dionaea_incidents_total{origin="dionaea.connection.tcp.accept"} counter
dionaea_bytes_received_total{protocol="http"} counter
dionaea_bytes_sent_total{protocol="http"} counter
dionaea_downloads_total{method="ftp"} counter
dionaea_throttle_sleeps_total{direction="in|out"} counter
dionaea_accounting_disconnects_total{} counter
dionaea_timeout_fires_total{type="idle|sustain|handshake"} counter
dionaea_nfq_throttled_total{} counter
dionaea_python_callback_duration_seconds{method="handle_io_in"} histogram
dionaea_errors_total{kind="python_exception"} counter
```

**Health check:** Optional HTTP endpoint (`/health`) returns 200 when the event loop is
running and at least one service is listening. Used by Docker HEALTHCHECK and orchestrators.

### Rust Idioms & Ownership

**Ownership across the Python boundary:**

The PyO3 bridge is where Rust's ownership model meets Python's garbage collector.
Connection state is split between two owners to keep the I/O hot path lock-free:

1. **Each connection's tokio task owns its I/O state.** The task directly owns the socket,
   receive buffer, state machine, and timeout futures. No shared map access is needed
   for I/O operations — this is the hot path and must be lock-free.

2. **A `ConnectionRegistry` holds metadata for Python access.** A
   `DashMap<ConnectionId, ConnectionMeta>` stores the fields Python reads via `#[pyo3(get)]`:
   addresses, transport type, protocol name, stats, timeout configs. The tokio task updates
   the registry when metadata changes (state transitions, stats). Python reads are lock-free
   (DashMap read shards). Python never touches I/O state directly.

3. **Python's `send()` goes through a channel, not shared memory.** Each connection has a
   `tokio::sync::mpsc::UnboundedSender<SendMessage>` that Python's `send()` method pushes to.
   `SendMessage` carries data (TCP/TLS), datagrams with addresses (UDP), and control messages
   (timeout/throttle changes from Python property setters). The connection task drains this
   channel and dispatches each variant. No mutex needed.

4. **Python owns all protocol handler objects.** The `Py<PyAny>` (Python protocol instance)
   is stored in a `Py<>` handle associated with the connection ID. PyO3's `Py<>` is
   reference-counted on the Python side and `Send` on the Rust side. When a connection
   closes, we drop the `Py<>` handle, which decrements the Python refcount.

5. **Incident data is copied, not shared.** When an incident is reported from Rust to Python,
   `OpaqueData` values are converted to Python objects (new allocations). When Python sets
   fields on a `PyIncident`, the data is converted to `OpaqueData` (Rust allocation). No
   shared mutable state between languages.

6. **No `Arc<Mutex<T>>` across the Python boundary.** The ConnectionId indirection
   eliminates this. The only locks are:
   - `ConnectionRegistry` uses `DashMap` (sharded concurrent map, no global lock)
   - Per-connection send/control uses `mpsc` channel (lock-free)

**What the compiler catches:**

- Lifetime errors: The borrow checker prevents returning references to connection data
  that might be removed from the registry. All returns are owned values or copies.
- Send/Sync violations: tokio tasks require `Send`. PyO3's `Py<PyAny>` is `Send` but not
  `Sync` — you can move it between threads but can't share it. This correctly models the
  GIL: only one thread can use a Python object at a time.
- Unused results: `#[must_use]` on `Result` ensures errors are handled, not silently dropped.

**What the compiler doesn't catch — use tools:**

- **Miri** (`cargo +nightly miri test`): Detects undefined behavior in unsafe code. We
  ban `unsafe` at the workspace level, but Miri can still catch UB in dependencies and
  in any `unsafe` blocks that get approved via `#[allow(unsafe_code)]` (e.g., if needed
  for raw FD handling). Run Miri on unit tests in CI.

- **`cargo careful`**: Runs the standard library with extra runtime checks (overflow,
  alignment). Useful for catching integer overflow in offset calculations (bistream,
  throttle byte counters).

- **Thread sanitizer** (`RUSTFLAGS="-Z sanitizer=thread" cargo test`): Detects data races.
  Particularly valuable for the `spawn_blocking` + GIL interaction where Rust and Python
  share data through `Py<>` handles.

- **Address sanitizer** (`RUSTFLAGS="-Z sanitizer=address"`): Detects use-after-free in
  FFI code (OpenSSL bindings, PyO3 internals).

**CI tooling summary:**
```yaml
# In addition to clippy/test/audit/deny:
- cargo +nightly miri test           # UB detection (unit tests only)
- cargo careful test                  # overflow/alignment checks
# Periodic (weekly, not per-PR — these are slow):
- RUSTFLAGS="-Z sanitizer=thread" cargo test
- RUSTFLAGS="-Z sanitizer=address" cargo test
```

**Idiomatic Rust patterns to use:**

- **Enums for state machines.** `ConnectionState` is an enum, not a bag of booleans.
  Invalid transitions are compile-time errors if we use the typestate pattern for
  critical transitions (e.g., `Handshake` → `Established` produces a different type).
- **`Result<T, Error>` everywhere.** No sentinel values (-1, NULL). Every fallible
  operation returns `Result`. The `?` operator propagates errors cleanly.
- **Bubble errors up, log at the call site.** Functions return `Result<T, Error>`, not
  `()` with internal logging. The *caller* decides whether to log, retry, or propagate.
  This keeps error-handling logic in one place and makes functions composable.
  Use `.inspect_err(|e| tracing::warn!(...))` when you need to log *and* propagate.
- **`let`-`else` over `match` for binary cases.** When you only care about one variant:
  ```rust
  let Some(conn) = table.get(&id) else { return Err(Error::ConnectionClosed) };
  ```
  Use `match` when you handle 3+ variants or need exhaustiveness checking.
- **Iterator combinators.** `.map()`, `.filter_map()`, `.collect()` over manual loops
  with `push()`. Build collections functionally, then `.append()` into a mutex-guarded
  `Vec` — fewer lock acquisitions and more readable:
  ```rust
  let results: Vec<_> = items.iter().filter_map(|i| process(i).ok()).collect();
  guarded_vec.lock().append(&mut results);  // one lock, not N
  ```
- **`From`/`Into` for conversions.** `OpaqueData` ↔ `PyObject` conversions use
  `impl From<OpaqueData> for PyObject` and vice versa. Prefer `impl From<X> for Y`
  over manual conversion functions — `.into()` is clean at call sites.
- **`impl Into<String>` for string parameters.** Functions that will own the string
  should take `impl Into<String>`, not `&str` (forcing `.to_string()` at every call
  site) or `String` (forcing callers to clone when they have a `&str`).
- **Builder pattern for config.** Complex types like `SslAcceptor` configuration use
  builders, not 15-argument constructors.
- **`Display` for user-facing strings.** `NodeInfo`, `ConnectionState`, `Error` all
  implement `Display` for logging. No manual format string construction.
- **Newtypes for IDs.** `ConnectionId(u64)` prevents accidentally passing a raw `u64`
  where a connection ID is expected.
- **Feature flags for optional modules.** Not runtime `if config.enabled` checks.
  Dead code is eliminated at compile time.
- **No `.unwrap()` in production code.** Use `.expect("reason")` when a `None`/`Err`
  is genuinely impossible — the message documents *why*. Use `?` to propagate. Use
  `#[allow(clippy::unwrap_used)]` with a comment only when `.expect()` would be too
  verbose and the invariant is obvious (e.g., poisoned mutex).
- **No macros unless unavoidable.** Macros are a different language — LSPs can't parse
  them, they're hard to debug, and they destroy code locality. Use functions and
  generics first. The only acceptable macros are derive macros (thiserror, serde,
  PyO3) and trivial declarative macros for repetitive trait impls. If you're writing
  a `macro_rules!` that spans more than 10 lines, reconsider.
- **`// SAFETY:` comments** on every `unsafe` block (if any get `#[allow]`ed) and on
  every `as` cast that narrows a type (e.g., `u64 as u32`). The comment explains why
  the invariant holds.
- **If you're fighting the compiler, you're doing something wrong.** Borrow checker
  errors are design feedback. Restructure the code rather than reaching for `Arc`,
  `Mutex`, `clone()`, or `unsafe`. The `ConnectionId` indirection pattern exists
  specifically because `Arc<Mutex<Connection>>` was a fight we shouldn't have.
- **Readability over performance.** Rust + LLVM optimizes well. Write clear code first.
  Only optimize hot paths identified by profiling — and the hot path is almost
  certainly the Python GIL, not Rust code.

**Dependency hygiene:**
- Run `cargo outdated` monthly. Small version bumps are easy; catching up after a year
  of neglect is painful.
- `cargo audit` runs in CI on every PR. `cargo deny check` validates licenses.

### Replacing GLib Patterns with Idiomatic Rust

The C code uses GLib extensively. We do NOT port GLib semantics to Rust — we use Rust's
native equivalents which are better.

| GLib pattern | C code | Rust replacement |
|-------------|--------|-----------------|
| `GHashTable` | Incident data, peer tables | `HashMap` / `DashMap` (concurrent) |
| `GList` (linked list) | Handler lists, connection lists | `Vec` (contiguous, cache-friendly) |
| `GNode` (tree) | Processor pipeline | `ProcessorNode` with `Vec<ProcessorNode>` children |
| `GString` | Growable byte buffers | `Vec<u8>` or `bytes::BytesMut` |
| `GPatternSpec` (glob matching) | Incident dispatch, log filtering | Custom wildcard matcher (~20 lines) |
| `g_malloc`/`g_free` | All allocation | Rust's allocator (automatic via ownership) |
| `g_error`/`g_warning`/`g_debug` | Logging | `tracing::error!`/`warn!`/`debug!` |
| `GKeyFile` (INI parser) | Main config | `serde` + `toml` crate |
| `GError` | Error propagation | `thiserror` enum + `Result<T, Error>` |
| `GThreadPool` | Processor thread pool | `tokio::task::spawn_blocking` pool |
| `GMainLoop` / `libev` | Event loop | `tokio` async runtime |
| `g_pattern_spec_match` | Glob with `*` matching dots | Simple wildcard: `*` = any chars, `?` = one char |
| `GRefCount` | Connection ref/unref | `AtomicU32` on `ConnectionMeta` in `ConnectionRegistry` |
| `GMutex` | Processor pipeline lock | `tokio::sync::Mutex` or `std::sync::Mutex` |

**Key behavioral differences to be aware of:**
- GLib's `g_error()` aborts the process. Rust's `tracing::error!` just logs. For truly
  fatal conditions, use `panic!` (caught at task boundaries) or `std::process::exit`.
- GLib's `GList` is a doubly-linked list. `Vec` is almost always better in Rust (cache
  locality). Only use `VecDeque` if we need O(1) push_front.
- GLib's memory functions never return NULL (they abort on OOM). Rust's allocator also
  aborts by default on OOM (`alloc::oom = abort`). Same behavior, no change needed.
- GLib's `g_pattern_spec_match` takes a `reversed` parameter for optimization. We don't
  need this — our patterns are short and matched infrequently.

### Network Model

**IPv4/IPv6 dual-stack:** Each service creates two listeners — one on `0.0.0.0` and one
on `[::]` with `IPV6_V6ONLY=true`. This matches how most network services work and avoids
platform-specific dual-stack socket behavior. The current C code supports both address
families. In `getifaddrs` mode, the interface enumeration returns both IPv4 and IPv6
addresses; each gets its own listener.

**Interface discovery (`getifaddrs` mode):** When `dionaea.listen.mode = "getifaddrs"`,
enumerate interfaces via `nix::ifaddrs::getifaddrs()` at startup. Filter by configured
interface names (if specified). Start one listener per address per service. On Linux
with the `netlink` feature, subscribe to address change notifications and dynamically
add/remove listeners. Without `netlink`, re-scan on SIGHUP.

**Interface separation:** Honeypot services and admin services bind to different
interfaces. Honeypot services (SMB, FTP, HTTP, etc.) bind to the externally-exposed
interface (configured via `dionaea.listen`). Admin services — metrics exporter, health
endpoint, and any future local REST API — bind to a separate admin interface (configured
via `dionaea.admin.listen`, defaults to `127.0.0.1`). This prevents attackers from
reaching admin endpoints, even if they discover the honeypot's IP. The management
transports (HTTPS poller, DNS poller) are outbound-only and don't listen at all.

**Outbound connections (`connect()` from Python):** Python calls `connection.connect(addr,
port)` synchronously. The C implementation is fire-and-forget: it queues the connect in
libev and returns immediately. The Rust implementation does the same:

1. Python calls `PyConnection::connect(addr, port)` — this is a `#[pymethod]`
2. The method validates args, creates a `ConnectionMeta` in the registry, and spawns a
   tokio task to handle the async connect (DNS resolution + TCP connect + optional TLS)
3. Returns immediately to Python (no GIL blocking on I/O)
4. When the connection is established, the tokio task calls `handle_established` on the
   Python protocol via `spawn_blocking` + GIL
5. If connect fails, calls `handle_error` instead

This matches the current C event-driven model exactly. The key insight: `connect()` doesn't
block because the underlying event loop is async. Python just triggers the action.

**`ref()` / `unref()` semantics:** In the C code, these increment/decrement a refcount that
prevents the connection from being freed while a background thread (processor pipeline) holds
a reference. With the Rust ownership model (ConnectionId + ConnectionRegistry), `ref()` and
`unref()` become lightweight pins:

- `ref()`: Increments an `AtomicU32` counter on the `ConnectionMeta` entry. While refcount > 0,
  the connection task delays cleanup even after the connection closes.
- `unref()`: Decrements the counter. When it reaches 0 and the connection is in `Close`
  state, the entry is removed from the registry.
- Both return the current refcount (matching C behavior).

This preserves the contract: processor threads (via `spawn_blocking`) ref before processing,
unref when done. Python can also hold refs to keep connections accessible for incident
reporting after disconnect.

### Performance

A honeypot can face thousands of simultaneous connections during port scans and worm
propagation. The Python GIL is the throughput ceiling — I/O multiplexing in Rust is
effectively free compared to Python callback overhead. Design around that.

**Tokio runtime configuration:**
```rust
tokio::runtime::Builder::new_multi_thread()
    .worker_threads(num_cpus::get().max(2))  // Match current C behavior (min 2)
    .max_blocking_threads(64)                 // For Python GIL-holding calls
    .enable_all()
    .build()
```

The `max_blocking_threads` pool is where all Python calls happen (via `spawn_blocking`).
64 threads is generous — in practice the GIL serializes them, but the pool prevents
starvation when many connections need Python callbacks simultaneously.

**Task-per-connection model:** Each accepted connection spawns a tokio task. The task owns
the connection's I/O loop (read → protocol callback → write). This is lightweight — tokio
tasks are ~300 bytes of overhead, not OS threads. Target: 10K+ concurrent connections
limited only by FDs and memory, not task overhead.

**Buffer management:**
- Receive buffer: Stack-allocated `[u8; 65536]` per read call (matching current
  `CONNECTION_MAX_RECV_SIZE`). No heap allocation per packet.
- Send path: Python's `send()` pushes `SendMessage::Data(Bytes)` (TCP/TLS) or
  `SendMessage::Datagram { data, local, remote }` (UDP) through an `mpsc` channel to the
  connection task. The task drains the channel, dispatches control messages (timeout/throttle
  changes), and writes data to the socket. The task owns a `BytesMut` write buffer for
  coalescing small TCP/TLS writes.

**Python callback overhead minimization:**
- Batch incident dispatch: acquire GIL once, call all matching handlers, release.
- Avoid Python↔Rust round-trips for connection metadata. Cache `transport`, `protocol`,
  `local`, `remote` as Rust fields; Python reads them via `#[pyo3(get)]` without
  re-acquiring data from the connection table.
- `handle_io_in` returns bytes consumed as `usize` — use this to avoid re-copying
  unconsumed data. Slice the buffer, don't allocate a new one.

**What NOT to optimize:** Don't add zero-copy I/O (splice, sendfile) or io_uring.
The bottleneck is Python, not syscalls. Keep it simple.

**Benchmarks (tracked per release):**
- Connections/second: TCP accept → established → close (no protocol)
- Protocol throughput: bytes/sec through echo protocol (measures Python overhead)
- Memory per connection: RSS / active connection count
- GIL contention: `dionaea_python_callback_duration_seconds` histogram P50/P99
- Baseline target: match or beat C version. If Python is the bottleneck in both,
  Rust I/O performance is irrelevant — just don't regress.

### Rate Limiting & Resource Management

The current C code has a layered rate limiting system. All layers must be preserved.

**Layer 1: Global FD limit (connection accept)**

Reject new connections when FD usage exceeds a configurable percentage of `RLIMIT_NOFILE`.

```rust
// Checked in tcp_accept() and tls_accept()
let fd_limit = resource::getrlimit(Resource::RLIMIT_NOFILE)?.rlim_cur;
let threshold = fd_limit * config.limits.max_fds_pct / 100;
if current_fd_count > threshold {
    tracing::warn!(fd = current_fd_count, limit = threshold, "FD limit reached, rejecting");
    metrics::counter!("dionaea_connections_rejected_total", "reason" => "fd_limit").increment(1);
    drop(stream);  // close immediately
    continue;
}
```

Default: 70% (matching current C behavior). Configurable in TOML.

**Layer 2: Per-IP connection limit**

`DashMap<IpAddr, AtomicU32>` tracks active connections per source IP. Checked at accept
time. When exceeded, reject the **new** connection (don't kill existing ones — they may
be mid-protocol and generating useful incident data).

Default: 50. Configurable per-protocol if needed.

**Layer 3: Per-connection bandwidth throttle (token bucket)**

Replicates the C token bucket in `connection.c:1812-1926`. Applied per-direction
(ingress/egress) on each connection.

```rust
pub struct Throttle {
    max_bytes_per_second: f64,  // 0 = unlimited
    interval_bytes: f64,         // bytes transferred in current interval
    interval_start: Instant,     // start of current 1-second interval
}

impl Throttle {
    /// Returns how many bytes may be transferred now.
    /// Returns 0 if the caller should sleep (minimum 200ms).
    pub fn available(&mut self) -> usize;

    /// Record that `n` bytes were transferred.
    pub fn update(&mut self, n: usize);
}
```

When `available()` returns 0, the connection task sleeps using `tokio::time::sleep`
(not thread sleep — this is cooperative, doesn't block the worker).

Protocols set throttle via Python API:
- HTTP: `self._out.speed.limit = 16*1024` (16 KB/s)
- UPnP: `self._out.speed.limit = 16*1024` (16 KB/s)
- Others: unlimited by default

**Layer 4: Per-stream accounting (total byte limits)**

Each direction has a cumulative byte counter with a configurable cap. When exceeded,
the connection closes.

```rust
pub struct Accounting {
    bytes: u64,   // total transferred
    limit: u64,   // max allowed (0 = unlimited)
}

impl Accounting {
    pub fn add(&mut self, n: usize) -> bool; // returns false if limit exceeded
}
```

Protocol-specific limits (from current code):
- Mirror: 100 KB per direction
- NFQ mirror: 200 KB per direction
- Command shell: 1 KB inbound
- SMB: unlimited (commented out in current code)

**Layer 5: Connection timeouts**

Six timeout types, all configurable per-connection from Python:

| Timeout | Default | Fires when |
|---------|---------|------------|
| `idle` | protocol-specific | No data for N seconds |
| `sustain` | protocol-specific | Connection open longer than N seconds |
| `listen` | protocol-specific | Listening socket open longer than N seconds |
| `handshake` | 10s | TLS handshake takes longer than N seconds |
| `connecting` | 5s | Outbound TCP connect takes longer than N seconds |
| `close` | 10s | Graceful shutdown takes longer than N seconds |

Each timeout is a `tokio::time::Sleep` future integrated into the connection task's
select loop:

```rust
tokio::select! {
    data = socket.read(&mut buf) => { /* handle I/O */ }
    _ = &mut idle_timeout => { /* call handle_timeout_idle */ }
    _ = &mut sustain_timeout => { /* call handle_timeout_sustain */ }
}
```

`idle` resets on every data transfer. `sustain` never resets (absolute deadline).
Python callbacks return `bool` — `true` means keep the connection alive (reset idle),
`false` means close it.

**Layer 6: NFQ SYN throttle (slot-based window)**

Application-level SYN flood protection. A sliding window of time slots, each tracking
connection count for that second.

```rust
pub struct NfqThrottle {
    window: Vec<(u64, u32)>,  // (timestamp, count) per slot
    window_size: usize,        // default: 30 seconds
    total_limit: u32,          // max connections across all slots (default: 30)
    slot_limit: u32,           // max connections per slot (default: 30)
}

impl NfqThrottle {
    /// Returns true if this connection should be accepted.
    pub fn allow(&mut self, now: u64) -> bool;
}
```

**Layer 7: Recv buffer cap**

Hard limit of 64 KB per read call (`CONNECTION_MAX_RECV_SIZE`). Prevents a single
connection from consuming unbounded memory in one read. This is a constant, not
configurable — it's a safety bound, not a tuning knob.

**Layer 8: IP deny list**

A `DashMap<IpAddr, Option<Instant>>` checked at accept time. Entries can have a TTL
(auto-expire) or be permanent. Managed via management commands or loaded from a
persistence file on startup.

**Config section:**
```toml
[dionaea.limits]
max_fds_pct = 70
max_connections_per_ip = 50
recv_buffer_size = 65536       # bytes, per read call
# max_memory_mb = 0            # 0 = no limit

[dionaea.deny_list]
persist_file = "/var/lib/dionaea/deny_list.json"
# Preloaded entries:
# deny = ["192.168.1.100", "10.0.0.0/8"]
```

### Security

This is a honeypot. It is *designed to be attacked*. Security means: the honeypot
must not be compromised, and must not become a tool for attacking others.

**Threat model — what attackers can do:**
1. Send arbitrary bytes to any listening port
2. Attempt to exploit the protocol parsers
3. Try to escape the Python sandbox
4. Use the honeypot as a relay/proxy (SSRF)
5. Exhaust resources (DoS the honeypot itself)
6. Attempt to write/read outside designated directories
7. Target the management channel

**Memory safety (Rust advantage):**
- No buffer overflows, use-after-free, or double-free in Rust code.
- `unsafe_code = "deny"` enforced at workspace level.
- FFI boundaries (OpenSSL, Python) are the remaining attack surface. OpenSSL is
  wrapped by the `openssl` crate (audited). PyO3 manages Python reference counting.
- Fuzz all code that processes untrusted input (see Testing Strategy).

**Input validation at boundaries:**
- All network reads go through a fixed-size buffer (64 KB). No unbounded reads.
- Protocol callback `handle_io_in` returns bytes consumed. If it returns 0 repeatedly
  (protocol stuck), increment a counter and close after N consecutive zero-returns
  (prevents infinite-loop bugs in Python protocol handlers).
- Timeout on every connection state (see Rate Limiting). No connection can live forever.

**File system containment:**
- All file writes go through a path validation helper that resolves symlinks and
  rejects paths outside designated directories (`download_dir`, `bistream_dir`, `log_dir`).
- Downloads are named by SHA256 hash — no attacker-controlled filenames on disk.
- Bistream dumps are named by connection ID — no attacker-controlled paths.

**Anti-relay / SSRF prevention:**
- The download module (replaces curl) only fetches URLs from `dionaea.download.offer`
  incidents. These are generated by protocol handlers when an attacker offers a
  malware URL (e.g., via FTP RETR or SMB write).
- Before fetching, validate the URL: reject `file://`, `gopher://`, and any scheme
  other than `http://` or `https://`.
- Reject private/loopback IPs as download targets (`127.0.0.0/8`, `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `::1`, `fe80::/10`). Prevents SSRF.
- Mirror/NFQ modules check `is_local_addr()` before forwarding traffic.

**Network interface isolation:**
- Admin endpoints (metrics, health) bind to `dionaea.admin.listen` (default `127.0.0.1`).
- Honeypot services bind to `dionaea.listen.addresses` (the exposed interface).
- Config validation rejects configs where admin and honeypot share the same external address.
- Management transports are outbound-only (poll a remote server) — no listening port.

**Sensitive data handling:**
- Incident fields containing "apikey", "password", "secret", "token" are redacted
  in log output (matching current C behavior).
- Management channel authenticated (TLS client certs or TSIG).
- Config file may contain credentials (hpfeeds, VirusTotal API keys). File permissions
  must be 0600, owned by the dionaea user. Validate at startup, warn if world-readable.

**Supply chain:**
- `cargo deny` checks licenses and advisories on every CI run.
- `cargo audit` checks for known CVEs in dependencies.
- Minimal dependency surface: 14 direct crates (see Dependencies section).

**Audit trail:**
- Every accepted connection is logged with source IP, port, transport, protocol, timestamp.
- Every incident is logged with origin and key fields.
- Logs are append-only (no log truncation or deletion from within the honeypot).
- Management reports include all incidents since last poll, ensuring centralized
  visibility even if the honeypot is compromised and local logs are tampered with.

### Remote Management

Dionaea instances are deployed remotely and need centralized management. Two poll-based
transport protocols are planned (JSON/HTTPS and DNS-based); the transport choice is deferred.
The Rust core provides the internal hooks both transports need.

**Architecture:** A `ManagementApi` trait exposes all management operations.
Transport modules (HTTPS poller, DNS poller) are consumers of this trait. The honeypot
itself never initiates outbound management connections — the transports poll a remote
server for commands and push status reports.

```rust
// crates/dionaea/src/management.rs

/// Read-only status snapshot, serializable for any transport.
#[derive(serde::Serialize)]
pub struct StatusReport {
    pub timestamp: String,                          // RFC3339
    pub uptime_seconds: u64,
    pub version: String,
    pub services: Vec<ServiceStatus>,               // per-service: name, listening addr, state
    pub connections: ConnectionSummary,              // active, total, per-protocol, per-source-ip
    pub incidents_since_last_report: Vec<IncidentSummary>,  // origin, timestamp, key fields
    pub alerts: Vec<Alert>,                         // high-priority events (filtered by AlertRules)
    pub log_tail: Vec<LogEntry>,                    // recent warning+ log lines
    pub resources: ResourceStatus,                  // fd_used, fd_limit, memory_rss
    pub errors_since_last_report: Vec<ErrorSummary>,
}

/// Commands the management server can send back.
#[derive(serde::Deserialize)]
pub enum ManagementCommand {
    /// Start a service that's configured but not running
    StartService { name: String },
    /// Stop a running service (drain connections first)
    StopService { name: String },
    /// Block a source IP (add to deny list)
    BlockIp { addr: IpAddr, duration_secs: Option<u64> },
    /// Unblock a source IP
    UnblockIp { addr: IpAddr },
    /// Change log level at runtime
    SetLogLevel { level: String },
    /// Graceful restart (stop all, reload config, start all)
    Restart,
    /// Request a full status report on next poll
    RequestStatus,
    /// Update a config value (limited to safe keys)
    SetConfig { key: String, value: String },
}

/// Trait that transports implement.
pub trait ManagementTransport: Send + Sync {
    /// Poll interval (transport-specific, configured per-transport)
    fn poll_interval(&self) -> Duration;

    /// Push a status report to the management server.
    /// Returns any pending commands from the server.
    async fn poll(&self, report: &StatusReport) -> Result<Vec<ManagementCommand>, Error>;
}
```

**Hooks into the core (what management needs access to):**

| Hook | Source | Purpose |
|------|--------|---------|
| `ConnectionRegistry::summary()` | connection/mod.rs | Active connection counts, per-protocol, per-IP |
| `IHandlerRegistry::recent_incidents()` | ihandler.rs | Ring buffer of recent incidents for reporting |
| `ServiceRegistry::list()` / `start()` / `stop()` | loader.rs | Service lifecycle control |
| `metrics::snapshot()` | metrics.rs | Current metric values |
| IP deny list (read/write) | throttle.rs | Block/unblock source IPs |
| `tracing` level filter (dynamic) | main.rs | Runtime log level changes |
| Config store (read, limited write) | config.rs | Runtime config updates |

**Ring buffer for incidents:** The `IHandlerRegistry` maintains a bounded ring buffer
(configurable size, default 1000) of recent `IncidentSummary` structs. Each poll drains
entries added since the last poll. This avoids unbounded memory growth between polls.

**IP deny list:** A `HashSet<IpAddr>` (with optional TTL per entry) checked at connection
accept time. Management commands can add/remove entries. Persisted to a file on graceful
shutdown, reloaded on startup.

**Transport modules are Cargo features:**
```toml
# crates/dionaea/Cargo.toml
[features]
mgmt-https = ["dep:reqwest"]   # JSON/HTTPS poll transport
mgmt-dns = []                  # DNS-based poll transport (no extra deps)
```

The transport implementations live in `crates/dionaea/src/management/`:
```
management/
├── mod.rs          # ManagementApi trait, StatusReport, ManagementCommand
├── state.rs        # Incident ring buffer, IP deny list, service registry queries
├── https.rs        # JSON/HTTPS poll transport (behind feature flag)
└── dns.rs          # DNS-based poll transport (behind feature flag)
```

**Poll cycle (same for both transports):**
1. Collect `StatusReport` from internal state
2. Serialize and send to management server via transport
3. Receive `Vec<ManagementCommand>` in response
4. Execute each command, log results
5. Sleep for `poll_interval`

**Security:** Management transports authenticate to the server (TLS client certs for
HTTPS, TSIG/HMAC for DNS). The honeypot never exposes a listening management port —
it only makes outbound poll connections. Commands are validated before execution
(e.g., `SetConfig` only allows a whitelist of safe keys).

---

## Project Layout

Two crates, not four. The original plan split `core`, `python`, and `dionaea` into
separate crates. That creates unnecessary indirection: `core` needs to call Python
(protocol callbacks, incident dispatch) but can't depend on `python` without a circular
dependency, so it has to use trait objects and callbacks. Nobody will use `core` without
Python — this is a honeypot that runs Python protocols. Collapsing them eliminates the
trait-object indirection and simplifies the dependency graph.

`shell-detect` stays separate: it's genuinely standalone (pure byte pattern scanning,
zero deps on the rest of the system). Could be published independently.

```
dionaea-v2/
├── Cargo.toml                       # Workspace root
├── deny.toml                        # cargo-deny config (licenses, advisories)
├── rustfmt.toml                     # Formatting config (see Linting & Formatting)
├── crates/
│   ├── dionaea/                     # The application (binary + library in one crate)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs             # Entry point: config, init, signal handling, tokio runtime
│   │       ├── lib.rs              # Crate root: re-exports for integration tests
│   │       ├── error.rs            # Error types (thiserror)
│   │       ├── config.rs           # TOML config loading, validation, env overrides
│   │       ├── connection/
│   │       │   ├── mod.rs          # ConnectionMeta, TaskState, state machine, lifecycle
│   │       │   ├── tcp.rs          # TCP accept, connect, I/O
│   │       │   ├── tls.rs          # TLS handshake, encrypted I/O
│   │       │   ├── udp.rs          # UDP listener, peer table
│   │       │   ├── throttle.rs     # Bandwidth throttle (token bucket) + byte accounting
│   │       │   └── limits.rs       # FD limits, per-IP counters, IP deny list
│   │       ├── incident.rs         # Incident struct, typed data, dispatch
│   │       ├── ihandler.rs         # IHandler registry, wildcard pattern matching
│   │       ├── processor.rs        # Processor pipeline tree
│   │       ├── bistream.rs         # Bidirectional stream recording
│   │       ├── dns.rs              # Async DNS resolution
│   │       ├── node_info.rs        # Network address info
│   │       ├── metrics.rs          # Prometheus metrics definitions
│   │       ├── python/             # PyO3 bridge (module, not separate crate)
│   │       │   ├── mod.rs          # Python init, module registration
│   │       │   ├── connection.rs   # #[pyclass] PyConnection
│   │       │   ├── incident.rs     # #[pyclass] PyIncident
│   │       │   ├── ihandler.rs     # #[pyclass] PyIHandler
│   │       │   ├── node_info.rs    # #[pyclass] PyNodeInfo
│   │       │   ├── stats.rs        # #[pyclass] speed/accounting/timeouts
│   │       │   ├── dionaea.rs      # #[pyclass] global singleton (config, version)
│   │       │   ├── convert.rs      # Rust ↔ Python type conversions
│   │       │   └── loader.rs       # Python module import, ServiceLoader/IHandlerLoader
│   │       └── management/
│   │           ├── mod.rs          # ManagementApi, StatusReport, commands
│   │           ├── state.rs        # Incident ring buffer, IP deny list, queries
│   │           ├── https.rs        # JSON/HTTPS poll transport (feature-gated)
│   │           └── dns.rs          # DNS-based poll transport (feature-gated)
│   │
│   └── shell-detect/                # Shellcode detection (standalone, zero deps on dionaea)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── x86.rs              # x86-32 GetPC patterns
│           ├── x64.rs              # x86-64 GetPC patterns
│           └── mips.rs             # MIPS GetPC patterns
│
├── conf/                            # Default configuration files
│   ├── dionaea.toml                # Main config (TOML, read by Rust)
│   ├── services/                   # Per-service YAML configs (read by Python)
│   └── ihandlers/                  # Per-handler YAML configs (read by Python)
│
├── python/                          # Python protocol modules (copied from current repo)
│   └── dionaea/
│       ├── __init__.py             # ServiceLoader, IHandlerLoader (minor edits for import path)
│       ├── smb/                    # All protocol modules unchanged
│       ├── http.py
│       ├── ftp.py
│       ├── mysql/
│       ├── sip/
│       └── ...                     # All other protocol + ihandler modules
│
├── fuzz/                            # cargo-fuzz targets
│   ├── Cargo.toml
│   └── fuzz_targets/
│       ├── shellcode_detect.rs
│       └── config_parse.rs
│
├── deploy/
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── dionaea.service             # systemd unit
│   └── dionaea.toml.example        # Annotated example config
│
└── tests/                           # Integration tests
    ├── common/mod.rs               # Test helpers (start daemon, connect, etc.)
    ├── tcp_echo.rs
    ├── tls_handshake.rs
    ├── incident_dispatch.rs
    ├── python_bridge.rs
    └── python/                      # Existing pytest suite (copied from current)
        ├── conftest.py
        ├── requirements.txt
        └── ... (tftp, ftp, smb, http, mysql tests)
```

**Why not more crates?** Optional modules (pcap, nfq, netlink, download, metrics,
management transports) are Cargo features on the `dionaea` crate, not separate crates.
They share core types and are too small to justify separate compilation units.

```toml
# crates/dionaea/Cargo.toml
[features]
default = ["download"]
pcap = ["dep:pcap"]
nfq = ["dep:nfq"]              # implies target_os = "linux"
netlink = ["dep:rtnetlink"]    # implies target_os = "linux"
download = ["dep:reqwest"]
metrics = ["dep:metrics", "dep:metrics-exporter-prometheus"]
mgmt-https = ["dep:reqwest"]   # JSON/HTTPS poll-based remote management
mgmt-dns = []                  # DNS-based poll-based remote management
```

---

## Phase 1: PyO3 Proof-of-Concept + Skeleton (Weeks 1-2)

**Goal:** Validate PyO3 integration (go/no-go gate), then set up workspace, config, and
logging.

### Days 1-3: PyO3 Proof-of-Concept (Go/No-Go Gate)

Before investing in infrastructure, validate the fundamental premise: can PyO3 replicate
the Cython binding API closely enough for existing Python protocols to work?

Build a minimal proof-of-concept that:
- [ ] Define `#[pyclass(subclass)]` `PyConnection` with `handle_io_in` and `send` methods
- [ ] Subclass it in Python: `class echo(connection): def handle_io_in(self, data): ...`
- [ ] Call `handle_io_in` from Rust via `spawn_blocking` + `Python::with_gil`
- [ ] Call `send()` from Python back into Rust
- [ ] Verify method resolution order works for all `handle_*` callbacks
- [ ] Verify `#[pyclass(subclass)]` supports Python `__init__` with `super().__init__()` call
- [ ] Measure `spawn_blocking` + GIL round-trip latency under load:
  - Target: <100μs P99 per callback
  - If >100μs P99: design alternative callback dispatch (dedicated Python thread with a
    queue, matching C's single-threaded model)

**This is a go/no-go gate.** If `#[pyclass(subclass)]` doesn't support the Python protocol
subclassing pattern, or if callback overhead is prohibitive, the plan needs revision before
proceeding.

### Days 4-10: Workspace Setup + Config + Logging

**Files to create:**
- Workspace `Cargo.toml` + `deny.toml`
- `crates/dionaea/Cargo.toml` + `src/main.rs`
- `crates/dionaea/src/lib.rs` + `src/error.rs` + `src/config.rs`
- `crates/dionaea/src/python/mod.rs`

**What main.rs does:**
1. Load and validate TOML config (with env var overrides: `DIONAEA_LISTEN_ADDR`, etc.)
2. Initialize tracing (JSON file logger + optional stdout, domain/level filtering per target)
3. Initialize Python via PyO3 (`pyo3::prepare_freethreaded_python()`)
4. Acquire GIL, import `sys`, log version
5. Start tokio runtime
6. Register signal handlers (SIGINT, SIGTERM → graceful shutdown; SIGHUP → log reopen)
7. Ignore SIGPIPE

**Config structure:**

```toml
[dionaea]
user = "dionaea"
group = "dionaea"
# workdir = "/opt/dionaea"  # optional, defaults to binary location

[dionaea.listen]
mode = "manual"  # or "getifaddrs"
addresses = ["0.0.0.0"]
interfaces = ["eth0"]

[dionaea.limits]
max_fds_pct = 70           # reject connections above this % of RLIMIT_NOFILE
max_connections_per_ip = 50
recv_buffer_size = 65536   # bytes per read call (safety cap)
# max_memory_mb = 0        # 0 = no limit

[dionaea.deny_list]
persist_file = "/var/lib/dionaea/deny_list.json"
# Preloaded entries (optional):
# deny = ["192.168.1.100"]

[logging]
level = "info"

[[logging.targets]]
type = "file"
path = "/var/log/dionaea/dionaea.log"
format = "json"            # or "text"
levels = "all,-debug"
domains = "*"

[[logging.targets]]
type = "stdout"
format = "text"
levels = "info,warning,error,critical"
domains = "*"

[modules]
download = true
pcap = false
nfq = false
netlink = false

[modules.python]
imports = ["dionaea"]
service_configs = ["/etc/dionaea/services-enabled/*.yaml"]
ihandler_configs = ["/etc/dionaea/ihandlers-enabled/*.yaml"]

[dionaea.admin]
listen = "127.0.0.1"              # admin interface (metrics, health) — separate from honeypot

# [admin.metrics]
# enabled = false
# port = 9090

# [admin.health]
# enabled = false
# port = 8080

# [management]
# transport = "https"          # or "dns"
# poll_interval_secs = 60
# server = "https://mgmt.example.com/api/v1/honeypot"
# # For HTTPS: TLS client cert for authentication
# client_cert = "/etc/dionaea/mgmt-client.pem"
# client_key = "/etc/dionaea/mgmt-client-key.pem"
# # For DNS: TSIG key for authentication
# # tsig_key_name = "dionaea-mgmt"
# # tsig_key_secret = "base64..."
# # dns_server = "mgmt-dns.example.com"
# incident_buffer_size = 1000  # ring buffer for incident reports
```

**Config validation (at load time, not runtime):**
- User/group exist (via `nix::unistd::User::from_name`)
- Listen addresses parse as valid IPs
- Admin listen address parses as valid IP, defaults to `127.0.0.1`
- Admin listen address is NOT the same as a honeypot listen address (prevent accidental exposure)
- Log file parent directories exist and are writable
- Service/ihandler config globs resolve to at least one file
- Port numbers in range

**Env var overrides:** Any config key can be overridden via `DIONAEA_` prefix with `__`
as section separator. Example: `DIONAEA_DIONAEA__LISTEN__MODE=getifaddrs` overrides
`dionaea.listen.mode`.

**Tests:**
- PoC: PyO3 subclass test (Python class extends `#[pyclass(subclass)]`, callbacks fire)
- PoC: spawn_blocking + GIL round-trip latency benchmark (<100μs P99 target)
- Unit: Config round-trip (struct → TOML → struct), env override merging, validation errors
- Integration: `cargo run -- -c test.toml` starts and exits cleanly on SIGTERM

---

## Phase 2: Core Types + Incident System (Weeks 3-4)

**Goal:** ConnectionMeta, TaskState, state machine, NodeInfo, OpaqueData, Incident, IHandler
dispatch. No I/O yet — just the types and their state transitions.

### `crates/dionaea/src/connection/mod.rs`

```rust
pub enum Transport { Tcp, Tls, Udp }
pub enum ConnectionType { Accept, Bind, Connect, Listen }

pub enum ConnectionState {
    None, Resolve, Connecting, Handshake,
    Established, Shutdown, Close, Reconnect,
}

pub struct ConnectionId(u64);  // Monotonic counter, not recycled

/// Metadata visible to Python and the incident system. Stored in ConnectionRegistry.
pub struct ConnectionMeta {
    id: ConnectionId,
    transport: Transport,
    connection_type: ConnectionType,
    state: ConnectionState,
    local: NodeInfo,
    remote: NodeInfo,
    stats: ConnectionStats,
    timeouts: ConnectionTimeouts,
}

/// I/O state owned exclusively by the connection's tokio task. Never shared.
struct TaskState {
    socket: TcpStream,  // or TlsStream<TcpStream>, or UdpSocket
    send_rx: mpsc::UnboundedReceiver<SendMessage>,  // drained by task, fed by Python send()
    recv_buf: [u8; 65536],
    idle_timeout: Pin<Box<Sleep>>,
    sustain_timeout: Pin<Box<Sleep>>,
    py_handler: Py<PyAny>,
}
```

**Ownership model:** Connection state is split between two owners (see Cross-Cutting Concerns
§Ownership for the full rationale):
- **The tokio task** owns I/O state (`TaskState`): socket, buffers, timeouts, Python handler
  reference. This is the hot path — no locks needed for I/O operations.
- **The `ConnectionRegistry`** (`DashMap<ConnectionId, ConnectionMeta>`) holds metadata that
  Python reads via `#[pyo3(get)]`. The task updates the registry on state transitions.
- **Python's `send()`** pushes `SendMessage` variants (data, datagrams, control messages)
  through an `mpsc::UnboundedSender<SendMessage>` channel to the task. No shared mutable
  buffers.

Python and incidents reference connections by `ConnectionId`, not by `Arc<Mutex<Connection>>`.
This avoids deadlocks, GIL + Mutex ordering issues, and lock contention on the I/O hot path.
Stale IDs (connection already closed) raise `ReferenceError("the object requested does not exist")`
to Python — matching the current Cython behavior.

### Connection Lifecycle

Methods are only valid in certain states. Calling a method in an invalid state returns an
error to Python.

| Method | None | Resolve | Connecting | Handshake | Established | Shutdown | Close |
|--------|------|---------|------------|-----------|-------------|----------|-------|
| `bind()` | yes | | | | | | |
| `listen()` | yes* | | | | | | |
| `connect()` | yes | | | | | | |
| `send()` | buffer | | buffer | | yes | | error |
| `close()` | yes | yes | yes | yes | yes | | |
| `ref()` | yes | yes | yes | yes | yes | yes | yes |
| `unref()` | yes | yes | yes | yes | yes | yes | yes |

\* `listen()` requires a prior `bind()`.

`__init__("tcp")` creates a `ConnectionMeta` entry in the registry with `state=None` and
allocates the `mpsc` channel pair. No tokio task is spawned yet. The task is spawned lazily:
- `listen()` spawns an accept loop task
- `connect()` spawns a connect + I/O task

`send()` in `None`/`Connecting` state buffers `SendMessage` variants in the channel. The task
drains buffered data when it reaches `Established`.

### `crates/dionaea/src/incident.rs`

```rust
pub enum OpaqueData {
    Int(i64),
    String(String),
    Bytes(Vec<u8>),
    ConnectionRef(ConnectionId),  // ID, not Arc<Mutex<>>
    List(Vec<OpaqueData>),
    Dict(HashMap<String, OpaqueData>),
    None,
}

pub struct Incident {
    origin: String,
    data: HashMap<String, OpaqueData>,
}
```

### `crates/dionaea/src/ihandler.rs`

```rust
pub struct IHandlerRegistry {
    handlers: Vec<IHandler>,
}

struct IHandler {
    pattern: WildcardPattern,  // Custom: '*' matches any chars including dots (not glob crate)
    // Callback is either a Rust function or a Python callable.
    // Python handlers dominate in practice.
}

impl IHandlerRegistry {
    pub fn dispatch(&self, incident: &Incident) {
        for handler in &self.handlers {
            if handler.pattern.matches(&incident.origin) {
                // Call handler (Python handlers via spawn_blocking + GIL)
            }
        }
    }
}
```

Pattern matching: `"dionaea.connection.*"` matches `"dionaea.connection.tcp.accept"`.

**Glob semantics:** GLib's `g_pattern_spec_match` treats `*` as matching **any characters
including dots**. The Rust `glob` crate is designed for file paths and treats `/` specially.
Don't use `glob` — implement a simple wildcard matcher directly (just `*` = match anything,
`?` = match one char). It's ~20 lines of code. Test against the full set of incident origin
strings and ihandler patterns in the current codebase to confirm behavior matches.

### DNS resolution

```rust
// crates/dionaea/src/dns.rs
// Wraps hickory-resolver for async A + AAAA lookups.
// Used by outbound connection.connect() when given a hostname.
pub async fn resolve(host: &str) -> Result<Vec<IpAddr>, Error> {
    // Parallel A + AAAA queries, return first successful
    // Timeout: 3 seconds (matching current libudns behavior)
}
```

**Tests:**
- Unit: Connection state machine transitions (valid and invalid)
- Unit: Incident set/get with all OpaqueData variants
- Unit: IHandler glob pattern matching (exact, wildcard, no-match)
- Unit: OpaqueData ↔ Python conversion round-trips
- Proptest: Any OpaqueData value round-trips through Python conversion

---

## Phase 3: PyO3 Bridge (Weeks 5-6)

**Goal:** Replicate binding.pyx (1,370 lines) as PyO3 classes. This is the hardest phase
because getting the API wrong means Python protocols won't work.

**Key reference file:** `modules/python/binding.pyx` — every line maps to a PyO3 impl.

**Classes to implement (maps to binding.pyx):**

### `crates/dionaea/src/python/connection.rs` — `#[pyclass(subclass, weakref)] PyConnection`

```rust
#[pyclass(subclass, weakref)]
pub struct PyConnection {
    id: Option<ConnectionId>,  // None after invalidation
    send_tx: Option<mpsc::UnboundedSender<SendMessage>>,
    bistream: Option<Py<PyList>>,  // Set by processor pipeline, None until processors() called
}
```

**Class decorators:** `subclass` is required — all Python protocols subclass `connection`.
`weakref` is required — `connection_new()` returns `weakref.proxy(connection(...))`.

Properties (read via registry lookup, write via channel/registry):
  remote: PyNodeInfo           # registry lookup; host/port settable (writes back to registry)
  local: PyNodeInfo            # registry lookup; host/port settable (writes back to registry)
  transport: String            # "tcp", "tls", "udp" — registry lookup
  protocol: String             # protocol name or class name — registry lookup
  status: String               # state as string — registry lookup
  timeouts: PyConnectionTimeouts  # read/write (see Property Write-Back below)
  _in: PyConnectionStats       # ingress stats (speed/accounting)
  _out: PyConnectionStats      # egress stats (speed/accounting)

Methods (#[pymethods]):
  __init__(proto: Option<String>)
  __hash__() -> u64            # returns self.id.0; required for dict/set storage
  __richcmp__(other, op) -> bool  # compares by ConnectionId
  bind(addr: String, port: u16, iface: Option<String>) -> PyResult<i32>
  listen(size: Option<i32>) -> PyResult<i32>
  connect(addr: String, port: u16, iface: Option<String>) -> PyResult<()>
  send(data: &[u8], local: Option<(String,u16)>, remote: Option<(String,u16)>) -> PyResult<()>
  close() -> PyResult<()>
  processors() -> PyResult<()>
  ref_() -> i32                # named ref_ to avoid Rust keyword
  unref() -> i32

Protocol callbacks (Python overrides these):
  handle_established()
  handle_io_in(data: &[u8]) -> usize  # returns bytes consumed
  handle_io_out()
  handle_disconnect() -> bool          # True = reconnect
  handle_error(err: PyObject)
  handle_timeout_idle() -> bool
  handle_timeout_sustain() -> bool
  handle_timeout_listen() -> bool
  handle_origin(parent: PyConnection)

**Connection invalidation:** Every method that accesses the registry checks `self.id.is_some()`
first. If `None`, raise `ReferenceError("the object requested does not exist")` — matching the
current Cython behavior exactly. `id` is set to `None` when:
- `handle_disconnect()` returns `false` (don't reconnect)
- The connection is freed (refcount reaches 0 after close)
Python protocols may still hold references to invalidated PyConnection objects (in dicts,
incident fields, etc.) — they get `ReferenceError` on any access, which is the existing contract.

### `crates/dionaea/src/python/incident.rs` — `#[pyclass] PyIncident`

```
Properties: origin (read-only)
Methods: __init__(origin), report(), keys(), set(key, value), get(key)
Dynamic attrs: __getattr__, __setattr__ with type dispatch
  (int, str, bytes, connection, list, dict, None)
No __getitem__/__setitem__ — the current Cython code doesn't implement subscript access
and no Python protocol uses it. All access is attribute-style: incident.con = value.
```

### `crates/dionaea/src/python/ihandler.rs` — `#[pyclass] PyIHandler`

```
Methods: __init__(pattern), start(), stop(), register(), unregister()
Callback: handle_incident(incident)
Dynamic dispatch: origin dots→underscores for method lookup (see below)
```

**IHandler dispatch pattern (must match exactly):** When an incident arrives, the dispatch
logic replaces dots with underscores in the origin and looks for a specific method:

```rust
// In spawn_blocking + Python::with_gil:
let origin = incident.origin.replace('.', "_");
let method_name = format!("handle_incident_{origin}");
match handler.bind(py).getattr(method_name.as_str()) {
    Ok(method) => method.call1((py_incident,))?,
    Err(_) => handler.bind(py).call_method1("handle_incident", (py_incident,))?,
};
```

Example: incident origin `"dionaea.connection.tcp.accept"` → try
`handle_incident_dionaea_connection_tcp_accept(incident)` first. If that method doesn't
exist (AttributeError), fall back to `handle_incident(incident)`. Every ihandler in the
codebase (logsql, log_json, hpfeeds, etc.) relies on this pattern.

### `crates/dionaea/src/python/node_info.rs` — `#[pyclass] PyNodeInfo`

```
Properties: host (r/w), port (r/w), hostname (r/o)
```

### `crates/dionaea/src/python/stats.rs`

```
PyConnectionTimeouts: idle, listen, sustain, handshake, connecting, reconnect (all f64 r/w)
PyConnectionSpeed: bps (r/o), limit (r/w)
PyConnectionAccounting: bytes (r/o), limit (r/w)
PyConnectionStats: speed, accounting (nested objects)
```

### `crates/dionaea/src/python/dionaea.rs` — `#[pyclass] PyDionaea`

```
Methods: config() -> dict, getifaddrs() -> dict, version() -> str
Global singleton exposed as g_dionaea
```

### `crates/dionaea/src/python/convert.rs`

```
Rust ↔ Python conversions:
  OpaqueData enum ↔ PyObject (int, str, bytes, connection, list, dict, None)
  HashMap<String, OpaqueData> ↔ Python dict
  Vec<OpaqueData> ↔ Python list
```

### `crates/dionaea/src/python/loader.rs`

Python module loading + service management:
- Set `sys.path` to include `python/` directory
- Import `dionaea` package → triggers `load_submodules()`
- Load YAML config files for ihandlers and services (Python reads these, not Rust)
- Instantiate ServiceLoaders and IHandlerLoaders
- For each configured service: find matching ServiceLoader, call `start(addr, iface, config)`

### Factory Instantiation (Accept Path)

When a listener accepts a new connection, the Rust core must create a **child** Python object
that is an instance of the **same subclass** as the listener. This is the hardest PyO3 problem
in the entire project.

**Current Cython behavior (binding.pyx `_factory()`):**
1. Get the parent (listener's Python protocol instance) from the connection context
2. Clone the parent's class — `PY_CLONE(parent)` creates a new instance of `type(parent)`
3. Set `factory = True` on the child (suppresses manual INCREF)
4. Set the C connection pointer on the child BEFORE calling `__init__`
5. Call `__init__()` — which sees `thisptr != NULL` and skips `connection_new()`
6. Call `apply_parent_config(parent)` to copy shared config values
7. Set the child as the protocol context on the new C connection

**PyO3 implementation:**

The challenge is that `#[new]` (PyO3's `__init__` equivalent) runs as part of object
construction. We need `__init__` to know it's being factory-created so it doesn't allocate
a new Rust connection. Use a thread-local flag:

```rust
thread_local! {
    static FACTORY_CON_ID: Cell<Option<ConnectionId>> = Cell::new(None);
}

/// Called by the accept loop task (inside spawn_blocking + GIL):
fn factory_create(py: Python<'_>, parent: &Py<PyAny>, con_id: ConnectionId,
                  send_tx: mpsc::UnboundedSender<SendMessage>) -> PyResult<Py<PyAny>> {
    // Set the thread-local so __init__ knows this is a factory call
    FACTORY_CON_ID.with(|f| f.set(Some(con_id)));

    // Instantiate the same class as the parent
    let parent_type = parent.bind(py).get_type();
    let transport_str = /* get transport string for this connection */;
    let child = parent_type.call1((transport_str,))?;

    // Clear the thread-local
    FACTORY_CON_ID.with(|f| f.set(None));

    // Copy shared config from parent
    if let Ok(method) = child.getattr("apply_parent_config") {
        let _ = method.call1((parent,));
    }

    Ok(child.into())
}

#[pymethods]
impl PyConnection {
    #[new]
    fn new(proto: Option<String>) -> PyResult<Self> {
        // Check if this is a factory call
        let factory_id = FACTORY_CON_ID.with(|f| f.take());
        if let Some(con_id) = factory_id {
            // Factory path: connection already exists in registry
            return Ok(PyConnection {
                id: Some(con_id),
                send_tx: /* passed through another thread-local or set after construction */,
                bistream: None,
            });
        }
        // Normal path: Python is creating a new connection
        // Allocate ConnectionMeta in registry, create mpsc channel
        // ...
    }
}
```

**`__init__` signature validation:** The current Cython code (binding.pyx line 464) inspects
`self.__init__` and raises `LoaderError` if any parameter lacks a default value. This prevents
protocol classes from defining `def __init__(self, required_arg)` which would break factory
instantiation. Replicate this check in `__init_subclass__` (called automatically when a Python
class subclasses `connection`):

```rust
#[pymethods]
impl PyConnection {
    #[classmethod]
    fn __init_subclass__(cls: &Bound<'_, PyType>, _kwargs: &Bound<'_, PyDict>) -> PyResult<()> {
        // Validate that __init__ has no required args (besides self)
        // This catches misconfigured protocol classes at import time
        Ok(())
    }
}
```

**Connection invalidation on `_garbage`:** When the connection task exits (close or error):
1. Remove the `ConnectionMeta` from the registry (when refcount = 0)
2. The next Python access finds the registry entry missing and sets `self.id = None`
3. All subsequent Python access raises `ReferenceError("the object requested does not exist")`

`handle_disconnect` returning `false` (don't reconnect) sets `self.id = None` immediately,
matching the current Cython behavior where `thisptr` is set to `NULL` on disconnect.

### Property Write-Back Design

Sub-object properties (`remote`, `local`, `timeouts`, `_in`, `_out`) need to read from and
write back to the connection state. Each sub-object holds a `ConnectionId` and a reference
to the registry/channel:

**Read path (all sub-objects):** Look up `ConnectionMeta` in the `ConnectionRegistry` by
`ConnectionId`. DashMap read shards are lock-free. Return the current value.

**Write path (depends on what's being written):**

| Property | Write target | Mechanism |
|----------|-------------|-----------|
| `remote.host`, `remote.port` | ConnectionMeta | Direct registry write (DashMap entry) |
| `local.host`, `local.port` | ConnectionMeta | Direct registry write |
| `timeouts.idle`, `.sustain`, etc. | TaskState | Send `ControlMessage::SetTimeout { which, value }` through mpsc channel |
| `_in.speed.limit`, `_out.speed.limit` | TaskState | Send `ControlMessage::SetThrottle { direction, limit }` through mpsc channel |
| `_in.accounting.limit`, `_out.accounting.limit` | TaskState | Send `ControlMessage::SetAccountingLimit { direction, limit }` through mpsc channel |
| `_in.speed.bps`, `_in.accounting.bytes` | ConnectionMeta | Read-only; task updates registry periodically |

The mpsc channel carries both data and control messages:

```rust
pub enum SendMessage {
    /// TCP/TLS: send data to the remote
    Data(Bytes),
    /// UDP: send data to a specific remote, from a specific local address
    Datagram { data: Bytes, local: SocketAddr, remote: SocketAddr },
    /// Control: update timeout value
    SetTimeout { which: TimeoutKind, value: f64 },
    /// Control: update throttle speed limit
    SetThrottle { direction: Direction, limit: f64 },
    /// Control: update accounting byte limit
    SetAccountingLimit { direction: Direction, limit: u64 },
}
```

This means the channel type changes from `mpsc::UnboundedSender<Bytes>` to
`mpsc::UnboundedSender<SendMessage>`. The connection task drains the channel and
dispatches each variant appropriately.

### Error Callback Exception Mapping

When the Rust core needs to call `handle_error`, it must create specific Python exception
instances from `dionaea.exception`. The current Cython code (binding.pyx lines 853-886) maps
error types to exception classes:

```rust
fn create_error_exception(
    py: Python<'_>,
    err: ConnectionError,
    connection: &Py<PyAny>,
) -> PyResult<PyObject> {
    let exception_mod = py.import("dionaea.exception")?;
    let (class_name, error_id) = match err {
        ConnectionError::DnsTimeout => ("ConnectionDNSTimeout", 0),
        ConnectionError::Unreachable => ("ConnectionUnreachable", 1),
        ConnectionError::NoSuchDomain => ("ConnectionNoSuchDomain", 2),
        ConnectionError::TooMany => ("ConnectionTooMany", 3),
    };
    let cls = exception_mod.getattr(class_name)?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("connection", connection)?;
    kwargs.set_item("error_id", error_id)?;
    Ok(cls.call((), Some(&kwargs))?.into())
}
```

The `handle_error` callback receives this exception object, not a raw error code.

### Callback Error Recovery

Protocol callback error handling must match the current Cython behavior exactly:

**`handle_io_in` on exception (binding.pyx lines 824-831):**
1. Log the error with traceback
2. If the connection is still valid: call `close()` on it
3. Return `len(data)` — consume all bytes (prevents re-delivery of the same data)

**`handle_established`, `handle_io_out` on exception (binding.pyx lines 814-817, 837-841):**
1. Log the error with traceback
2. If the connection is still valid: call `close()` on it

**`handle_disconnect` on exception:**
1. Log the error
2. Return `false` (don't reconnect)

**`handle_origin`, timeout callbacks on exception:**
1. Log the error with traceback
2. Continue (don't close — the connection may still be usable)

This error recovery is a safety net: a buggy Python protocol handler that raises once won't
crash the whole system. Without it, a single exception in `handle_io_in` would cause the
same data to be re-delivered infinitely.

### Bistream Attribute

The processor pipeline adds a `bistream` attribute to connection instances — a Python list of
`('in', data)` / `('out', data)` tuples. In the current Cython code, `process_process` sets
`instance.bistream = []` when the processor tree attaches, and `process_io_in`/`process_io_out`
append chunks.

In PyO3, `PyConnection` stores `bistream: Option<Py<PyList>>`. When `processors()` is called
and the processor tree attaches, set `self.bistream = Some(PyList::empty(py).into())`. The
processor's `io_in`/`io_out` callbacks append `('in', data)` or `('out', data)` tuples to
this list inside `spawn_blocking` + GIL.

**Tests:**
- Unit: Write a minimal echo.py protocol. Import via PyO3. Verify all properties accessible.
  Verify handle_* callbacks are called.
- Unit: Create PyIncident, set fields of every type, verify __getattr__/__setattr__ work.
  Verify __getitem__/__setitem__ are NOT implemented (no subscript access).
- Unit: Create PyIHandler with pattern, register, create incident, verify dispatch calls
  the Python handler's specific method (dots→underscores), then falls back to handle_incident.
- Unit: Factory instantiation — create listener, accept child, verify child is same class.
- Unit: Connection invalidation — close connection, verify ReferenceError on property access.
- Unit: Error recovery — protocol that raises in handle_io_in, verify connection closes and
  bytes are consumed.
- Integration: Full round-trip — load echo.py, start listener, connect, send data, verify echo.

---

## Phase 4: TCP/UDP I/O + TLS (Weeks 7-9)

**Goal:** Real network I/O. TCP accept/connect, UDP recv/send, TLS handshake.
Wire up to Python protocol callbacks.

### `crates/dionaea/src/connection/tcp.rs`

Key functions (async with tokio):
- `tcp_listen(addr, port)` → TcpListener
- `tcp_accept(listener)` → factory-instantiate child PyConnection (see Phase 3 §Factory
  Instantiation), create ConnectionMeta in registry, spawn handler task
- `tcp_connect(addr, port)` → ConnectionMeta (with DNS resolution if hostname)
- Handler task I/O loop: read → call `handle_io_in` via `spawn_blocking` (await before
  next read — see GIL Strategy rule 6) → drain `SendMessage` channel → dispatch control
  messages, write data to socket
- Callback error recovery: see Phase 3 §Callback Error Recovery for per-callback behavior
- `tcp_disconnect(connection)` → graceful shutdown, set `PyConnection.id = None` if
  `handle_disconnect` returns false, update registry, remove when refcount=0

### `crates/dionaea/src/connection/tls.rs`

- Uses `openssl` crate (`SslAcceptor`, `SslConnector`)
- `tokio-openssl` for async TLS streams
- Support weak ciphers via `SslMethod::tls()` + `set_cipher_list()`
- Self-signed cert generation (`X509Builder`) with configurable subject fields:
  ```toml
  [ssl.default]
  c = "US"              # Country
  cn = "localhost"      # Common Name
  o = "Server"          # Organization
  ou = "IT"             # Organizational Unit
  key_bits = 2048       # RSA key size
  ```
  These matter for honeypot deception — making the cert resemble a specific vendor/service.
- DH parameter loading for old clients (1024, 2048, 3072, 4096, 6144, 8192-bit RFC primes)
- `SSL_set_dh_auto` as fallback

### `crates/dionaea/src/connection/udp.rs`

- `UdpSocket` with peer table (`HashMap<SocketAddr, ConnectionId>`)
- `recvmsg` via `nix` crate for `IP_PKTINFO` (capture destination IP)
- Per-peer connection objects
- Packet queuing for send
- Platform: `IP_PKTINFO` on Linux, fallback to basic `recvfrom` on macOS

### `crates/dionaea/src/connection/throttle.rs`

Implements all per-connection rate limiting (see "Rate Limiting & Resource Management"
in Cross-Cutting Concerns for the full design):
- `Throttle` struct: token bucket bandwidth limiter (Layer 3)
- `Accounting` struct: cumulative byte counter with cap (Layer 4)
- Connection timeout management: idle, sustain, listen, handshake, connecting, close (Layer 5)
- `ConnectionLimits` struct: global FD check (Layer 1) + per-IP counter (Layer 2)
- `IpDenyList` struct: blocked IPs with optional TTL (Layer 8)

Sleep-based backpressure uses `tokio::time::sleep` (cooperative, not blocking).
Timeouts integrate into the connection task's `tokio::select!` loop.

**Tests:**
- Unit: Throttle token bucket — proptest: any (rate, elapsed_time, bytes_sent) tuple
  produces correct allowance. Edge cases: rate=0 (unlimited), rate=1, huge burst.
- Unit: Accounting — bytes accumulate correctly, limit triggers at exact boundary.
- Unit: Timeout firing — idle resets on activity, sustain never resets.
- Unit: Per-IP counter — increment on accept, decrement on close, reject above limit.
- Unit: IP deny list — add/remove, TTL expiry, persistence round-trip.
- Integration: TCP echo round-trip through Python protocol handler
- Integration: TLS handshake with strong and weak cipher suites
- Integration: UDP send/receive with peer table management
- Fuzz: Feed random bytes to TCP read path, verify no panics

---

## Phase 5: Processor Pipeline + Bistream + Shellcode (Week 10)

**Goal:** Processor tree, bistream recording, shellcode detection.

### `crates/dionaea/src/processor.rs`

The processor pipeline is a **tree**, not a chain. The current C code uses `GNode` to build
parent/child relationships configured like:

```
filter
├── speakeasy
├── streamdumper
└── emu
```

```rust
pub trait Processor: Send {
    fn name(&self) -> &str;
    fn on_connect(&self, con: &ConnectionMeta) -> bool;  // should this processor attach?
    fn io_in(&mut self, data: &[u8]) -> ProcessorResult;
    fn io_out(&mut self, data: &[u8]) -> ProcessorResult;
}
// No Sync bound: processors are owned by the connection task, not shared.
// ConnectionMeta (not Connection) because that's what's available for the check.

pub struct ProcessorNode {
    processor: Box<dyn Processor>,
    children: Vec<ProcessorNode>,
}

pub struct ProcessorTree {
    root: ProcessorNode,
}

impl ProcessorTree {
    pub fn from_config(config: &ProcessorConfig) -> Self;

    // Walk tree depth-first, passing data through each processor
    pub fn process_io_in(&mut self, data: &[u8]) -> ProcessorResult;
}
```

**Processor config (TOML):**

```toml
# Processor tree: each processor has a name, optional config, and children.
# Current C config: [processor.filter.child.0] name=speakeasy
# TOML equivalent:

[[processors]]
name = "filter"
config = { protocols = ["ftpd", "smbd", "httpd", "mysqld", "sip", "mssqld", "pptp"] }

  [[processors.children]]
  name = "shellcode"   # GetPC detection (Rust, replaces speakeasy C module)
  config = { save_dir = "/var/lib/dionaea/shellcode" }

  [[processors.children]]
  name = "streamdumper"
  config = { save_dir = "/var/lib/dionaea/bistreams" }
```

The filter processor decides per-connection whether to attach (based on protocol name).
Children run only if the parent attaches.
```

Processors that do CPU-heavy work (shellcode detection) run via `tokio::task::spawn_blocking`.

### `crates/dionaea/src/bistream.rs`

```rust
pub struct BiStream {
    sequence: Vec<StreamChunk>,      // master timeline (interleaved)
    streams: [Vec<StreamChunk>; 2],  // [ingress, egress] separate
}

pub struct StreamChunk {
    data: Vec<u8>,
    bistream_offset: u32,
    stream_offset: u32,
    direction: Direction,
}
```

Stream dumper processor writes bistream to disk (configurable path).

### `crates/shell-detect/` — Shellcode detection

Standalone crate (no Python dependency) for GetPC pattern detection:
- **x86-32:** call $+5; pop, FPU GetPC, jmp+call+pop patterns
- **x86-64:** Port `detect_shellcode_x64()` (~90 lines of byte scanning)
- **MIPS:** Port `detect_shellcode_mips()` (~80 lines)
- ARM: Skip (too many false positives, currently disabled in C code)

When shellcode detected:
1. Save to disk (SHA256-named .bin + .txt metadata, using `sha2` crate)
2. Emit `dionaea.shellcode.detected` incident with fields: data, offset, arch, connection
3. Python Speakeasy ihandler (registered for `dionaea.shellcode.detected`) receives the
   incident, loads the saved shellcode file, and runs it through Speakeasy's Windows API
   emulator for IOC extraction. This is purely incident-driven — no direct Rust↔Speakeasy
   integration needed.

**Tests:**
- Unit: Processor tree construction from config, depth-first traversal order
- Unit: BiStream interleaving (alternating in/out chunks)
- Unit: Shellcode detection against known samples (from current test fixtures)
- Unit: Shellcode detection against benign data (no false positives)
- Fuzz: Random bytes → shellcode detector (no panics, reasonable false positive rate)
- Proptest: Any bistream produces valid offsets (monotonically increasing, no gaps)

---

## Phase 6: Infrastructure Modules (Weeks 11-12)

All behind Cargo features on the `dionaea` crate.

### `download` feature (replaces curl module)

- Listen for `dionaea.download.offer` incidents
- Use `reqwest` for async HTTP download
- Save to temp file, report `dionaea.download.complete` with SHA256 hash
- Upload support via multipart form
- Timeout: configurable (default 30s)
- Size limit: configurable (default 10MB)

### `pcap` feature (Linux/macOS)

- `pcap` crate with `capture-stream` feature for async
- Open interfaces, compile BPF filters
- Detect TCP RST with seq=0 → report `dionaea.connection.tcp.reject`

### `nfq` feature (Linux only, `#[cfg(target_os = "linux")]`)

- `nfq` crate (pure Rust, MIT licensed)
- Capture packets from netfilter queue
- Slot-based throttling (matching current Python nfq.py: 30-second window, per-slot limits)
- Create pending connection → report `dionaea.connection.tcp.pending`

### `netlink` feature (Linux only)

- `rtnetlink` crate for interface monitoring
- Detect address add/remove → report `dionaea.module.nl.addr.new/del`

### Remote management transports (feature-gated)

Both transports implement `ManagementTransport` trait (see Cross-Cutting Concerns).

**`mgmt-https` feature:**
- Uses `reqwest` with TLS client certificate authentication
- POST `StatusReport` as JSON to configured server URL
- Response body contains `Vec<ManagementCommand>` as JSON
- Configurable poll interval (default: 60s)

**`mgmt-dns` feature:**
- Encodes `StatusReport` fields as DNS TXT record queries
- Receives `ManagementCommand` encoded in DNS responses
- TSIG/HMAC authentication on queries
- Configurable poll interval (default: 60s)
- Lower bandwidth than HTTPS, works through restrictive firewalls

**Log and alert forwarding:** The management poll cycle includes recent log entries and
alerts alongside status data. The `StatusReport` struct contains:
- `incidents_since_last_report`: Incident summaries with origin, timestamp, key fields
- `alerts`: High-priority events (new unique malware download, shellcode detected,
  authentication attempt with real credentials, service crash/restart)
- `log_tail`: Configurable number of recent log lines (default: 100, filtered to
  warning+ severity to keep payload small)

Alerts are a filtered subset of incidents. An `AlertRule` config determines which
incident origins trigger alerts:

```toml
# In [management] config section
[[management.alert_rules]]
pattern = "dionaea.download.complete.unique"   # new malware
severity = "high"

[[management.alert_rules]]
pattern = "dionaea.shellcode.detected"
severity = "high"

[[management.alert_rules]]
pattern = "dionaea.connection.*.accept"
severity = "info"
# rate_limit: only include first N per poll interval to avoid flooding
rate_limit = 100
```

The management server receives structured incident/alert data and can forward to
its own alerting pipeline (PagerDuty, Slack, SIEM, etc.). The honeypot itself doesn't
need to know about those downstream systems.

### Privilege dropping (in `crates/dionaea/src/main.rs`)

```rust
// 1. Bind all service ports while root (or with CAP_NET_BIND_SERVICE)
// 2. Set resource limits (RLIMIT_NOFILE, optional RLIMIT_AS)
// 3. On Linux: drop capabilities except CAP_NET_BIND_SERVICE
#[cfg(target_os = "linux")]
{
    caps::clear(None, CapSet::Effective)?;
    caps::raise(None, CapSet::Effective, Capability::CAP_NET_BIND_SERVICE)?;
}
// 4. Switch to unprivileged user/group
nix::unistd::setgroups(&[])?;
nix::unistd::setgid(gid)?;
nix::unistd::setuid(uid)?;
// 5. macOS: setregid/setreuid (no setresgid/setresuid)
```

**Tests:**
- Unit: Download handler saves file with correct hash
- Integration: Download a test file via HTTP, verify incident chain
- Unit: NFQ throttle window math
- Unit: StatusReport serialization round-trip
- Unit: ManagementCommand deserialization (all variants)
- Unit: Incident ring buffer (add, drain, overflow)
- Unit: Alert rule pattern matching and rate limiting
- Unit: IP deny list (add, remove, TTL expiry, persistence)
- Integration: Mock management server, verify poll cycle delivers status + receives commands

---

## Phase 7: Integration Testing + Acceptance (Weeks 13-14)

By this point, every phase has its own tests. This phase is about **end-to-end acceptance**
and **feature parity validation** against the C version.

### Run existing pytest suite

The current `tests/` directory has integration tests that connect to a live daemon:
- TFTP (tftpy client)
- FTP (ftplib)
- SMB (smbprotocol, impacket)
- HTTP (requests)
- MySQL (pymysql)
- EPMAP (custom RPC client)
- NBNS (custom UDP)
- SNMP (custom UDP)

These tests use `conftest.py` fixtures with configurable host/port. Run them against the
Rust binary:

```bash
# Start Rust daemon
./target/release/dionaea -c test.toml &
# Run existing tests
cd tests && pip install -r requirements.txt && pytest -v --timeout=30
```

**Feature parity checklist — one row per protocol:**

| Protocol | Bind | Accept | Handshake | Data Exchange | Incidents | Timeouts | Reconnect |
|----------|------|--------|-----------|---------------|-----------|----------|-----------|
| echo     | | | | | | | |
| blackhole| | | | | | | |
| ftp      | | | | | | | |
| http     | | | | | | | |
| mysql    | | | | | | | |
| smb      | | | | | | | |
| tftp     | | | | | | | |
| sip      | | | | | | | |

### Performance comparison

Benchmark against the C version on the same hardware:
- Connections/second (TCP accept throughput)
- Memory per connection (RSS / active connection count)
- Throughput (bytes/sec through protocol handler)
- Python callback overhead (Rust→Python→Rust round-trip latency)

Use `criterion` or `hyperfine` for benchmarks. Store results for regression tracking.

---

## Phase 8: Deployment + Packaging (Week 15)

### Docker image

```dockerfile
# Stage 1: Build Rust binary
FROM rust:1.83 AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock deny.toml ./
COPY crates/ crates/
RUN cargo build --release --features "download,pcap"

# Stage 2: Runtime
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libpcap0.8 && rm -rf /var/lib/apt/lists/*

# Install Python deps for protocols
RUN pip install --no-cache-dir pyyaml speakeasy-emulator

COPY --from=builder /build/target/release/dionaea /usr/local/bin/
COPY python/ /opt/dionaea/lib/python/
COPY conf/ /etc/dionaea/
COPY deploy/entrypoint.sh /opt/dionaea/

# Capabilities instead of root
RUN setcap cap_net_bind_service=+ep /usr/local/bin/dionaea

RUN useradd -r -s /usr/sbin/nologin dionaea

EXPOSE 21 42 80 135 443 445 1433 1723 1883 3306 5060 5061 11211 27017
VOLUME ["/var/lib/dionaea", "/var/log/dionaea"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/opt/dionaea/entrypoint.sh"]
```

### systemd unit

```ini
# deploy/dionaea.service
[Unit]
Description=Dionaea Honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=dionaea
Group=dionaea
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ExecStart=/usr/local/bin/dionaea -c /etc/dionaea/dionaea.toml
Restart=on-failure
RestartSec=5

# Hardening
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/dionaea /var/log/dionaea
PrivateTmp=yes
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```

### Log rotation

`tracing-appender` with daily rotation. Alternatively, rely on `logrotate.d` config
for the JSON log file (send SIGHUP to reopen file handles).

---

## Graceful Shutdown Sequence

On SIGTERM or SIGINT:

1. **Stop accepting new connections.** Drop all TcpListeners and UdpSockets.
2. **Send final management report.** If management transport is active, send a
   "shutting down" status report with all pending incidents/alerts/logs.
3. **Drain in-flight connections.** Set a deadline (configurable, default 30s).
   Each active connection gets a chance to finish its current exchange.
4. **Stop Python services.** Call ServiceLoader `stop()` on each running service.
5. **Stop Python ihandlers.** Call IHandlerLoader `stop()` on each handler.
6. **Stop management transport.** Cancel the poll loop.
7. **Persist IP deny list.** Write current deny list to disk for reload on restart.
8. **Flush metrics.** Push final metrics to Prometheus endpoint if enabled.
9. **Flush logs.** Ensure all tracing subscribers flush pending writes.
10. **Finalize Python.** Drop all PyO3 references, allow Python interpreter to clean up.
    (PyO3 handles this on process exit; we just ensure no Rust code holds GIL references.)
11. **Remove PID file.** Clean up.

SIGHUP: Reopen log file handles (for logrotate compatibility). Do NOT reload config
(config reload is complex and not worth the risk for v1).

---

## What Changes in Python Code

### Minimal changes required:

1. **Import path**: `from dionaea.core import connection, incident, ihandler, g_dionaea`
   — same names, but now backed by PyO3 instead of Cython
2. **`__init__.py`**: Minor edits for the Rust module import path. Config loading stays YAML.
3. **Rust core config** (`dionaea.toml`): Written fresh in TOML. Not a migration — new file.
4. **Python service/ihandler configs stay YAML.** The Rust core doesn't read these files —
   Python's `ServiceLoader` and `IHandlerLoader` load them directly. Existing YAML configs
   work as-is, modulo any key changes needed for the v2 feature set. This avoids touching
   every protocol module's config loading code.

### What does NOT change:

- All protocol handler classes (smb, http, ftp, etc.)
- All incident handler classes (logsql, log_json, hpfeeds, etc.)
- ServiceLoader / IHandlerLoader metaclass pattern
- Timer / SubTimer classes (pure Python using `threading.Thread` — no C/Rust dependency)
- Exception hierarchy
- handle_* callback signatures

### Data continuity

Existing data directories are fully compatible with v2:
- **SQLite databases** (logsql.py): Written by Python, not C. Same Python code, same DB.
- **Downloaded malware** (store.py): SHA256-named files. Same naming in v2.
- **Bistream dumps**: Named by connection, written by Rust instead of C. New dumps use
  the same format; old dumps are still readable.
- **Log files**: Format changes (JSON by default instead of text). Old logs are not
  migrated — they remain on disk as-is.

### Config files

Python service and ihandler configs stay YAML. The Rust core doesn't read these files —
Python's `ServiceLoader` and `IHandlerLoader` load them directly. Existing YAML configs
work as-is, modulo any key changes needed for the v2 feature set.

`pyyaml` is needed at runtime: service/ihandler configs use it, and Speakeasy imports it
internally. The Dockerfile keeps it in the pip install.

---

## Post-v1: Python Modules Worth Porting to Rust

After the core rewrite is stable, some Python modules are good candidates for porting to
Rust. These are I/O-heavy, rarely change, and would benefit from eliminating GIL
contention on the hot path.

**Port (high value, stable, I/O-bound):**

| Module | Lines | Why |
|--------|-------|-----|
| `logsql.py` | 1,266 | Runs on every incident. SQLite writes via `rusqlite` + `spawn_blocking` eliminate GIL contention on the hottest path. Schema is stable (16 commits over ~2 years, mostly modernization). |
| `log_json.py` | 283 | JSON serialization + file/HTTP I/O. Simple, rarely changes. `serde_json` + async writes are a natural fit. |
| `store.py` | 78 | File dedup for downloads. SHA256 + file rename. Trivial to port, pure I/O. |
| `fail2ban.py` | 63 | Writes log lines. Trivial. |

**Don't port:**

| Module | Why not |
|--------|---------|
| Protocol services (smb, http, ftp, etc.) | They're the product — users extend them, they evolve. Python is the right language for rapid protocol prototyping. |
| External API handlers (virustotal, s3, hpfeeds) | Python's HTTP/API ecosystem is better. These are deploy-specific and change with API updates. |
| Speakeasy integration | It's a Python library. Wrapping it from Rust adds complexity for no gain. |
| Tiny loaders (`__init__.py` stubs) | 20-40 lines of Python. Not worth the porting effort. |

**How:** Each ported module becomes a Rust `#[pyclass]` that implements the same
`IHandlerLoader` interface. Python code can use either the Python or Rust version
transparently. Port one at a time, validate with the existing pytest suite.

---

## Platform Support

| Feature | Linux | macOS | Note |
|---------|-------|-------|------|
| TCP/TLS/UDP | Yes | Yes | Core networking |
| IP_PKTINFO (UDP source addr) | Yes | Fallback | macOS uses basic recvfrom |
| Privilege drop (capabilities) | Yes | No | macOS: just setreuid/setregid |
| NFQ | Yes | No | Kernel feature |
| Netlink | Yes | No | Kernel feature |
| Pcap | Yes | Yes | libpcap on both |
| SIOCINQ | Yes | No | macOS: hardcoded 16KB buffer |

macOS is the development platform; Linux is the deployment target. All features must
compile on macOS (behind `#[cfg]` where needed) so `cargo check` works locally.

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Python GIL blocks tokio workers | All Python calls via spawn_blocking. Measure callback latency early (Phase 3). |
| PyO3 API doesn't match Cython exactly | Phase 3 validates against real protocols before building I/O layer. |
| TLS weak cipher config is complex | Use openssl crate directly, not rustls. Test against old SSL clients in Phase 4. |
| TOML config missing required keys | Use current YAML configs as reference. Validate all required keys at startup. |
| Performance regression vs C | Benchmark in Phase 7. Tokio should match or beat libev for I/O; Python callback overhead is the bottleneck regardless of language. |
| Arc<Mutex<Connection>> deadlocks | Avoided: use ConnectionId + ConnectionRegistry (DashMap) + mpsc channels. |
| Panic in protocol handler crashes process | catch_unwind at every task boundary. Test with intentionally-panicking protocol. |
| Stale ConnectionId after close | Set `id = None`, raise `ReferenceError("the object requested does not exist")` — matches current Cython behavior. Test explicitly. |
| Management transport unreachable | Poll loop retries with exponential backoff. Buffer incidents locally (ring buffer). Log but don't crash. |
| Management commands used maliciously | Authenticate all transports (TLS client certs / TSIG). Validate commands against whitelist. No arbitrary code execution. |
| Log/alert volume overwhelms management server | Rate-limit alerts per rule. Cap log_tail size. Incident buffer is bounded (drops oldest). |
| SSRF via download module | Reject private/loopback IPs and non-HTTP schemes before fetching. |
| Attacker-controlled file paths | All file writes use SHA256 or connection ID names. Path validation rejects traversal. |
| Slow-read / slowloris attacks | Handshake timeout (10s), idle timeout (protocol-specific), sustain timeout (absolute deadline). |
| GIL contention under load | Monitor `python_callback_duration_seconds` P99. spawn_blocking pool (64 threads) absorbs bursts. |
| Python protocol handler infinite loop | Track consecutive zero-byte returns from handle_io_in. Close after N (default: 100). |

---

## Verification Checklist (per phase)

After each phase:
1. `cargo build` succeeds with no warnings
2. `cargo test` passes all unit + integration tests for that phase
3. `cargo clippy -- -D warnings` clean
4. New fuzz targets run for ≥1 minute without findings
5. Phase-specific acceptance test passes (documented in each phase)

Final acceptance:
1. All current Python pytest tests pass against Rust binary
2. All supported protocols accept connections and handle data exchange
3. Incidents are generated and dispatched to Python handlers
4. Logging works with domain filtering and multiple targets (JSON + stdout)
5. Metrics endpoint reports connection/incident counters (if enabled)
6. Docker image builds, starts, passes HEALTHCHECK, handles SIGTERM
7. systemd unit starts, stops, restarts cleanly
8. Memory usage is equal to or better than C version
9. No `unsafe` in our code (enforced by workspace lint)
10. Management poll cycle works end-to-end (status reports, commands, log/alert forwarding)
11. IP deny list persists across restarts
