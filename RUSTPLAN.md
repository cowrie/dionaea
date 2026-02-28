# Dionaea v2: Rust Migration Implementation Plan

## Context

Dionaea is a C+Python honeypot (~10K C core, ~35K Python protocols). The C core handles
event-driven networking (TCP/TLS/UDP/DTLS), module loading, incident dispatch, and stream
processing. Python handles all protocol emulation and logging. We're rewriting the C core
in Rust with PyO3, keeping all Python protocols unchanged.

**Decisions made:**
- Language: Rust (PyO3 for Python bridge)
- Shellcode: Drop libemu entirely. Port GetPC detection (~300 lines) to Rust.
  Keep Python Speakeasy handler for Windows API emulation (IOC extraction).
  No unicorn-engine dependency in Rust core — Speakeasy already uses unicorn
  internally via Python.
- Config: TOML for everything (migrate Python YAML configs)
- Privileges: Linux capabilities (CAP_NET_BIND_SERVICE), no pchild fork
- Modules: Compile-time Cargo features, no dynamic loading
- TLS: openssl crate (mandatory for weak cipher honeypot support + DTLS)

---

## Dependencies (14 direct crates)

```toml
[workspace.dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# TLS/DTLS (must use openssl for weak cipher honeypot support)
openssl = "0.10"
tokio-openssl = "0.6"

# Python embedding
pyo3 = { version = "0.28", features = ["auto-initialize"] }

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Config
serde = { version = "1", features = ["derive"] }
toml = "0.8"

# HTTP client (replaces curl module)
reqwest = { version = "0.12", default-features = false, features = ["native-tls"] }

# System/privileges
nix = { version = "0.29", features = ["socket", "uio", "user", "process", "fs", "net"] }
caps = "0.5"           # Linux-only

# Platform-specific (Linux only, behind cfg)
pcap = "2.3"           # libpcap bindings
nfq = "0.2"            # netfilter queue (pure Rust, MIT)
rtnetlink = "0.18"     # netlink interface monitoring
```

No unicorn-engine dependency in Rust — Speakeasy uses unicorn internally via Python.
GetPC pattern detection is pure Rust (no external deps needed — it's byte pattern scanning).
Drop libemu and the vendor/unicorn-libemu-shim entirely.

---

## Project Layout

```
dionaea-v2/                          # New directory alongside existing code
├── Cargo.toml                       # Workspace root
├── crates/
│   ├── dionaea/                     # Binary crate (entry point)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs             # Init, config, signal handling, event loop
│   │
│   ├── core/                        # Core library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── config.rs           # TOML config loading + serde structs
│   │       ├── connection/
│   │       │   ├── mod.rs          # Connection struct, state machine, lifecycle
│   │       │   ├── tcp.rs          # TCP accept, connect, I/O
│   │       │   ├── tls.rs          # TLS handshake, encrypted I/O
│   │       │   ├── udp.rs          # UDP listener, peer table
│   │       │   └── dtls.rs         # DTLS cookie verification, peer management
│   │       ├── incident.rs         # Incident struct, typed data, dispatch
│   │       ├── protocol.rs         # Protocol trait (the vtable)
│   │       ├── processor.rs        # Processor pipeline tree
│   │       ├── bistream.rs         # Bidirectional stream recording
│   │       ├── node_info.rs        # Network address info
│   │       └── throttle.rs         # Connection rate limiting + accounting
│   │
│   ├── python/                      # PyO3 Python bridge
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── connection.rs       # #[pyclass] PyConnection
│   │       ├── incident.rs         # #[pyclass] PyIncident
│   │       ├── ihandler.rs         # #[pyclass] PyIHandler
│   │       ├── node_info.rs        # #[pyclass] PyNodeInfo
│   │       ├── stats.rs            # #[pyclass] speed/accounting/timeouts
│   │       ├── dionaea.rs          # #[pyclass] global singleton (config, version)
│   │       ├── convert.rs          # Rust ↔ Python type conversions
│   │       └── loader.rs           # Python module import, ServiceLoader/IHandlerLoader
│   │
│   └── modules/                     # Infrastructure modules (Cargo features)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── pcap.rs             # Passive packet sniffing
│           ├── nfq.rs              # Netfilter queue (Linux)
│           ├── netlink.rs          # Interface monitoring (Linux)
│           └── download.rs         # HTTP download/upload (replaces curl)
│
├── conf/                            # Configuration files
│   ├── dionaea.toml                # Main config (migrated from .cfg)
│   ├── services/                   # Per-service TOML configs
│   └── ihandlers/                  # Per-handler TOML configs
│
├── python/                          # Python protocol modules (COPIED from current)
│   └── dionaea/
│       ├── __init__.py             # ServiceLoader, IHandlerLoader (minor edits for TOML)
│       ├── services.py
│       ├── ihandlers.py
│       ├── exception.py
│       ├── smb/                    # All protocol modules unchanged
│       ├── http.py
│       ├── ftp.py
│       ├── mysql/
│       ├── tftp.py
│       ├── sip/
│       ├── ... (all others)
│       ├── logsql.py               # Logging handlers unchanged
│       ├── log_json.py
│       └── ...
│
└── tests/                           # Integration tests
    ├── test_connection.rs
    ├── test_python_bridge.rs
    └── python/                      # Python protocol tests (copied from current)
```

---

## Phase 1: Project Skeleton + PyO3 Hello World (Week 1)

**Goal:** Cargo workspace builds, embeds Python, calls a trivial Python function.

**Files to create:**
- `dionaea-v2/Cargo.toml` (workspace)
- `dionaea-v2/crates/dionaea/Cargo.toml` + `src/main.rs`
- `dionaea-v2/crates/core/Cargo.toml` + `src/lib.rs`
- `dionaea-v2/crates/python/Cargo.toml` + `src/lib.rs`

**What main.rs does:**
1. Initialize tracing
2. Initialize Python via PyO3 (`pyo3::prepare_freethreaded_python()`)
3. Acquire GIL, import `sys`, print version
4. Start tokio runtime
5. Handle SIGINT/SIGTERM for shutdown

**Test:** `cargo build && cargo run` prints Python version and exits cleanly on Ctrl-C.

---

## Phase 2: PyO3 Bridge — Python API Surface (Weeks 2-3)

**Goal:** Replicate binding.pyx (1,370 lines) as PyO3 classes. This is the hardest phase
because getting the API wrong means Python protocols won't work.

**Classes to implement (maps to binding.pyx):**

### `crates/python/src/connection.rs` — `#[pyclass] PyConnection`

```
Properties (read-only via #[pyo3(get)]):
  remote: PyNodeInfo
  local: PyNodeInfo
  transport: String           # "tcp", "tls", "udp", "dtls"
  protocol: String            # protocol name or class name
  status: String              # state as string
  timeouts: PyConnectionTimeouts
  _in: PyConnectionStats      # ingress stats
  _out: PyConnectionStats     # egress stats

Methods (#[pymethods]):
  __init__(proto: Option<String>)
  bind(addr: String, port: u16, iface: Option<String>) -> PyResult<i32>
  listen(size: Option<i32>) -> PyResult<i32>
  connect(addr: String, port: u16, iface: Option<String>) -> PyResult<()>
  send(data: &[u8], local: Option<(String,u16)>, remote: Option<(String,u16)>) -> PyResult<()>
  close() -> PyResult<()>
  processors() -> PyResult<()>
  ref_() -> i32               # named ref_ to avoid Rust keyword
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
```

### `crates/python/src/incident.rs` — `#[pyclass] PyIncident`

```
Properties: origin (read-only)
Methods: __init__(origin), report(), keys()
Dynamic attrs: __getattr__, __setattr__ with type dispatch
  (int, str, bytes, connection, list, dict, None)
Subscript: __getitem__, __setitem__
```

### `crates/python/src/ihandler.rs` — `#[pyclass] PyIHandler`

```
Methods: __init__(pattern), start(), stop(), register(), unregister()
Callback: handle_incident(incident)
Dynamic dispatch: origin dots→underscores for method lookup
```

### `crates/python/src/node_info.rs` — `#[pyclass] PyNodeInfo`

```
Properties: host (r/w), port (r/w), hostname (r/o)
```

### `crates/python/src/stats.rs`

```
PyConnectionTimeouts: idle, listen, sustain, handshake, connecting, reconnect (all f64 r/w)
PyConnectionSpeed: bps (r/o), limit (r/w)
PyConnectionAccounting: bytes (r/o), limit (r/w)
PyConnectionStats: speed, accounting (nested objects)
```

### `crates/python/src/dionaea.rs` — `#[pyclass] PyDionaea`

```
Methods: config() -> dict, getifaddrs() -> dict, version() -> str
Global singleton exposed as g_dionaea
```

### `crates/python/src/convert.rs`

```
Rust ↔ Python conversions:
  OpaqueData enum ↔ PyObject (int, str, bytes, connection, list, dict, None)
  HashMap<String, OpaqueData> ↔ Python dict
  Vec<OpaqueData> ↔ Python list
```

### `crates/python/src/loader.rs`

```
Python module loading:
  - Set sys.path to include python/ directory
  - Import dionaea package
  - Call load_submodules()
  - Load config from TOML files
  - Instantiate ServiceLoaders and IHandlerLoaders
```

**Test:** Write a minimal echo.py-style protocol in Python. Import it via PyO3. Verify
all properties and methods are accessible. Verify handle_* callbacks are called.

**Key reference file:** `modules/python/binding.pyx` — every line maps to a PyO3 impl.

---

## Phase 3: Connection Core (Weeks 4-6)

**Goal:** Connection struct, state machine, TCP/UDP/TLS/DTLS transport handling.

### `crates/core/src/connection/mod.rs`

```rust
pub enum Transport { Tcp, Tls, Udp, Dtls }
pub enum ConnectionType { Accept, Bind, Connect, Listen }
pub enum ConnectionState { None, Resolve, Connecting, Handshake, Established, Shutdown, Close, Reconnect }

pub struct Connection {
    transport: Transport,
    connection_type: ConnectionType,
    state: ConnectionState,
    local: NodeInfo,
    remote: NodeInfo,
    transport_data: TransportData,
    stats: ConnectionStats,
    socket: Option<RawFd>,
    // ... protocol callbacks via PyO3
}
```

### `crates/core/src/connection/tcp.rs`

Key functions (async with tokio):
- `tcp_listen(addr, port)` → TcpListener
- `tcp_accept(listener)` → new Connection
- `tcp_connect(addr, port)` → Connection
- `tcp_io_in(connection)` → read, buffer, call protocol.io_in
- `tcp_io_out(connection)` → flush send buffer
- `tcp_disconnect(connection)` → graceful shutdown

### `crates/core/src/connection/tls.rs`

- Uses `openssl` crate (`SslAcceptor`, `SslConnector`)
- `tokio-openssl` for async TLS streams
- Support weak ciphers via `SslMethod::tls()` + `set_cipher_list()`
- Self-signed cert generation (`X509Builder`)
- DH parameter loading for old clients

### `crates/core/src/connection/udp.rs`

- `UdpSocket` with peer table (`HashMap<SocketAddr, Connection>`)
- `recvmsg` via `nix` crate for `IP_PKTINFO` (capture destination IP)
- Per-peer connection objects
- Packet queuing for send

### `crates/core/src/connection/dtls.rs`

- `openssl::ssl::SslMethod::dtls()` for DTLS
- Cookie verification (`SslContext::set_cookie_generate_cb`)
- Memory BIOs for DTLS packet handling
- Peer table like UDP

**Test:** Accept a TCP connection, receive data, call Python protocol's handle_io_in,
send response via handle_established → connection.send(). Test with netcat.

---

## Phase 4: Incident System + Logging (Week 7)

### `crates/core/src/incident.rs`

```rust
pub enum OpaqueData {
    Int(i64),
    String(String),
    Bytes(Vec<u8>),
    Connection(Arc<Mutex<Connection>>),
    List(Vec<OpaqueData>),
    Dict(HashMap<String, OpaqueData>),
    None,
}

pub struct Incident {
    origin: String,
    data: HashMap<String, OpaqueData>,
}

impl Incident {
    pub fn new(origin: &str) -> Self;
    pub fn set(&mut self, key: &str, value: OpaqueData);
    pub fn get(&self, key: &str) -> Option<&OpaqueData>;
    pub fn report(&self, handlers: &[IHandler]);
}
```

### IHandler dispatch

```rust
pub struct IHandler {
    pattern: glob::Pattern,   # or simple wildcard matching
    callback: Box<dyn Fn(&Incident)>,
}

// Pattern matching: "dionaea.connection.*" matches "dionaea.connection.tcp.accept"
// Report iterates all handlers, calls matching ones
```

### Logging setup

- `tracing` with `EnvFilter` for domain-based filtering
- Targets map to Dionaea domains: `dionaea::connection`, `dionaea::smb`, etc.
- File output via `tracing-appender`
- Config-driven: read log targets + levels from TOML

**Test:** Create incident, set fields, report, verify Python ihandler receives it.

---

## Phase 5: Python Module Loading + Service Management (Week 8)

### `crates/python/src/loader.rs`

Replicate the current Python startup sequence:

1. Initialize Python interpreter
2. Set `sys.path` to include `python/` directory
3. Import `dionaea` package → triggers `load_submodules()`
4. Load TOML config files for ihandlers and services
5. For each IHandlerLoader in registry: call `start(config)` → get ihandler instances
6. For each configured service:
   - Find matching ServiceLoader by name
   - Call `start(addr, iface, config)` → get connection instances
   - Each connection binds + listens

### Config migration

Current Python uses YAML via `load_config_from_files()` in `__init__.py`.
Need to modify this function to load TOML instead.

**Changes to Python code (minimal):**
- `__init__.py`: Replace `yaml.safe_load()` with `tomllib.load()` (Python 3.11+ stdlib)
  or `tomli` for older Python
- Config file format changes (YAML → TOML syntax)

**Test:** Load the echo.py and blackhole.py protocols. Start listeners. Accept connections.
Full round-trip through Python protocol handler.

---

## Phase 6: Infrastructure Modules (Weeks 9-10)

### `crates/modules/src/download.rs` (replaces curl module)

- Listen for `dionaea.download.offer` incidents
- Use `reqwest` for async HTTP download
- Save to temp file, report `dionaea.download.complete` with hash
- Upload support via multipart form

### `crates/modules/src/pcap.rs` (Linux/macOS)

- `pcap` crate with `capture-stream` feature for async
- Open interfaces, compile BPF filters
- Detect TCP RST with seq=0 → report `dionaea.connection.tcp.reject`

### `crates/modules/src/nfq.rs` (Linux only, `#[cfg(target_os = "linux")]`)

- `nfq` crate (pure Rust, MIT licensed)
- Capture packets from netfilter queue
- Create pending connection → report `dionaea.connection.tcp.pending`

### `crates/modules/src/netlink.rs` (Linux only)

- `rtnetlink` crate for interface monitoring
- Detect address add/remove → report `dionaea.module.nl.addr.new/del`
- ARP/neighbor cache lookup for MAC addresses

### Privilege dropping (in `crates/dionaea/src/main.rs`)

```rust
// 1. Bind all service ports while still root
// 2. Drop capabilities except CAP_NET_BIND_SERVICE
caps::clear(None, CapSet::Effective)?;
caps::raise(None, CapSet::Effective, Capability::CAP_NET_BIND_SERVICE)?;
// 3. Switch to unprivileged user
nix::unistd::setgid(gid)?;
nix::unistd::setuid(uid)?;
```

---

## Phase 7: Processor Pipeline + Bistream (Week 11)

### `crates/core/src/processor.rs`

```rust
pub trait Processor: Send + Sync {
    fn name(&self) -> &str;
    fn process(&self, con: &Connection) -> bool;  // should this processor run?
    fn io_in(&self, data: &[u8]) -> ProcessorResult;
    fn io_out(&self, data: &[u8]) -> ProcessorResult;
}

// Tree of processors per connection
pub struct ProcessorChain {
    processors: Vec<Box<dyn Processor>>,
}
```

### `crates/core/src/bistream.rs`

```rust
pub struct BiStream {
    sequence: Vec<StreamChunk>,   // master timeline
    streams: [Vec<StreamChunk>; 2],  // [in, out]
}

pub struct StreamChunk {
    data: Vec<u8>,
    bistream_offset: u32,
    stream_offset: u32,
    direction: Direction,
}
```

### Shellcode detection processor (replaces C speakeasy/detect.c + libemu)

Port the GetPC pattern matching from `modules/speakeasy/detect.c` to Rust:
- x86-32: Replace `emu_shellcode_test_x86()` (libemu) with pure pattern matching
  (call $+5; pop, FPU GetPC, jmp+call+pop — same patterns detect.c already uses for x64)
- x86-64: Port `detect_shellcode_x64()` (~90 lines of byte scanning)
- MIPS: Port `detect_shellcode_mips()` (~80 lines)
- ARM: Currently disabled (too many false positives) — skip for now

When shellcode detected:
1. Save to disk (SHA256-named .bin + .txt metadata)
2. Emit `dionaea.shellcode.detected` incident with data, offset, arch, connection
3. Python Speakeasy handler picks it up for full Windows API emulation

### Other processor integration

- Stream dumper processor writes bistream to disk
- Config-driven processor chain
- Processors run on tokio blocking tasks (not main async loop)

---

## Phase 8: Integration Testing (Weeks 12-13)

### Test each protocol module

For each Python protocol, verify:
1. Service starts and binds correctly
2. Connections are accepted
3. Protocol handshake works
4. Data exchange works (io_in/io_out callbacks)
5. Incidents are generated and dispatched
6. Timeouts fire correctly
7. Connection cleanup works

### Protocols to test (priority order)

1. **echo** — simplest, validates basic callback flow
2. **blackhole** — validates service loader pattern
3. **ftp** — moderate complexity, tests active/passive modes
4. **http** — tests request parsing, Jinja2 templates
5. **mysql** — tests stateful protocol with auth
6. **smb** — most complex, tests DCE/RPC
7. **tftp** — tests UDP transport
8. **sip** — tests UDP + SDP parsing

### Port existing Python tests

Copy `tests/` directory from current codebase. Run with pytest against new Rust core.

### Performance benchmarks

- Connections/second (TCP accept throughput)
- Memory usage per connection
- Throughput (bytes/sec through protocol handler)
- Compare against C version for regression

---

## Phase 9: Config Migration + Packaging (Week 14)

### TOML config structure

```toml
[dionaea]
user = "dionaea"
group = "dionaea"

[dionaea.listen]
mode = "manual"  # or "getifaddrs"
addresses = ["0.0.0.0"]
interfaces = ["eth0"]

[logging]
level = "info"

[logging.file]
path = "/var/log/dionaea/dionaea.log"
levels = "all,-debug"
domains = "*"

[modules]
enabled = ["python", "pcap", "download"]

[modules.python]
imports = ["dionaea"]
service_configs = ["/etc/dionaea/services-enabled/*.toml"]
ihandler_configs = ["/etc/dionaea/ihandlers-enabled/*.toml"]
```

### Docker image (multi-stage build)

```dockerfile
# Stage 1: Build
FROM rust:1.83 AS builder
COPY . .
RUN cargo build --release

# Stage 2: Runtime
FROM python:3.12-slim
COPY --from=builder /target/release/dionaea /usr/local/bin/
COPY python/ /opt/dionaea/lib/python/
COPY conf/ /etc/dionaea/
```

---

## What Changes in Python Code

### Minimal changes required:

1. **`__init__.py`**: Replace `yaml.safe_load()` with `tomllib.load()` (3 lines)
2. **Config files**: Migrate YAML → TOML syntax (format change, not logic)
3. **Import path**: `from dionaea.core import connection, incident, ihandler, g_dionaea`
   — same names, but now backed by PyO3 instead of Cython

### What does NOT change:

- All protocol handler classes (smb, http, ftp, etc.)
- All incident handler classes (logsql, log_json, hpfeeds, etc.)
- ServiceLoader / IHandlerLoader metaclass pattern
- Timer / SubTimer classes
- Exception hierarchy
- handle_* callback signatures

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| PyO3 API doesn't match Cython exactly | Phase 2 first — validate against real protocols before building core |
| TLS weak cipher config is complex | Use openssl crate directly, not rustls. Test against old SSL clients early |
| DTLS via openssl crate is poorly documented | Prototype DTLS in Phase 3 before committing to this path |
| Python config migration breaks things | Write config migration tool + validation |
| Performance regression vs C | Benchmark in Phase 8; tokio should match or beat libev |

---

## Verification Plan

After each phase, verify:
1. `cargo build` succeeds with no warnings
2. `cargo test` passes all unit tests
3. `cargo clippy` clean
4. Integration test: start honeypot, connect with netcat, verify response

Final acceptance:
1. All current Python protocol tests pass
2. Can accept connections on all supported protocols
3. Incidents are generated and dispatched to handlers
4. Logging works with domain filtering
5. Docker image builds and runs
6. Memory usage is equal to or better than C version
