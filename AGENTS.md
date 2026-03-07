# Coding Agent Guide

This document helps AI coding agents understand the dionaea project structure,
conventions, and design decisions.

## Project Overview

Dionaea is a low-interaction honeypot that emulates network services to capture
malware and log attacker behavior. The core is written in Rust (migrated from C
in 2025-2026), with protocol emulation in Python via PyO3.

**Architecture:** Rust async core (tokio) → PyO3 bridge → Python protocol handlers

## Repository Layout

```
crates/
  dionaea/              Main binary + library crate
    src/
      main.rs           Entry point, CLI, signal handling, logging
      lib.rs            Public module declarations
      config.rs         TOML config parsing with env var overrides
      error.rs          Central error enum
      runtime.rs        Global state (OnceLock<Arc<RuntimeState>>)
      connection/       Network connection management
        mod.rs          ConnectionMeta, ConnectionRegistry, state machine
        tcp.rs          TCP listener + accept loop
        tls.rs          TLS via openssl crate (feature-gated)
        udp.rs          UDP socket + peer table
        callback.rs     Python callback dispatch (handle_io_in, etc.)
        limits.rs       Per-IP and global connection limits
        throttle.rs     Bandwidth throttling
      python/           PyO3 bridge (replaces old Cython binding.pyx)
        mod.rs          Module registration, dionaea.core sys.modules entry
        connection.rs   PyConnection #[pyclass]
        incident.rs     PyIncident #[pyclass]
        ihandler.rs     PyIHandler #[pyclass]
        node_info.rs    PyNodeInfo #[pyclass]
        dionaea.rs      PyDionaea singleton + dlhfn logging bridge
        stats.rs        PyConnectionTimeouts, PyConnectionSpeed, etc.
        convert.rs      Rust ↔ Python type conversion
        loader.rs       Python module import, start(), stop()
      incident.rs       Incident model + OpaqueData enum
      ihandler.rs       Handler registry with wildcard pattern matching
      processor.rs      Stream processor pipeline (shellcode, streamdumper)
      bistream.rs       Bidirectional I/O recording
      node_info.rs      Network endpoint metadata (IP, port, hostname)
      privileges.rs     Unix privilege dropping (setuid/setgid, RLIMIT)
      download.rs       HTTP download capture (feature-gated)
      upload.rs         Multipart upload to external services
    tests/              Rust integration tests (one test per file)
  shell-detect/         Standalone crate for shellcode GetPC pattern detection
    src/lib.rs          detect() → Option<Detection>, supports x86/x64/MIPS

modules/python/dionaea/ Python protocol handlers (the "product")
  smb/                  SMB1/2 + DCE/RPC (~8K lines, most complex)
  mysql/                MySQL server protocol
  http.py               HTTP server with Jinja2 templates
  ftp.py                FTP with active/passive modes
  tftp.py               TFTP (RFC 1350/2348)
  sip/                  VoIP SIP protocol
  mqtt/                 MQTT message broker
  mssql/                SQL Server TDS protocol
  ...                   20+ more protocol emulations
  logsql.py             SQLite incident logging
  log_json.py           JSON incident logging
  hpfeeds.py            HPFeeds centralized logging

conf/                   TOML configuration
  dionaea.toml          Main daemon config
  services/*.toml       Per-protocol service configs (42 files)
  ihandlers/*.toml      Per-handler configs (19 files)

tests/                  Python integration tests (pytest, require running daemon)
  conftest.py           Shared fixtures (dionaea_host, dionaea_ports)
  shellcode/            Shellcode detection smoke tests
  ftp/, http/, smb/...  Protocol-specific tests

docker/                 Container support
  entrypoint.sh         Container startup script
Dockerfile              Multi-stage build (rust:1-bookworm → python:3.12-slim)
```

## Build & Test

### Rust

```bash
# Build
cargo build --release

# Run all tests (unit + integration)
cargo test --features download,upload,tls

# Clippy (CI enforces -D warnings)
cargo clippy --all-features -- -D warnings

# Format check
cargo fmt --check
```

### Python lint

```bash
pip install ruff mypy
ruff check modules/
tox -e lint           # runs both ruff and mypy
```

### Integration tests (require running dionaea)

```bash
cd tests
pip install -r requirements.txt
pytest -v --timeout=30
```

### Docker

```bash
docker build -t dionaea .
docker run -d --name dionaea dionaea
```

### Nix dev shell

```bash
nix-shell   # provides rustc, cargo, clippy, rustfmt, openssl, python
```

## Feature Flags

| Feature | Default | Dependencies | Purpose |
|---------|---------|--------------|---------|
| `tls` | yes | openssl, tokio-openssl | TLS listener support |
| `dns` | yes | hickory-resolver | Async DNS resolution |
| `download` | yes | reqwest | HTTP download capture |
| `deny-list` | yes | ip_network, ip_network_table | IP CIDR deny lists |
| `upload` | no | reqwest | Upload to external services |
| `pcap` | no | pcap | Packet capture (Linux) |
| `nfq` | no | nfq | Netfilter queue (Linux) |
| `netlink` | no | rtnetlink | Interface monitoring (Linux) |

## Conventions

### File Headers

Every code file must start with a 2-line ABOUTME comment:

```rust
// ABOUTME: Brief description of what this file does.
// ABOUTME: Second line with more context if needed.
```

```python
# ABOUTME: Brief description of what this file does.
# ABOUTME: Second line with more context if needed.
```

### Rust Style

- **Edition 2024**, minimum Rust 1.85
- `unsafe_code = "deny"` — no unsafe anywhere
- `clippy::all = "deny"`, `clippy::pedantic = "warn"`
- `clippy::unwrap_used = "deny"` — use `?` or explicit error handling
- Error type: `crate::error::Error` enum, `crate::error::Result<T>` alias
- Logging: `tracing` crate (`tracing::info!`, `tracing::debug!`, etc.)
- Async: tokio with `#[tokio::main]` and `spawn`/`spawn_blocking`

### Python Style

- Checked by `ruff` (linter) and `mypy` (type checker)
- Protocol handlers subclass `connection` from `dionaea.core`
- Incident handlers subclass `ihandler` from `dionaea.core`

### Naming

- Names describe purpose, not implementation or history
- No temporal names: "new", "old", "legacy", "improved", "enhanced"
- No implementation-detail names: "ZodValidator", "MCPWrapper"
- No pattern names unless they add clarity: "Tool" not "ToolFactory"

### Error Handling

- Rust: `Result<T, Error>` everywhere, `?` propagation, no `.unwrap()`
- Python callbacks: errors caught at the PyO3 boundary and logged

### Testing

- Rust unit tests: inline `#[cfg(test)] mod tests` in each file
- Rust integration tests: `crates/dionaea/tests/`, one test per file
  (OnceLock global state means each test needs its own process)
- Python integration tests: `tests/` directory, pytest, require running daemon
- No mocks in integration tests — real network I/O, real Python handlers

## Architecture Decisions

### Why Rust + PyO3 (not Go, not pure Rust)

Python protocol modules (~35K lines) are the product — years of protocol
emulation logic. PyO3 exposes Rust types as Python classes with `#[pyclass]`,
replacing the old Cython bridge. Go has no viable Python embedding library.

### Why openssl (not rustls) for TLS

Dionaea intentionally supports weak TLS (TLS 1.0, export ciphers, 1024-bit DH)
to attract old attack tools. rustls doesn't support these. The `openssl` crate
wraps the system OpenSSL, preserving full honeypot cipher compatibility.

### Global RuntimeState (OnceLock)

`runtime::get()` returns `&Arc<RuntimeState>` holding the connection registry,
handler registry, config, and processor tree. Initialized once at startup.
This avoids threading `Arc<RuntimeState>` through every function and matches
how the C code used a global `struct dionaea` singleton.

### Connection IDs (not pointers)

Python holds `ConnectionId(u64)` values, not raw pointers. The Rust side looks
up metadata in `DashMap<ConnectionId, ConnectionMeta>`. IDs are monotonic and
never recycled, preventing use-after-free bugs at the Rust↔Python boundary.

### One integration test per file

Each Rust integration test file compiles to a separate binary. This is required
because `runtime::init()` uses `OnceLock` and can only be called once per
process. Each test needs its own RuntimeState configuration.

### Processor pipeline

Configured as a tree in TOML. Template tree built at startup, cloned
per-connection with filter rules (protocol + connection type matching).
Processors see raw byte streams and can detect shellcode, dump bistreams, etc.

### SendMessage channel

Python → Rust I/O communication uses `tokio::sync::mpsc`. When Python calls
`connection.send(data)`, it puts a `SendMessage::Data` on the channel. The
async I/O task drains the channel and writes to the socket. This decouples
the GIL-holding Python thread from the async I/O loop.

## Key PyO3 Patterns

```rust
// Exposing a Rust struct to Python
#[pyclass(subclass)]
pub struct PyConnection {
    id: ConnectionId,
}

#[pymethods]
impl PyConnection {
    #[new]
    fn new() -> Self { ... }

    fn send(&self, py: Python<'_>, data: &[u8]) -> PyResult<()> { ... }

    #[getter]
    fn remote(&self, py: Python<'_>) -> PyResult<PyNodeInfo> { ... }
}
```

```rust
// Calling Python from Rust (in spawn_blocking for GIL)
tokio::task::spawn_blocking(move || {
    Python::attach(|py| {
        handler.call1(py, (data,))?;
        Ok(())
    })
}).await??;
```

## Config System

TOML-based with environment variable overrides:
- `DIONAEA_DIONAEA__USER=nobody` → `[dionaea] user = "nobody"`
- Double underscore `__` separates section from key
- Env vars take precedence over file values

## Incident System

Events are dispatched via pattern matching:
- Origin strings: `dionaea.connection.tcp.accept`, `dionaea.download.complete`
- Handlers register wildcard patterns: `dionaea.connection.*`
- Data is `HashMap<String, OpaqueData>` (int, string, bytes, connection ref, list, dict)
- `report()` collects matching handlers under lock, releases lock, then dispatches

## Common Tasks

### Adding a new Python protocol

1. Create `modules/python/dionaea/myproto.py` (subclass `connection`)
2. Create `conf/services/myproto.toml` with bind addresses and settings
3. Add import to `conf/dionaea.toml` under `[modules.python]`
4. Protocol auto-registers via the service loader

### Adding a Rust processor

1. Implement `Processor` and `ProcessorCtx` traits
2. Register in `processor.rs` `build_processor()` match
3. Add config section in `conf/dionaea.toml` under `[[processors]]`

### Adding a feature-gated module

1. Add dependency to `crates/dionaea/Cargo.toml` under `[dependencies]` as optional
2. Add feature flag under `[features]`
3. Gate code with `#[cfg(feature = "myfeature")]`
4. Add to CI test command if it should be tested
