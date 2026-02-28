# Dionaea v2: Migration Analysis & Recommendations

**Author:** Claude (with Michel)
**Date:** 2026-02-28
**Status:** Analysis Complete - Awaiting Decision

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Architecture Deep Dive](#2-current-architecture-deep-dive)
3. [Codebase Inventory](#3-codebase-inventory)
4. [External Dependencies](#4-external-dependencies)
5. [Language Comparison: Rust vs Go](#5-language-comparison-rust-vs-go)
6. [Migration Strategy Options](#6-migration-strategy-options)
7. [Recommended Approach](#7-recommended-approach)
8. [Phase-by-Phase Migration Plan](#8-phase-by-phase-migration-plan)
9. [Risk Analysis](#9-risk-analysis)
10. [What We Lose, What We Gain](#10-what-we-lose-what-we-gain)
11. [Open Questions](#11-open-questions)

---

## 1. Executive Summary

Dionaea is a ~87,000 line honeypot (48K C, 38K Python, 1.4K Cython) built on libev, GLib,
OpenSSL, and an embedded Python interpreter. The C core handles event-driven networking
(TCP/TLS/UDP/DTLS), module loading, incident dispatch, and stream processing. Python handles
all protocol emulation (SMB, HTTP, FTP, MySQL, etc.) and logging/reporting.

**Key finding:** The Python protocol layer (~38K lines) is the actual "product" — it's where
the honeypot intelligence lives. The C core (~10K lines excluding auto-generated code) is
infrastructure glue that could be replaced. The Cython bridge (~1.4K lines) ties them together.

**Recommendation:** Rewrite the C core in Rust, keep the Python protocol modules, replace the
Cython bridge with PyO3. This gives us memory safety where it matters most (network-facing C
code) while preserving the protocol emulation logic that took years to develop.

---

## 2. Current Architecture Deep Dive

### 2.1 Core Architecture

```
┌────────────────────────────────────────────────────────────┐
│                      dionaea.c (main)                       │
│  ┌──────────┐  ┌──────────┐  ┌────────┐  ┌──────────────┐ │
│  │ Event    │  │ Module   │  │ Thread │  │ Privileged   │ │
│  │ Loop     │  │ Loader   │  │ Pool   │  │ Child (pchild)│ │
│  │ (libev)  │  │ (GModule)│  │(GThread)│  │              │ │
│  └────┬─────┘  └────┬─────┘  └───┬────┘  └──────┬───────┘ │
│       │              │            │               │         │
│  ┌────┴──────────────┴────────────┴───────────────┴──────┐  │
│  │              Connection Manager                        │  │
│  │  TCP | TLS | UDP | DTLS (union-based transport)       │  │
│  │  State Machine: none→resolve→connecting→handshake→    │  │
│  │                 established→shutdown→close→reconnect   │  │
│  └────┬───────────────────────────────────┬──────────────┘  │
│       │                                   │                 │
│  ┌────┴─────────┐              ┌──────────┴──────────────┐  │
│  │ Processor    │              │ Incident System          │  │
│  │ Pipeline     │              │ Pattern-matched dispatch │  │
│  │ (tree of     │              │ to C and Python handlers │  │
│  │  analyzers)  │              └─────────────────────────┘  │
│  └──────────────┘                                           │
└────────────────────────────────────────────────────────────┘
         │
    ┌────┴─────────────────────────────────────────┐
    │         Python Module (embedded interpreter)  │
    │  ┌─────────────┐    ┌──────────────────────┐ │
    │  │ Cython      │    │ Protocol Handlers    │ │
    │  │ Bindings    │    │ SMB, HTTP, FTP,      │ │
    │  │ (binding.pyx│    │ MySQL, TFTP, SIP,    │ │
    │  │  1370 lines)│    │ MQTT, MSSQL, etc.    │ │
    │  └─────────────┘    └──────────────────────┘ │
    │                     ┌──────────────────────┐ │
    │                     │ Incident Handlers    │ │
    │                     │ SQL, JSON, hpfeeds,  │ │
    │                     │ VirusTotal, S3, etc. │ │
    │                     └──────────────────────┘ │
    └──────────────────────────────────────────────┘
```

### 2.2 Threading Model

- **Single-threaded event loop** (libev) handles all I/O
- **GThreadPool** (CPU-count threads) for CPU-intensive work (shellcode emulation)
- **Thread→main communication** via GAsyncQueue + ev_async watcher
- **GIL management** in Python module for thread safety
- **Reference counting** (with GMutex) for connection lifecycle

### 2.3 Connection Object

The `struct connection` is the central data structure (~120 fields). Key components:

| Component | Description |
|-----------|-------------|
| `transport` union | TCP (GString buffers), TLS (SSL*, GString buffers + retry), UDP (GList packets + peer table), DTLS (SSL*, BIO*, cookie) |
| `events` struct | 2 ev_io watchers + 11 ev_timer watchers |
| `protocol` struct | 13 callback function pointers (ctx_new, established, io_in, io_out, disconnect, error, timeouts, etc.) |
| `stats` struct | Per-connection throttling (bytes/sec) and accounting (total bytes) |
| `processor_data` | Tree of stream analyzers with bistream capture |
| `refcount` | Thread-safe reference counting |
| `node_info` x2 | Local and remote address info (sockaddr, strings, DNS state) |

### 2.4 Module System

Modules are dynamic shared libraries loaded via GModule. Module API:

```
config()  → Load configuration (before privilege drop)
prepare() → Allocate shared memory (before fork)
new()     → Create instances, bind sockets (after fork)
start()   → Start operations (after privilege drop)
hup()     → SIGHUP reload
free()    → Cleanup on shutdown
```

### 2.5 Incident System

Events are dispatched via pattern-matching:
- Origin strings like `dionaea.connection.tcp.accept`, `dionaea.module.smb.exploit`
- Handlers register glob patterns like `dionaea.connection.*`
- Data is a GHashTable of typed values (int, string, bytes, connection ptr, list, dict)
- Both C and Python handlers supported

### 2.6 Processor Pipeline

Configurable tree of stream analyzers per connection:
- Processors see raw byte streams (in/out)
- Can run in main thread or thread pool
- Examples: shellcode detection (emu), pattern matching (xmatch), stream dumping
- Bistream recording for forensic analysis

### 2.7 Privileged Child (pchild)

Forked process that retains root privileges for binding ports <1024:
- Parent sends socket FD via SCM_RIGHTS
- Child calls bind() with elevated privileges
- Returns result over Unix socket pair

### 2.8 Python Protocol Callbacks

Python protocols implement these callbacks (mapped through Cython):

```python
class MyProtocol(connection):
    def handle_established(self): ...
    def handle_io_in(self, data): return bytes_consumed
    def handle_io_out(self): ...
    def handle_disconnect(self): return should_reconnect
    def handle_error(self, err): ...
    def handle_timeout_idle(self): return should_extend
    def handle_timeout_sustain(self): return should_extend
```

---

## 3. Codebase Inventory

### 3.1 C Core (src/)

| File | Lines | Purpose |
|------|-------|---------|
| connection.c | 2,277 | Connection lifecycle, state machine, connect/listen |
| dionaea.c | 920 | Main entry, initialization, event loop |
| processor.c | 889 | Processor pipeline tree creation & I/O routing |
| connection_tls.c | 869 | TLS handshake, encrypted I/O |
| connection_dtls.c | 474 | DTLS with cookie verification |
| incident.c | 452 | Incident creation, dispatch, typed data |
| connection_udp.c | 386 | UDP listener, peer management |
| connection_tcp.c | 381 | TCP accept, stream I/O |
| log.c | 331 | Multi-backend logging with domain filtering |
| bistream.c | 327 | Bidirectional stream recording |
| util.c | 289 | Utility functions |
| modules.c | 237 | Dynamic module loading |
| pchild.c | 228 | Privileged child process |
| ssl.c | 169 | OpenSSL DH/RSA parameter generation |
| node_info.c | 159 | Address string formatting |
| threads.c | 123 | Thread pool management |
| signals.c | 114 | Signal handlers (SIGINT, SIGSEGV) |
| dns.c | 79 | Async DNS via udns |
| refcount.c | 45 | Thread-safe reference counting |
| **TOTAL** | **~8,750** | |

### 3.2 Header Files (include/)

| File | Lines | Key Structures |
|------|-------|---------------|
| connection.h | 395 | struct connection, enums, macros |
| incident.h | 115 | struct incident, struct ihandler, opaque_data |
| log.h | 117 | struct logger, log_filter |
| modules.h | 99 | struct module, module_api |
| processor.h | 83 | struct processor, processor_data |
| threads.h | 72 | struct thread, async_cmd |
| dionaea.h | 80 | struct dionaea (global state) |
| protocol.h | 59 | struct protocol (callback vtable) |
| others | 270 | util, bistream, pchild, node_info, dns, refcount, signals |
| **TOTAL** | **~1,290** | |

### 3.3 C Modules

| Module | Lines | Files | Dependencies | Purpose |
|--------|-------|-------|--------------|---------|
| python | ~2,500 | 3 | Python3, Cython | Embedded Python interpreter + bindings |
| emu | ~2,500 | 5 | libemu | x86 shellcode emulation |
| curl | ~700 | 1 | libcurl | Async HTTP download/upload |
| nl | ~460 | 1 | libnl | Network interface monitoring |
| pcap | ~440 | 1 | libpcap | Passive packet sniffing |
| nc | ~290 | 2 | (none) | Generic protocol stubs |
| nfq | ~260 | 1 | libnetfilter_queue | Linux NFQ packet capture |
| xmatch | ~200 | 2 | libxmatch | Pattern matching |
| speakeasy | ~150 | 2 | unicorn | Shellcode detection |
| **TOTAL** | **~7,500** | | | |

### 3.4 Vendor Code

| Library | Lines | Purpose |
|---------|-------|---------|
| unicorn-libemu-shim | 987 | Unicorn-based libemu compatibility |

### 3.5 Python Protocol Modules

| Module | Lines | Complexity | Notes |
|--------|-------|------------|-------|
| smb/ (total) | ~8,200 | Very High | SMB1/2, DCE/RPC, 5+ files |
| mysql/ | ~3,700 | High | Server protocol + variable defs |
| tftp.py | 1,458 | High | RFC 1350/2348, UDP, Construct lib |
| logsql.py | 1,266 | High | SQLite3 connection tracking |
| http.py | 1,227 | High | Full HTTP server, Jinja2 templates |
| sip/ | ~880 | Medium | VoIP protocol |
| ftp.py | 720 | Medium | Active/passive modes |
| printer.py | 600 | Medium | PJL/PCL emulation |
| hpfeeds.py | 460 | Medium | Centralized logging protocol |
| speakeasy.py | 420 | Medium | Malware emulation integration |
| virustotal.py | 320 | Medium | Sample submission |
| log_json.py | 280 | Low | JSON incident logging |
| upnp/ | ~250 | Low | UPnP device emulation |
| ndrlib.py | 250 | Low | NDR encoding for RPC |
| nfq.py | 210 | Low | Netfilter queue integration |
| services.py | 179 | Low | Service lifecycle management |
| log_incident.py | 170 | Low | JSON file/HTTP logging |
| wireguard.py | 170 | Low | WireGuard tunnel emulation |
| nbns/ | ~200 | Low | NetBIOS Name Service |
| memcache/ | ~300 | Low | Memcached emulation |
| Others | ~1,500 | Low | echo, blackhole, p0f, fail2ban, etc. |
| **TOTAL** | **~35,300** | | |

### 3.6 Cython Bridge

| File | Lines | Purpose |
|------|-------|---------|
| binding.pyx | 1,370 | C↔Python type conversion, callback dispatch |
| binding.c | 32,506 | Auto-generated (excluded from counts) |

### 3.7 Tests

| Category | Lines | Coverage |
|----------|-------|----------|
| Python tests | ~3,185 | FTP, HTTP, MySQL, NBNS, printer, RDP, SIP, SMB, SNMP, TFTP |

### 3.8 Summary

| Category | Lines | Percentage |
|----------|-------|------------|
| C core (src/) | 8,750 | 10% |
| C headers | 1,290 | 1.5% |
| C modules | 7,500 | 8.5% |
| Cython bridge | 1,370 | 1.5% |
| Vendor C | 987 | 1% |
| Python protocols | 35,300 | 40% |
| Python tests | 3,185 | 3.5% |
| Auto-generated C | 32,506 | (excluded) |
| **Total (meaningful)** | **~58,400** | |

---

## 4. External Dependencies

### 4.1 Required Dependencies

| Library | Used By | Purpose | Rust Equivalent | Go Equivalent |
|---------|---------|---------|-----------------|---------------|
| **libev** | Core | Event loop | tokio / mio | goroutines (built-in) |
| **GLib 2.0** | Core | Data structures, strings, hash tables, mutexes | std collections + parking_lot | stdlib |
| **GModule 2.0** | Core | Dynamic module loading | libloading | plugin (limited) |
| **OpenSSL** | Core | TLS/SSL, crypto | rustls or openssl crate | crypto/tls (stdlib) |
| **udns** | Core | Async DNS | trust-dns / hickory-dns | net.Resolver (stdlib) |
| **Python 3** | Module | Embedded interpreter | pyo3 | go-python (CGo) |
| **Cython** | Module | C↔Python bindings | pyo3 (replaces Cython) | N/A |

### 4.2 Optional Dependencies

| Library | Module | Purpose | Rust Equivalent | Go Equivalent |
|---------|--------|---------|-----------------|---------------|
| **libcurl** | curl | HTTP client | reqwest / hyper | net/http (stdlib) |
| **libpcap** | pcap | Packet capture | pcap crate | gopacket |
| **libnetfilter_queue** | nfq | Linux NFQ | nfqueue crate | go-nfqueue |
| **libnl** | nl | Netlink | netlink crate (rtnetlink) | vishvananda/netlink |
| **libemu** | emu | Shellcode emulation | No direct equivalent | No direct equivalent |
| **unicorn** | speakeasy | CPU emulation | unicorn-engine crate | go-unicorn |

### 4.3 Python Module Dependencies

| Library | Used By | Purpose |
|---------|---------|---------|
| SQLAlchemy | log_db_sql | Multi-DB logging |
| Jinja2 | http | Template rendering |
| Construct | tftp | Binary packet parsing |
| PyYAML | config | Configuration loading |
| Scapy | various | Packet construction/parsing |
| boto3 | s3 | AWS S3 uploads |

---

## 5. Language Comparison: Rust vs Go

### 5.1 Memory Safety

| Concern | Rust | Go |
|---------|------|-----|
| Buffer overflows | Compile-time prevention | Runtime bounds checking |
| Use-after-free | Ownership system prevents | GC prevents |
| Data races | Compile-time prevention (Send/Sync) | Runtime detection (-race flag) |
| Null pointer | No null (Option<T>) | Nil panics at runtime |
| Memory leaks | Possible but rare (cycles with Rc) | GC handles most cases |

**Verdict:** Rust wins on safety guarantees. Both are massive improvements over C.

### 5.2 Async I/O / Event Loop

| Feature | Rust | Go |
|---------|------|-----|
| Model | async/await with tokio (epoll/kqueue) | Goroutines with netpoller |
| Closest to current | Very similar (explicit event loop) | Different paradigm (CSP) |
| Connection handling | tokio::net::{TcpListener, TcpStream} | net.Listener, net.Conn |
| TLS | tokio-rustls or tokio-native-tls | crypto/tls (stdlib) |
| UDP | tokio::net::UdpSocket | net.UDPConn |
| Timer management | tokio::time | time.Timer |
| Channel communication | tokio::sync::mpsc | channels (built-in) |

**Verdict:** Go is simpler. Rust is closer to the current architecture and gives more control.

### 5.3 Python Integration (In-Process Embedding)

Both options embed a CPython interpreter in the same process — no subprocess IPC.

#### Rust: PyO3

| Aspect | Details |
|--------|---------|
| Library | PyO3 (10K+ stars, very active, multiple releases/year) |
| Define Python class from Rust | `#[pyclass]` macro — one line |
| Expose methods | `#[pymethods]` block — natural Rust syntax |
| Expose properties | `#[pyo3(get, set)]` attribute |
| GIL management | `Python::with_gil(\|py\| { ... })` — type-safe, scoped |
| Callbacks (Python→Rust) | Automatic via trait impl |
| Memory safety | Compile-time guarantees across the boundary |
| Thread safety | Compile-time Send/Sync enforcement |
| Production users | polars, pydantic-core, cryptography, ruff, many others |

#### Go: The Landscape

**There is no single well-maintained Go-Python embedding library.** The ecosystem is
fragmented:

| Project | Stars | Last Active | Python Ver | Status |
|---------|-------|-------------|------------|--------|
| go-python/cpy3 | 346 | June 2022 | 3.7 only | Dead (3.7 is EOL) |
| nhatthm/go-cpy | 2 | July 2025 | 3.12 only | Minimal adoption |
| nhatthm/go-python | 6 | July 2025 | 3.12 only | Minimal adoption |
| py4go | 183 | Low activity | Various | Proof-of-concept |
| go-embed-python | 332 | Jan 2025 | Various | **Subprocess, not embedded** |
| gpython | — | — | 3.4 reimpl | Unusable (20% CPython speed, missing stdlib) |

**gopy** (2,300 stars, actively maintained) does exist but solves the **reverse problem**:
it generates CPython extension modules _from_ Go packages. It lets Python call Go, not
Go embed Python. Not applicable to our use case.

#### The Core Problem: Exposing Host Types to Python

Dionaea's Python protocols call `self.connection.send()`, `self.connection.close()`,
access `self.remote.host`, etc. This requires the host language to expose structs as
Python classes with methods and properties.

| Capability | Rust (PyO3) | Go |
|-----------|-------------|-----|
| Define Python class from host | `#[pyclass]` — 1 line | Hand-write C `PyTypeObject` + `PyMethodDef` + `PyGetSetDef` |
| Expose method | `#[pymethods]` block | Write C glue fn → `//export` Go fn → register via function pointer |
| Expose property | `#[pyo3(get)]` | Write C getter/setter → `//export` Go fn |
| Boilerplate per type | ~10 lines | ~200+ lines of C + Go |
| Tooling for this | Built into PyO3 | **Nothing exists** |

**No Go library or code generator can define Python classes from Go structs.** The only
production system that does Go→Python callbacks is Datadog Agent, and they:
- Built a custom C++ middleware layer ("rtloader") between Go and Python
- Only expose module-level functions, NOT object methods
- Don't expose Go structs as Python classes at all

#### GIL + Goroutine Interaction

This is the hardest part of Go-Python embedding:

1. Python's GIL is **thread-specific**. Go's scheduler migrates goroutines between OS
   threads freely.
2. Every goroutine touching Python must call `runtime.LockOSThread()` to prevent the
   scheduler from migrating it mid-GIL-hold — otherwise: **segfault**.
3. `LockOSThread()` pins a goroutine to a real OS thread with a megabyte stack, losing
   Go's lightweight concurrency advantage.
4. There is no `Python::with_gil()` equivalent — you manually call
   `C.PyGILState_Ensure()` / `C.PyGILState_Release()`.

Rust's PyO3 handles this correctly by design — `Python::with_gil()` is type-safe and
Rust's `Send`/`Sync` traits prevent you from accidentally sharing Python objects across
threads.

#### CGo Overhead

Per published benchmarks (Go 1.21):
- **~40ns per CGo call** (single-threaded), **~5ns** with parallelism
- **~95ns round-trip** for C-to-Go callbacks
- This is ~100x slower than a pure Go function call (~1.8ns)

For a honeypot, this overhead is not a bottleneck. The real costs are GIL serialization
and `LockOSThread` requirements, not call overhead.

#### CGo Pointer Rules

Go's CGo rules prohibit passing Go pointers that contain other Go pointers to C. This
means Go structs can't be stored directly in Python objects. You need handle tables
(int64 keys mapped to Go objects via a global map) or C-allocated proxy structs. This
adds complexity and another class of potential bugs (stale handles, leaked entries).

#### What It Would Take to Do This in Go

To replicate the current Cython binding.pyx (1,370 lines) in Go, you would need:

1. A C shim layer defining `PyTypeObject` for each type (connection, incident, ihandler,
   node_info, etc.) — **~500+ lines of C**
2. `PyMethodDef` and `PyGetSetDef` tables for each type — **~300+ lines of C**
3. `//export` Go functions for each method/property callback — **~400+ lines of Go**
4. A handle table mapping int64 IDs to Go objects — **~100 lines of Go**
5. Manual GIL management wrappers — **~50 lines of Go**
6. Type conversion functions (Go ↔ Python for int, str, bytes, list, dict) — **~200 lines**

Total: ~1,500+ lines of hand-written C + Go glue, all without compile-time safety
guarantees. And maintaining this across Python version changes (3.12 → 3.13 → 3.14)
would be a recurring burden.

#### Verdict

**Rust (PyO3) wins decisively.** This isn't a close call. The Go ecosystem for in-process
Python embedding is fragmented, undermaintained, and lacks the fundamental capability we
need most: exposing host-language types as Python classes. The only production user
(Datadog) needed a custom C++ middleware layer and still only exposes module-level
functions, not object methods. For Dionaea's use case — where Python protocols hold
references to host objects and call methods on them bidirectionally — Go would require
building and maintaining a bespoke C glue layer that PyO3 provides out of the box.

### 5.4 System Programming

| Feature | Rust | Go |
|---------|------|-----|
| Raw sockets | Yes (libc crate, socket2) | Yes (syscall package) |
| Unix domain sockets | Yes | Yes |
| SCM_RIGHTS (FD passing) | Yes (sendmsg/recvmsg) | Yes |
| Privilege dropping | Yes (nix crate: setuid, chroot) | Yes (syscall) |
| Signal handling | Yes (tokio::signal, ctrlc) | os/signal |
| libpcap | pcap crate (mature) | gopacket (mature) |
| Netfilter queue | nfqueue crate | go-nfqueue |

**Verdict:** Roughly equal. Both can do everything we need.

### 5.5 Plugin System

| Feature | Rust | Go |
|---------|------|-----|
| Dynamic loading (.so) | libloading crate | plugin package (Linux/macOS only, limited) |
| Trait-based plugins | Yes — define trait, load impl | Interfaces work but plugin pkg is fragile |
| WASM plugins | wasmtime/wasmer support | wazero support |
| Compile-time plugins | Feature flags | Build tags |

**Verdict:** Rust wins. Go's plugin system is notoriously unreliable and limited.

### 5.6 Ecosystem & Community

| Feature | Rust | Go |
|---------|------|-----|
| Security tooling | Growing fast (security community loves Rust) | Mature (many security tools in Go) |
| Honeypot projects | Few but growing | Several (Cowrie-like projects) |
| Async networking | Mature (tokio ecosystem) | Mature (stdlib) |
| Build complexity | cargo (excellent) | go build (excellent) |
| Cross-compilation | Good (cross crate) | Excellent (GOOS/GOARCH) |
| Compile times | Slow | Fast |
| Learning curve | Steep | Gentle |

**Verdict:** Go has easier onboarding. Rust has better security tooling trajectory.

### 5.7 Comparison Summary

| Factor | Weight | Rust | Go | Notes |
|--------|--------|------|-----|-------|
| Memory safety | High | ★★★★★ | ★★★★ | Both good; Rust prevents more at compile time |
| Python embedding | **Critical** | ★★★★★ | ★ | PyO3 vs fragmented/dead CGo wrappers |
| Expose types to Python | **Critical** | ★★★★★ | ★ | #[pyclass] vs hand-written C glue (no tooling) |
| GIL safety | High | ★★★★★ | ★★ | Type-safe with_gil() vs manual + LockOSThread |
| Async I/O model | High | ★★★★★ | ★★★★ | Rust closer to current libev model |
| Plugin system | Medium | ★★★★ | ★★ | Go plugins are fragile |
| System programming | High | ★★★★★ | ★★★★ | Both capable |
| Learning curve | Medium | ★★ | ★★★★★ | Go much easier to learn |
| Compile speed | Low | ★★ | ★★★★★ | Go much faster |
| Cross-compilation | Medium | ★★★ | ★★★★★ | Go trivial, Rust needs setup |
| Community/ecosystem | Medium | ★★★★ | ★★★★ | Both strong |

**Overall Recommendation: Rust**

The Python embedding story alone makes this decision. The Go ecosystem for in-process
Python embedding is effectively dead — the main library (go-python/cpy3) hasn't been
updated since 2022 and only supports Python 3.7 (EOL). The only production user (Datadog)
built a custom C++ middleware layer and still only exposes module-level functions, not
object methods. No Go library or code generator can expose Go structs as Python classes —
the fundamental capability Dionaea needs.

PyO3, by contrast, is a thriving project (10K+ stars) used by polars, pydantic-core,
cryptography, and ruff. It provides `#[pyclass]` and `#[pymethods]` macros that make
exposing Rust types to Python trivial, with compile-time safety guarantees for GIL
management and memory. Since ~60% of our codebase is Python and will remain Python,
this is the decisive factor.

---

## 6. Migration Strategy Options

### Option A: Big Rewrite (Not Recommended)

Rewrite everything from scratch in Rust. Rewrite all Python protocols too.

- **Effort:** 12-18 months
- **Risk:** Extremely high (second system effect)
- **Benefit:** Clean architecture, full Rust
- **Problem:** Throws away ~35K lines of battle-tested protocol emulation

### Option B: Core Rewrite, Keep Python (Recommended)

Rewrite the C core (~10K lines) in Rust. Replace Cython with PyO3. Keep all Python
protocol modules and handlers with minimal changes.

- **Effort:** 4-8 months
- **Risk:** Medium (well-bounded scope)
- **Benefit:** Memory safety where it matters, preserves protocol intelligence
- **Problem:** Still maintaining Python; two languages

### Option C: Incremental FFI Replacement (Not Recommended)

Gradually replace C functions with Rust via FFI, keeping the C build system.

- **Effort:** 6-12 months
- **Risk:** Medium-High (two build systems, FFI complexity)
- **Benefit:** Gradual migration, always working
- **Problem:** C/Rust interop is painful, maintains CMake + Cargo simultaneously

### Option D: Wrap in Go, Shell Out to Python (Not Recommended)

Rewrite core in Go, communicate with Python via subprocess/RPC.

- **Effort:** 4-6 months
- **Risk:** Medium
- **Benefit:** Simple Go code
- **Problem:** Loses the tight C↔Python integration; adds IPC latency and complexity;
  Python protocols would need significant rework

---

## 7. Recommended Approach

**Option B: Core Rewrite in Rust + PyO3**

### Why This Works

1. **Clear boundary:** The C core (connection management, event loop, module loading,
   incident dispatch) is a well-defined ~10K line subsystem with clean interfaces

2. **PyO3 replaces Cython naturally:** The current binding.pyx (1,370 lines) defines
   exactly the Python↔native interface. PyO3 can expose the same classes and callbacks
   with better ergonomics and type safety

3. **Python protocols don't change:** The 35K lines of protocol emulation code call a
   defined set of APIs (connection.send(), connection.close(), incident.report(), etc.).
   As long as the Rust core exposes the same Python API, protocols keep working

4. **Tokio maps well to libev:** The current architecture is already async/event-driven.
   Tokio's reactor model is conceptually the same as libev, just with Rust's async/await
   syntax instead of C callbacks

5. **Rust's ownership model prevents the bugs that matter:** Network-facing code handling
   untrusted input is exactly where memory safety matters most. Buffer overflows in
   connection handling code are the #1 risk in a honeypot

### What Changes

| Component | Current | After Migration |
|-----------|---------|-----------------|
| Event loop | libev (C) | tokio (Rust) |
| Data structures | GLib (GString, GList, GHashTable) | std (String, Vec, HashMap) |
| TLS | OpenSSL (C) | rustls or native-tls |
| DNS | udns (C) | hickory-dns |
| Module loading | GModule (C) | libloading or compile-time features |
| Python bridge | Cython (binding.pyx) | PyO3 |
| Reference counting | Custom (GMutex + int) | Arc<T> |
| Thread pool | GThreadPool | tokio tasks or rayon |
| Privileged ops | fork + Unix socket | Same pattern, Rust implementation |
| Config | GKeyFile (INI) | serde + YAML/TOML |
| Logging | Custom (log.c) | tracing crate |
| HTTP client | libcurl | reqwest |
| Packet capture | libpcap (C module) | pcap crate |
| Netfilter | libnetfilter_queue | nfqueue crate |

### What Stays the Same

- All Python protocol modules (SMB, HTTP, FTP, MySQL, TFTP, SIP, etc.)
- All Python incident handlers (logsql, log_json, hpfeeds, virustotal, etc.)
- The conceptual architecture (event loop + connections + protocols + incidents)
- The Python API surface (connection class, incident class, ihandler class)
- Configuration format (can keep YAML, which Python modules already use)

---

## 8. Phase-by-Phase Migration Plan

### Phase 0: Preparation (1-2 weeks)

**Goal:** Set up the Rust project structure and verify PyO3 integration works.

- [ ] Initialize Cargo workspace
- [ ] Set up PyO3 with embedded Python interpreter
- [ ] Write a minimal "hello world" that embeds Python and calls a function
- [ ] Verify PyO3 can expose a Rust struct as a Python class with callbacks
- [ ] Set up CI (build + test)

### Phase 1: Python Bridge (2-3 weeks)

**Goal:** Recreate the Python API surface in Rust via PyO3.

Port binding.pyx (1,370 lines) to PyO3. This defines the Python-visible API:

- [ ] `connection` class — properties (remote, local, transport, protocol, status),
  methods (bind, listen, connect, send, close), protocol callbacks
- [ ] `incident` class — key/value storage, report()
- [ ] `ihandler` class — pattern registration, callback dispatch
- [ ] `node_info` class — host, port, hostname properties
- [ ] `connection_speed`, `connection_accounting`, `connection_stats`,
  `connection_timeouts` — config classes
- [ ] `dionaea` singleton — config access, version
- [ ] Type conversion: Python ↔ Rust for int, str, bytes, list, dict, connection, None

**Success criterion:** Python protocol modules can import the new bridge and the API
signatures match. Unit tests for type conversions pass.

### Phase 2: Connection Core (3-4 weeks)

**Goal:** Implement the connection state machine and transport handling in Rust.

- [ ] Connection struct with transport enum (TCP, TLS, UDP, DTLS)
- [ ] Connection state machine (none → resolve → connecting → handshake → established →
  shutdown → close)
- [ ] TCP: accept, connect (async), io_in, io_out, disconnect
- [ ] UDP: listener with peer table, packet queuing
- [ ] TLS: handshake (rustls or native-tls), encrypted I/O
- [ ] DTLS: cookie verification, peer management
- [ ] DNS resolution (hickory-dns async)
- [ ] Connection statistics and throttling
- [ ] Timeout management (idle, sustain, listen, connecting, handshake, close, reconnect)
- [ ] Reference counting → Arc<Mutex<Connection>> or similar

**Success criterion:** Can accept TCP and TLS connections, pass data to protocol callbacks,
send responses. Basic integration test with a simple echo protocol in Python.

### Phase 3: Incident System + Logging (1-2 weeks)

**Goal:** Implement incident dispatch and logging infrastructure.

- [ ] Incident struct with typed key-value data
- [ ] Pattern-matching handler dispatch (glob patterns on origin strings)
- [ ] Python ihandler callback integration
- [ ] Logging via `tracing` crate with domain filtering
- [ ] Bistream recording for bidirectional traffic capture

**Success criterion:** Python incident handlers receive incidents from Rust-initiated
connections. Logging works with domain/level filtering.

### Phase 4: Module System (1-2 weeks)

**Goal:** Implement module loading and lifecycle management.

**Decision point:** Do we keep dynamic loading (.so) or switch to compile-time features?

Dynamic loading pros: Same architecture, user can add modules without recompiling.
Compile-time pros: Simpler, faster, better optimization, no ABI concerns.

- [ ] Module trait definition (config, prepare, start, new, free, hup)
- [ ] Module lifecycle management
- [ ] Service management (bind addresses, start protocols)

### Phase 5: Infrastructure Modules (2-3 weeks)

**Goal:** Port the C modules that provide infrastructure services.

- [ ] pcap module → pcap crate
- [ ] curl module → reqwest (async HTTP)
- [ ] nfq module → nfqueue crate (Linux only)
- [ ] nl module → rtnetlink crate
- [ ] Privileged child (pchild) → Rust fork + FD passing

### Phase 6: Shellcode Detection (2-3 weeks)

**Goal:** Port or integrate shellcode detection.

- [ ] Evaluate: port emu module or use existing Rust/Python shellcode tools
- [ ] Processor pipeline in Rust
- [ ] speakeasy integration (unicorn-engine crate)
- [ ] xmatch pattern matching (regex or aho-corasick crate)

### Phase 7: Integration Testing (2-3 weeks)

**Goal:** Full system testing with all Python protocols.

- [ ] Test each Python protocol module against the new Rust core
- [ ] Port existing Python tests
- [ ] Performance benchmarking (connections/sec, memory usage)
- [ ] Fuzzing network-facing code
- [ ] Security audit of the Rust↔Python boundary

### Phase 8: Deployment & Packaging (1-2 weeks)

- [ ] Docker image (multi-stage build — this also addresses the existing TODO)
- [ ] Configuration migration (document any config format changes)
- [ ] Deployment documentation
- [ ] Migration guide for users

### Timeline Summary

| Phase | Duration | Cumulative |
|-------|----------|------------|
| 0: Preparation | 1-2 weeks | 1-2 weeks |
| 1: Python Bridge | 2-3 weeks | 3-5 weeks |
| 2: Connection Core | 3-4 weeks | 6-9 weeks |
| 3: Incidents + Logging | 1-2 weeks | 7-11 weeks |
| 4: Module System | 1-2 weeks | 8-13 weeks |
| 5: Infrastructure Modules | 2-3 weeks | 10-16 weeks |
| 6: Shellcode Detection | 2-3 weeks | 12-19 weeks |
| 7: Integration Testing | 2-3 weeks | 14-22 weeks |
| 8: Deployment | 1-2 weeks | 15-24 weeks |

**Estimated total: 4-6 months**

---

## 9. Risk Analysis

### High Risk

| Risk | Impact | Mitigation |
|------|--------|------------|
| PyO3 API mismatch with existing Python protocols | Python modules need changes | Port binding.pyx first, test API compatibility early |
| Tokio async model doesn't map cleanly to current patterns | Architectural rework needed | Prototype Phase 2 connection handling before committing |
| TLS configuration complexity (weak ciphers for honeypot) | Can't attract old attack tools | Use native-tls (OpenSSL backend) instead of rustls if needed |

### Medium Risk

| Risk | Impact | Mitigation |
|------|--------|------------|
| Python GIL interaction with Rust async | Performance bottleneck | PyO3 handles this well; profile early |
| Dynamic module loading ABI stability | Plugins break across versions | Consider compile-time features instead |
| Privileged child pattern in Rust | Complex unsafe code | Well-bounded; use nix crate for safety |
| DTLS cookie handling | Security-critical code | Port carefully, fuzz extensively |

### Low Risk

| Risk | Impact | Mitigation |
|------|--------|------------|
| Rust learning curve | Slower development | C developers find Rust natural after the initial hump |
| Build time | Developer experience | Use cargo's incremental compilation; workspace structure helps |
| Cross-compilation | Deployment friction | Set up CI cross-compilation early |

### TLS Compatibility Concern

**This deserves special attention.** Dionaea intentionally supports weak TLS to attract old
attack tools. rustls does NOT support:
- TLS 1.0/1.1
- Export ciphers
- Weak DH parameters (1024-bit)
- Self-signed certificates with weak keys

**Options:**
1. Use `native-tls` with OpenSSL backend (supports everything, but depends on OpenSSL)
2. Use `openssl` crate directly (full control, same as current)
3. Use rustls for modern TLS + separate OpenSSL-based "legacy TLS" handler
4. Accept that the modern TLS-only approach is fine (most current malware uses TLS 1.2+)

**Recommendation:** Start with the `openssl` crate for full compatibility. Consider rustls
later if we decide to drop legacy TLS support.

---

## 10. What We Lose, What We Gain

### We Lose

1. **GLib ecosystem** — GLib is battle-tested and consistent. Rust stdlib + crates are
   more fragmented (multiple async runtimes, multiple TLS libraries, etc.)

2. **Simple C debugging** — GDB on C is straightforward. Rust async debugging is harder
   (stack traces through tokio are noisy)

3. **Dynamic module hot-loading** — Current GModule system allows dropping in new .so
   files. Rust modules would likely be compiled in

4. **Existing contributor knowledge** — Anyone who knows C can contribute today. Rust
   has a steeper learning curve

5. **Build simplicity** — CMake + make is well-understood. Adding Cargo + PyO3 build
   integration has complexity

6. **Libemu integration** — The emu module's deep integration with libemu (Windows API
   hooks, etc.) would be hard to port. May need to keep as a C library called via FFI

### We Gain

1. **Memory safety** — No more buffer overflows, use-after-free, double-free in
   network-facing code handling attacker-controlled input

2. **Thread safety guarantees** — Rust's Send/Sync traits prevent data races at compile
   time. The current GMutex-based approach is correct but fragile

3. **Better error handling** — Result<T, E> instead of C's "check return code and errno"
   pattern. No more silent failures

4. **Modern async/await** — Cleaner than C callback soup. The current connection.c is
   2,277 lines of callback management that would be much simpler with async/await

5. **Package management** — Cargo vs hunting for system libraries. Dependencies are
   versioned and reproducible

6. **Testing** — Rust's built-in test framework + property testing (proptest) + fuzzing
   (cargo-fuzz) vs the current minimal test situation

7. **Refactoring confidence** — The compiler catches mistakes. Changing the connection
   struct doesn't silently break 20 files

8. **Performance** — Rust is as fast as C, sometimes faster due to better optimization
   opportunities (no aliasing concerns)

9. **PyO3 is better than Cython** — Type-safe, better error handling, no generated C
   code, active community

10. **Modern TLS by default** — rustls provides secure defaults while we can opt into
    OpenSSL for honeypot-specific weak cipher support

---

## 11. Open Questions

These need Michel's input before proceeding:

### Architecture Decisions

1. **Dynamic modules vs compile-time features?**
   - Dynamic: More flexible, users can add modules without recompiling
   - Compile-time: Simpler, faster, better optimization, cargo features
   - Hybrid: Compile core modules in, allow dynamic for user modules?

2. **TLS library: rustls vs openssl crate?**
   - rustls: Pure Rust, secure by default, but no weak cipher support
   - openssl: Full compatibility with current behavior, but external C dependency
   - Could use both (rustls default + openssl for legacy honeypot mode)

3. **Config format: Keep INI (GKeyFile) or migrate to YAML/TOML?**
   - Python modules already use YAML for their configs
   - TOML is the Rust ecosystem standard
   - Migration to a single YAML config would simplify things

4. **Do we keep the privileged child (pchild) pattern?**
   - Alternative: Use Linux capabilities (CAP_NET_BIND_SERVICE) instead
   - Alternative: Use systemd socket activation
   - pchild is complex but proven

5. **What happens to the emu module?** → DECIDED
   - Drop libemu entirely (and vendor/unicorn-libemu-shim)
   - Port GetPC pattern detection (~300 lines) to pure Rust
   - Keep Python Speakeasy handler for Windows API emulation (IOC extraction)
   - No unicorn-engine dependency in Rust core — Speakeasy uses unicorn via Python

### Scope Decisions

6. **Do Python protocols need any changes?**
   - Goal is zero changes, but some APIs might need minor adjustments
   - Need to verify: can PyO3 expose identical API to current Cython?

7. **Do we maintain backward compatibility with current config files?**
   - If migrating INI → YAML, need a migration tool?
   - Or just document the new format?

8. **What's the minimum Python version we target?**
   - Current: Python 3.6+
   - PyO3 requires Python 3.7+
   - Recommend: Python 3.9+ (drops a lot of compatibility baggage)

9. **Do we want to keep the interactive Python shell (REPL)?**
   - Current: If running in a terminal, you get a Python prompt
   - Nice for debugging but adds complexity

### Process Decisions

10. **Do we develop in a new repo or a branch?**
    - New repo: Clean start, no legacy baggage
    - Branch: Git history preserved, easier to reference old code

11. **What's the acceptance criteria for "done"?**
    - All current Python protocols work?
    - All current tests pass?
    - Performance parity?
    - New features (fuzzing, better logging)?

---

## Appendix A: Key File Reference

### C Core Files to Port

```
src/dionaea.c          → main.rs (entry point, initialization)
src/connection.c       → connection/mod.rs (state machine, lifecycle)
src/connection_tcp.c   → connection/tcp.rs
src/connection_tls.c   → connection/tls.rs
src/connection_udp.c   → connection/udp.rs
src/connection_dtls.c  → connection/dtls.rs
src/incident.c         → incident.rs
src/log.c              → (replaced by tracing crate)
src/modules.c          → modules.rs
src/processor.c        → processor.rs
src/bistream.c         → bistream.rs
src/pchild.c           → pchild.rs
src/ssl.c              → (absorbed into connection/tls.rs)
src/dns.c              → (replaced by hickory-dns)
src/threads.c          → (replaced by tokio tasks)
src/signals.c          → signals.rs
src/node_info.c        → node_info.rs
src/refcount.c         → (replaced by Arc<T>)
src/util.c             → util.rs
```

### Cython → PyO3 Mapping

```
binding.pyx class connection  → #[pyclass] struct PyConnection
binding.pyx class incident    → #[pyclass] struct PyIncident
binding.pyx class ihandler    → #[pyclass] struct PyIHandler
binding.pyx class node_info   → #[pyclass] struct PyNodeInfo
binding.pyx class dionaea     → #[pyclass] struct PyDionaea

binding.pyx py_to_opaque()    → impl FromPyObject for OpaqueData
binding.pyx py_from_opaque()  → impl IntoPy<PyObject> for OpaqueData
```

### Python Files That Need No Changes (Goal)

```
modules/python/dionaea/__init__.py     (ServiceLoader, IHandlerLoader)
modules/python/dionaea/services.py     (service lifecycle)
modules/python/dionaea/ihandlers.py    (handler lifecycle)
modules/python/dionaea/smb/            (all SMB protocol files)
modules/python/dionaea/http.py         (HTTP protocol)
modules/python/dionaea/ftp.py          (FTP protocol)
modules/python/dionaea/mysql/          (MySQL protocol)
modules/python/dionaea/tftp.py         (TFTP protocol)
modules/python/dionaea/sip/            (SIP protocol)
modules/python/dionaea/mqtt/           (MQTT protocol)
... (all other protocol modules)
modules/python/dionaea/logsql.py       (SQL logging)
modules/python/dionaea/log_json.py     (JSON logging)
modules/python/dionaea/hpfeeds.py      (hpfeeds logging)
... (all other handlers)
```

## Appendix B: Current Connection Callback Interface

This is the exact interface that PyO3 must replicate (from binding.pyx):

```python
# Protocol callbacks (C → Python)
def handle_established(self) → None
def handle_io_in(self, data: bytes) → int  # returns bytes consumed
def handle_io_out(self) → None
def handle_disconnect(self) → bool  # True = reconnect
def handle_error(self, err: int) → None
def handle_timeout_idle(self) → bool  # True = extend
def handle_timeout_sustain(self) → bool  # True = extend
def handle_timeout_listen(self) → bool  # True = extend
def handle_origin(self, parent: connection) → None

# Connection API (Python → C)
connection.bind(addr: str, port: int, proto: str) → None
connection.listen(addr: str, port: int) → None
connection.connect(host: str, port: int) → None
connection.send(data: bytes) → None
connection.close() → None
connection.ref() → None
connection.unref() → None

# Properties
connection.remote → node_info  # .host, .port, .hostname
connection.local → node_info
connection.transport → str  # "tcp", "tls", "udp", "dtls"
connection.protocol → str
connection.status → str
connection.timeouts → connection_timeouts
connection.stats → connection_stats

# Incident API
incident(origin: str) → incident
incident[key] = value  # __setitem__ with type dispatch
incident[key] → value  # __getitem__
incident.report() → None

# IHandler API
ihandler(pattern: str) → ihandler
ihandler.handle_incident(incident) → None  # override in subclass
```

## Appendix C: Incident Origins Reference

These are all incident origin strings found in the codebase:

```
# Connection lifecycle
dionaea.connection.tcp.listen
dionaea.connection.tcp.accept
dionaea.connection.tcp.connect
dionaea.connection.tcp.reject     (from pcap module)
dionaea.connection.tcp.pending    (from nfq module)
dionaea.connection.tls.accept
dionaea.connection.tls.connect
dionaea.connection.udp.connect
dionaea.connection.dtls.connect
dionaea.connection.link           (parent-child relationship)
dionaea.connection.free

# Module events
dionaea.module.nl.addr.new
dionaea.module.nl.addr.del
dionaea.module.nl.connection.info.mac

# Download/Upload
dionaea.download.offer
dionaea.download.complete
dionaea.download.complete.hash
dionaea.upload.request

# Shell
dionaea.*.mkshell

# Protocol-specific (from Python modules)
dionaea.modules.python.smb.*
dionaea.modules.python.http.*
dionaea.modules.python.ftp.*
dionaea.modules.python.mysql.*
... (each protocol generates its own)
```
