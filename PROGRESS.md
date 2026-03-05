# Dionaea v2 Rust Migration — Implementation Plan

## Phases 1–4: Foundation ✅ COMPLETE

All core infrastructure is done: workspace, config, error handling, logging,
PyO3 bridge (full binding.pyx API), TCP/UDP/TLS I/O, connection lifecycle,
incident system, ihandler dispatch, throttling, accounting, limits, deny list.

146 unit tests passing (now 217 after Phase 6).

---

## Phase 5: End-to-End Protocol Validation

### 5.1 echo.py end-to-end ✅
- Real echo.py loads, welcome banner, data reversal verified
- Fixed: `__new__` keyword arg, drain_control_messages data loss

### 5.2 http.py end-to-end ✅
- Real http.py loads, serves static files, HTTP GET → 200 OK
- Fixed: apply_parent_config stub, py_to_opaque missing connection type

### 5.3 Full service loading chain ✅
- services.new() → load_submodules() → services.start() → ServiceLoader dispatch
- Blackhole + HTTP both start and accept connections via config-driven chain

### 5.4 TLS listen from Python ✅
- Wire `listen()` for transport "tls": generate self-signed cert, build SslAcceptor, call tls_listen()
- Test: httpd with proto='tls' starts, HTTPS GET works
- Committed: `468a332`

### 5.5 handle_io_out callback after writes ✅
- After writing data to socket, call `handle_io_out` on Python handler via spawn_blocking
- Test: HTTP GET for 128KB file transfers in 2 chunks via handle_io_out
- Committed: `b9a5b74`

### 5.6 FTP protocol test ✅
- Real FTP protocol loads, 220 banner, USER/PASS login, PWD works
- Committed: `5d175f7`

### 5.7 SMB/EPMAP protocol test ✅
- SMB negotiate: connect, send NBT+SMB negotiate request, verify response
- EPMAP: connect, send DCERPC bind request, verify bind_ack response
- Fixed: factory_create to call type() with no args (matching C PY_CLONE/PY_INIT)
- Committed: `61d6e10`

### 5.8 MySQL protocol test ✅
- Connect, verify greeting packet: protocol version 10, version string, scramble
- Committed: `4ba0fff`

### 5.9 ihandler loading chain test ✅
- Custom ihandler receives connection lifecycle incidents (accept, free)
- Real LogJsonHandler writes valid JSON incident log to file
- Fixed: PyIncident.keys() returns bytes (matching C char* behavior)
- Fixed: PyIHandler.__new__() accepts **kwargs from subclasses
- Committed: `49dcc2f`

### 5.10 Run daemon binary end-to-end ✅
- `./target/debug/dionaea -c tmp/test_daemon.toml` starts in ~0.2s
- Blackhole on 8023, HTTP on 8080
- `curl http://127.0.0.1:8080/` → 200 OK with HTML body
- Clean shutdown on SIGTERM, exit 0

---

## Phase 6: Processor Pipeline + Shellcode Detection ✅ COMPLETE

### 6.1 shell-detect crate ✅
- [x] GetPC pattern scanning: x86 call+pop, FPU fnstenv, jmp+call
- [x] x86-64 RIP-relative lea, MIPS bgezal
- [x] 17 unit tests (all patterns, edge cases, priority)
- Committed: `4247687`

### 6.2 BiStream data structure ✅
- [x] Thread-safe bidirectional stream buffer (Vec under Mutex)
- [x] Per-direction offset tracking, chunk history
- [x] 4 unit tests
- Committed: `a739303`

### 6.3 Processor trait + FilterProcessor ✅
- [x] Processor trait (name/accepts/io_in/io_out/new_ctx)
- [x] ProcessorNode template tree, ProcessorPipeline per-connection instantiation
- [x] FilterProcessor with allow/deny rules (protocol + connection type matching)
- [x] 9 unit tests
- Committed: `3727fd8`

### 6.4 StreamDumper processor ✅
- [x] Python-eval-compatible bistream format (`stream = [('in', b'...'), ...]`)
- [x] Lazy file creation, strftime path expansion (%Y/%m/%d/%H/%M/%S)
- [x] Proper byte escaping for non-printable characters
- [x] 5 unit tests
- Committed: `ce6ac19`

### 6.5 ShellcodeProcessor ✅
- [x] Calls shell_detect::detect() on incoming data
- [x] Content-addressable file storage (SHA256 filename, deduplication)
- [x] Emits `dionaea.shellcode.detected` incident (arch, offset, hash, path)
- [x] Per-connection scan offset tracking
- [x] 4 unit tests
- Committed: `328a10a`

### 6.6 Config parsing + tree builder ✅
- [x] `[[processors]]` TOML config with name, label, next, allow, deny, path
- [x] `build_tree()` resolves label/next references into ProcessorNode tree
- [x] Root nodes = entries not referenced by any other's `next`
- [x] 5 unit tests (config parsing + tree building)
- Committed: `ccdde15`

### 6.7 Wire into I/O loop + PyConnection.processors() ✅
- [x] `AttachProcessors(ProcessorPipeline)` variant in SendMessage
- [x] `handle_connection` feeds io_in/io_out through pipeline
- [x] `drain_control_messages` returns pipeline from handle_established
- [x] `PyConnection.processors()` builds pipeline from global tree, sends via channel
- [x] `RuntimeState.processor_tree` built from config at startup
- Committed: `adc6455`

---

## Phase 7: Infrastructure Modules

### 7.1 Download module (behind `download` feature) ✅
- [x] Listen for `dionaea.download.offer` incidents (Rust ihandler)
- [x] Async HTTP download via reqwest with streaming SHA256
- [x] Save to temp file, rename on completion with SHA256 hash (content-addressable)
- [x] Emit `dionaea.download.complete` incident
- [x] Size limit + timeout config
- [x] URL validation: http/https only, SSRF protection (reject private/loopback IPs)
- [x] Deduplication: duplicate content reuses existing file
- Committed: `b6d4ae6`, `02ddbc3`, `d420819`
- Also: `c28be32` (Rust handler dispatch), `a7d1f20` (config fields)

### 7.2 Privilege dropping ✅
- [x] Resolve user/group from config (names or numeric IDs)
- [x] Raise RLIMIT_NOFILE to hard limit
- [x] Drop supplementary groups (Linux), setgid, setuid
- [x] Skip gracefully when not running as root
- [ ] Linux: drop capabilities except CAP_NET_BIND_SERVICE (deferred, C version doesn't either)
- Committed: `a7fcf29`

### 7.3 Graceful shutdown improvements ✅
- [x] Call Python module stop() on shutdown (services, ihandlers)
- [x] Clear ihandler registry on shutdown
- [x] Stop all listeners on shutdown
- [ ] Drain in-flight connections with configurable deadline (deferred)
- [ ] Persist IP deny list to disk (deferred)
- Committed: `b386caf`

### 7.4 SIGHUP log reopening ✅
- [x] Fix SIGHUP to continue running (was falling through to shutdown)
- [x] SIGHUP handler loops back to wait for signals
- [ ] Actual file handle reopening (deferred until file-based log targets)
- Committed: `68d5171`

### 7.5 pcap module (Linux/macOS, behind `pcap` feature)
- [ ] Capture interface packets, detect TCP RST with seq=0
- [ ] Emit `dionaea.connection.tcp.reject` incident

### 7.6 nfq module (Linux only, behind `nfq` feature)
- [ ] Netfilter queue capture with slot-based throttling
- [ ] Emit `dionaea.connection.tcp.pending` incident

### 7.7 netlink module (Linux only, behind `netlink` feature)
- [ ] Monitor interface address changes via rtnetlink
- [ ] Emit `dionaea.module.nl.addr.new/del` incidents

---

## Phase 8: Integration Testing + Acceptance

- [ ] Run existing pytest suite against Rust binary
- [ ] Feature parity checklist per protocol (bind, accept, data exchange, incidents)
- [ ] Performance benchmarks vs C version (connections/sec, memory, throughput)
- [ ] Fuzz testing: random bytes to TCP read path

---

## Phase 9: Deployment + Packaging

- [ ] Multi-stage Dockerfile (Rust build + Python runtime)
- [ ] systemd unit file with security hardening
- [ ] logrotate config
- [ ] Operational monitoring (Prometheus alert rules)

---

## Current State

- **Branch:** `dionaea-v2-rust`
- **Tests:** 217 unit + 11 integration, all green
- **Flaky:** Some timing-sensitive network tests under parallel load (pre-existing)
- **Next:** Phase 7.5+ (pcap, nfq, netlink) or Phase 8 (acceptance)

## Files Modified/Created

```
Phases 1-4:
  NEW: crates/dionaea/src/config.rs, error.rs, main.rs, lib.rs, runtime.rs
  NEW: crates/dionaea/src/node_info.rs, ihandler.rs, incident.rs
  NEW: crates/dionaea/src/connection/{mod,tcp,tls,udp,callback,limits,throttle}.rs
  NEW: crates/dionaea/src/python/{mod,connection,incident,ihandler,dionaea,node_info,stats,convert,loader}.rs
  NEW: crates/shell-detect/src/lib.rs (stub)
  NEW: crates/dionaea/tests/listen_connect.rs

Phase 5:
  NEW: crates/dionaea/tests/echo_protocol.rs
  NEW: crates/dionaea/tests/http_protocol.rs
  NEW: crates/dionaea/tests/service_loading.rs
  NEW: crates/dionaea/tests/smb_epmap_protocol.rs
  NEW: crates/dionaea/tests/mysql_protocol.rs
  NEW: crates/dionaea/tests/ihandler_chain.rs
  MOD: crates/dionaea/src/connection/tcp.rs  (drain_control_messages, incidents)
  MOD: crates/dionaea/src/connection/callback.rs  (emit_connection_incident)
  MOD: crates/dionaea/src/python/connection.rs  (__new__ kwarg, factory_create fix)
  MOD: crates/dionaea/src/python/incident.rs  (keys() returns bytes)
  MOD: crates/dionaea/src/python/ihandler.rs  (__new__ accepts **kwargs)
  MOD: crates/dionaea/src/python/convert.rs  (PyConnection → ConnectionRef)

Phase 7:
  NEW: crates/dionaea/src/download.rs  (HTTP download module behind download feature)
  NEW: crates/dionaea/tests/rust_ihandler.rs  (Rust handler dispatch test)
  NEW: crates/dionaea/tests/download_module.rs  (download E2E test)
  MOD: crates/dionaea/src/ihandler.rs  (Arc<Fn> for Rust callbacks)
  MOD: crates/dionaea/src/python/incident.rs  (dispatch to Rust handlers in report())
  MOD: crates/dionaea/src/config.rs  (download timeout/size_limit, Clone)
  MOD: crates/dionaea/src/lib.rs  (download module)
  MOD: crates/dionaea/src/main.rs  (register download handler at startup)

Phase 6:
  NEW: crates/dionaea/src/bistream.rs  (bidirectional stream buffer)
  NEW: crates/dionaea/src/processor.rs  (pipeline, filter, streamdumper, shellcode)
  MOD: crates/shell-detect/src/lib.rs  (stub → real GetPC pattern scanning)
  MOD: crates/dionaea/src/connection/mod.rs  (AttachProcessors in SendMessage)
  MOD: crates/dionaea/src/connection/tcp.rs  (pipeline in I/O loop, drain returns pipeline)
  MOD: crates/dionaea/src/python/connection.rs  (processors() implementation)
  MOD: crates/dionaea/src/config.rs  (ProcessorConfig, FilterRuleConfig)
  MOD: crates/dionaea/src/runtime.rs  (processor_tree field)
  MOD: crates/dionaea/src/main.rs  (build processor tree from config)
  MOD: crates/dionaea/src/lib.rs  (bistream, processor modules)
  MOD: crates/dionaea/Cargo.toml  (sha2 non-optional, tempfile dev-dep)
```
