# Dionaea v2 Rust Migration — Implementation Plan

## Phases 1–4: Foundation ✅ COMPLETE

All core infrastructure is done: workspace, config, error handling, logging,
PyO3 bridge (full binding.pyx API), TCP/UDP/TLS I/O, connection lifecycle,
incident system, ihandler dispatch, throttling, accounting, limits, deny list.

146 unit tests passing.

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

### 5.6 FTP protocol test
- [ ] Start FTP service via ServiceLoader
- [ ] Connect with raw TCP, verify banner (220), login sequence, directory listing
- [ ] FTP uses outbound connect() for data channels — tests connect() path
- Depends on: 5.5 (FTP sends files via handle_io_out)

### 5.7 SMB/EPMAP protocol test
- [ ] Start SMB + EPMAP services via ServiceLoader
- [ ] Connect, verify initial SMB negotiate response
- [ ] EPMAP is simpler (port mapper) — good sanity check

### 5.8 MySQL protocol test
- [ ] Start MySQL service via ServiceLoader
- [ ] Connect, verify greeting packet (version, salt, capabilities)

### 5.9 ihandler loading chain test
- [ ] Load ihandlers via dionaea.ihandlers module
- [ ] Start a log_json or store ihandler from config
- [ ] Trigger an incident, verify handler receives it
- [ ] Test with real ihandler config TOML files

### 5.10 Run daemon binary end-to-end
- [ ] `cargo run -- -c conf/dionaea.toml` with service configs
- [ ] Connect with curl, nmap, verify responses
- [ ] Verify clean shutdown on SIGTERM
- Depends on: 5.4, 5.5, 5.9

---

## Phase 6: Processor Pipeline + Shellcode (POSTPONED)

Not needed for basic protocol operation. `self.processors()` is a no-op stub.
Will implement after all protocols are validated.

- [ ] Processor trait + tree structure (ProcessorNode, ProcessorPipeline)
- [ ] Filter processor (allow/deny by protocol/connection type)
- [ ] StreamDumper processor (bistream recording to disk)
- [ ] BiStream data structure (interleaved bidirectional recording)
- [ ] shell-detect crate (GetPC pattern scanning: x86, x86-64, MIPS)
- [ ] Shellcode processor (scan ingress, save + emit incident)
- [ ] Config parsing + tree construction from TOML
- [ ] Wire into I/O loop via SendMessage::AttachProcessors
- [ ] PyConnection.processors() creates pipeline from template

---

## Phase 7: Infrastructure Modules

### 7.1 Download module (behind `download` feature)
- [ ] Listen for `dionaea.download.offer` incidents
- [ ] Async HTTP download via reqwest
- [ ] Save to temp file, rename on completion with SHA256 hash
- [ ] Emit `dionaea.download.complete` incident
- [ ] Size limit + timeout config

### 7.2 Privilege dropping
- [ ] Bind all service ports while root
- [ ] Linux: drop capabilities except CAP_NET_BIND_SERVICE
- [ ] macOS: setregid/setreuid to configured user/group
- [ ] Set RLIMIT_NOFILE

### 7.3 Graceful shutdown improvements
- [ ] Call Python services stop() on shutdown
- [ ] Call Python ihandlers stop() on shutdown
- [ ] Drain in-flight connections with configurable deadline
- [ ] Persist IP deny list to disk

### 7.4 SIGHUP log reopening
- [ ] Reopen log file handles on SIGHUP (for logrotate)

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
- **Tests:** 145 unit + 5 integration, all green
- **Flaky:** `test_spawn_blocking_gil_latency` (GIL contention, not a regression)
- **Next:** 5.6 (FTP protocol test)

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
  MOD: crates/dionaea/src/connection/tcp.rs  (drain_control_messages preserves Data)
  MOD: crates/dionaea/src/python/connection.rs  (__new__ kwarg, apply_parent_config)
  MOD: crates/dionaea/src/python/convert.rs  (PyConnection → ConnectionRef)
```
