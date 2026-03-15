# Rust Anti-Pattern Review

Review based on [rustic-prompt anti-patterns guide](https://github.com/Ranrar/rustic-prompt/blob/main/.github/instructions/rust/rust.instructions.md#6-identify-and-avoid-common-anti-patterns).

## 1. Unnecessary Cloning

### Production Code Issues

**`bistream.rs:67` — Cloning entire Vec on read**
```rust
pub fn chunks(&self) -> Vec<StreamChunk> {
    self.chunks.lock().expect("bistream lock").clone()
}
```
Returns a full deep-copy of all recorded chunks. Since `StreamChunk.data` is `Bytes` (ref-counted), the clone is cheap per-element, but returning a `Vec` forces allocation. If callers only need iteration, an alternative would be to accept a closure or return chunk count + indexed access. However, given the Mutex, cloning out is the simplest safe pattern here — **acceptable but worth noting**.

**`download.rs:210` — Cloning string from borrowed data**
```rust
Some(OpaqueData::String(s)) => s.clone(),
```
The `s` is borrowed from the incident map. The clone is necessary because it's used after the borrow ends. **Acceptable**.

**`download.rs:231` — Cloning entire DownloadConfig**
```rust
let config = state.config.dionaea.download.clone();
```
Clones the full download config to move into an async block. Could use `Arc<DownloadConfig>` to share instead of copying, but this runs once per download so the overhead is negligible. **Low priority**.

**`processor.rs:198-205` — Cloning Vec<String> pairs during tree build**
```rust
.map(|r| (r.protocols.clone(), r.types.clone()))
```
Clones protocol/type string vectors during one-time startup tree construction. **Acceptable — startup-only code**.

**`upload.rs:105,111` — Cloning into multipart form**
```rust
let mut part = reqwest::multipart::Part::text(value.clone());
form = form.part(name.clone(), part);
```
The reqwest API consumes owned strings. Clones are necessary here. **Required by API**.

**`connection/tcp.rs` — Widespread Arc cloning**
Extensive `.clone()` on `Arc<ConnectionRegistry>` and `Arc<ConnectionLimits>` for spawning tasks. This is the correct usage pattern for `Arc` — **not an anti-pattern**.

### Verdict
Most clones are either necessary (moving data into async tasks, API requirements) or on `Arc` types (cheap ref-count increment). No significant unnecessary cloning found.

---

## 2. Overusing Error Suppression (`.unwrap()` / `.expect()`)

### Critical Production Code Issues (FIXED)

**`runtime.rs:60,65` — Mutex lock panics**
```rust
self.listeners.lock().expect("lock").push(abort);
```
If the mutex is poisoned (a thread panicked while holding it), this crashes the daemon. **Fixed**: replaced with `unwrap_or_else` that recovers from poisoning.

**`bistream.rs:41,57,67,72` — Mutex lock panics**
```rust
self.chunks.lock().expect("bistream lock")
```
Same mutex poisoning concern in a hot path (every data chunk). **Fixed**: replaced with poison recovery.

**`python/ihandler.rs:69` — Mutex lock panic**
```rust
.expect("ihandler registry lock")
```
Panics in Python callback context would crash the Python interpreter. **Fixed**: replaced with `map_err` returning a `PyRuntimeError`.

**`download.rs:271` and `upload.rs:293` — Mutex lock panics**
```rust
.expect("registry lock")
```
Registration-time panics. **Fixed**: replaced with logging + early return.

**`pcap.rs:344` — Thread spawn panic**
```rust
.expect("spawn pcap thread");
```
If OS can't spawn a thread (resource exhaustion), this crashes instead of degrading gracefully. **Fixed**: replaced with error logging and skip.

### Acceptable Uses of `.expect()`

- **`runtime.rs:89`** — `init()` panic on double-init is intentional (programming error, documented)
- **`main.rs:744`** — `signal()` expect in SIGPIPE ignore is standard practice; failure here is unrecoverable
- **Test code** — All `.unwrap()` / `.expect()` in `#[cfg(test)]` modules are fine

---

## 3. Premature Collection

**No significant issues found.** Most `.collect()` calls build data structures that are subsequently used in full (e.g., config parsing, BPF filter construction). The `processor.rs` tree builder collects into `Vec` because it needs random access. `main.rs:384` collects args, which is standard.

---

## 4. Unsafe Code

**`main.rs:742-745` — Single justified `unsafe` block**
```rust
#[allow(unsafe_code)]
unsafe {
    signal(Signal::SIGPIPE, SigHandler::SigIgn).expect("ignore SIGPIPE");
}
```
Well-documented SAFETY comment, minimal scope, standard practice for network daemons. **No issue**.

No other `unsafe` blocks exist in the codebase. The crate likely has `#![deny(unsafe_code)]` with this single exception.

---

## 5. Over-Abstraction

**No issues found.** The trait usage is minimal and purposeful:
- `Processor` trait in `processor.rs` for the pipeline pattern (filter, streamdumper, shellcode)
- Standard `Debug`, `Clone`, `Default` derives
- No unnecessary generic parameters or complex trait hierarchies

---

## 6. Global Mutable State

**Two instances using `OnceLock` (acceptable pattern):**

- **`runtime.rs:15`** — `static RUNTIME: OnceLock<Arc<RuntimeState>>` — Write-once global for daemon state. Properly wrapped in `Arc` with interior mutability via `Mutex` for mutable fields. This is the standard Rust pattern for daemon-wide state.

- **`python/mod.rs:76`** — `static CWD: OnceLock<PathBuf>` — Write-once working directory cache.

Both are write-once values, not mutable global state. **No issue**.

---

## 7. Threading GUI Operations

**Not applicable** — This is a network daemon with no GUI.

---

## 8. Macro Opacity

**No `macro_rules!` definitions found** in the codebase. The project uses derive macros from external crates (`serde`, `pyo3`) which is standard practice. **No issue**.

---

## 9. Lifetime Annotation Gaps

**No issues found.** The codebase primarily uses owned types (`String`, `Vec`, `Arc`) and avoids complex lifetime relationships. Where borrows are used (e.g., `&Incident`, `&str` parameters), lifetimes are elided correctly by the compiler.

---

## 10. Premature Optimization

**No issues found.** The code is straightforward and readable. No hand-rolled SIMD, manual memory management, or unnecessary micro-optimizations. Performance-relevant choices (like `Bytes` for zero-copy buffers) are appropriate for a network daemon.

---

## Summary

| Anti-Pattern | Severity | Count | Status |
|---|---|---|---|
| Unnecessary cloning | Low | ~5 spots | Acceptable (required by async/API) |
| Error suppression (unwrap/expect) | **High** | 7 in production | **Fixed** |
| Premature collection | None | 0 | Clean |
| Unsafe code | None | 1 (justified) | Clean |
| Over-abstraction | None | 0 | Clean |
| Global mutable state | None | 0 (OnceLock is fine) | Clean |
| Macro opacity | None | 0 | Clean |
| Lifetime gaps | None | 0 | Clean |
| Premature optimization | None | 0 | Clean |

The main actionable finding was **Mutex `.expect()` calls in production code** that could crash the daemon on mutex poisoning. These have been replaced with poison-recovery patterns or proper error propagation.
