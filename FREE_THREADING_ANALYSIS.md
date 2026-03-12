# Python 3.14 Free-Threading Impact Analysis for Dionaea v2 (Rust/PyO3)

## Executive Summary

Dionaea v2 uses **PyO3 0.28** with a **Rust + tokio** core that invokes Python protocol
handlers via `spawn_blocking` + `Python::attach`. The architecture already serializes
most Python access through the GIL (now "attach") boundary. Moving to free-threaded
Python 3.14t introduces **three categories of risk**: PyO3 API compatibility, Rust-side
concurrency assumptions, and Python-side shared mutable state.

**Overall risk: MODERATE.** The Rust-side architecture is well-suited for free-threading,
but several specific areas need attention before running on `python3.14t`.

---

## 1. PyO3 Version and Compatibility

| Item | Current | Required for 3.14t |
|---|---|---|
| PyO3 version | 0.28 | 0.28+ (supported since 0.23) |
| API naming | `Python::attach` / `Python::detach` | Already using new names |
| `abi3` feature | Not used | Good — `abi3` is incompatible with free-threaded ABI |
| `#[pymodule]` declaration | None (classes registered manually) | Should declare `gil_used` or not |

**Status: PyO3 0.28 supports free-threaded Python 3.14t.** The codebase already uses the
modern API naming (`Python::attach` instead of deprecated `with_gil`).

---

## 2. Rust-Side Analysis

### 2.1 Thread Model

The current architecture uses `tokio::task::spawn_blocking` to run Python callbacks:

```
[tokio async task] --spawn_blocking--> [blocking thread] --Python::attach--> [Python callback]
```

With the GIL, only one `spawn_blocking` thread runs Python at a time. **Under
free-threading, multiple `spawn_blocking` threads can run Python simultaneously.**
This is the fundamental change that affects all subsequent analysis.

### 2.2 `DISPATCH_ACTIVE` Serialization Lock (incident.rs:68)

```rust
static DISPATCH_ACTIVE: AtomicBool = AtomicBool::new(false);
```

This `AtomicBool` spinlock serializes incident dispatch across threads. The comment
explains this exists because sqlite3 releases the GIL during `cursor.execute()`,
allowing concurrent dispatch even WITH the GIL.

**Impact: CRITICAL — This is essential and must be KEPT for free-threading.**

Under free-threading, without this lock, multiple threads could simultaneously:
- Call `logsqlhandler.handle_incident_*()` methods
- Access shared `self.cursor` / `self.dbh` sqlite3 objects
- Corrupt the SQLite database

The current implementation using `py.detach()` (was `allow_threads`) while spinning
is correct for free-threading — it releases the thread state while waiting.

**However**, the `AtomicBool` spinlock has a subtle issue: it uses `compare_exchange_weak`
with `yield_now()`, which could starve under high contention on free-threaded Python
where many threads truly run in parallel. Consider upgrading to a proper `Mutex` or
`parking_lot::Mutex`.

### 2.3 Thread-Local State (connection.rs:25-27)

```rust
thread_local! {
    static FACTORY_CON_ID: Cell<Option<ConnectionId>> = const { Cell::new(None) };
    static FACTORY_SEND_TX: Cell<Option<mpsc::Sender<SendMessage>>> = const { Cell::new(None) };
}
```

**Impact: SAFE.** Thread-locals are per-thread by definition. Under free-threading,
each `spawn_blocking` thread has its own copy. The factory pattern (set TLS, call
Python constructor, read TLS) works correctly because the set-call-read sequence
happens on a single thread within a single `Python::attach` block.

### 2.4 `DISPATCH_REENTRANT` Thread-Local (incident.rs:71-73)

```rust
thread_local! {
    static DISPATCH_REENTRANT: Cell<bool> = const { Cell::new(false) };
}
```

**Impact: SAFE.** Correctly tracks per-thread reentrant dispatch. Under free-threading,
each thread independently tracks whether it's already dispatching.

### 2.5 Global Runtime State (runtime.rs:15)

```rust
static RUNTIME: OnceLock<Arc<RuntimeState>> = OnceLock::new();
```

**Impact: SAFE.** `OnceLock` is thread-safe. `RuntimeState` is initialized once and
read-only after init (except for the `Mutex`-protected fields).

### 2.6 `IHandlerRegistry` Behind `Mutex` (runtime.rs:29)

```rust
pub ihandler_registry: Mutex<IHandlerRegistry>,
```

**Impact: NEEDS REVIEW.** The mutex is correctly used — it's locked to find matching
handlers, then released before dispatching. However, under free-threading:

- Multiple threads could register/unregister handlers concurrently with dispatch
- The lock-release-dispatch pattern is correct but the window between releasing
  the lock and dispatching is wider under true parallelism
- `HandlerCallback::Python(Py<PyAny>)` — the `Py<PyAny>` is `Send` and `Sync` in
  PyO3, but calling methods on the bound object requires thread safety in the
  Python handler itself

### 2.7 `ConnectionRegistry` (DashMap) (connection/mod.rs:349)

```rust
pub struct ConnectionRegistry {
    connections: DashMap<ConnectionId, ConnectionMeta>,
}
```

**Impact: SAFE.** `DashMap` is inherently thread-safe with sharded locks. Connection
metadata access/mutation through `get()`/`get_mut()` is correctly synchronized.

### 2.8 `AtomicU64` Connection ID Counter (connection/mod.rs:45)

```rust
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
```

**Impact: SAFE.** Atomic operations are thread-safe.

### 2.9 `#[pyclass]` Definitions

All `#[pyclass]` types use PyO3's default interior mutability (runtime borrow checking):

| Class | Attributes | `frozen`? | Risk |
|---|---|---|---|
| `PyConnection` | `subclass, weakref` | No | **MEDIUM** — `&mut self` methods could race |
| `PyIncident` | `subclass` | No | **LOW** — typically short-lived, single-owner |
| `PyIHandler` | `subclass` | No | **LOW** — registered once, pattern is read-only |
| `PyDionaea` | — | No | **LOW** — stateless singleton, all methods take `&self` |
| `PyNodeInfo` | — | No | **LOW** — value type, set once per connection |

**`PyConnection` is the highest risk** because:
- It has `&mut self` methods (`__init__`, `invalidate`, setters)
- Under free-threading, a Python protocol handler on one thread could call `send()`
  while the I/O task on another thread calls `invalidate()`
- PyO3's runtime borrow checker will panic on concurrent `&self` + `&mut self` access

**Recommendation:** Consider `#[pyclass(frozen)]` for `PyDionaea` (it's stateless).
For `PyConnection`, the mutable fields need protection — either via `#[pyclass(frozen)]`
with internal `Mutex`, or by ensuring all access is single-threaded (which the current
`spawn_blocking` pattern effectively guarantees, since each connection's handler is
only called from one task at a time).

### 2.10 `Py<PyAny>` Handler Ownership in I/O Loop (tcp.rs)

The I/O loop moves the `Py<PyAny>` handler into `spawn_blocking` and gets it back:

```rust
let (handler_back, post) = tokio::task::spawn_blocking(move || {
    Python::attach(|py| {
        let bound = handler.bind(py);
        let post = callback::call_handle_io_in(&bound, &data);
        (handler.clone_ref(py), post)
    })
}).await?;
handler = handler_back;
```

**Impact: SAFE under free-threading.** Each connection's handler is owned by exactly
one I/O task. The move-in/move-out pattern ensures exclusive access. Even under
free-threading, only one thread at a time holds the `Py<PyAny>` for a given connection.

---

## 3. Python-Side Analysis

### 3.1 `logsql.py` — SQLite Handler (**HIGH RISK**)

```python
self.dbh = sqlite3.connect(self.filename, check_same_thread=False)
self.cursor = self.dbh.cursor()
```

The `check_same_thread=False` flag is already set, acknowledging cross-thread access.
Under the GIL, sqlite3's `cursor.execute()` releases the GIL during I/O but the
Rust-side `DISPATCH_ACTIVE` lock prevents concurrent dispatch.

**Under free-threading:**
- The `DISPATCH_ACTIVE` lock still protects against concurrent dispatch
- However, sqlite3 itself may not be thread-safe in the free-threaded build
- `self.attacks` (dict), `self.pending` (dict), `self.cursor` are all shared
  mutable state on `self`

**Recommendation:** The `DISPATCH_ACTIVE` serialization lock makes this safe in practice.
Verify sqlite3 module compatibility with free-threaded Python.

### 3.2 `ihandlers.py` — Global Handler Registry (**MEDIUM RISK**)

```python
g_handlers: dict[IHandlerLoader, list] = {}
g_handler_configs: list = []
```

Module-level mutable globals modified via `global` keyword in `new()`, `start()`, `stop()`.

**Under free-threading:** These are only modified during startup/shutdown (single-threaded
phases), so concurrent access is unlikely. But if `new()`/`start()`/`stop()` were ever
called concurrently, the global dicts would race.

**Recommendation:** Low practical risk due to lifecycle serialization.

### 3.3 `services.py` — Global Service State (**MEDIUM RISK**)

```python
g_slave = None
g_service_configs: list = []
```

Same pattern as `ihandlers.py` — globals modified during startup only.

**Recommendation:** Same as above — safe in practice due to lifecycle.

### 3.4 `__init__.py` — Timer / Thread Usage (**MEDIUM RISK**)

```python
class SubTimer(Thread):
    def run(self):
        self.finished.wait(self.delay)
        if not self.finished.is_set():
            self.function(*self.args, **self.kwargs)
```

`SubTimer` creates actual OS threads that call callback functions. Under the GIL,
the callback and main thread are serialized. Under free-threading, the timer callback
runs truly concurrently with the main thread.

**Impact:** If timer callbacks access shared state (e.g., connection objects, handler
state), data races are possible.

**Recommendation:** Audit all `Timer` usage to ensure callbacks are thread-safe.

### 3.5 `sip/extras.py` — SQLite with `check_same_thread=False` (**MEDIUM RISK**)

```python
self._conn = sqlite3.connect(self.users, check_same_thread=False)
```

Another sqlite3 connection with cross-thread access. Protected by the same
`DISPATCH_ACTIVE` serialization.

### 3.6 Protocol Handlers (smb, http, ftp, etc.) (**LOW RISK**)

Each protocol handler instance is created per-connection and owned by a single I/O
task. Under the current architecture, a protocol handler is only accessed from one
`spawn_blocking` thread at a time (the move-in/move-out pattern in tcp.rs).

**Impact: SAFE** as long as the single-owner-per-connection invariant holds.

### 3.7 `RegisterClasses` Metaclass (**MEDIUM RISK**)

```python
class RegisterClasses(type):
    def __init__(cls, name, bases, nmspc):
        cls.registry.add(cls)
        cls.registry -= set(bases)
```

The class `registry` set is modified during class definition (import time). Under
free-threading, if modules are imported concurrently, the set mutations could race.

**Recommendation:** Module imports are serialized by Python's import lock, so this is
safe in practice.

---

## 4. Required Changes for Free-Threading Support

### 4.1 Must-Have (Correctness)

1. **Verify PyO3 0.28 free-threading compatibility** — Run the test suite with
   `python3.14t`. PyO3 0.28 should work, but verify no panics from the runtime
   borrow checker.

2. **Keep `DISPATCH_ACTIVE` serialization** — This is essential. Consider upgrading
   from `AtomicBool` spinlock to `std::sync::Mutex` to avoid spin-waiting under
   high contention.

3. **Audit `#[pyclass]` borrow patterns** — Ensure no `#[pymethods]` that take
   `&mut self` can be called concurrently with methods that take `&self` on the
   same object. The single-owner-per-connection pattern should prevent this, but
   verify for `PyConnection`.

4. **Test sqlite3 module** — Verify the `sqlite3` module works correctly under
   free-threaded Python. The Python ecosystem tracker shows sqlite3 as needing
   attention.

### 4.2 Should-Have (Robustness)

5. **Add `#[pyclass(frozen)]` to `PyDionaea`** — It's stateless; marking it frozen
   avoids runtime borrow checking overhead.

6. **Add module-level `gil_used` declaration** — Explicitly declare whether the
   extension supports free-threading:
   ```rust
   // When ready:
   #[pymodule]  // defaults to allowing free-threading in PyO3 0.28
   // Or to opt out temporarily:
   #[pymodule(gil_used = true)]
   ```

7. **Consider `#[pyclass(frozen)]` for `PyIHandler`** — The `pattern` field is
   set once in `__init__` and never mutated. Use interior mutability only if needed.

### 4.3 Nice-to-Have (Performance)

8. **Replace `DISPATCH_ACTIVE` spinlock with parking_lot::Mutex** — Proper blocking
   instead of yield-spinning under contention.

9. **Profile `Python::attach` overhead** — Under free-threading, `Python::attach`
   no longer needs to acquire the GIL, which should reduce `spawn_blocking` latency.

10. **Evaluate removing `DISPATCH_ACTIVE`** — If Python handlers are made thread-safe
    (e.g., per-handler sqlite connections), the serialization lock could be removed
    to allow true parallel incident dispatch.

---

## 5. Architecture Assessment

The dionaea v2 Rust architecture is **well-positioned** for free-threading:

| Aspect | Status | Notes |
|---|---|---|
| Per-connection handler ownership | GOOD | Move-in/move-out ensures single-threaded access |
| `DashMap` for connection registry | GOOD | Already thread-safe |
| Atomic connection ID generation | GOOD | Lock-free |
| Incident dispatch serialization | GOOD | `DISPATCH_ACTIVE` prevents races |
| `OnceLock` for runtime state | GOOD | Safe initialization |
| `Mutex` for handler registry | GOOD | Proper locking |
| Thread-local factory state | GOOD | Per-thread by design |

The main risks are in the **Python-side code** (sqlite3, global state) rather than
the Rust core. The existing `DISPATCH_ACTIVE` serialization effectively maintains
single-threaded semantics for incident dispatch, which is the primary cross-cutting
concern.

---

## 6. Testing Strategy

1. **Build against Python 3.14t** — Set `PYO3_PYTHON=python3.14t` and build.
2. **Run existing test suite** — All `cargo test` should pass.
3. **Stress test concurrent connections** — Multiple simultaneous connections to
   verify no borrow-checker panics in `PyConnection`.
4. **Stress test incident dispatch** — Multiple incidents reported simultaneously
   to verify `DISPATCH_ACTIVE` holds under true parallelism.
5. **Profile GIL removal benefit** — Measure latency reduction in `spawn_blocking`
   callbacks now that `Python::attach` doesn't acquire the GIL.

---

## References

- [PyO3 Free-Threading Guide](https://pyo3.rs/main/free-threading.html)
- [PyO3 Thread Safety](https://pyo3.rs/v0.28.2/class/thread-safety)
- [PyO3 Migration Guide](https://pyo3.rs/main/migration.html)
- [PEP 703 — Making the GIL Optional](https://peps.python.org/pep-0703/)
- [PEP 779 — Free-Threading Supported in 3.14](https://peps.python.org/pep-0779/)
- [Python Free-Threading Compatibility Tracker](https://py-free-threading.github.io/tracking/)
- [What's New in Python 3.14](https://docs.python.org/3/whatsnew/3.14.html)
