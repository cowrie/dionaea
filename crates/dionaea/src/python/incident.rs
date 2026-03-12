// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Python-visible incident class for event dispatch between components.
// ABOUTME: Supports dynamic attribute access via __getattr__/__setattr__.

use crate::ihandler::HandlerCallback;
use crate::incident::{Incident, OpaqueData};
use crate::python::connection::PyConnection;
use crate::python::convert::{opaque_to_py, py_to_opaque};
use crate::python::ihandler::dispatch_to_handler;
use crate::runtime;
use pyo3::prelude::*;
use pyo3::types::PyList;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::{Condvar, Mutex};

/// Incident exposed to Python protocol handlers and ihandlers.
///
/// Dynamic attributes are stored in a `HashMap<String, OpaqueData>` and accessed
/// via `__getattr__`/`__setattr__`. The `origin` property is read-only.
///
/// Connection objects are also stored as `Py<PyAny>` in `py_refs` so that Python
/// handlers get back the original object (with .protocol, .transport, etc.)
/// instead of a bare connection ID integer.
///
#[gen_stub_pyclass]
#[pyclass(subclass, name = "incident", module = "dionaea.core")]
pub struct PyIncident {
    origin: String,
    pub(crate) data: HashMap<String, OpaqueData>,
    /// Original Python objects for attributes that lose fidelity through OpaqueData
    /// (e.g. connection objects which become ConnectionRef(id)).
    pub(crate) py_refs: HashMap<String, Py<PyAny>>,
}

impl PyIncident {
    /// Create from a Rust `Incident`.
    pub fn from_incident(incident: &Incident) -> Self {
        PyIncident {
            origin: incident.origin.clone(),
            data: incident.data.clone(),
            py_refs: HashMap::new(),
        }
    }

    /// Convert back to a Rust `Incident`.
    pub fn to_incident(&self) -> Incident {
        let mut incident = Incident::new(self.origin.clone());
        for (k, v) in &self.data {
            incident.set(k.clone(), v.clone());
        }
        incident
    }
}

/// Serializes incident dispatch across threads.
///
/// Python handlers (logsql, etc.) share mutable state that isn't thread-safe.
/// sqlite3 releases the GIL during cursor operations, which allows concurrent
/// dispatch from different spawn_blocking threads. This lock ensures only one
/// thread dispatches at a time, matching the C single-threaded event loop model.
///
/// Uses a Mutex+Condvar pair instead of an AtomicBool spinlock. This is critical
/// for free-threaded Python (3.13t+) where threads run truly in parallel — a
/// spinlock would burn CPU cycles, while a condvar blocks efficiently.
///
/// Under normal (GIL) Python, the GIL is released via `py.detach()` while
/// blocking on the condvar. Under free-threaded Python, `py.detach()` detaches
/// the thread state, and the condvar blocks the OS thread directly.
static DISPATCH_LOCK: Mutex<bool> = Mutex::new(false);
static DISPATCH_CONDVAR: Condvar = Condvar::new();

// Per-thread flag to detect reentrant dispatch (handler reports another incident).
thread_local! {
    static DISPATCH_REENTRANT: Cell<bool> = const { Cell::new(false) };
}

/// Acquire the dispatch lock, releasing the GIL (if present) while waiting.
///
/// Returns `true` if the lock was acquired, or `false` for reentrant
/// dispatch (same thread already holds the lock).
fn acquire_dispatch(py: Python<'_>) -> bool {
    if DISPATCH_REENTRANT.with(|f| f.get()) {
        return false;
    }
    // Release GIL (or detach thread state under free-threading) while blocking
    // on the condvar. This prevents deadlock: the thread holding the dispatch
    // lock may need the GIL to complete its Python handler callbacks.
    py.detach(|| {
        let mut active = DISPATCH_LOCK.lock().expect("dispatch lock poisoned");
        while *active {
            active = DISPATCH_CONDVAR
                .wait(active)
                .expect("dispatch condvar poisoned");
        }
        *active = true;
    });
    DISPATCH_REENTRANT.with(|f| f.set(true));
    true
}

/// Release the dispatch lock.
fn release_dispatch(acquired: bool) {
    if acquired {
        DISPATCH_REENTRANT.with(|f| f.set(false));
        let mut active = DISPATCH_LOCK.lock().expect("dispatch lock poisoned");
        *active = false;
        DISPATCH_CONDVAR.notify_one();
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl PyIncident {
    /// Create an incident with an optional origin path.
    #[new]
    #[pyo3(signature = (origin=None))]
    pub fn new(origin: Option<String>) -> Self {
        PyIncident {
            origin: origin.unwrap_or_default(),
            data: HashMap::new(),
            py_refs: HashMap::new(),
        }
    }

    /// The incident origin path (e.g. "dionaea.connection.tcp.accept").
    #[getter]
    fn origin(&self) -> &str {
        &self.origin
    }

    /// Report this incident to all matching handlers in the registry.
    ///
    /// Locks the registry to find matching handlers, releases the lock,
    /// then dispatches to each handler. This ordering prevents deadlocks
    /// when a handler callback reports another incident.
    ///
    /// Dispatch is serialized across threads to match the C single-threaded
    /// model. Python handlers (e.g. logsql) share mutable state (sqlite3
    /// cursors) that isn't thread-safe, and sqlite3 releases the GIL during
    /// cursor.execute(), which would allow concurrent dispatch without this
    /// serialization.
    ///
    /// Errors in individual handlers are logged but not propagated,
    /// matching the C behavior.
    fn report(&self, py: Python<'_>) -> PyResult<()> {
        let Some(state) = runtime::get() else {
            tracing::debug!(origin = %self.origin, "incident reported (no runtime)");
            return Ok(());
        };

        let incident = self.to_incident();

        // Collect matching handlers while holding the lock, then release.
        // Rust handlers are cloned as Arc; Python handlers are cloned as Py<PyAny>.
        let (rust_handlers, py_handlers) = {
            let registry = state.ihandler_registry.lock().expect("registry lock");
            let indices = registry.matching_handlers(&incident);
            let mut rust_cbs: Vec<Arc<dyn Fn(&Incident) + Send + Sync>> = Vec::new();
            let mut py_cbs: Vec<Py<PyAny>> = Vec::new();
            for &i in &indices {
                if let Some(h) = registry.get(i) {
                    match &h.callback {
                        HandlerCallback::Rust(f) => rust_cbs.push(f.clone()),
                        HandlerCallback::Python(py_obj) => py_cbs.push(py_obj.clone_ref(py)),
                    }
                }
            }
            (rust_cbs, py_cbs)
        };
        // Lock is released here

        // Serialize dispatch across threads. The GIL alone isn't sufficient
        // because Python C extensions (sqlite3, etc.) can release it during I/O,
        // allowing another thread to enter dispatch concurrently.
        //
        // Under free-threaded Python (no GIL), this serialization is even more
        // critical since threads run truly in parallel.
        //
        // Reentrant dispatch (handler reports another incident on the same thread)
        // is allowed — acquire_dispatch returns None when the current thread
        // already holds the lock.
        let guard = acquire_dispatch(py);

        tracing::debug!(
            origin = %self.origin,
            rust_handlers = rust_handlers.len(),
            py_handlers = py_handlers.len(),
            "dispatching incident"
        );

        for handler in &rust_handlers {
            handler(&incident);
        }

        for handler in &py_handlers {
            let bound = handler.bind(py);
            if let Err(e) = dispatch_to_handler(py, bound, self) {
                tracing::error!(
                    origin = %self.origin,
                    error = %e,
                    "error dispatching incident to handler"
                );
            }
        }

        release_dispatch(guard);

        Ok(())
    }

    /// List all data keys as bytes, matching C behavior where keys are `char *`.
    fn keys<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, pyo3::types::PyBytes>>> {
        Ok(self
            .data
            .keys()
            .map(|k| pyo3::types::PyBytes::new(py, k.as_bytes()))
            .collect())
    }

    /// Set a data field by key.
    fn set(&mut self, py: Python<'_>, key: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let opaque = py_to_opaque(py, value)?;
        self.data.insert(key, opaque);
        Ok(())
    }

    /// Get a data field by key.
    fn get(&self, py: Python<'_>, key: &str) -> PyResult<Py<PyAny>> {
        match self.data.get(key) {
            Some(value) => opaque_to_py(py, value),
            None => Err(pyo3::exceptions::PyAttributeError::new_err(format!(
                "{key} does not exist"
            ))),
        }
    }

    /// Dynamic attribute access: `incident.con`, `incident.port`, etc.
    ///
    /// Returns the original Python object for connection-type attributes,
    /// falling back to OpaqueData conversion for everything else.
    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        if let Some(py_ref) = self.py_refs.get(name) {
            return Ok(py_ref.clone_ref(py));
        }
        self.get(py, name)
    }

    /// Dynamic attribute setting: `incident.con = value`, etc.
    ///
    /// Connection objects are stored as both OpaqueData (for Rust handlers)
    /// and as the original Python object (for Python handlers).
    fn __setattr__(&mut self, py: Python<'_>, key: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        if value.cast::<PyConnection>().is_ok() {
            self.py_refs.insert(key.clone(), value.clone().unbind());
        }
        self.set(py, key, value)
    }

    /// Dump incident contents (for debugging).
    fn dump(&self, py: Python<'_>) -> PyResult<()> {
        let keys_list = PyList::new(py, self.data.keys().collect::<Vec<_>>())?;
        tracing::info!(origin = %self.origin, keys = %keys_list, "incident dump");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::{PyBytes, PyDict};
    use std::sync::Arc;

    #[test]
    fn test_incident_create_and_origin() {
        Python::attach(|py| {
            let inc = Py::new(
                py,
                PyIncident::new(Some("dionaea.connection.tcp.accept".into())),
            )
            .unwrap();
            let bound = inc.bind(py);
            let origin: String = bound.getattr("origin").unwrap().extract().unwrap();
            assert_eq!(origin, "dionaea.connection.tcp.accept");
        });
    }

    #[test]
    fn test_incident_set_get_int() {
        Python::attach(|py| {
            let inc = Py::new(py, PyIncident::new(Some("test.origin".into()))).unwrap();
            let bound = inc.bind(py);
            bound
                .call_method1("set", ("port", 445i64))
                .unwrap();
            let val: i64 = bound
                .call_method1("get", ("port",))
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(val, 445);
        });
    }

    #[test]
    fn test_incident_set_get_string() {
        Python::attach(|py| {
            let inc = Py::new(py, PyIncident::new(Some("test".into()))).unwrap();
            let bound = inc.bind(py);
            bound
                .call_method1("set", ("host", "10.0.0.1"))
                .unwrap();
            let val: String = bound
                .call_method1("get", ("host",))
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(val, "10.0.0.1");
        });
    }

    #[test]
    fn test_incident_set_get_bytes() {
        Python::attach(|py| {
            let inc = Py::new(py, PyIncident::new(Some("test".into()))).unwrap();
            let bound = inc.bind(py);
            let data = PyBytes::new(py, b"\xDE\xAD");
            bound.call_method1("set", ("payload", data)).unwrap();
            let val: Vec<u8> = bound
                .call_method1("get", ("payload",))
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(val, vec![0xDE, 0xAD]);
        });
    }

    #[test]
    fn test_incident_set_get_none() {
        Python::attach(|py| {
            let inc = Py::new(py, PyIncident::new(Some("test".into()))).unwrap();
            let bound = inc.bind(py);
            bound
                .call_method1("set", ("empty", py.None()))
                .unwrap();
            let val = bound.call_method1("get", ("empty",)).unwrap();
            assert!(val.is_none());
        });
    }

    #[test]
    fn test_incident_dynamic_attrs() {
        Python::attach(|py| {
            let inc = Py::new(py, PyIncident::new(Some("test".into()))).unwrap();
            let bound = inc.bind(py);
            // Set via __setattr__
            bound.setattr("port", 445i64).unwrap();
            // Get via __getattr__
            let val: i64 = bound.getattr("port").unwrap().extract().unwrap();
            assert_eq!(val, 445);
        });
    }

    #[test]
    fn test_incident_getattr_missing() {
        Python::attach(|py| {
            let inc = Py::new(py, PyIncident::new(Some("test".into()))).unwrap();
            let bound = inc.bind(py);
            let result = bound.getattr("nonexistent");
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_incident_keys() {
        Python::attach(|py| {
            let inc = Py::new(py, PyIncident::new(Some("test".into()))).unwrap();
            let bound = inc.bind(py);
            bound.setattr("alpha", 1i64).unwrap();
            bound.setattr("beta", 2i64).unwrap();
            let keys: Vec<Vec<u8>> = bound
                .call_method0("keys")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(keys.len(), 2);
            assert!(keys.contains(&b"alpha".to_vec()));
            assert!(keys.contains(&b"beta".to_vec()));
        });
    }

    #[test]
    fn test_incident_dict_value() {
        Python::attach(|py| {
            let inc = Py::new(py, PyIncident::new(Some("test".into()))).unwrap();
            let bound = inc.bind(py);
            let dict = PyDict::new(py);
            dict.set_item("key", "value").unwrap();
            bound.call_method1("set", ("metadata", dict)).unwrap();

            let result = bound.call_method1("get", ("metadata",)).unwrap();
            let result_dict = result.cast::<PyDict>().unwrap();
            let val: String = result_dict.get_item("key").unwrap().unwrap().extract().unwrap();
            assert_eq!(val, "value");
        });
    }

    #[test]
    fn test_incident_list_value() {
        Python::attach(|py| {
            let inc = Py::new(py, PyIncident::new(Some("test".into()))).unwrap();
            let bound = inc.bind(py);
            let list = PyList::new(py, vec![1i64, 2, 3]).unwrap();
            bound.call_method1("set", ("items", list)).unwrap();

            let result = bound.call_method1("get", ("items",)).unwrap();
            let vals: Vec<i64> = result.extract().unwrap();
            assert_eq!(vals, vec![1, 2, 3]);
        });
    }

    #[test]
    fn test_incident_roundtrip_rust() {
        let mut rust_incident = Incident::new("dionaea.download.complete");
        rust_incident.set("url", OpaqueData::String("http://evil.com/mal.exe".into()));
        rust_incident.set("size", OpaqueData::Int(1024));

        let py_incident = PyIncident::from_incident(&rust_incident);
        assert_eq!(py_incident.origin, "dionaea.download.complete");

        let back = py_incident.to_incident();
        assert_eq!(back.origin, "dionaea.download.complete");
        assert_eq!(
            back.get("url"),
            Some(&OpaqueData::String("http://evil.com/mal.exe".into()))
        );
        assert_eq!(back.get("size"), Some(&OpaqueData::Int(1024)));
    }

    /// Verify that the dispatch lock serializes concurrent access from multiple threads.
    ///
    /// This test is critical for free-threaded Python (3.13t+) where threads run
    /// truly in parallel without the GIL. It spawns multiple OS threads that each
    /// acquire/release the dispatch lock and verifies no concurrent execution occurs.
    #[test]
    fn test_dispatch_lock_serializes_threads() {
        use std::sync::atomic::{AtomicU32, Ordering};

        // Counter that tracks how many threads are inside the "critical section"
        let concurrent_count = Arc::new(AtomicU32::new(0));
        let max_concurrent = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(4));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let concurrent = concurrent_count.clone();
                let max = max_concurrent.clone();
                let bar = barrier.clone();
                std::thread::spawn(move || {
                    bar.wait(); // Synchronize thread start
                    for _ in 0..10 {
                        Python::attach(|py| {
                            let guard = acquire_dispatch(py);

                            // We're inside the critical section
                            let count = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
                            // Track maximum concurrent entries
                            max.fetch_max(count, Ordering::SeqCst);

                            // Simulate some work
                            std::thread::yield_now();

                            concurrent.fetch_sub(1, Ordering::SeqCst);
                            release_dispatch(guard);
                        });
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        // Under correct serialization, max concurrent should be exactly 1
        assert_eq!(
            max_concurrent.load(Ordering::SeqCst),
            1,
            "dispatch lock must serialize access: max concurrent was > 1"
        );
    }

    /// Verify that reentrant dispatch (same thread) doesn't deadlock.
    #[test]
    fn test_dispatch_lock_allows_reentrancy() {
        Python::attach(|py| {
            // Outer acquire
            let outer = acquire_dispatch(py);
            assert!(outer, "first acquire should return true");

            // Inner acquire (reentrant) — should return false, not deadlock
            let inner = acquire_dispatch(py);
            assert!(!inner, "reentrant acquire should return false");

            release_dispatch(inner);
            release_dispatch(outer);

            // After release, should be able to acquire again
            let again = acquire_dispatch(py);
            assert!(again, "acquire after release should succeed");
            release_dispatch(again);
        });
    }
}
