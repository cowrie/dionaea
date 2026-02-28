// ABOUTME: Python-visible incident class for event dispatch between components.
// ABOUTME: Supports dynamic attribute access (__getattr__/__setattr__) matching binding.pyx.

use crate::incident::{Incident, OpaqueData};
use crate::python::convert::{opaque_to_py, py_to_opaque};
use pyo3::prelude::*;
use pyo3::types::PyList;
use std::collections::HashMap;

/// Incident exposed to Python protocol handlers and ihandlers.
///
/// Dynamic attributes are stored in a `HashMap<String, OpaqueData>` and accessed
/// via `__getattr__`/`__setattr__`. The `origin` property is read-only.
///
/// Matches the Cython `incident` class in binding.pyx.
#[pyclass(subclass)]
pub struct PyIncident {
    origin: String,
    data: HashMap<String, OpaqueData>,
}

impl PyIncident {
    /// Create from a Rust `Incident`.
    pub fn from_incident(incident: &Incident) -> Self {
        PyIncident {
            origin: incident.origin.clone(),
            data: incident.data.clone(),
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

#[pymethods]
impl PyIncident {
    #[new]
    #[pyo3(signature = (origin=None))]
    fn new(origin: Option<String>) -> Self {
        PyIncident {
            origin: origin.unwrap_or_default(),
            data: HashMap::new(),
        }
    }

    /// The incident origin path (e.g. "dionaea.connection.tcp.accept").
    #[getter]
    fn origin(&self) -> &str {
        &self.origin
    }

    /// Report this incident to the handler registry.
    ///
    /// In the current implementation this is a no-op placeholder.
    /// The actual dispatch happens in the Rust incident system.
    fn report(&self) {
        // Will be wired to IHandlerRegistry::dispatch in Phase 4.
        tracing::debug!(origin = %self.origin, "incident reported");
    }

    /// List all data keys.
    fn keys(&self) -> Vec<String> {
        self.data.keys().cloned().collect()
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
    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        self.get(py, name)
    }

    /// Dynamic attribute setting: `incident.con = value`, etc.
    fn __setattr__(&mut self, py: Python<'_>, key: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
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
            let keys: Vec<String> = bound
                .call_method0("keys")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(keys.len(), 2);
            assert!(keys.contains(&"alpha".to_string()));
            assert!(keys.contains(&"beta".to_string()));
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
}
