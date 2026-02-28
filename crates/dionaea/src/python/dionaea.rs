// ABOUTME: Python-visible dionaea singleton for global config and version access.
// ABOUTME: Exposed as g_dionaea matching the binding.pyx dionaea class.

use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Global dionaea singleton exposed to Python.
///
/// Provides access to config, interface addresses, and version information.
/// Matches the Cython `dionaea` class in binding.pyx.
#[pyclass]
pub struct PyDionaea {
    version: String,
}

impl Default for PyDionaea {
    fn default() -> Self {
        Self::new()
    }
}

impl PyDionaea {
    /// Create the singleton instance.
    pub fn new() -> Self {
        PyDionaea {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[pymethods]
impl PyDionaea {
    /// Return the parsed configuration as a Python dict.
    ///
    /// Reads from the global config state. Returns an empty dict if no config is loaded.
    fn config<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        // Will be wired to the actual config in Phase 4.
        // For now, return an empty dict.
        Ok(PyDict::new(py))
    }

    /// Return network interface addresses.
    ///
    /// Returns a dict mapping interface names to lists of addresses.
    fn getifaddrs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        // Will be implemented in Phase 6 (infrastructure modules).
        Ok(PyDict::new(py))
    }

    /// Return the dionaea version string.
    fn version(&self) -> &str {
        &self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dionaea_version() {
        Python::attach(|py| {
            let d = Py::new(py, PyDionaea::new()).unwrap();
            let bound = d.bind(py);
            let version: String = bound
                .call_method0("version")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(version, env!("CARGO_PKG_VERSION"));
        });
    }

    #[test]
    fn test_dionaea_config_returns_dict() {
        Python::attach(|py| {
            let d = Py::new(py, PyDionaea::new()).unwrap();
            let bound = d.bind(py);
            let config = bound.call_method0("config").unwrap();
            assert!(config.cast::<PyDict>().is_ok());
        });
    }

    #[test]
    fn test_dionaea_getifaddrs_returns_dict() {
        Python::attach(|py| {
            let d = Py::new(py, PyDionaea::new()).unwrap();
            let bound = d.bind(py);
            let addrs = bound.call_method0("getifaddrs").unwrap();
            assert!(addrs.cast::<PyDict>().is_ok());
        });
    }
}
