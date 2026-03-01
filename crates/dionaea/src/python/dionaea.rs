// ABOUTME: Python-visible dionaea singleton for global config and version access.
// ABOUTME: Exposed as g_dionaea matching the binding.pyx dionaea class.

use crate::runtime;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

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
    /// Builds the flat-dotted-key dict format matching the C module.c output:
    /// ```python
    /// {
    ///     "dionaea": {"listen.mode": "...", "listen.addresses": [...], ...},
    ///     "module": {"service_configs": [...], "ihandler_configs": [...]},
    /// }
    /// ```
    fn config<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let Some(state) = runtime::get() else {
            return Ok(PyDict::new(py));
        };

        let result = PyDict::new(py);

        // "dionaea" section
        let dionaea_dict = PyDict::new(py);
        dionaea_dict.set_item("listen.mode", &state.config.dionaea.listen.mode)?;

        let addrs: Vec<String> = state
            .config
            .dionaea
            .listen
            .addresses
            .iter()
            .map(|a| a.to_string())
            .collect();
        dionaea_dict.set_item("listen.addresses", PyList::new(py, &addrs)?)?;
        dionaea_dict.set_item(
            "listen.interfaces",
            PyList::new(py, &state.config.dionaea.listen.interfaces)?,
        )?;

        result.set_item("dionaea", dionaea_dict)?;

        // "module" section
        let module_dict = PyDict::new(py);
        module_dict.set_item(
            "service_configs",
            PyList::new(py, &state.config.modules.python.service_configs)?,
        )?;
        module_dict.set_item(
            "ihandler_configs",
            PyList::new(py, &state.config.modules.python.ihandler_configs)?,
        )?;
        result.set_item("module", module_dict)?;

        Ok(result)
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
