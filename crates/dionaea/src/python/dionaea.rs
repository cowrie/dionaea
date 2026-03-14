// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Python-visible dionaea singleton for global config and version access.
// ABOUTME: Exposed as g_dionaea to Python protocol handlers and ihandlers.

use crate::runtime;
use git_version::git_version;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods};

/// Version derived from git describe at compile time.
/// Falls back to Cargo.toml version when built outside a git repo.
pub const VERSION: &str = git_version!(fallback = env!("CARGO_PKG_VERSION"));

/// Global dionaea singleton exposed to Python.
///
/// Provides access to config, interface addresses, and version information.
#[gen_stub_pyclass]
#[pyclass(name = "dionaea", module = "dionaea.core")]
pub struct PyDionaea;

impl Default for PyDionaea {
    fn default() -> Self {
        Self::new()
    }
}

impl PyDionaea {
    /// Create the singleton instance.
    pub fn new() -> Self {
        PyDionaea
    }
}

#[gen_stub_pymethods]
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
    #[allow(clippy::unused_self)]
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
            .map(std::string::ToString::to_string)
            .collect();
        dionaea_dict.set_item("listen.addresses", PyList::new(py, &addrs)?)?;
        dionaea_dict.set_item(
            "listen.interfaces",
            PyList::new(py, &state.config.dionaea.listen.interfaces)?,
        )?;
        dionaea_dict.set_item(
            "download.dir",
            state.config.dionaea.download.dir.to_string_lossy().as_ref(),
        )?;
        dionaea_dict.set_item("download.suffix", &state.config.dionaea.download.suffix)?;

        result.set_item("dionaea", dionaea_dict)?;

        // "module" section — nested under "python" to match log.py expectations
        let python_dict = PyDict::new(py);
        python_dict.set_item(
            "service_configs",
            PyList::new(py, &state.config.modules.python.service_configs)?,
        )?;
        python_dict.set_item(
            "ihandler_configs",
            PyList::new(py, &state.config.modules.python.ihandler_configs)?,
        )?;
        let module_dict = PyDict::new(py);
        module_dict.set_item("python", python_dict)?;
        result.set_item("module", module_dict)?;

        Ok(result)
    }

    /// Return network interface addresses.
    ///
    /// Returns a dict matching the C module.c format:
    /// ```python
    /// {"en0": {2: [{"addr": "192.168.1.1"}], 10: [{"addr": "fe80::1"}]}}
    /// ```
    /// Keys: interface name → AF number (2=`AF_INET`, 10=`AF_INET6`) → list of addr dicts.
    #[allow(clippy::unused_self)]
    fn getifaddrs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let result = PyDict::new(py);

        let addrs = nix::ifaddrs::getifaddrs()
            .map_err(|e| pyo3::exceptions::PyOSError::new_err(format!("getifaddrs: {e}")))?;

        for iface in addrs {
            let Some(addr) = iface.address else {
                continue;
            };

            let (af, addr_str) = if let Some(sin) = addr.as_sockaddr_in() {
                let af = nix::sys::socket::AddressFamily::Inet as i32;
                (af, sin.ip().to_string())
            } else if let Some(sin6) = addr.as_sockaddr_in6() {
                let af = nix::sys::socket::AddressFamily::Inet6 as i32;
                (af, sin6.ip().to_string())
            } else {
                continue;
            };

            // Get or create the interface dict
            let iface_dict = if let Some(existing) = result.get_item(&iface.interface_name)? {
                existing.cast::<PyDict>()?.clone()
            } else {
                let d = PyDict::new(py);
                result.set_item(&iface.interface_name, &d)?;
                d
            };

            // Get or create the AF list
            let af_list = if let Some(existing) = iface_dict.get_item(af)? {
                existing.cast::<PyList>()?.clone()
            } else {
                let l = PyList::empty(py);
                iface_dict.set_item(af, &l)?;
                l
            };

            let entry = PyDict::new(py);
            entry.set_item("addr", addr_str)?;
            af_list.append(entry)?;
        }

        Ok(result)
    }

    /// Return the dionaea version string.
    #[allow(clippy::unused_self)]
    fn version(&self) -> &str {
        VERSION
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
            let version: String = bound.call_method0("version").unwrap().extract().unwrap();
            assert_eq!(version, VERSION);
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
    fn test_dionaea_getifaddrs_returns_interfaces() {
        Python::attach(|py| {
            let d = Py::new(py, PyDionaea::new()).unwrap();
            let bound = d.bind(py);
            let addrs = bound.call_method0("getifaddrs").unwrap();
            let dict = addrs.cast::<PyDict>().unwrap();
            // Every machine has at least the loopback interface
            assert!(
                !dict.is_empty(),
                "getifaddrs should return at least one interface"
            );

            // Check structure: interface → AF dict → list of addr dicts
            for (iface_name, af_dict) in dict.iter() {
                let _name: String = iface_name.extract().unwrap();
                let af_dict = af_dict.cast::<PyDict>().unwrap();
                for (_af, addr_list) in af_dict.iter() {
                    let addr_list = addr_list.cast::<PyList>().unwrap();
                    for entry in addr_list.iter() {
                        let entry_dict = entry.cast::<PyDict>().unwrap();
                        let _addr: String = entry_dict
                            .get_item("addr")
                            .unwrap()
                            .unwrap()
                            .extract()
                            .unwrap();
                    }
                }
            }
        });
    }
}
