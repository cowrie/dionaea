// ABOUTME: Python-visible network address info for connections.
// ABOUTME: Exposes host, port, and hostname properties matching binding.pyx node_info.

use pyo3::prelude::*;

/// Network endpoint address exposed to Python protocol handlers.
///
/// Properties match the Cython `node_info` class in binding.pyx.
/// The `host` and `port` properties are read-write; `hostname` is read-only.
#[pyclass]
pub struct PyNodeInfo {
    /// IP address as string.
    pub host: String,
    /// Port number.
    pub port: u16,
    /// Hostname (empty if unset).
    pub hostname: String,
}

impl PyNodeInfo {
    /// Create a copy from another PyNodeInfo.
    pub fn from_other(other: &PyNodeInfo) -> Self {
        PyNodeInfo {
            host: other.host.clone(),
            port: other.port,
            hostname: other.hostname.clone(),
        }
    }

    /// Create from Rust `NodeInfo`.
    pub fn from_node_info(info: &crate::node_info::NodeInfo) -> Self {
        PyNodeInfo {
            host: info.host.to_string(),
            port: info.port,
            hostname: info.hostname.clone().unwrap_or_default(),
        }
    }
}

#[pymethods]
impl PyNodeInfo {
    #[new]
    pub fn new() -> Self {
        PyNodeInfo {
            host: "0.0.0.0".to_string(),
            port: 0,
            hostname: String::new(),
        }
    }

    /// The node's address as a string.
    #[getter]
    fn host(&self) -> &str {
        &self.host
    }

    #[setter]
    fn set_host(&mut self, addr: String) {
        self.host = addr;
    }

    /// The node's hostname (empty string if unset, matching Cython behavior).
    #[getter]
    fn hostname(&self) -> &str {
        &self.hostname
    }

    /// The node's port in host byte order.
    #[getter]
    fn port(&self) -> u16 {
        self.port
    }

    #[setter]
    fn set_port(&mut self, port: u16) {
        self.port = port;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_info_defaults() {
        Python::attach(|py| {
            let ni = Py::new(py, PyNodeInfo::new()).expect("create");
            let bound = ni.bind(py);
            let host: String = bound.getattr("host").unwrap().extract().unwrap();
            assert_eq!(host, "0.0.0.0");
            let port: u16 = bound.getattr("port").unwrap().extract().unwrap();
            assert_eq!(port, 0);
            let hostname: String = bound.getattr("hostname").unwrap().extract().unwrap();
            assert_eq!(hostname, "");
        });
    }

    #[test]
    fn test_node_info_set_properties() {
        Python::attach(|py| {
            let ni = Py::new(py, PyNodeInfo::new()).expect("create");
            let bound = ni.bind(py);
            bound.setattr("host", "192.168.1.1").unwrap();
            bound.setattr("port", 8080u16).unwrap();
            let host: String = bound.getattr("host").unwrap().extract().unwrap();
            assert_eq!(host, "192.168.1.1");
            let port: u16 = bound.getattr("port").unwrap().extract().unwrap();
            assert_eq!(port, 8080);
        });
    }

    #[test]
    fn test_from_rust_node_info() {
        use crate::node_info::NodeInfo;
        let mut info = NodeInfo::from_socket_addr("10.0.0.1:443".parse().unwrap());
        info.hostname = Some("example.com".to_string());
        let py_info = PyNodeInfo::from_node_info(&info);
        assert_eq!(py_info.host, "10.0.0.1");
        assert_eq!(py_info.port, 443);
        assert_eq!(py_info.hostname, "example.com");
    }
}
