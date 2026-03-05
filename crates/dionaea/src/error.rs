// SPDX-License-Identifier: GPL-3.0-only
// ABOUTME: Central error type for the dionaea crate.
// ABOUTME: Converts between Rust, Python, I/O, TLS, and config errors.

/// All errors produced by the dionaea crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error (network, file system).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration parsing or validation error.
    #[error("config error: {0}")]
    Config(String),

    /// Python error (converted from PyErr at the boundary).
    #[error("Python error: {0}")]
    Python(String),

    /// TOML deserialization error.
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
}

impl From<pyo3::PyErr> for Error {
    fn from(err: pyo3::PyErr) -> Self {
        Error::Python(err.to_string())
    }
}

impl From<Error> for pyo3::PyErr {
    fn from(err: Error) -> Self {
        pyo3::exceptions::PyRuntimeError::new_err(err.to_string())
    }
}

/// Convenience type alias.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
        assert!(err.to_string().contains("file gone"));
    }

    #[test]
    fn test_config_error() {
        let err = Error::Config("missing field 'listen'".to_string());
        assert!(err.to_string().contains("missing field"));
    }

    #[test]
    fn test_python_error_conversion() {
        pyo3::Python::attach(|py| {
            let py_err = pyo3::exceptions::PyValueError::new_err("bad value");
            let err: Error = py_err.into();
            assert!(matches!(err, Error::Python(_)));
            assert!(err.to_string().contains("bad value"));

            // And back to PyErr
            let py_err2: pyo3::PyErr = Error::Config("test".into()).into();
            assert!(py_err2.to_string().contains("test"));
            let _ = py;
        });
    }
}
