// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Central error type for the dionaea crate.
// ABOUTME: Converts between Rust, Python, I/O, TLS, and config errors.

/// All errors produced by the dionaea crate.
#[derive(Debug)]
pub enum Error {
    /// I/O error (network, file system).
    Io(std::io::Error),

    /// Configuration parsing or validation error.
    Config(String),

    /// Python error (converted from `PyErr` at the boundary).
    Python(String),

    /// TOML deserialization error.
    Toml(toml::de::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Config(msg) => write!(f, "config error: {msg}"),
            Error::Python(msg) => write!(f, "Python error: {msg}"),
            Error::Toml(e) => write!(f, "TOML parse error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<toml::de::Error> for Error {
    fn from(err: toml::de::Error) -> Self {
        Error::Toml(err)
    }
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
