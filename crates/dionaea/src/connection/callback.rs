// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: Python callback error recovery for connection I/O events.
// ABOUTME: Each callback type has specific error handling (continue, close, propagate).

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::python::incident::PyIncident;

/// What the I/O task should do after a Python callback returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostCallback {
    /// Callback succeeded normally, continue the I/O loop.
    Continue,
    /// Callback failed or requested close, tear down the connection.
    Close,
    /// Outbound disconnect handler returned true, reconnect.
    Reconnect,
}

/// Call `handle_origin(parent)` on the Python connection object.
///
/// On exception: log and continue (no close).
pub fn call_handle_origin(conn: &Bound<'_, PyAny>, parent: &Bound<'_, PyAny>) -> PostCallback {
    match conn.call_method1("handle_origin", (parent,)) {
        Ok(_) => PostCallback::Continue,
        Err(e) => {
            tracing::error!(err = %e, "handle_origin raised exception, continuing");
            PostCallback::Continue
        }
    }
}

/// Call `handle_established()` on the Python connection object.
///
/// On exception: log and continue (no close).
pub fn call_handle_established(conn: &Bound<'_, PyAny>) -> PostCallback {
    match conn.call_method0("handle_established") {
        Ok(_) => PostCallback::Continue,
        Err(e) => {
            tracing::error!(err = %e, "handle_established raised exception, continuing");
            PostCallback::Continue
        }
    }
}

/// Call `handle_io_in(data)` on the Python connection object.
///
/// On exception: log, close connection, return len(data).
/// Returns `(PostCallback, bytes_consumed)`.
pub fn call_handle_io_in(conn: &Bound<'_, PyAny>, data: &[u8]) -> (PostCallback, usize) {
    let py = conn.py();
    let py_data = PyBytes::new(py, data);
    match conn.call_method1("handle_io_in", (py_data,)) {
        Ok(result) => {
            let consumed: usize = result.extract().unwrap_or(data.len());
            (PostCallback::Continue, consumed)
        }
        Err(e) => {
            tracing::error!(err = %e, "handle_io_in raised exception, closing");
            (PostCallback::Close, data.len())
        }
    }
}

/// Call `handle_io_out()` on the Python connection object.
///
/// On exception: log, close connection.
pub fn call_handle_io_out(conn: &Bound<'_, PyAny>) -> PostCallback {
    match conn.call_method0("handle_io_out") {
        Ok(_) => PostCallback::Continue,
        Err(e) => {
            tracing::error!(err = %e, "handle_io_out raised exception, closing");
            PostCallback::Close
        }
    }
}

/// Call `handle_disconnect()` on the Python connection object.
///
/// On exception: treat as "don't reconnect" and close.
/// Returns `PostCallback::Reconnect` if the handler returns `True`.
pub fn call_handle_disconnect(conn: &Bound<'_, PyAny>) -> PostCallback {
    match conn.call_method0("handle_disconnect") {
        Ok(result) => {
            let reconnect: bool = result.extract().unwrap_or(false);
            if reconnect {
                PostCallback::Reconnect
            } else {
                PostCallback::Close
            }
        }
        Err(e) => {
            tracing::error!(err = %e, "handle_disconnect raised exception");
            PostCallback::Close
        }
    }
}

/// Call `handle_timeout_idle()` on the Python connection object.
///
/// On exception: close the connection.
/// Returns `true` if the handler says to keep the connection alive.
pub fn call_handle_timeout_idle(conn: &Bound<'_, PyAny>) -> PostCallback {
    match conn.call_method0("handle_timeout_idle") {
        Ok(result) => {
            let keep_alive: bool = result.extract().unwrap_or(false);
            if keep_alive {
                PostCallback::Continue
            } else {
                PostCallback::Close
            }
        }
        Err(e) => {
            tracing::error!(err = %e, "handle_timeout_idle raised exception");
            PostCallback::Close
        }
    }
}

/// Call `handle_timeout_sustain()` on the Python connection object.
///
/// On exception: close the connection.
/// Returns `true` if the handler says to keep the connection alive.
pub fn call_handle_timeout_sustain(conn: &Bound<'_, PyAny>) -> PostCallback {
    match conn.call_method0("handle_timeout_sustain") {
        Ok(result) => {
            let keep_alive: bool = result.extract().unwrap_or(false);
            if keep_alive {
                PostCallback::Continue
            } else {
                PostCallback::Close
            }
        }
        Err(e) => {
            tracing::error!(err = %e, "handle_timeout_sustain raised exception");
            PostCallback::Close
        }
    }
}

/// Call `handle_timeout_listen()` on the Python connection object.
///
/// On exception: close the connection.
/// Returns `true` if the handler says to keep listening.
pub fn call_handle_timeout_listen(conn: &Bound<'_, PyAny>) -> PostCallback {
    match conn.call_method0("handle_timeout_listen") {
        Ok(result) => {
            let keep_alive: bool = result.extract().unwrap_or(false);
            if keep_alive {
                PostCallback::Continue
            } else {
                PostCallback::Close
            }
        }
        Err(e) => {
            tracing::error!(err = %e, "handle_timeout_listen raised exception");
            PostCallback::Close
        }
    }
}

/// Emit a connection lifecycle incident (e.g. `dionaea.connection.tcp.accept`).
///
/// Must be called with the GIL held. Creates a PyIncident with `con` set to
/// the connection handler, then reports it. Errors are logged but not propagated.
pub fn emit_connection_incident(py: Python<'_>, conn: &Bound<'_, PyAny>, origin: &str) {
    let inc = match Py::new(py, PyIncident::new(Some(origin.to_string()))) {
        Ok(inc) => inc,
        Err(e) => {
            tracing::warn!(origin = %origin, err = %e, "failed to create incident");
            return;
        }
    };
    let bound = inc.bind(py);
    // Set con = handler
    if let Err(e) = bound.setattr("con", conn) {
        tracing::warn!(origin = %origin, err = %e, "failed to set incident.con");
        return;
    }
    if let Err(e) = bound.call_method0("report") {
        tracing::warn!(origin = %origin, err = %e, "failed to report incident");
    }
}

/// Call `handle_error(err)` on the Python connection object.
///
/// Called on outbound connect failure.
/// Returns `Reconnect` if the handler returns a truthy value (matching C behavior
/// where `handle_error` can request reconnection on connect failure).
/// Exceptions are logged and result in `Continue` (no reconnect).
pub fn call_handle_error(conn: &Bound<'_, PyAny>, error_msg: &str) -> PostCallback {
    let py = conn.py();
    match conn.call_method1("handle_error", (error_msg.into_pyobject(py).expect("string"),)) {
        Ok(result) => {
            let reconnect: bool = result.extract().unwrap_or(false);
            if reconnect {
                PostCallback::Reconnect
            } else {
                PostCallback::Continue
            }
        }
        Err(e) => {
            tracing::error!(err = %e, "handle_error raised exception, continuing");
            PostCallback::Continue
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::python::connection::PyConnection;
    use pyo3::types::PyModule;

    fn register_test_module(py: Python<'_>, name: &str) {
        let module = PyModule::new(py, name).expect("module creation");
        module
            .add_class::<PyConnection>()
            .expect("add PyConnection");
        let c_name = std::ffi::CString::new(name).expect("CString");
        py.import(c_name.as_c_str())
            .expect_err("module not in sys.modules yet");
        py.import(c"sys")
            .expect("import sys")
            .getattr("modules")
            .expect("get modules")
            .set_item(name, module)
            .expect("set module");
    }

    #[test]
    fn test_handle_origin_exception_continues() {
        Python::attach(|py| {
            register_test_module(py, "cb_test_origin");
            py.run(
                c"
from cb_test_origin import connection as PyConnection
class FailOrigin(PyConnection):
    def handle_origin(self, parent):
        raise RuntimeError('origin boom')
conn = FailOrigin('tcp')
",
                None,
                None,
            )
            .unwrap();

            let conn = py.eval(c"conn", None, None).unwrap();
            let parent = py.eval(c"conn", None, None).unwrap(); // use self as parent for test
            let result = call_handle_origin(&conn, &parent);
            assert_eq!(result, PostCallback::Continue);
        });
    }

    #[test]
    fn test_handle_established_exception_continues() {
        Python::attach(|py| {
            register_test_module(py, "cb_test_est");
            py.run(
                c"
from cb_test_est import connection as PyConnection
class FailEstablished(PyConnection):
    def handle_established(self):
        raise RuntimeError('established boom')
conn = FailEstablished('tcp')
",
                None,
                None,
            )
            .unwrap();

            let conn = py.eval(c"conn", None, None).unwrap();
            let result = call_handle_established(&conn);
            assert_eq!(result, PostCallback::Continue);
        });
    }

    #[test]
    fn test_handle_io_in_exception_closes() {
        Python::attach(|py| {
            register_test_module(py, "cb_test_io_in");
            py.run(
                c"
from cb_test_io_in import connection as PyConnection
class FailIoIn(PyConnection):
    def handle_io_in(self, data):
        raise RuntimeError('io_in boom')
conn = FailIoIn('tcp')
",
                None,
                None,
            )
            .unwrap();

            let conn = py.eval(c"conn", None, None).unwrap();
            let (result, consumed) = call_handle_io_in(&conn, b"hello");
            assert_eq!(result, PostCallback::Close);
            assert_eq!(consumed, 5); // returns len(data) on error
        });
    }

    #[test]
    fn test_handle_io_in_success_returns_consumed() {
        Python::attach(|py| {
            register_test_module(py, "cb_test_io_in_ok");
            py.run(
                c"
from cb_test_io_in_ok import connection as PyConnection
class PartialConsume(PyConnection):
    def handle_io_in(self, data):
        return 3  # only consume 3 bytes
conn = PartialConsume('tcp')
",
                None,
                None,
            )
            .unwrap();

            let conn = py.eval(c"conn", None, None).unwrap();
            let (result, consumed) = call_handle_io_in(&conn, b"hello");
            assert_eq!(result, PostCallback::Continue);
            assert_eq!(consumed, 3);
        });
    }

    #[test]
    fn test_handle_io_out_exception_closes() {
        Python::attach(|py| {
            register_test_module(py, "cb_test_io_out");
            py.run(
                c"
from cb_test_io_out import connection as PyConnection
class FailIoOut(PyConnection):
    def handle_io_out(self):
        raise RuntimeError('io_out boom')
conn = FailIoOut('tcp')
",
                None,
                None,
            )
            .unwrap();

            let conn = py.eval(c"conn", None, None).unwrap();
            let result = call_handle_io_out(&conn);
            assert_eq!(result, PostCallback::Close);
        });
    }

    #[test]
    fn test_handle_disconnect_returns_reconnect() {
        Python::attach(|py| {
            register_test_module(py, "cb_test_disc");
            py.run(
                c"
from cb_test_disc import connection as PyConnection
class ReconnectProto(PyConnection):
    def handle_disconnect(self):
        return True
class CloseProto(PyConnection):
    def handle_disconnect(self):
        return False
reconnect = ReconnectProto('tcp')
close = CloseProto('tcp')
",
                None,
                None,
            )
            .unwrap();

            let reconnect = py.eval(c"reconnect", None, None).unwrap();
            assert_eq!(call_handle_disconnect(&reconnect), PostCallback::Reconnect);

            let close = py.eval(c"close", None, None).unwrap();
            assert_eq!(call_handle_disconnect(&close), PostCallback::Close);
        });
    }

    #[test]
    fn test_handle_disconnect_exception_closes() {
        Python::attach(|py| {
            register_test_module(py, "cb_test_disc_err");
            py.run(
                c"
from cb_test_disc_err import connection as PyConnection
class FailDisconnect(PyConnection):
    def handle_disconnect(self):
        raise RuntimeError('disconnect boom')
conn = FailDisconnect('tcp')
",
                None,
                None,
            )
            .unwrap();

            let conn = py.eval(c"conn", None, None).unwrap();
            assert_eq!(call_handle_disconnect(&conn), PostCallback::Close);
        });
    }

    #[test]
    fn test_handle_timeout_idle_keep_alive() {
        Python::attach(|py| {
            register_test_module(py, "cb_test_timeout");
            py.run(
                c"
from cb_test_timeout import connection as PyConnection
class KeepAlive(PyConnection):
    def handle_timeout_idle(self):
        return True
class LetDie(PyConnection):
    def handle_timeout_idle(self):
        return False
keep = KeepAlive('tcp')
die = LetDie('tcp')
",
                None,
                None,
            )
            .unwrap();

            let keep = py.eval(c"keep", None, None).unwrap();
            assert_eq!(call_handle_timeout_idle(&keep), PostCallback::Continue);

            let die = py.eval(c"die", None, None).unwrap();
            assert_eq!(call_handle_timeout_idle(&die), PostCallback::Close);
        });
    }

    #[test]
    fn test_handle_error_continues() {
        Python::attach(|py| {
            register_test_module(py, "cb_test_error");
            py.run(
                c"
from cb_test_error import connection as PyConnection
class ErrorHandler(PyConnection):
    def handle_error(self, err):
        self.last_error = str(err)
conn = ErrorHandler('tcp')
",
                None,
                None,
            )
            .unwrap();

            let conn = py.eval(c"conn", None, None).unwrap();
            let result = call_handle_error(&conn, "connection refused");
            assert_eq!(result, PostCallback::Continue);

            let last: String = conn
                .getattr("last_error")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(last, "connection refused");
        });
    }

    #[test]
    fn test_handle_error_returns_reconnect() {
        Python::attach(|py| {
            register_test_module(py, "cb_test_error_recon");
            py.run(
                c"
from cb_test_error_recon import connection as PyConnection
class ReconnectOnError(PyConnection):
    def handle_error(self, err):
        return True
class NoReconnect(PyConnection):
    def handle_error(self, err):
        return False
reconnect = ReconnectOnError('tcp')
no_reconnect = NoReconnect('tcp')
",
                None,
                None,
            )
            .unwrap();

            let reconnect = py.eval(c"reconnect", None, None).unwrap();
            assert_eq!(call_handle_error(&reconnect, "conn refused"), PostCallback::Reconnect);

            let no_reconnect = py.eval(c"no_reconnect", None, None).unwrap();
            assert_eq!(call_handle_error(&no_reconnect, "conn refused"), PostCallback::Continue);
        });
    }
}
