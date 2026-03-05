// SPDX-License-Identifier: GPL-3.0-only
// ABOUTME: Python-visible connection statistics and timeout configuration.
// ABOUTME: Maps to binding.pyx connection_timeouts, connection_speed, connection_accounting, connection_stats.

use pyo3::prelude::*;
use tokio::sync::mpsc;

use crate::connection::{Direction, SendMessage, TimeoutKind};

/// Connection timeout configuration exposed to Python.
///
/// Matches the Cython `connection_timeouts` class. All values are in seconds (f64).
/// Read/write: gets snapshot from metadata, writes send control messages through the channel.
#[pyclass]
pub struct PyConnectionTimeouts {
    /// Idle timeout (seconds).
    pub idle: f64,
    /// Sustain timeout (seconds).
    pub sustain: f64,
    /// Listen timeout (seconds).
    pub listen: f64,
    /// Handshake timeout (seconds).
    pub handshake: f64,
    /// Connecting timeout (seconds).
    pub connecting: f64,
    /// Reconnect timeout (seconds).
    pub reconnect: f64,
    /// Channel for sending timeout updates to the I/O task. None if disconnected.
    send_tx: Option<mpsc::Sender<SendMessage>>,
}

impl PyConnectionTimeouts {
    /// Create from Rust timeout values and an optional send channel.
    pub fn from_values(
        timeouts: &crate::connection::ConnectionTimeouts,
        send_tx: Option<mpsc::Sender<SendMessage>>,
    ) -> Self {
        PyConnectionTimeouts {
            idle: timeouts.idle,
            sustain: timeouts.sustain,
            listen: timeouts.listen,
            handshake: timeouts.handshake,
            connecting: timeouts.connecting,
            reconnect: 0.0, // reconnect timeout not in ConnectionTimeouts struct yet
            send_tx,
        }
    }
}

#[pymethods]
impl PyConnectionTimeouts {
    #[new]
    pub fn new() -> Self {
        PyConnectionTimeouts {
            idle: 120.0,
            sustain: 300.0,
            listen: 0.0,
            handshake: 10.0,
            connecting: 5.0,
            reconnect: 0.0,
            send_tx: None,
        }
    }

    /// Idle timeout for established connections.
    #[getter]
    fn idle(&self) -> f64 {
        self.idle
    }

    #[setter]
    fn set_idle(&mut self, value: f64) {
        self.idle = value;
        self.send_timeout(TimeoutKind::Idle, value);
    }

    /// Sustain (session) timeout.
    #[getter]
    fn sustain(&self) -> f64 {
        self.sustain
    }

    #[setter]
    fn set_sustain(&mut self, value: f64) {
        self.sustain = value;
        self.send_timeout(TimeoutKind::Sustain, value);
    }

    /// Listen timeout.
    #[getter]
    fn listen(&self) -> f64 {
        self.listen
    }

    #[setter]
    fn set_listen(&mut self, value: f64) {
        self.listen = value;
        self.send_timeout(TimeoutKind::Listen, value);
    }

    /// TLS handshake timeout.
    #[getter]
    fn handshake(&self) -> f64 {
        self.handshake
    }

    #[setter]
    fn set_handshake(&mut self, value: f64) {
        self.handshake = value;
        self.send_timeout(TimeoutKind::Handshake, value);
    }

    /// Outbound connect timeout.
    #[getter]
    fn connecting(&self) -> f64 {
        self.connecting
    }

    #[setter]
    fn set_connecting(&mut self, value: f64) {
        self.connecting = value;
        self.send_timeout(TimeoutKind::Connecting, value);
    }

    /// Reconnect delay timeout.
    #[getter]
    fn reconnect(&self) -> f64 {
        self.reconnect
    }

    #[setter]
    fn set_reconnect(&mut self, value: f64) {
        self.reconnect = value;
        // Reconnect timeout is not dispatched to the I/O task (it's used by the
        // connection manager, not by the per-connection task).
    }
}

impl PyConnectionTimeouts {
    fn send_timeout(&self, which: TimeoutKind, value: f64) {
        if let Some(tx) = &self.send_tx {
            let _ = tx.try_send(SendMessage::SetTimeout { which, value });
        }
    }
}

/// Speed (throughput) statistics for one direction.
///
/// Matches the Cython `connection_speed` class.
#[pyclass]
pub struct PyConnectionSpeed {
    bps: f64,
    limit: f64,
    direction: Direction,
    send_tx: Option<mpsc::Sender<SendMessage>>,
}

impl PyConnectionSpeed {
    /// Create a speed stats object.
    pub fn new(bps: f64, limit: f64, direction: Direction, send_tx: Option<mpsc::Sender<SendMessage>>) -> Self {
        PyConnectionSpeed { bps, limit, direction, send_tx }
    }
}

#[pymethods]
impl PyConnectionSpeed {
    /// Current speed in bytes per second.
    #[getter]
    fn bps(&self) -> f64 {
        self.bps
    }

    /// Speed limit in bytes per second (0 = unlimited).
    #[getter]
    fn limit(&self) -> f64 {
        self.limit
    }

    #[setter]
    fn set_limit(&mut self, limit: f64) {
        self.limit = limit;
        if let Some(tx) = &self.send_tx {
            let _ = tx.try_send(SendMessage::SetThrottle {
                direction: self.direction,
                limit,
            });
        }
    }
}

/// Byte accounting for one direction.
///
/// Matches the Cython `connection_accounting` class.
#[pyclass]
pub struct PyConnectionAccounting {
    bytes: f64,
    limit: f64,
    direction: Direction,
    send_tx: Option<mpsc::Sender<SendMessage>>,
}

impl PyConnectionAccounting {
    /// Create an accounting stats object.
    pub fn new(bytes: f64, limit: f64, direction: Direction, send_tx: Option<mpsc::Sender<SendMessage>>) -> Self {
        PyConnectionAccounting { bytes, limit, direction, send_tx }
    }
}

#[pymethods]
impl PyConnectionAccounting {
    /// Bytes transferred so far.
    #[getter]
    fn bytes(&self) -> f64 {
        self.bytes
    }

    /// Byte limit (0 = unlimited).
    #[getter]
    fn limit(&self) -> f64 {
        self.limit
    }

    #[setter]
    fn set_limit(&mut self, limit: f64) {
        self.limit = limit;
        if let Some(tx) = &self.send_tx {
            let _ = tx.try_send(SendMessage::SetAccountingLimit {
                direction: self.direction,
                limit: limit as u64,
            });
        }
    }
}

/// Combined stats for one direction (speed + accounting).
///
/// Matches the Cython `connection_stats` class.
#[pyclass]
pub struct PyConnectionStats {
    speed: Py<PyConnectionSpeed>,
    accounting: Py<PyConnectionAccounting>,
}

impl PyConnectionStats {
    /// Create a stats object wrapping speed and accounting.
    pub fn new(py: Python<'_>, speed: PyConnectionSpeed, accounting: PyConnectionAccounting) -> PyResult<Self> {
        Ok(PyConnectionStats {
            speed: Py::new(py, speed)?,
            accounting: Py::new(py, accounting)?,
        })
    }
}

#[pymethods]
impl PyConnectionStats {
    /// Speed statistics for this direction.
    #[getter]
    fn speed(&self, py: Python<'_>) -> Py<PyConnectionSpeed> {
        self.speed.clone_ref(py)
    }

    /// Accounting statistics for this direction.
    #[getter]
    fn accounting(&self, py: Python<'_>) -> Py<PyConnectionAccounting> {
        self.accounting.clone_ref(py)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeouts_defaults() {
        Python::attach(|py| {
            let t = Py::new(py, PyConnectionTimeouts::new()).unwrap();
            let bound = t.bind(py);
            let idle: f64 = bound.getattr("idle").unwrap().extract().unwrap();
            assert!((idle - 120.0).abs() < f64::EPSILON);
            let sustain: f64 = bound.getattr("sustain").unwrap().extract().unwrap();
            assert!((sustain - 300.0).abs() < f64::EPSILON);
        });
    }

    #[test]
    fn test_timeouts_set_sends_message() {
        Python::attach(|py| {
            let (tx, mut rx) = mpsc::channel(16);
            let mut t = PyConnectionTimeouts::new();
            t.send_tx = Some(tx);
            let t = Py::new(py, t).unwrap();
            let bound = t.bind(py);
            bound.setattr("idle", 60.0).unwrap();

            let msg = rx.try_recv().unwrap();
            match msg {
                SendMessage::SetTimeout { which: TimeoutKind::Idle, value } => {
                    assert!((value - 60.0).abs() < f64::EPSILON);
                }
                other => panic!("unexpected message: {other:?}"),
            }
        });
    }

    #[test]
    fn test_speed_limit_sends_message() {
        Python::attach(|py| {
            let (tx, mut rx) = mpsc::channel(16);
            let speed = PyConnectionSpeed::new(0.0, 0.0, Direction::In, Some(tx));
            let s = Py::new(py, speed).unwrap();
            let bound = s.bind(py);
            bound.setattr("limit", 1024.0).unwrap();

            let msg = rx.try_recv().unwrap();
            match msg {
                SendMessage::SetThrottle { direction: Direction::In, limit } => {
                    assert!((limit - 1024.0).abs() < f64::EPSILON);
                }
                other => panic!("unexpected message: {other:?}"),
            }
        });
    }

    #[test]
    fn test_accounting_limit_sends_message() {
        Python::attach(|py| {
            let (tx, mut rx) = mpsc::channel(16);
            let acct = PyConnectionAccounting::new(100.0, 0.0, Direction::Out, Some(tx));
            let a = Py::new(py, acct).unwrap();
            let bound = a.bind(py);

            let bytes_val: f64 = bound.getattr("bytes").unwrap().extract().unwrap();
            assert!((bytes_val - 100.0).abs() < f64::EPSILON);

            bound.setattr("limit", 5000.0).unwrap();
            let msg = rx.try_recv().unwrap();
            match msg {
                SendMessage::SetAccountingLimit { direction: Direction::Out, limit } => {
                    assert_eq!(limit, 5000);
                }
                other => panic!("unexpected message: {other:?}"),
            }
        });
    }

    #[test]
    fn test_connection_stats_nested() {
        Python::attach(|py| {
            let speed = PyConnectionSpeed::new(512.0, 1024.0, Direction::In, None);
            let acct = PyConnectionAccounting::new(1000.0, 0.0, Direction::In, None);
            let stats = PyConnectionStats::new(py, speed, acct).unwrap();
            let s = Py::new(py, stats).unwrap();
            let bound = s.bind(py);

            let speed_obj = bound.getattr("speed").unwrap();
            let bps: f64 = speed_obj.getattr("bps").unwrap().extract().unwrap();
            assert!((bps - 512.0).abs() < f64::EPSILON);

            let acct_obj = bound.getattr("accounting").unwrap();
            let bytes_val: f64 = acct_obj.getattr("bytes").unwrap().extract().unwrap();
            assert!((bytes_val - 1000.0).abs() < f64::EPSILON);
        });
    }
}
