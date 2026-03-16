// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Metrics instrumentation using the `metrics` facade crate.
// ABOUTME: Records counters and histograms for Python callback and incident handler performance.

//! Metrics for observability of Rust-to-Python boundary performance.
//!
//! Uses the [`metrics`] facade crate so any exporter (Prometheus, StatsD,
//! OpenTelemetry) can be installed at startup without changing instrumentation.
//!
//! # Metric names
//!
//! | Name | Type | Labels | Description |
//! |------|------|--------|-------------|
//! | `dionaea.python.callback.duration_seconds` | Histogram | `callback`, `handler` | Time spent in a Python protocol callback |
//! | `dionaea.python.callback.total` | Counter | `callback`, `handler` | Number of Python protocol callback invocations |
//! | `dionaea.python.callback.slow_total` | Counter | `callback`, `handler` | Callbacks exceeding the slow threshold |
//! | `dionaea.python.incident.duration_seconds` | Histogram | `handler`, `method`, `origin` | Time spent in a Python incident handler |
//! | `dionaea.python.incident.total` | Counter | `handler`, `method` | Number of incident handler invocations |
//! | `dionaea.python.incident.slow_total` | Counter | `handler`, `method` | Incident handlers exceeding the slow threshold |

use std::time::Duration;

/// Record a Python protocol callback invocation.
pub fn record_callback(callback: &str, handler: &str, duration: Duration, slow: bool) {
    let labels = [
        ("callback", callback.to_string()),
        ("handler", handler.to_string()),
    ];
    metrics::histogram!("dionaea.python.callback.duration_seconds", &labels)
        .record(duration.as_secs_f64());
    metrics::counter!("dionaea.python.callback.total", &labels).increment(1);
    if slow {
        metrics::counter!("dionaea.python.callback.slow_total", &labels).increment(1);
    }
}

/// Record a Python incident handler invocation.
pub fn record_incident_handler(
    handler: &str,
    method: &str,
    origin: &str,
    duration: Duration,
    slow: bool,
) {
    let labels = [
        ("handler", handler.to_string()),
        ("method", method.to_string()),
        ("origin", origin.to_string()),
    ];
    metrics::histogram!("dionaea.python.incident.duration_seconds", &labels)
        .record(duration.as_secs_f64());

    let count_labels = [
        ("handler", handler.to_string()),
        ("method", method.to_string()),
    ];
    metrics::counter!("dionaea.python.incident.total", &count_labels).increment(1);
    if slow {
        metrics::counter!("dionaea.python.incident.slow_total", &count_labels).increment(1);
    }
}

/// Install the Prometheus metrics exporter.
///
/// Returns the `PrometheusHandle` which can serve `/metrics` via HTTP.
/// Only available with the `prometheus` feature.
#[cfg(feature = "prometheus")]
pub fn install_prometheus_exporter() -> metrics_exporter_prometheus::PrometheusHandle {
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    builder
        .install_recorder()
        .expect("failed to install Prometheus recorder")
}
