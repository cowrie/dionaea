// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Incident handler registry with wildcard pattern matching.
// ABOUTME: Dispatches incidents to registered handlers based on origin glob patterns.

use std::sync::Arc;

use crate::incident::Incident;

/// Wildcard pattern matcher.
///
/// Supports `*` (match any characters including dots) and `?` (match one character).
/// This matches GLib's `g_pattern_spec_match` semantics, not filesystem glob semantics.
#[derive(Debug, Clone)]
pub struct WildcardPattern {
    pattern: String,
}

impl WildcardPattern {
    /// Create a new pattern.
    pub fn new(pattern: impl Into<String>) -> Self {
        WildcardPattern {
            pattern: pattern.into(),
        }
    }

    /// Test if a string matches this pattern.
    pub fn matches(&self, text: &str) -> bool {
        wildcard_match(self.pattern.as_bytes(), text.as_bytes())
    }

    /// The pattern string.
    pub fn as_str(&self) -> &str {
        &self.pattern
    }
}

/// Recursive wildcard matching.
/// `*` matches zero or more characters (including dots).
/// `?` matches exactly one character.
fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let mut p = 0;
    let mut t = 0;
    let mut star_p = usize::MAX;
    let mut star_t = 0;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star_p = p;
            star_t = t;
            p += 1;
        } else if star_p != usize::MAX {
            p = star_p + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }

    p == pattern.len()
}

/// Callback for handling incidents. Either Rust or Python.
pub enum HandlerCallback {
    /// A Rust function callback (Arc for cloning out of registry during dispatch).
    Rust(Arc<dyn Fn(&Incident) + Send + Sync>),
    /// A Python callback (handled via spawn_blocking + GIL in dispatch).
    Python(pyo3::Py<pyo3::PyAny>),
}

impl std::fmt::Debug for HandlerCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandlerCallback::Rust(_) => write!(f, "Rust(...)"),
            HandlerCallback::Python(_) => write!(f, "Python(...)"),
        }
    }
}

/// A registered incident handler.
#[derive(Debug)]
pub struct IHandler {
    /// Wildcard pattern to match incident origins.
    pub pattern: WildcardPattern,
    /// Callback to invoke when pattern matches.
    pub callback: HandlerCallback,
}

/// Registry of incident handlers.
///
/// Handlers are checked in registration order. All matching handlers
/// are called (not just the first match).
#[derive(Debug, Default)]
pub struct IHandlerRegistry {
    handlers: Vec<IHandler>,
}

impl IHandlerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        IHandlerRegistry {
            handlers: Vec::new(),
        }
    }

    /// Register a handler.
    pub fn register(&mut self, handler: IHandler) {
        self.handlers.push(handler);
    }

    /// Remove all handlers (for shutdown).
    pub fn clear(&mut self) {
        self.handlers.clear();
    }

    /// Find all handlers whose pattern matches the incident origin.
    /// Returns indices into the internal handler list.
    pub fn matching_handlers(&self, incident: &Incident) -> Vec<usize> {
        self.handlers
            .iter()
            .enumerate()
            .filter(|(_, h)| h.pattern.matches(&incident.origin))
            .map(|(i, _)| i)
            .collect()
    }

    /// Get a handler by index.
    pub fn get(&self, index: usize) -> Option<&IHandler> {
        self.handlers.get(index)
    }

    /// Number of registered handlers.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether no handlers are registered.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Remove a handler identified by Python object pointer identity.
    ///
    /// Returns true if a handler was found and removed.
    pub fn unregister_python(&mut self, ptr: *mut pyo3::ffi::PyObject) -> bool {
        let before = self.handlers.len();
        self.handlers.retain(|h| match &h.callback {
            HandlerCallback::Python(py_obj) => py_obj.as_ptr() != ptr,
            HandlerCallback::Rust(_) => true,
        });
        self.handlers.len() < before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let pat = WildcardPattern::new("dionaea.connection.tcp.accept");
        assert!(pat.matches("dionaea.connection.tcp.accept"));
        assert!(!pat.matches("dionaea.connection.tcp.reject"));
        assert!(!pat.matches("dionaea.connection.tcp"));
    }

    #[test]
    fn test_star_matches_dots() {
        let pat = WildcardPattern::new("dionaea.connection.*");
        assert!(pat.matches("dionaea.connection.tcp.accept"));
        assert!(pat.matches("dionaea.connection.tls.accept"));
        assert!(pat.matches("dionaea.connection.udp"));
        assert!(!pat.matches("dionaea.download.complete"));
    }

    #[test]
    fn test_star_at_beginning() {
        let pat = WildcardPattern::new("*.accept");
        assert!(pat.matches("dionaea.connection.tcp.accept"));
        assert!(pat.matches("foo.accept"));
        assert!(!pat.matches("dionaea.connection.tcp.reject"));
    }

    #[test]
    fn test_multiple_stars() {
        let pat = WildcardPattern::new("dionaea.*.tcp.*");
        assert!(pat.matches("dionaea.connection.tcp.accept"));
        assert!(pat.matches("dionaea.x.tcp.y"));
        assert!(!pat.matches("dionaea.connection.udp.accept"));
    }

    #[test]
    fn test_question_mark() {
        let pat = WildcardPattern::new("dionaea.connection.tc?");
        assert!(pat.matches("dionaea.connection.tcp"));
        assert!(!pat.matches("dionaea.connection.tc"));
        assert!(!pat.matches("dionaea.connection.tcpp"));
    }

    #[test]
    fn test_star_only() {
        let pat = WildcardPattern::new("*");
        assert!(pat.matches("anything.at.all"));
        assert!(pat.matches(""));
    }

    #[test]
    fn test_empty_pattern_empty_text() {
        let pat = WildcardPattern::new("");
        assert!(pat.matches(""));
        assert!(!pat.matches("nonempty"));
    }

    #[test]
    fn test_registry_dispatch() {
        let mut registry = IHandlerRegistry::new();

        let called = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let called_clone = called.clone();

        registry.register(IHandler {
            pattern: WildcardPattern::new("dionaea.connection.*"),
            callback: HandlerCallback::Rust(Arc::new(move |_incident| {
                called_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            })),
        });

        registry.register(IHandler {
            pattern: WildcardPattern::new("dionaea.download.*"),
            callback: HandlerCallback::Rust(Arc::new(|_| {})),
        });

        let incident = Incident::new("dionaea.connection.tcp.accept");
        let matches = registry.matching_handlers(&incident);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], 0);

        // Call the matching handler
        if let HandlerCallback::Rust(f) = &registry.get(matches[0]).expect("handler").callback {
            f(&incident);
        }
        assert_eq!(called.load(std::sync::atomic::Ordering::Relaxed), 1);

        // Non-matching incident
        let incident2 = Incident::new("dionaea.shellcode.detected");
        assert!(registry.matching_handlers(&incident2).is_empty());
    }

    #[test]
    fn test_real_incident_origins() {
        // Test against actual incident origins from the codebase
        let pat = WildcardPattern::new("dionaea.connection.*");
        assert!(pat.matches("dionaea.connection.tcp.accept"));
        assert!(pat.matches("dionaea.connection.tls.accept"));
        assert!(pat.matches("dionaea.connection.udp.connect"));
        assert!(pat.matches("dionaea.connection.free"));
        assert!(pat.matches("dionaea.connection.link"));

        let pat2 = WildcardPattern::new("dionaea.download.complete.*");
        assert!(pat2.matches("dionaea.download.complete.hash"));
        assert!(pat2.matches("dionaea.download.complete.unique"));
        assert!(!pat2.matches("dionaea.download.offer"));
    }
}
