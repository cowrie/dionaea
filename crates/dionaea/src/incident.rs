// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: Incident data model for event dispatch between components.
// ABOUTME: OpaqueData supports int, string, bytes, connection ref, list, dict, and None.

use crate::connection::ConnectionId;
use std::collections::HashMap;

/// Dynamically-typed data carried by incidents.
///
/// Converts to/from Python objects at the bridge boundary.
/// All conversions are by value (copy), not by reference.
#[derive(Debug, Clone, PartialEq)]
pub enum OpaqueData {
    /// 64-bit integer.
    Int(i64),
    /// UTF-8 string.
    String(String),
    /// Raw bytes.
    Bytes(Vec<u8>),
    /// Reference to a connection by ID (not a direct pointer).
    ConnectionRef(ConnectionId),
    /// Ordered list of values.
    List(Vec<OpaqueData>),
    /// String-keyed map of values.
    Dict(HashMap<String, OpaqueData>),
    /// Python None / null.
    None,
}

/// An event dispatched through the incident handler system.
///
/// Origin strings use dot-separated paths like "dionaea.connection.tcp.accept".
/// IHandlers register glob patterns to match origins.
pub struct Incident {
    /// Dot-separated origin path (e.g. "dionaea.connection.tcp.accept").
    pub origin: String,
    /// Key-value data associated with this incident.
    pub data: HashMap<String, OpaqueData>,
}

impl Incident {
    /// Create a new incident with the given origin.
    pub fn new(origin: impl Into<String>) -> Self {
        Incident {
            origin: origin.into(),
            data: HashMap::new(),
        }
    }

    /// Set a data field.
    pub fn set(&mut self, key: impl Into<String>, value: OpaqueData) {
        self.data.insert(key.into(), value);
    }

    /// Get a data field.
    pub fn get(&self, key: &str) -> Option<&OpaqueData> {
        self.data.get(key)
    }

    /// List all data keys.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.data.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_create_and_set() {
        let mut incident = Incident::new("dionaea.connection.tcp.accept");
        assert_eq!(incident.origin, "dionaea.connection.tcp.accept");

        incident.set("con", OpaqueData::ConnectionRef(ConnectionId(42)));
        incident.set("port", OpaqueData::Int(445));
        incident.set("remote_host", OpaqueData::String("10.0.0.1".into()));

        assert_eq!(incident.get("port"), Some(&OpaqueData::Int(445)));
        assert_eq!(
            incident.get("con"),
            Some(&OpaqueData::ConnectionRef(ConnectionId(42)))
        );
        assert!(incident.get("nonexistent").is_none());
    }

    #[test]
    fn test_opaque_data_all_variants() {
        let values = vec![
            OpaqueData::Int(42),
            OpaqueData::String("hello".into()),
            OpaqueData::Bytes(vec![0xDE, 0xAD]),
            OpaqueData::ConnectionRef(ConnectionId(1)),
            OpaqueData::List(vec![OpaqueData::Int(1), OpaqueData::Int(2)]),
            OpaqueData::Dict({
                let mut m = HashMap::new();
                m.insert("key".into(), OpaqueData::String("value".into()));
                m
            }),
            OpaqueData::None,
        ];

        // All variants should be clonable and comparable
        for v in &values {
            assert_eq!(v, &v.clone());
        }
    }

    #[test]
    fn test_incident_keys() {
        let mut incident = Incident::new("test.origin");
        incident.set("alpha", OpaqueData::Int(1));
        incident.set("beta", OpaqueData::Int(2));

        let mut keys: Vec<&String> = incident.keys().collect();
        keys.sort();
        assert_eq!(keys.len(), 2);
    }
}
