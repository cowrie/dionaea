// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: Bidirectional conversion between Rust OpaqueData and Python objects.
// ABOUTME: Handles int, str, bytes, connection ref, list, dict, and None.

use crate::incident::OpaqueData;
use crate::python::connection::PyConnection;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyInt, PyList, PyString};
use std::collections::HashMap;

/// Convert a Rust `OpaqueData` value to a Python object.
pub fn opaque_to_py(py: Python<'_>, value: &OpaqueData) -> PyResult<Py<PyAny>> {
    match value {
        OpaqueData::Int(i) => Ok(i.into_pyobject(py)?.into_any().unbind()),
        OpaqueData::String(s) => Ok(s.into_pyobject(py)?.into_any().unbind()),
        OpaqueData::Bytes(b) => Ok(PyBytes::new(py, b).into_any().unbind()),
        OpaqueData::ConnectionRef(id) => {
            // Return the raw connection ID as an integer.
            // The caller is responsible for wrapping this in a PyConnection
            // if needed (e.g., during incident attribute access).
            Ok(id.0.into_pyobject(py)?.into_any().unbind())
        }
        OpaqueData::List(items) => {
            let py_list = PyList::empty(py);
            for item in items {
                py_list.append(opaque_to_py(py, item)?)?;
            }
            Ok(py_list.into_any().unbind())
        }
        OpaqueData::Dict(map) => {
            let py_dict = PyDict::new(py);
            for (k, v) in map {
                py_dict.set_item(k, opaque_to_py(py, v)?)?;
            }
            Ok(py_dict.into_any().unbind())
        }
        OpaqueData::None => Ok(py.None()),
    }
}

/// Maximum nesting depth for recursive Python → OpaqueData conversion.
const MAX_NESTING_DEPTH: usize = 100;

/// Convert a Python object to a Rust `OpaqueData` value.
///
/// Type dispatch order: connection, int, str, bytes, list/tuple, dict, None.
/// Since we don't have access to PyConnection here (it would create a circular dependency),
/// connection detection is handled by the caller.
pub fn py_to_opaque(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<OpaqueData> {
    py_to_opaque_inner(py, obj, 0)
}

fn py_to_opaque_inner(py: Python<'_>, obj: &Bound<'_, PyAny>, depth: usize) -> PyResult<OpaqueData> {
    if depth > MAX_NESTING_DEPTH {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("nested structure exceeds maximum depth of {MAX_NESTING_DEPTH}")
        ));
    }
    if obj.is_none() {
        return Ok(OpaqueData::None);
    }
    // Check for connection subclass (must be before int since ConnectionId is numeric)
    if let Ok(conn) = obj.cast::<PyConnection>() {
        if let Some(id) = conn.borrow().connection_id() {
            return Ok(OpaqueData::ConnectionRef(id));
        }
        return Ok(OpaqueData::None);
    }
    // Check int before str because bool is a subclass of int in Python
    if let Ok(i) = obj.cast::<PyInt>() {
        let val: i64 = i.extract()?;
        return Ok(OpaqueData::Int(val));
    }
    if let Ok(s) = obj.cast::<PyString>() {
        let val: String = s.extract()?;
        return Ok(OpaqueData::String(val));
    }
    if let Ok(b) = obj.cast::<PyBytes>() {
        return Ok(OpaqueData::Bytes(b.as_bytes().to_vec()));
    }
    if let Ok(list) = obj.cast::<PyList>() {
        let mut items = Vec::with_capacity(list.len());
        for item in list.iter() {
            items.push(py_to_opaque_inner(py, &item, depth + 1)?);
        }
        return Ok(OpaqueData::List(items));
    }
    // Check for tuple (list and tuple convert to the same OpaqueData::List)
    if obj.is_instance_of::<pyo3::types::PyTuple>() {
        let items: Vec<Bound<'_, PyAny>> = obj.extract()?;
        let mut result = Vec::with_capacity(items.len());
        for item in &items {
            result.push(py_to_opaque_inner(py, item, depth + 1)?);
        }
        return Ok(OpaqueData::List(result));
    }
    if let Ok(dict) = obj.cast::<PyDict>() {
        let mut map = HashMap::new();
        for (k, v) in dict.iter() {
            let key: String = k.extract()?;
            map.insert(key, py_to_opaque_inner(py, &v, depth + 1)?);
        }
        return Ok(OpaqueData::Dict(map));
    }
    Err(pyo3::exceptions::PyTypeError::new_err(format!(
        "cannot convert {} to OpaqueData",
        obj.get_type().name()?
    )))
}

/// Convert a Rust `HashMap<String, OpaqueData>` to a Python dict.
pub fn data_map_to_py(
    py: Python<'_>,
    map: &HashMap<String, OpaqueData>,
) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    for (k, v) in map {
        dict.set_item(k, opaque_to_py(py, v)?)?;
    }
    Ok(dict.unbind())
}

/// Convert a Python dict to a Rust `HashMap<String, OpaqueData>`.
pub fn py_dict_to_data_map(
    py: Python<'_>,
    dict: &Bound<'_, PyDict>,
) -> PyResult<HashMap<String, OpaqueData>> {
    let mut map = HashMap::new();
    for (k, v) in dict.iter() {
        let key: String = k.extract()?;
        map.insert(key, py_to_opaque(py, &v)?);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ConnectionId;

    #[test]
    fn test_int_roundtrip() {
        Python::attach(|py| {
            let data = OpaqueData::Int(42);
            let py_obj = opaque_to_py(py, &data).expect("to_py");
            let back = py_to_opaque(py, py_obj.bind(py)).expect("from_py");
            assert_eq!(back, OpaqueData::Int(42));
        });
    }

    #[test]
    fn test_string_roundtrip() {
        Python::attach(|py| {
            let data = OpaqueData::String("hello".into());
            let py_obj = opaque_to_py(py, &data).expect("to_py");
            let back = py_to_opaque(py, py_obj.bind(py)).expect("from_py");
            assert_eq!(back, OpaqueData::String("hello".into()));
        });
    }

    #[test]
    fn test_bytes_roundtrip() {
        Python::attach(|py| {
            let data = OpaqueData::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
            let py_obj = opaque_to_py(py, &data).expect("to_py");
            let back = py_to_opaque(py, py_obj.bind(py)).expect("from_py");
            assert_eq!(back, OpaqueData::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        });
    }

    #[test]
    fn test_none_roundtrip() {
        Python::attach(|py| {
            let data = OpaqueData::None;
            let py_obj = opaque_to_py(py, &data).expect("to_py");
            let back = py_to_opaque(py, py_obj.bind(py)).expect("from_py");
            assert_eq!(back, OpaqueData::None);
        });
    }

    #[test]
    fn test_list_roundtrip() {
        Python::attach(|py| {
            let data = OpaqueData::List(vec![
                OpaqueData::Int(1),
                OpaqueData::String("two".into()),
                OpaqueData::None,
            ]);
            let py_obj = opaque_to_py(py, &data).expect("to_py");
            let back = py_to_opaque(py, py_obj.bind(py)).expect("from_py");
            assert_eq!(
                back,
                OpaqueData::List(vec![
                    OpaqueData::Int(1),
                    OpaqueData::String("two".into()),
                    OpaqueData::None,
                ])
            );
        });
    }

    #[test]
    fn test_dict_roundtrip() {
        Python::attach(|py| {
            let mut map = HashMap::new();
            map.insert("key".into(), OpaqueData::Int(99));
            map.insert("name".into(), OpaqueData::String("test".into()));
            let data = OpaqueData::Dict(map.clone());
            let py_obj = opaque_to_py(py, &data).expect("to_py");
            let back = py_to_opaque(py, py_obj.bind(py)).expect("from_py");
            assert_eq!(back, OpaqueData::Dict(map));
        });
    }

    #[test]
    fn test_nested_structure() {
        Python::attach(|py| {
            let mut inner_map = HashMap::new();
            inner_map.insert("nested".into(), OpaqueData::Int(7));
            let data = OpaqueData::List(vec![
                OpaqueData::Dict(inner_map.clone()),
                OpaqueData::List(vec![OpaqueData::Bytes(vec![1, 2, 3])]),
            ]);
            let py_obj = opaque_to_py(py, &data).expect("to_py");
            let back = py_to_opaque(py, py_obj.bind(py)).expect("from_py");
            assert_eq!(
                back,
                OpaqueData::List(vec![
                    OpaqueData::Dict(inner_map),
                    OpaqueData::List(vec![OpaqueData::Bytes(vec![1, 2, 3])]),
                ])
            );
        });
    }

    #[test]
    fn test_connection_ref_to_py() {
        Python::attach(|py| {
            let data = OpaqueData::ConnectionRef(ConnectionId(42));
            let py_obj = opaque_to_py(py, &data).expect("to_py");
            // ConnectionRef is exposed as an integer on the Python side
            let val: u64 = py_obj.extract(py).expect("extract");
            assert_eq!(val, 42);
        });
    }

    #[test]
    fn test_python_tuple_to_list() {
        Python::attach(|py| {
            let tuple = py
                .eval(c"(1, 'two', None)", None, None)
                .expect("eval tuple");
            let data = py_to_opaque(py, &tuple).expect("from_py");
            assert_eq!(
                data,
                OpaqueData::List(vec![
                    OpaqueData::Int(1),
                    OpaqueData::String("two".into()),
                    OpaqueData::None,
                ])
            );
        });
    }

    #[test]
    fn test_deeply_nested_list_rejected() {
        Python::attach(|py| {
            // Build a list nested 150 levels deep (exceeds MAX_NESTING_DEPTH=100)
            let setup = c"
result = [1]
for _ in range(150):
    result = [result]
";
            py.run(setup, None, None).expect("run");
            let obj = py.eval(c"result", None, None).expect("eval");
            let err = py_to_opaque(py, &obj);
            assert!(err.is_err());
            let msg = err.unwrap_err().to_string();
            assert!(msg.contains("maximum depth"), "unexpected error: {msg}");
        });
    }

    #[test]
    fn test_moderately_nested_list_accepted() {
        Python::attach(|py| {
            // Build a list nested 50 levels deep (within MAX_NESTING_DEPTH=100)
            let setup = c"
result2 = [42]
for _ in range(50):
    result2 = [result2]
";
            py.run(setup, None, None).expect("run");
            let obj = py.eval(c"result2", None, None).expect("eval");
            let result = py_to_opaque(py, &obj);
            assert!(result.is_ok(), "50 levels should be within limit");
        });
    }

    #[test]
    fn test_unsupported_type_error() {
        Python::attach(|py| {
            let obj = py.eval(c"object()", None, None).expect("eval");
            let result = py_to_opaque(py, &obj);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("cannot convert"));
        });
    }

    #[test]
    fn test_data_map_roundtrip() {
        Python::attach(|py| {
            let mut map = HashMap::new();
            map.insert("port".into(), OpaqueData::Int(445));
            map.insert("host".into(), OpaqueData::String("10.0.0.1".into()));
            map.insert("payload".into(), OpaqueData::Bytes(vec![0xFF]));

            let py_dict = data_map_to_py(py, &map).expect("to_py");
            let back =
                py_dict_to_data_map(py, py_dict.bind(py)).expect("from_py");
            assert_eq!(back, map);
        });
    }
}
