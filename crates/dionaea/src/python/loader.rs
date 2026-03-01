// ABOUTME: Python module loader that registers dionaea.core and imports Python packages.
// ABOUTME: Replicates the C module.c loading sequence: register classes, set sys.path, import, new(), start().

use crate::config::PythonModuleConfig;
use pyo3::prelude::*;
use pyo3::types::PyModule;

/// Load and start Python modules.
///
/// Must be called with the GIL held. Sequence:
/// 1. Create `dionaea.core` module with all PyO3 classes
/// 2. Add class aliases (connection, ihandler, incident) for Python compatibility
/// 3. Register `dionaea.core` in `sys.modules`
/// 4. Prepend `python_path` to `sys.path` if configured
/// 5. Import each module from `config.imports`
/// 6. Call `module.new()` on each imported module (if the function exists)
/// 7. Call `module.start()` on each imported module (if the function exists)
pub fn load(py: Python<'_>, config: &PythonModuleConfig) -> PyResult<()> {
    // Step 1-3: Register dionaea.core in sys.modules
    register_core_module(py)?;

    // Step 4: Add python_path to sys.path
    if let Some(ref path) = config.python_path {
        let sys = py.import(c"sys")?;
        let sys_path = sys.getattr("path")?;
        let path_str = path.to_string_lossy().to_string();
        sys_path.call_method1("insert", (0, path_str))?;
        tracing::info!(path = %path.display(), "added to sys.path");
    }

    // Step 5: Import modules
    let mut modules = Vec::new();
    for name in &config.imports {
        tracing::info!(module = %name, "importing Python module");
        match py.import(name.as_str()) {
            Ok(module) => {
                modules.push(module);
            }
            Err(e) => {
                tracing::error!(module = %name, error = %e, "failed to import Python module");
                e.print(py);
                return Err(e);
            }
        }
    }

    // Step 6: Call new() on each module
    for module in &modules {
        if let Ok(func) = module.getattr("new") {
            if func.is_callable() {
                tracing::debug!(module = %module.name()?, "calling new()");
                if let Err(e) = func.call0() {
                    tracing::error!(module = %module.name()?, error = %e, "module new() failed");
                    e.print(py);
                }
            }
        }
    }

    // Step 7: Call start() on each module
    for module in &modules {
        if let Ok(func) = module.getattr("start") {
            if func.is_callable() {
                tracing::debug!(module = %module.name()?, "calling start()");
                if let Err(e) = func.call0() {
                    tracing::error!(module = %module.name()?, error = %e, "module start() failed");
                    e.print(py);
                }
            }
        }
    }

    tracing::info!(count = modules.len(), "Python modules loaded");
    Ok(())
}

/// Register `dionaea.core` in sys.modules with all PyO3 classes and aliases.
///
/// Python code does `from dionaea.core import connection, ihandler, incident, g_dionaea`.
/// The aliases map Cython-era names to our PyO3 class names.
fn register_core_module(py: Python<'_>) -> PyResult<()> {
    let core = PyModule::new(py, "dionaea.core")?;

    // Register all PyO3 classes
    super::register_classes(&core)?;

    // Add Cython-compatible aliases: Python code uses lowercase names
    let connection = core.getattr("PyConnection")?;
    core.add("connection", connection)?;

    let ihandler = core.getattr("PyIHandler")?;
    core.add("ihandler", ihandler)?;

    let incident = core.getattr("PyIncident")?;
    core.add("incident", incident)?;

    // Register in sys.modules
    let sys = py.import(c"sys")?;
    sys.getattr("modules")?.set_item("dionaea.core", &core)?;

    tracing::info!("registered dionaea.core in sys.modules");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_core_module() {
        Python::attach(|py| {
            register_core_module(py).expect("register core module");

            // Verify module is in sys.modules and aliases exist
            let sys_modules = py.import(c"sys").unwrap().getattr("modules").unwrap();
            let core = sys_modules.get_item("dionaea.core").expect("get dionaea.core");
            assert!(core.getattr("connection").is_ok());
            assert!(core.getattr("ihandler").is_ok());
            assert!(core.getattr("incident").is_ok());
            assert!(core.getattr("g_dionaea").is_ok());
            assert!(core.getattr("connection_new").is_ok());
        });
    }

    #[test]
    fn test_import_from_dionaea_core() {
        Python::attach(|py| {
            register_core_module(py).expect("register core module");

            // Verify Python import works
            py.run(
                c"from dionaea.core import connection, ihandler, incident, g_dionaea",
                None,
                None,
            )
            .expect("import from dionaea.core should work");
        });
    }

    #[test]
    fn test_load_empty_imports() {
        Python::attach(|py| {
            let config = crate::config::PythonModuleConfig {
                imports: vec![],
                service_configs: vec![],
                ihandler_configs: vec![],
                python_path: None,
            };
            load(py, &config).expect("load with empty imports");

            // dionaea.core should still be registered in sys.modules
            let sys_modules = py.import(c"sys").unwrap().getattr("modules").unwrap();
            assert!(sys_modules.get_item("dionaea.core").is_ok());
        });
    }

    #[test]
    fn test_load_with_python_path() {
        Python::attach(|py| {
            let config = crate::config::PythonModuleConfig {
                imports: vec![],
                service_configs: vec![],
                ihandler_configs: vec![],
                python_path: Some("/tmp/test_dionaea_modules".into()),
            };
            load(py, &config).expect("load with python_path");

            // Verify path was added to sys.path
            let sys_path: Vec<String> = py
                .import(c"sys")
                .unwrap()
                .getattr("path")
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                sys_path.contains(&"/tmp/test_dionaea_modules".to_string()),
                "python_path should be in sys.path"
            );
        });
    }
}
