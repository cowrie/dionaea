// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
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

    // Step 4a: If VIRTUAL_ENV is set, add its site-packages to sys.path.
    // PyO3's embedded interpreter doesn't detect activated venvs.
    add_virtualenv_site_packages(py)?;

    // Step 4b: Add python_path to sys.path
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

/// Call stop() on all loaded Python modules.
///
/// Must be called with the GIL held. Re-imports each module by name
/// and calls `stop()` if the function exists. Errors are logged but
/// not propagated (shutdown must continue regardless).
pub fn shutdown(py: Python<'_>, config: &PythonModuleConfig) {
    for name in &config.imports {
        match py.import(name.as_str()) {
            Ok(module) => {
                if let Ok(func) = module.getattr("stop") {
                    if func.is_callable() {
                        tracing::debug!(module = %name, "calling stop()");
                        if let Err(e) = func.call0() {
                            tracing::error!(module = %name, error = %e, "module stop() failed");
                            e.print(py);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(module = %name, error = %e, "failed to re-import for shutdown");
            }
        }
    }
    tracing::info!("Python modules stopped");
}

/// Add virtualenv site-packages to sys.path if VIRTUAL_ENV is set.
///
/// PyO3's embedded interpreter links against a specific libpython and doesn't
/// detect activated virtualenvs. This reads VIRTUAL_ENV, derives the
/// site-packages path, and prepends it to sys.path so that venv-installed
/// packages (like speakeasy) are importable.
fn add_virtualenv_site_packages(py: Python<'_>) -> PyResult<()> {
    let venv = match std::env::var("VIRTUAL_ENV") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            // Detect sudo without -E: SUDO_USER set means we're under sudo,
            // but VIRTUAL_ENV missing means env vars were stripped.
            if std::env::var("SUDO_USER").is_ok() {
                tracing::warn!(
                    "running under sudo without VIRTUAL_ENV — use `sudo -E` to preserve the virtualenv"
                );
            }
            return Ok(());
        }
    };

    let version_info = py.import(c"sys")?.getattr("version_info")?;
    let major: i64 = version_info.getattr("major")?.extract()?;
    let minor: i64 = version_info.getattr("minor")?.extract()?;
    let version = format!("{major}.{minor}");

    let site_packages = if cfg!(target_os = "windows") {
        format!("{venv}/Lib/site-packages")
    } else {
        format!("{venv}/lib/python{version}/site-packages")
    };

    let path = std::path::Path::new(&site_packages);
    if path.is_dir() {
        let site = py.import(c"site")?;
        site.call_method1("addsitedir", (&site_packages,))?;
        tracing::info!(path = %site_packages, "added virtualenv site-packages to sys.path");
    } else {
        tracing::warn!(
            path = %site_packages,
            "VIRTUAL_ENV set but site-packages directory not found"
        );
    }

    Ok(())
}

/// Register `dionaea.core` in sys.modules with all PyO3 classes and aliases.
///
/// Python code does `from dionaea.core import connection, ihandler, incident, g_dionaea`.
/// The lowercase aliases match the names expected by Python protocol code.
fn register_core_module(py: Python<'_>) -> PyResult<()> {
    let core = PyModule::new(py, "dionaea.core")?;

    // Register all PyO3 classes
    super::register_classes(&core)?;

    // Add aliases with Py-prefixed names for backward compatibility
    let connection = core.getattr("connection")?;
    core.add("PyConnection", connection)?;

    let ihandler = core.getattr("ihandler")?;
    core.add("PyIHandler", ihandler)?;

    let incident = core.getattr("incident")?;
    core.add("PyIncident", incident)?;

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

    #[test]
    fn test_add_virtualenv_site_packages_no_env() {
        // When VIRTUAL_ENV is not set (typical CI), should be a no-op.
        // We can't set/unset env vars (unsafe_code denied), so just verify
        // the function doesn't fail in the current environment.
        Python::attach(|py| {
            add_virtualenv_site_packages(py).expect("should not fail");
        });
    }

    #[test]
    fn test_shutdown_empty_imports() {
        Python::attach(|py| {
            let config = crate::config::PythonModuleConfig {
                imports: vec![],
                service_configs: vec![],
                ihandler_configs: vec![],
                python_path: None,
            };
            // Should complete without error even with no modules
            shutdown(py, &config);
        });
    }
}
