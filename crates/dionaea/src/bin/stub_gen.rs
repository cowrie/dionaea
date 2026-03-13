// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Generates Python type stubs (.pyi) for the dionaea.core module.
// ABOUTME: Run with `cargo run --bin stub_gen` to regenerate after changing PyO3 bindings.

//! Generate Python type stubs (.pyi) from PyO3 class definitions.

use std::io::Write;

fn main() {
    let stub = dionaea::stub_info().expect("failed to gather stub info");
    stub.generate().expect("failed to generate stubs");

    // Append module-level attributes that pyo3-stub-gen can't discover
    // (added via module.add() at runtime, not via #[pyfunction]).
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let stub_path = crate_dir.join("../../modules/python/dionaea/core/__init__.pyi");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&stub_path)
        .unwrap_or_else(|e| panic!("open {}: {e}", stub_path.display()));
    writeln!(f, "g_dionaea: dionaea").expect("write g_dionaea stub");

    eprintln!("Stubs generated successfully");
}
