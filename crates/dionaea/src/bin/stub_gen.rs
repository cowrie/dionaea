// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Generates Python type stubs (.pyi) for the dionaea.core module.
// ABOUTME: Run with `cargo run --bin stub_gen` to regenerate after changing PyO3 bindings.

fn main() {
    let stub = dionaea::stub_info().expect("failed to gather stub info");
    stub.generate().expect("failed to generate stubs");
    eprintln!("Stubs generated successfully");
}
