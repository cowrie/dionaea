# Dionaea build environment
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Rust toolchain
    rustc
    cargo
    clippy
    rustfmt

    # Build dependencies
    pkg-config
    openssl.dev

    # Python (for PyO3)
    python312
  ];
}
