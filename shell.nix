# Dionaea build environment
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Build tools
    pkg-config
    cmake

    # C libraries
    glib.dev
    udns
    libev
    openssl.dev
    curl.dev
    libpcap

    # Python
    python312Packages.setuptools
    python312Packages.cython
  ];
}
