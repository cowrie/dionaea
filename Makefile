# ABOUTME: Build shortcuts for the dionaea Rust honeypot.
# ABOUTME: Wraps common cargo, test, and lint commands.

.PHONY: build release test check fmt clippy lint spdx integration clean

build:
	cargo build

release:
	cargo build --release

test:
	cargo test --features download,upload,tls

check: fmt clippy

fmt:
	cargo fmt --check

clippy:
	cargo clippy --all-features -- -D warnings

lint:
	ruff check modules/
	tox -e lint

spdx:
	python3 scripts/check-spdx.py .

integration:
	cd tests && pytest -v --timeout=30

clean:
	cargo clean
