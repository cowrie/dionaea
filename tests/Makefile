# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

.PHONY: all test smoke legacy clean

# Run all tests (requires dionaea running on localhost)
all: test

# Run pytest smoke tests for all protocols
test:
	pytest tftp/ ftp/ smb/ http/tests/test_http_smoke.py -v

# Run smoke tests only (alias)
smoke: test

# Run legacy per-protocol tests (mysql, printer)
legacy:
	cd mysql && make
	cd printer && make

clean:
	rm -rf __pycache__ .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
