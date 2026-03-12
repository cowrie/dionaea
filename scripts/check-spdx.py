#!/usr/bin/env python3
# ABOUTME: Lint script that checks all Rust and Python source files for SPDX headers.
# ABOUTME: Verifies SPDX-FileCopyrightText and SPDX-License-Identifier are present and valid.

# SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial

"""Check that all Rust and Python source files have valid SPDX headers.

Verifies:
  1. Every .rs and .py file has an SPDX-License-Identifier line
  2. Every .rs and .py file has an SPDX-FileCopyrightText line
  3. License identifiers are from the allowed set
  4. Dual-licensed files (crates/, modbus, rdp) use the correct identifier

Exit code 0 on success, 1 if any violations found.
"""

import argparse
import re
import sys
from pathlib import Path

ALLOWED_LICENSES = {
    "AGPL-3.0-only",
    "AGPL-3.0-only OR LicenseRef-Cowrie-Commercial",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-2.0-or-later AND MIT",
    "MIT",
    "CC0-1.0",
}

# Files under these paths MUST use the dual license
DUAL_LICENSE_PATHS = {
    "crates/",
}

# Individual files that must use dual license
DUAL_LICENSE_FILES = {
    "modules/python/dionaea/modbus.py",
    "modules/python/dionaea/rdp/rdp.py",
    "modules/python/dionaea/rdp/__init__.py",
    "modules/python/dionaea/rdp/packets.py",
    "modules/python/dionaea/rdp/include/packets.py",
    "modules/python/dionaea/rdp/include/crypto.py",
    "modules/python/dionaea/rdp/include/__init__.py",
    "modules/python/dionaea/rdp/include/test_packets.py",
    "modules/python/dionaea/rdp/include/test_crypto.py",
}

DUAL_LICENSE = "AGPL-3.0-only OR LicenseRef-Cowrie-Commercial"

RE_LICENSE = re.compile(r"SPDX-License-Identifier:\s*(.+)")
RE_COPYRIGHT = re.compile(r"SPDX-FileCopyrightText:\s*(.+)")

# How many lines from the top to scan for headers
SCAN_LINES = 20


def check_file(path: Path, root: Path) -> list[str]:
    """Return list of error messages for a single file."""
    errors: list[str] = []
    rel = path.relative_to(root)
    rel_str = str(rel)

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return [f"{rel}: cannot read: {e}"]

    header = "\n".join(lines[:SCAN_LINES])

    # Determine if this file requires the dual license
    needs_dual = any(rel_str.startswith(p) for p in DUAL_LICENSE_PATHS)
    needs_dual = needs_dual or rel_str in DUAL_LICENSE_FILES

    # Check SPDX-License-Identifier
    license_match = RE_LICENSE.search(header)
    if not license_match:
        errors.append(f"{rel}: missing SPDX-License-Identifier")
    else:
        license_id = license_match.group(1).strip()
        if license_id not in ALLOWED_LICENSES:
            errors.append(
                f"{rel}: unknown license '{license_id}' "
                f"(allowed: {', '.join(sorted(ALLOWED_LICENSES))})"
            )
        elif needs_dual and license_id != DUAL_LICENSE:
            errors.append(
                f"{rel}: must use dual license '{DUAL_LICENSE}', "
                f"found '{license_id}'"
            )

    # Check SPDX-FileCopyrightText
    copyright_match = RE_COPYRIGHT.search(header)
    if not copyright_match:
        errors.append(f"{rel}: missing SPDX-FileCopyrightText")
    else:
        copyright_text = copyright_match.group(1).strip()
        if copyright_text == "none" and needs_dual:
            errors.append(
                f"{rel}: dual-licensed file should have a copyright holder, "
                f"not 'none'"
            )

    return errors


def find_source_files(root: Path) -> list[Path]:
    """Find all .rs and .py source files, excluding generated/vendored."""
    files: list[Path] = []
    for pattern in ("**/*.rs", "**/*.py"):
        for path in root.glob(pattern):
            rel = str(path.relative_to(root))
            # Skip build artifacts and generated files
            if rel.startswith("target/") or rel.startswith(".git/"):
                continue
            files.append(path)
    return sorted(files)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Repository root directory (default: current directory)",
    )
    parser.add_argument(
        "--fix-missing",
        action="store_true",
        help="Print suggested fixes for missing headers (does not modify files)",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    files = find_source_files(root)
    all_errors: list[str] = []

    for path in files:
        errors = check_file(path, root)
        all_errors.extend(errors)

    if all_errors:
        print(f"SPDX header check failed with {len(all_errors)} error(s):\n")
        for error in all_errors:
            print(f"  ERROR: {error}")

        if args.fix_missing:
            print("\nSuggested fixes for missing headers:")
            for error in all_errors:
                if "missing SPDX-License-Identifier" in error:
                    filepath = error.split(":")[0]
                    if filepath.endswith(".rs"):
                        print(f"  {filepath}: add '// SPDX-License-Identifier: ...' near top")
                    else:
                        print(f"  {filepath}: add '# SPDX-License-Identifier: ...' near top")

        return 1

    print(f"SPDX header check passed: {len(files)} files OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
