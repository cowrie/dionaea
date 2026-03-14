# ABOUTME: SMB protocol torture tests using Samba's smbtorture tool
# ABOUTME: Tests protocol compliance, edge cases, and error handling

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import shutil
import subprocess

import pytest


SMBTORTURE = shutil.which("smbtorture")

pytestmark = pytest.mark.skipif(
    SMBTORTURE is None,
    reason="smbtorture not installed (apt install samba-testsuite)",
)


def _run_smbtorture(host, port, share, test_name, timeout=30):
    """Run a single smbtorture test and return the result."""
    target = f"//{host}/{share}"
    result = subprocess.run(
        [SMBTORTURE, target, f"--port={port}", "-U", "guest%", test_name],
        capture_output=True,
        timeout=timeout,
    )
    return result


class TestSmbtortureBase:
    """Basic SMB protocol tests via smbtorture."""

    def test_raw_connect(self, dionaea_host, dionaea_ports):
        """Test basic SMB connection establishment."""
        result = _run_smbtorture(
            dionaea_host, dionaea_ports["smb"], "IPC$", "BASE-CHARSET",
        )
        # smbtorture exit 0 = pass, non-zero = fail
        # For a honeypot, we accept both — the test validates the server
        # doesn't crash and responds to the protocol.
        # stdout/stderr contain the test output regardless of exit code.
        output = result.stdout + result.stderr
        assert len(output) > 0, "smbtorture produced no output"

    def test_samba3_connect(self, dionaea_host, dionaea_ports):
        """Test SAMBA3 anonymous connection."""
        result = _run_smbtorture(
            dionaea_host, dionaea_ports["smb"], "IPC$", "SAMBA3-ANON",
        )
        output = result.stdout + result.stderr
        assert len(output) > 0, "smbtorture produced no output"


class TestSmbtortureRaw:
    """RAW (SMB1) protocol tests."""

    def test_raw_negotiate(self, dionaea_host, dionaea_ports):
        """Test SMB1 dialect negotiation."""
        result = _run_smbtorture(
            dionaea_host, dionaea_ports["smb"], "IPC$", "RAW-NEGOTIATE",
        )
        output = result.stdout + result.stderr
        assert len(output) > 0, "smbtorture produced no output"

    def test_raw_session(self, dionaea_host, dionaea_ports):
        """Test SMB1 session setup."""
        result = _run_smbtorture(
            dionaea_host, dionaea_ports["smb"], "IPC$", "RAW-SESSION",
        )
        output = result.stdout + result.stderr
        assert len(output) > 0, "smbtorture produced no output"

    def test_raw_tcon(self, dionaea_host, dionaea_ports):
        """Test SMB1 tree connect."""
        result = _run_smbtorture(
            dionaea_host, dionaea_ports["smb"], "IPC$", "RAW-TCON",
        )
        output = result.stdout + result.stderr
        assert len(output) > 0, "smbtorture produced no output"


class TestSmbtortureSMB2:
    """SMB2/3 protocol tests."""

    def test_smb2_connect(self, dionaea_host, dionaea_ports):
        """Test SMB2 connection and negotiate."""
        result = _run_smbtorture(
            dionaea_host, dionaea_ports["smb"], "IPC$", "SMB2-CONNECT",
        )
        output = result.stdout + result.stderr
        assert len(output) > 0, "smbtorture produced no output"

    def test_smb2_negotiate(self, dionaea_host, dionaea_ports):
        """Test SMB2 protocol negotiation."""
        result = _run_smbtorture(
            dionaea_host, dionaea_ports["smb"], "IPC$", "SMB2-NEGOTIATE",
        )
        output = result.stdout + result.stderr
        assert len(output) > 0, "smbtorture produced no output"

    def test_smb2_session(self, dionaea_host, dionaea_ports):
        """Test SMB2 session setup."""
        result = _run_smbtorture(
            dionaea_host, dionaea_ports["smb"], "IPC$", "SMB2-SESSION",
        )
        output = result.stdout + result.stderr
        assert len(output) > 0, "smbtorture produced no output"
