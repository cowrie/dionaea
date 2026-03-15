# ABOUTME: Unit tests for FTP file system commands.
# ABOUTME: Tests PWD, CWD, CDUP, SIZE, MDTM, TYPE, DELE, RMD, MKD, RNFR, RNTO.

# SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial

import os

import pytest

from dionaea.ftp.state import State


def make_ftpd(basedir):
    """Create an authenticated FTPd with given basedir."""
    from dionaea.ftp.server import FTPd

    d = FTPd()
    d.basedir = basedir
    d.handle_established()
    d.handle_io_in(b"USER test\r\n")
    d.handle_io_in(b"PASS test\r\n")
    d._sent.clear()
    return d


def last_reply(ftpd):
    lines = []
    for chunk in ftpd._sent:
        text = chunk.decode() if isinstance(chunk, bytes) else chunk
        for line in text.split("\r\n"):
            if line:
                lines.append(line)
    return lines[-1] if lines else ""


def feed(ftpd, text):
    return ftpd.handle_io_in((text + "\r\n").encode())


@pytest.fixture
def tmproot(tmp_path):
    """Create a temp FTP root with some files and dirs."""
    root = tmp_path / "ftproot"
    root.mkdir()
    (root / "file.txt").write_text("hello world")
    (root / "subdir").mkdir()
    (root / "subdir" / "nested.txt").write_text("nested content")
    return str(root)


class TestPWD:
    def test_pwd_returns_root(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "PWD")
        reply = last_reply(d)
        assert "257" in reply
        assert '"/"' in reply

    def test_pwd_after_cwd(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "CWD subdir")
        d._sent.clear()
        feed(d, "PWD")
        reply = last_reply(d)
        assert "257" in reply
        assert '"/subdir"' in reply


class TestCWD:
    def test_cwd_to_existing_dir(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "CWD subdir")
        assert "250" in last_reply(d)

    def test_cwd_to_nonexistent(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "CWD nosuchdir")
        assert "550" in last_reply(d)

    def test_cwd_path_traversal_blocked(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "CWD ../../etc")
        assert "550" in last_reply(d)

    def test_cwd_absolute_path(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "CWD /subdir")
        assert "250" in last_reply(d)


class TestCDUP:
    def test_cdup_from_subdir(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "CWD subdir")
        d._sent.clear()
        feed(d, "CDUP")
        assert "250" in last_reply(d)
        d._sent.clear()
        feed(d, "PWD")
        assert '"/"' in last_reply(d)

    def test_cdup_from_root(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "CDUP")
        assert "250" in last_reply(d)
        d._sent.clear()
        feed(d, "PWD")
        assert '"/"' in last_reply(d)


class TestTYPE:
    def test_type_i(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "TYPE I")
        assert "200" in last_reply(d)

    def test_type_unsupported(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "TYPE A")
        assert "504" in last_reply(d)


class TestSIZE:
    def test_size_existing_file(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "SIZE file.txt")
        reply = last_reply(d)
        assert "213" in reply
        assert "11" in reply  # len('hello world')

    def test_size_nonexistent(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "SIZE nosuch.txt")
        assert "550" in last_reply(d)

    def test_size_path_traversal(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "SIZE ../../etc/passwd")
        assert "550" in last_reply(d)


class TestMDTM:
    def test_mdtm_existing_file(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "MDTM file.txt")
        reply = last_reply(d)
        assert "213" in reply
        # Should be 14-digit timestamp YYYYMMDDHHMMSS
        parts = reply.split()
        assert len(parts) >= 2
        assert len(parts[1]) == 14
        assert parts[1].isdigit()

    def test_mdtm_nonexistent(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "MDTM nosuch.txt")
        assert "550" in last_reply(d)


class TestDELE:
    def test_dele_existing_file(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "DELE file.txt")
        assert "250" in last_reply(d)
        assert not os.path.exists(os.path.join(tmproot, "file.txt"))

    def test_dele_nonexistent(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "DELE nosuch.txt")
        assert "550" in last_reply(d)

    def test_dele_path_traversal(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "DELE ../../etc/passwd")
        assert "550" in last_reply(d)


class TestRMD:
    def test_rmd_empty_dir(self, tmproot):
        os.mkdir(os.path.join(tmproot, "emptydir"))
        d = make_ftpd(tmproot)
        feed(d, "RMD emptydir")
        assert "250" in last_reply(d)
        assert not os.path.exists(os.path.join(tmproot, "emptydir"))

    def test_rmd_nonexistent(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "RMD nosuchdir")
        assert "550" in last_reply(d)


class TestMKD:
    def test_mkd_creates_dir(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "MKD newdir")
        assert "250" in last_reply(d) or "257" in last_reply(d)
        assert os.path.isdir(os.path.join(tmproot, "newdir"))

    def test_mkd_already_exists(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "MKD subdir")
        assert "550" in last_reply(d)


class TestRename:
    def test_rnfr_rnto_sequence(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "RNFR file.txt")
        assert "350" in last_reply(d)
        assert d.state == State.RENAMING
        d._sent.clear()
        feed(d, "RNTO renamed.txt")
        assert "250" in last_reply(d)
        assert d.state == State.AUTHENTICATED
        assert not os.path.exists(os.path.join(tmproot, "file.txt"))
        assert os.path.exists(os.path.join(tmproot, "renamed.txt"))

    def test_rnfr_nonexistent(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "RNFR nosuch.txt")
        assert "550" in last_reply(d)
        assert d.state == State.AUTHENTICATED

    def test_rnto_without_rnfr(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "RNTO newname.txt")
        # RNTO not valid in AUTHENTICATED state
        assert "503" in last_reply(d) or "530" in last_reply(d)

    def test_rnfr_path_traversal(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "RNFR ../../etc/passwd")
        assert "550" in last_reply(d)
