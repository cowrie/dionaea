# ABOUTME: Unit tests for FTP data connections and transfer commands.
# ABOUTME: Tests PASV, PORT, LIST, RETR, STOR with mock connections.

# SPDX-License-Identifier: AGPL-3.0-only


import pytest


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


def all_replies(ftpd):
    lines = []
    for chunk in ftpd._sent:
        text = chunk.decode() if isinstance(chunk, bytes) else chunk
        for line in text.split("\r\n"):
            if line:
                lines.append(line)
    return lines


def feed(ftpd, text):
    return ftpd.handle_io_in((text + "\r\n").encode())


@pytest.fixture
def tmproot(tmp_path):
    root = tmp_path / "ftproot"
    root.mkdir()
    (root / "file.txt").write_text("hello world")
    (root / "subdir").mkdir()
    return str(root)


class TestPASV:
    def test_pasv_responds_227(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "PASV")
        reply = last_reply(d)
        assert "227" in reply

    def test_pasv_creates_dtf(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "PASV")
        assert d.dtf is not None

    def test_pasv_closes_previous_dtf(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "PASV")
        first_dtf = d.dtf
        feed(d, "PASV")
        assert first_dtf._closed


class TestPORT:
    def test_port_with_valid_address(self, tmproot):
        d = make_ftpd(tmproot)
        d.remote.host = "127.0.0.1"
        feed(d, "PORT 127,0,0,1,4,1")
        # PORT should create a dtp or reply OK
        assert d.dtp is not None or "200" in last_reply(d)

    def test_port_bounce_detection(self, tmproot):
        d = make_ftpd(tmproot)
        d.remote.host = "10.0.0.1"
        d._sent.clear()
        feed(d, "PORT 192,168,1,1,4,1")
        # Should detect bounce and not create connection
        assert d.dtp is None


class TestLIST:
    def test_list_without_data_connection(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "LIST")
        # No data connection — should warn or error
        reply = last_reply(d)
        assert "425" in reply or "150" not in reply

    def test_list_syntax(self, tmproot):
        """LIST with a specific path argument."""
        d = make_ftpd(tmproot)
        feed(d, "LIST subdir")
        # Without data connection, should report can't open
        reply = last_reply(d)
        assert "425" in reply or "150" not in reply


class TestRETR:
    def test_retr_without_data_connection(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "RETR file.txt")
        # No data connection
        reply = last_reply(d)
        assert "425" in reply or "150" not in reply

    def test_retr_nonexistent(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "RETR nosuch.txt")
        assert "550" in last_reply(d)

    def test_retr_path_traversal(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "RETR ../../etc/passwd")
        assert "550" in last_reply(d)

    def test_retr_no_argument(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "RETR")
        assert "501" in last_reply(d)


class TestSTOR:
    def test_stor_without_data_connection(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "STOR upload.txt")
        reply = last_reply(d)
        assert "425" in reply or "150" not in reply

    def test_stor_no_argument(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "STOR")
        assert "501" in last_reply(d)

    def test_stor_path_traversal(self, tmproot):
        d = make_ftpd(tmproot)
        feed(d, "STOR ../../etc/evil")
        assert "550" in last_reply(d)


class TestDataConClasses:
    def test_ftpdatacon_init(self):
        from dionaea.ftp.data import FTPDataCon

        dc = FTPDataCon(ctrl=None)
        assert dc.proto == "tcp"
        assert dc.ctrl is None

    def test_ftpdatacon_proto_override(self):
        from dionaea.ftp.data import FTPDataCon

        dc = FTPDataCon(proto="tls", ctrl=None)
        assert dc.proto == "tls"
