# ABOUTME: Unit tests for FTP STARTTLS (RFC 4217) command handlers.
# ABOUTME: Tests AUTH TLS, PBSZ, PROT, CCC and security state sequencing.

# SPDX-License-Identifier: AGPL-3.0-only


from dionaea.ftp.state import State


def make_ftpd(**kwargs):
    from dionaea.ftp.server import FTPd

    d = FTPd()
    d.basedir = kwargs.get("basedir", "/tmp/ftp_test")
    d.handle_established()
    d._sent.clear()
    return d


def make_authed_ftpd(**kwargs):
    d = make_ftpd(**kwargs)
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


class TestAUTH:
    def test_auth_tls_before_login(self):
        d = make_ftpd()
        feed(d, "AUTH TLS")
        assert "234" in last_reply(d)
        assert d.tls_active
        assert d._tls_started

    def test_auth_tls_resets_state(self):
        d = make_authed_ftpd()
        feed(d, "AUTH TLS")
        assert d.state == State.NOT_AUTHENTICATED
        assert d.pbsz_done is False
        assert d.prot_level == "C"

    def test_auth_already_active(self):
        d = make_ftpd()
        feed(d, "AUTH TLS")
        d._sent.clear()
        feed(d, "AUTH TLS")
        assert "503" in last_reply(d)

    def test_auth_bad_mechanism(self):
        d = make_ftpd()
        feed(d, "AUTH SSL")
        assert "504" in last_reply(d)
        assert not d.tls_active

    def test_auth_case_insensitive(self):
        d = make_ftpd()
        feed(d, "AUTH tls")
        assert "234" in last_reply(d)
        assert d.tls_active


class TestPBSZ:
    def test_pbsz_without_tls(self):
        d = make_ftpd()
        feed(d, "PBSZ 0")
        assert "503" in last_reply(d)

    def test_pbsz_zero_after_auth(self):
        d = make_ftpd()
        feed(d, "AUTH TLS")
        d._sent.clear()
        feed(d, "PBSZ 0")
        assert "200" in last_reply(d)
        assert d.pbsz_done

    def test_pbsz_nonzero(self):
        d = make_ftpd()
        feed(d, "AUTH TLS")
        d._sent.clear()
        feed(d, "PBSZ 1024")
        assert "501" in last_reply(d)
        assert not d.pbsz_done


class TestPROT:
    def test_prot_without_tls(self):
        d = make_ftpd()
        feed(d, "PROT P")
        assert "503" in last_reply(d)

    def test_prot_without_pbsz(self):
        d = make_ftpd()
        feed(d, "AUTH TLS")
        d._sent.clear()
        feed(d, "PROT P")
        assert "503" in last_reply(d)

    def test_prot_p_full_sequence(self):
        d = make_ftpd()
        feed(d, "AUTH TLS")
        feed(d, "PBSZ 0")
        d._sent.clear()
        feed(d, "PROT P")
        assert "200" in last_reply(d)
        assert d.prot_level == "P"

    def test_prot_c(self):
        d = make_ftpd()
        feed(d, "AUTH TLS")
        feed(d, "PBSZ 0")
        d._sent.clear()
        feed(d, "PROT C")
        assert "200" in last_reply(d)
        assert d.prot_level == "C"

    def test_prot_unknown_level(self):
        d = make_ftpd()
        feed(d, "AUTH TLS")
        feed(d, "PBSZ 0")
        d._sent.clear()
        feed(d, "PROT S")
        assert "504" in last_reply(d)

    def test_prot_case_insensitive(self):
        d = make_ftpd()
        feed(d, "AUTH TLS")
        feed(d, "PBSZ 0")
        d._sent.clear()
        feed(d, "PROT p")
        assert "200" in last_reply(d)
        assert d.prot_level == "P"


class TestCCC:
    def test_ccc_refused(self):
        d = make_authed_ftpd()
        feed(d, "CCC")
        assert "534" in last_reply(d)


class TestPASVWithProtP:
    def test_pasv_uses_tls_proto_when_prot_p(self):
        d = make_authed_ftpd()
        d.tls_active = True
        d.pbsz_done = True
        d.prot_level = "P"
        feed(d, "PASV")
        assert d.dtf is not None
        assert d.dtf.proto == "tls"

    def test_pasv_uses_tcp_proto_when_prot_c(self):
        d = make_authed_ftpd()
        d.tls_active = True
        d.pbsz_done = True
        d.prot_level = "C"
        feed(d, "PASV")
        assert d.dtf is not None
        assert d.dtf.proto == "tcp"
