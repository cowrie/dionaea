# ABOUTME: Unit tests for FTP server command dispatch and login sequence.
# ABOUTME: Tests processcmd routing, state transitions, and pre-auth commands.

# SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial



from dionaea.core import incident as MockIncident


def make_ftpd(**kwargs):
    """Create an FTPd instance with a temp basedir."""
    from dionaea.ftp.server import FTPd

    d = FTPd()
    d.basedir = kwargs.get("basedir", "/tmp/ftp_test")
    return d


def sent_lines(ftpd):
    """Return all sent data as decoded lines."""
    return [
        b.decode() if isinstance(b, bytes) else b
        for chunk in ftpd._sent
        for b in (
            chunk.decode().split("\r\n")
            if isinstance(chunk, bytes)
            else chunk.split("\r\n")
        )
        if b
    ]


def last_reply(ftpd):
    """Return the last non-empty line sent."""
    lines = sent_lines(ftpd)
    return lines[-1] if lines else ""


def feed(ftpd, text):
    """Feed a line of text into handle_io_in as bytes."""
    data = (text + "\r\n").encode()
    return ftpd.handle_io_in(data)


class TestBanner:
    def test_handle_established_sends_banner(self):
        d = make_ftpd()
        d.handle_established()
        assert last_reply(d).startswith("220")

    def test_handle_established_calls_processors(self):
        d = make_ftpd()
        d.handle_established()
        assert d._processors_called


class TestDispatch:
    def test_unknown_command_returns_502(self):
        d = make_ftpd()
        d.handle_established()
        d._sent.clear()
        feed(d, "XYZZY")
        assert "502" in last_reply(d)

    def test_auth_required_before_login(self):
        d = make_ftpd()
        d.handle_established()
        d._sent.clear()
        feed(d, "PWD")
        assert "530" in last_reply(d)

    def test_bad_sequence_in_awaiting_pass(self):
        d = make_ftpd()
        d.handle_established()
        feed(d, "USER testuser")
        d._sent.clear()
        feed(d, "PWD")
        assert "503" in last_reply(d)

    def test_incident_fired_for_commands(self):
        MockIncident._all_incidents.clear()
        d = make_ftpd()
        d.handle_established()
        feed(d, "NOOP")
        ftp_incidents = [
            i
            for i in MockIncident._all_incidents
            if i.origin == "dionaea.modules.python.ftp.command"
        ]
        assert len(ftp_incidents) >= 1


class TestLogin:
    def test_user_transitions_to_awaiting_pass(self):
        from dionaea.ftp.state import State

        d = make_ftpd()
        d.handle_established()
        d._sent.clear()
        feed(d, "USER testuser")
        assert d.state == State.AWAITING_PASS
        assert "331" in last_reply(d)

    def test_anonymous_user(self):
        d = make_ftpd()
        d.handle_established()
        d._sent.clear()
        feed(d, "USER anonymous")
        reply = last_reply(d)
        assert "331" in reply
        assert "email" in reply.lower() or "guest" in reply.lower()

    def test_pass_completes_login(self):
        from dionaea.ftp.state import State

        d = make_ftpd()
        d.handle_established()
        feed(d, "USER testuser")
        d._sent.clear()
        feed(d, "PASS secret")
        assert d.state == State.AUTHENTICATED
        assert "230" in last_reply(d)

    def test_anonymous_pass_login(self):
        d = make_ftpd()
        d.handle_established()
        feed(d, "USER anonymous")
        d._sent.clear()
        feed(d, "PASS test@test.com")
        assert "230" in last_reply(d)

    def test_login_incident(self):
        MockIncident._all_incidents.clear()
        d = make_ftpd()
        d.handle_established()
        feed(d, "USER testuser")
        feed(d, "PASS secret")
        login_incidents = [
            i
            for i in MockIncident._all_incidents
            if i.origin == "dionaea.modules.python.ftp.login"
        ]
        assert len(login_incidents) == 1
        assert login_incidents[0]._attrs["username"] == "testuser"
        assert login_incidents[0]._attrs["password"] == "secret"

    def test_user_requires_argument(self):
        d = make_ftpd()
        d.handle_established()
        d._sent.clear()
        feed(d, "USER")
        assert "500" in last_reply(d)

    def test_pass_requires_argument(self):
        d = make_ftpd()
        d.handle_established()
        feed(d, "USER testuser")
        d._sent.clear()
        feed(d, "PASS")
        assert "500" in last_reply(d)

    def test_re_login(self):
        """USER after authenticated should restart login."""
        from dionaea.ftp.state import State

        d = make_ftpd()
        d.handle_established()
        feed(d, "USER testuser")
        feed(d, "PASS secret")
        assert d.state == State.AUTHENTICATED
        feed(d, "USER other")
        assert d.state == State.AWAITING_PASS


class TestPreAuth:
    def test_feat_before_login(self):
        d = make_ftpd()
        d.handle_established()
        d._sent.clear()
        feed(d, "FEAT")
        text = "".join(b.decode() if isinstance(b, bytes) else b for b in d._sent)
        assert "211" in text
        assert "AUTH TLS" in text
        assert "PBSZ" in text
        assert "PROT" in text

    def test_syst(self):
        d = make_ftpd()
        d.handle_established()
        d._sent.clear()
        feed(d, "SYST")
        assert "215" in last_reply(d)

    def test_noop(self):
        d = make_ftpd()
        d.handle_established()
        d._sent.clear()
        feed(d, "NOOP")
        assert "200" in last_reply(d)

    def test_quit_sends_goodbye_and_closes(self):
        d = make_ftpd()
        d.handle_established()
        d._sent.clear()
        feed(d, "QUIT")
        assert "221" in last_reply(d)
        assert d._closed

    def test_help(self):
        d = make_ftpd()
        d.handle_established()
        d._sent.clear()
        feed(d, "HELP")
        assert "214" in last_reply(d) or "211" in last_reply(d)


class TestIoIn:
    def test_partial_line_returns_zero(self):
        d = make_ftpd()
        d.handle_established()
        consumed = d.handle_io_in(b"NOOP")
        assert consumed == 0

    def test_complete_line_returns_consumed(self):
        d = make_ftpd()
        d.handle_established()
        consumed = d.handle_io_in(b"NOOP\r\n")
        assert consumed == 6

    def test_multiple_lines(self):
        d = make_ftpd()
        d.handle_established()
        consumed = d.handle_io_in(b"NOOP\r\nSYST\r\n")
        assert consumed == 12
