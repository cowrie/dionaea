# ABOUTME: Speakeasy-based shellcode emulation and IOC extraction for dionaea.
# ABOUTME: Analyzes shellcode for downloads, shells, and command execution via Mandiant Speakeasy v2.

# SPDX-FileCopyrightText: dionaea developers
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

from typing import Any
import logging
import json

from dionaea import IHandlerLoader
from dionaea.core import ihandler, incident, connection

logger = logging.getLogger("speakeasy")


class SpeakeasyHandler(IHandlerLoader):
    """Handler loader for Speakeasy shellcode analysis"""

    name = "speakeasy"

    @classmethod
    def start(cls, config: dict[str, Any] | None = None) -> "SpeakeasyShellcodeHandler":
        return SpeakeasyShellcodeHandler("dionaea.shellcode.detected", config=config)


class SpeakeasyShellcodeHandler(ihandler):
    """
    Handles shellcode detection and analysis using Speakeasy emulation framework.

    Receives shellcode.detected incidents from the processor pipeline and performs
    Windows API emulation to extract IOCs and behavioral patterns.

    Requires speakeasy-emulator >= 2.0.0b1.
    """

    def __init__(self, path: str, config: dict[str, Any] | None = None) -> None:
        ihandler.__init__(self, path)

        try:
            import speakeasy

            self.speakeasy = speakeasy
            self.speakeasy_available = True
            logger.info("Speakeasy emulation framework loaded")
        except ImportError:
            self.speakeasy = None
            self.speakeasy_available = False
            logger.warning(
                "Speakeasy not available - install with: pip install speakeasy-emulator>=2.0.0b1"
            )

        self.config = config or {}

        # Suppress noisy speakeasy internal logging (invalid_read, invalid_write, etc.)
        logging.getLogger("speakeasy").setLevel(logging.CRITICAL + 10)

    def handle_incident_dionaea_shellcode_detected(self, icd: incident) -> None:
        if not self.speakeasy_available:
            logger.debug("Speakeasy not available, skipping analysis")
            return

        try:
            shellcode_data = icd.get("data")
            con: connection | None = icd.get("con")
            arch = icd.get("arch") or "x86"
            offset = icd.get("offset") or 0
        except (AttributeError, KeyError) as e:
            logger.error("Missing required incident data: %s", e)
            return

        if arch not in ("x86", "x86_64"):
            logger.info(
                "Shellcode detected: %d bytes (arch: %s) - no emulation available",
                len(shellcode_data), arch,
            )
            return

        logger.info(
            "Analyzing shellcode: %d bytes (arch: %s, offset: %d)",
            len(shellcode_data), arch, offset
        )

        try:
            report = self._analyze_shellcode(shellcode_data, arch, offset)
            if report:
                self._process_results(report, con)
        except Exception as e:
            logger.error("Speakeasy analysis failed: %s", e, exc_info=True)

    def _analyze_shellcode(
        self, data: bytes, arch: str = "x86", offset: int = 0
    ) -> dict[str, Any] | None:
        """
        Run Speakeasy emulation on shellcode.

        Returns emulation report as a dict (via model_dump), or None on failure.
        """
        try:
            import speakeasy
        except ImportError:
            return None

        if not data:
            logger.error("Shellcode data is empty or None!")
            return None

        speakeasy_arch = "x64" if arch == "x86_64" else "x86"

        report = None
        for try_offset in ([offset, 0] if offset > 0 else [0]):
            se = None
            try:
                se = speakeasy.Speakeasy(config=None)

                if 0 < try_offset < len(data):
                    shellcode_data = data[try_offset:]
                    logger.debug("Trying from offset %d (%d bytes)", try_offset, len(shellcode_data))
                else:
                    shellcode_data = data
                    logger.debug("Trying from offset 0 (%d bytes)", len(shellcode_data))

                sc_addr = se.load_shellcode("shellcode", speakeasy_arch, data=shellcode_data)
                se.run_shellcode(sc_addr)

            except Exception as e:
                logger.debug("Emulation from offset %d stopped: %s", try_offset, e)

            if se is None:
                continue

            # v2: get_report() returns a Pydantic model; convert to dict for uniform access
            raw_report = se.get_report()
            report = raw_report.model_dump() if hasattr(raw_report, "model_dump") else raw_report

            total_apis = sum(
                len([ev for ev in ep.get("events", []) or [] if ev.get("event") == "api"])
                for ep in report.get("entry_points", [])
            )

            if total_apis > 0:
                logger.info(
                    "Speakeasy emulation completed: %d API calls from offset %d",
                    total_apis, try_offset
                )
                return report
            else:
                logger.debug("No API calls from offset %d, trying next", try_offset)

        logger.info(
            "Speakeasy emulation completed: 0 API calls across %d entry points",
            len(report.get("entry_points", [])) if report else 0,
        )
        return report

    def _process_results(self, results: dict[str, Any], con: connection | None) -> None:
        """
        Process Speakeasy emulation results and generate dionaea incidents.

        Analyzes the unified event stream to detect:
        - Download attempts (URLDownloadToFile)
        - Bind shells (socket, bind, listen, accept, CreateProcess)
        - Reverse shells (socket, connect, CreateProcess)
        - Command execution (WinExec, CreateProcess)
        """
        entry_points = results.get("entry_points", [])
        if not entry_points:
            logger.debug("No entry points in emulation report")
            return

        all_api_events = []
        for ep in entry_points:
            ep_type = ep.get("ep_type", "unknown")
            logger.debug("Processing entry point: %s", ep_type)

            events = ep.get("events") or []

            # Split events by type
            api_events = [ev for ev in events if ev.get("event") == "api"]
            net_traffic = [ev for ev in events if ev.get("event") == "net_traffic"]
            net_dns = [ev for ev in events if ev.get("event") == "net_dns"]
            process_creates = [ev for ev in events if ev.get("event") == "process_create"]

            all_api_events.extend(api_events)

            if api_events:
                logger.debug(
                    "Entry point %s: %d API calls, %d net events, %d DNS, %d process creates",
                    ep_type, len(api_events), len(net_traffic), len(net_dns), len(process_creates)
                )

            # Detect behaviors from API call sequences
            self._detect_downloads(api_events, con)
            self._detect_bind_shell(api_events, con)
            self._detect_reverse_shell(api_events, con)
            self._detect_command_execution(api_events, process_creates, con)

            # Detect from structured network events (more reliable than API arg parsing)
            self._process_network_events(net_traffic, net_dns, con)

        # Emit generic profile incident with all API events
        if all_api_events:
            i = incident("dionaea.module.emu.profile")
            i.set("profile", json.dumps(all_api_events))
            if con:
                i.set("con", con)
            i.report()

    def _detect_downloads(self, api_events: list[dict], con: connection | None) -> None:
        """Detect URL download attempts from API calls."""
        for ev in api_events:
            api_name = ev.get("api_name", "")
            # v2 prefixes module name: "urlmon.URLDownloadToFile"
            if "URLDownloadToFile" not in api_name:
                continue

            args = ev.get("args", [])
            # URLDownloadToFile(pCaller, szURL, szFileName, dwReserved, lpfnCB)
            if len(args) < 2:
                continue
            url = args[1]

            if url:
                logger.info("Detected download: %s", url)
                i = incident("dionaea.download.offer")
                i.set("url", url)
                if con:
                    i.set("con", con)
                i.report()

    def _detect_bind_shell(self, api_events: list[dict], con: connection | None) -> None:
        """Detect bind shell pattern: socket -> bind -> listen -> accept -> CreateProcess"""
        state = "NONE"
        host = None
        port = None

        for ev in api_events:
            api_name = ev.get("api_name", "")
            args = ev.get("args", [])

            if state == "NONE" and _api_matches(api_name, ["socket", "WSASocketA", "WSASocketW"]):
                state = "SOCKET"
            elif state == "SOCKET" and _api_matches(api_name, ["bind"]):
                state = "BIND"
                # bind(s, "host:port", namelen) — args[1] is "host:port" string
                host, port = _parse_host_port(args, 1)
            elif state == "BIND" and _api_matches(api_name, ["listen"]):
                state = "LISTEN"
            elif state == "LISTEN" and _api_matches(api_name, ["accept"]):
                state = "ACCEPT"
            elif state == "ACCEPT" and _api_matches(api_name, ["CreateProcessA", "CreateProcessW"]):
                logger.info("Detected bind shell on %s:%s", host, port)
                i = incident("dionaea.service.shell.listen")
                if port is not None:
                    i.set("port", port)
                if host:
                    i.set("host", host)
                if con:
                    i.set("con", con)
                i.report()
                state = "DONE"

    def _detect_reverse_shell(self, api_events: list[dict], con: connection | None) -> None:
        """Detect reverse shell pattern: socket -> connect -> CreateProcess"""
        state = "NONE"
        host = None
        port = None

        for ev in api_events:
            api_name = ev.get("api_name", "")
            args = ev.get("args", [])

            if state == "NONE" and _api_matches(api_name, ["socket", "WSASocketA", "WSASocketW"]):
                state = "SOCKET"
            elif state == "SOCKET" and _api_matches(api_name, ["connect", "WSAConnect"]):
                state = "CONNECT"
                # connect(s, "host:port", namelen) — args[1] is "host:port" string
                host, port = _parse_host_port(args, 1)
            elif state == "CONNECT" and _api_matches(api_name, ["CreateProcessA", "CreateProcessW"]):
                logger.info("Detected reverse shell to %s:%s", host, port)
                i = incident("dionaea.service.shell.connect")
                if port is not None:
                    i.set("port", port)
                if host:
                    i.set("host", host)
                if con:
                    i.set("con", con)
                i.report()
                state = "DONE"

    def _detect_command_execution(
        self, api_events: list[dict], process_creates: list[dict],
        con: connection | None,
    ) -> None:
        """Detect command execution from API calls and process creation events."""
        from dionaea.cmd import cmdexe

        # Check structured ProcessCreateEvent first (v2 only, most reliable)
        for ev in process_creates:
            cmdline = ev.get("cmdline", "")
            if cmdline:
                logger.info("Detected process create: %s", cmdline)
                r = cmdexe(None)
                if con:
                    r.con = con  # type: ignore[attr-defined]
                r.handle_io_in(cmdline.encode() + b"\0")
                return  # One command execution per entry point is enough

        # Fall back to API event inspection
        for ev in api_events:
            api_name = ev.get("api_name", "")
            args = ev.get("args", [])

            if _api_matches(api_name, ["WinExec"]):
                # WinExec(lpCmdLine, uCmdShow) — args[0] is command line
                if args:
                    cmd = args[0]
                    logger.info("Detected WinExec: %s", cmd)
                    r = cmdexe(None)
                    if con:
                        r.con = con  # type: ignore[attr-defined]
                    r.handle_io_in(cmd.encode() + b"\0")
                    return

            elif _api_matches(api_name, ["CreateProcessA", "CreateProcessW"]):
                # CreateProcess(lpApp, lpCmdLine, ...) — args[1] is command line
                if len(args) >= 2 and args[1]:
                    cmdline = args[1]
                    logger.info("Detected CreateProcess: %s", cmdline)
                    r = cmdexe(None)
                    if con:
                        r.con = con  # type: ignore[attr-defined]
                    r.handle_io_in(cmdline.encode() + b"\0")
                    return

    def _process_network_events(
        self, net_traffic: list[dict], net_dns: list[dict],
        con: connection | None,
    ) -> None:
        """
        Process structured network events from the event stream.

        These are more reliable than parsing API arguments since speakeasy
        pre-parses the connection details.
        """
        for query in net_dns:
            domain = query.get("query")
            if domain:
                logger.info("DNS query: %s", domain)

        for conn in net_traffic:
            server = conn.get("server")
            port = conn.get("port")
            conn_type = conn.get("type")
            proto = conn.get("proto", "unknown")
            method = conn.get("method")

            if conn_type == "connect" and server and port:
                logger.info(
                    "Network connection: %s://%s:%d (method: %s)",
                    proto, server, port, method,
                )
                i = incident("dionaea.service.shell.connect")
                i.set("host", server)
                i.set("port", int(port))
                if con:
                    i.set("con", con)
                i.report()

            elif conn_type == "bind" and port:
                logger.info("Network bind: %s on port %d", proto, port)
                i = incident("dionaea.service.shell.listen")
                i.set("port", int(port))
                if con:
                    i.set("con", con)
                i.report()


def _api_matches(api_name: str, patterns: list[str]) -> bool:
    """Check if an API name matches any pattern, ignoring module prefix.

    v2 uses "module.function" format (e.g. "ws2_32.connect"),
    v1 uses bare function names (e.g. "connect").
    """
    bare_name = api_name.rsplit(".", 1)[-1] if "." in api_name else api_name
    return bare_name in patterns


def _parse_host_port(args: list[str], index: int) -> tuple[str | None, int | None]:
    """Parse a "host:port" string from a positional argument list.

    Speakeasy formats bind/connect sockaddr as "host:port" in the args list.
    Returns (host, port) or (None, None) if parsing fails.
    """
    if index >= len(args):
        return None, None
    value = args[index]
    if ":" not in value:
        return None, None
    # Handle IPv6 "[::1]:port" and IPv4 "1.2.3.4:port"
    if value.startswith("["):
        # IPv6: [addr]:port
        bracket_end = value.rfind("]")
        if bracket_end < 0 or bracket_end + 1 >= len(value) or value[bracket_end + 1] != ":":
            return None, None
        host = value[1:bracket_end]
        port_str = value[bracket_end + 2:]
    else:
        # IPv4: addr:port
        last_colon = value.rfind(":")
        host = value[:last_colon]
        port_str = value[last_colon + 1:]
    try:
        return host, int(port_str)
    except ValueError:
        return None, None
