# ABOUTME: Speakeasy-based shellcode detection and analysis for dionaea
# ABOUTME: Replaces libemu with modern Mandiant Speakeasy emulation framework

from typing import Any
import logging
import json

from dionaea import IHandlerLoader
from dionaea.core import ihandler, incident, connection

logger = logging.getLogger('speakeasy')
logger.setLevel(logging.DEBUG)


class SpeakeasyHandler(IHandlerLoader):
    """Handler loader for Speakeasy shellcode analysis"""
    name = "speakeasy"

    @classmethod
    def start(cls, config: dict[str, Any] | None = None) -> 'SpeakeasyShellcodeHandler':
        return SpeakeasyShellcodeHandler("dionaea.shellcode.detected", config=config)


class SpeakeasyShellcodeHandler(ihandler):
    """
    Handles shellcode detection and analysis using Speakeasy emulation framework.

    Receives shellcode.detected incidents from the emu processor and performs
    comprehensive Windows API emulation to extract IOCs and behavioral patterns.
    """

    def __init__(self, path: str, config: dict[str, Any] | None = None) -> None:
        logger.info("%s initialized" % self.__class__.__name__)
        ihandler.__init__(self, path)

        # Import Speakeasy (lazy import to fail gracefully if not installed)
        try:
            import speakeasy
            self.speakeasy = speakeasy
            self.speakeasy_available = True
            logger.info("Speakeasy emulation framework loaded successfully")
        except ImportError:
            self.speakeasy = None
            self.speakeasy_available = False
            logger.warning(
                "Speakeasy not available - install with: pip install speakeasy-emulator"
            )

        # Configuration
        # Note: Speakeasy config must be a complete, validated config object
        # For now we use Speakeasy's defaults (60s timeout, 256k max API calls)
        # Custom config support can be added later (see doc/speakeasy-future-improvements.md)
        self.config = config or {}

    def handle_incident_dionaea_shellcode_detected(self, icd: incident) -> None:
        """
        Handle shellcode detection incident.

        Receives incident with:
        - data: shellcode bytes
        - offset: detected shellcode offset
        - arch: architecture (x86 or x86_64)
        - con: connection object
        """

        if not self.speakeasy_available:
            logger.debug("Speakeasy not available, skipping analysis")
            return

        # Extract incident data
        try:
            shellcode_data = icd.get("data")
            con: connection | None = icd.get("con")

            # Get architecture (may be None for old C code without x64 support)
            arch = icd.get("arch")
            if arch is None:
                arch = "x86"  # Default to x86 for backwards compatibility
        except (AttributeError, KeyError) as e:
            logger.error("Missing required incident data: %s", e)
            return

        logger.info("Analyzing shellcode: %d bytes (arch: %s)", len(shellcode_data), arch)

        # Analyze with Speakeasy
        try:
            results = self._analyze_shellcode(shellcode_data, arch)
            if results:
                self._process_results(results, con)
        except Exception as e:
            logger.error("Speakeasy analysis failed: %s", e, exc_info=True)

    def _analyze_shellcode(self, data: bytes, arch: str = "x86") -> dict[str, Any] | None:
        """
        Run Speakeasy emulation on shellcode.

        Args:
            data: Shellcode bytes starting from GetPC position
            arch: Architecture - "x86" for 32-bit or "x86_64" for 64-bit

        Returns emulation results with API calls, network activity, file operations, etc.
        """
        try:
            import speakeasy
        except ImportError:
            return None

        logger.debug("Starting Speakeasy emulation (arch: %s)", arch)

        # Validate shellcode data
        if not data or len(data) == 0:
            logger.error("Shellcode data is empty or None!")
            return None

        # Create Speakeasy emulator instance with custom logger
        # Pass config=None to use Speakeasy's built-in defaults (60s timeout, 256k max API calls)
        se = speakeasy.Speakeasy(logger=logger, config=None)

        # Map architecture name to Speakeasy format
        # C code sends "x86" or "x86_64", Speakeasy expects "x86" or "x64"
        speakeasy_arch = "x64" if arch == "x86_64" else "x86"

        # Run shellcode emulation
        try:
            # Load shellcode into emulation space
            sc_addr = se.load_shellcode(
                'shellcode',
                speakeasy_arch,
                data=data
            )

            # Execute shellcode from loaded address
            se.run_shellcode(sc_addr)

        except Exception as e:
            logger.warning("Speakeasy emulation stopped: %s", e)
            # Don't return None - we still want partial results

        finally:
            # Always get report, even if emulation crashed or timed out
            report = se.get_report()

            # Count total API calls across all entry points
            total_apis = sum(len(ep.get('apis', []))
                           for ep in report.get('entry_points', []))

            logger.info("Speakeasy emulation completed: %d API calls across %d entry points",
                       total_apis, len(report.get('entry_points', [])))

            return report

    def _process_results(self, results: dict[str, Any], con: connection | None) -> None:
        """
        Process Speakeasy emulation results and generate dionaea incidents.

        Analyzes API calls to detect:
        - Download attempts (URLDownloadToFile, etc.)
        - Bind shells (socket, bind, listen, accept)
        - Reverse shells (socket, connect)
        - Command execution (WinExec, CreateProcess, system)
        - File operations (CreateFile, WriteFile)
        """

        # Speakeasy reports have entry_points at top level
        entry_points = results.get('entry_points', [])
        if not entry_points:
            logger.debug("No entry points in emulation report")
            return

        # Process each entry point (shellcode can have multiple execution paths)
        all_apis = []
        for ep in entry_points:
            ep_type = ep.get('ep_type', 'unknown')
            logger.debug("Processing entry point: %s", ep_type)

            # Extract APIs from this entry point
            apis = ep.get('apis', [])
            all_apis.extend(apis)

            # Extract network events (structured data for better detection)
            network_events = ep.get('network_events', {})

            # Log API trace for this entry point
            if apis:
                logger.debug("Entry point %s API trace: %s", ep_type, json.dumps(apis, indent=2))

            # Analyze for specific behaviors in this entry point
            self._detect_downloads(apis, con)
            self._detect_bind_shell(apis, con)
            self._detect_reverse_shell(apis, con)
            self._detect_command_execution(apis, con)

            # Process network events separately for more reliable detection
            self._process_network_events(network_events, con)

        # Emit generic profile incident with all APIs (compatible with existing handlers)
        if all_apis:
            i = incident("dionaea.module.emu.profile")
            i.set("profile", json.dumps(all_apis))
            if con:
                i.set("con", con)
            i.report()

    def _detect_downloads(self, apis: list[dict], con: connection | None) -> None:
        """Detect URL download attempts"""
        for api in apis:
            api_name = api.get('api_name', '')

            if api_name == 'URLDownloadToFileA' or api_name == 'URLDownloadToFileW':
                args = api.get('args', {})
                url = args.get('szURL') or args.get('url')

                if url:
                    logger.info("Detected download: %s", url)
                    i = incident("dionaea.download.offer")
                    i.set("url", url)
                    if con:
                        i.set("con", con)
                    i.report()

    def _detect_bind_shell(self, apis: list[dict], con: connection | None) -> None:
        """Detect bind shell pattern: socket → bind → listen → accept → CreateProcess"""
        state = "NONE"
        host = None
        port = None

        for api in apis:
            api_name = api.get('api_name', '')
            args = api.get('args', {})

            if state == "NONE" and api_name in ['socket', 'WSASocketA']:
                state = "SOCKET"
            elif state == "SOCKET" and api_name == 'bind':
                state = "BIND"
                # Extract bind address
                if 'name' in args:
                    sockaddr = args['name']
                    host = sockaddr.get('sin_addr', {}).get('s_addr')
                    port = sockaddr.get('sin_port')
            elif state == "BIND" and api_name == 'listen':
                state = "LISTEN"
            elif state == "LISTEN" and api_name == 'accept':
                state = "ACCEPT"
            elif state == "ACCEPT" and api_name in ['CreateProcessA', 'CreateProcessW']:
                logger.info("Detected bind shell on port %s", port)
                i = incident("dionaea.service.shell.listen")
                if port:
                    i.set("port", int(port))
                if con:
                    i.set("con", con)
                i.report()
                state = "DONE"

    def _detect_reverse_shell(self, apis: list[dict], con: connection | None) -> None:
        """Detect reverse shell pattern: socket → connect → CreateProcess"""
        state = "NONE"
        host = None
        port = None

        for api in apis:
            api_name = api.get('api_name', '')
            args = api.get('args', {})

            if state == "NONE" and api_name in ['socket', 'WSASocketA']:
                state = "SOCKET"
            elif state == "SOCKET" and api_name == 'connect':
                state = "CONNECT"
                # Extract connect address
                if 'name' in args:
                    sockaddr = args['name']
                    host = sockaddr.get('sin_addr', {}).get('s_addr')
                    port = sockaddr.get('sin_port')
            elif state == "CONNECT" and api_name in ['CreateProcessA', 'CreateProcessW']:
                logger.info("Detected reverse shell to %s:%s", host, port)
                i = incident("dionaea.service.shell.connect")
                if port:
                    i.set("port", int(port))
                if host:
                    i.set("host", host)
                if con:
                    i.set("con", con)
                i.report()
                state = "DONE"

    def _detect_command_execution(self, apis: list[dict], con: connection | None) -> None:
        """Detect command execution attempts"""
        from dionaea.cmd import cmdexe

        for api in apis:
            api_name = api.get('api_name', '')
            args = api.get('args', {})

            if api_name == 'WinExec':
                cmd = args.get('lpCmdLine', '')
                if cmd:
                    logger.info("Detected WinExec: %s", cmd)
                    # Emulate command execution
                    r = cmdexe(None)
                    if con:
                        r.con = con  # type: ignore[attr-defined]
                    r.handle_io_in(cmd.encode() + b'\0')

            elif api_name in ['CreateProcessA', 'CreateProcessW']:
                cmdline = args.get('lpCommandLine', '')
                if cmdline:
                    logger.info("Detected CreateProcess: %s", cmdline)
                    r = cmdexe(None)
                    if con:
                        r.con = con  # type: ignore[attr-defined]
                    r.handle_io_in(cmdline.encode() + b'\0')

    def _process_network_events(self, network_events: dict[str, Any], con: connection | None) -> None:
        """
        Process structured network events from Speakeasy report.

        Network events provide pre-parsed connection info that's more reliable
        than trying to extract it from raw API arguments.
        """

        # Process DNS queries
        dns_queries = network_events.get('dns', [])
        for query in dns_queries:
            domain = query.get('request')
            if domain:
                logger.info("DNS query: %s", domain)

        # Process network traffic (connections)
        traffic = network_events.get('traffic', [])
        for conn in traffic:
            proto = conn.get('proto', 'unknown')
            server = conn.get('server')
            port = conn.get('port')
            conn_type = conn.get('type')  # 'connect', 'bind', etc.
            method = conn.get('method')  # 'winsock.connect', etc.

            if conn_type == 'connect' and server and port:
                logger.info("Network connection: %s://%s:%d (method: %s)",
                          proto, server, port, method)

                # Emit reverse shell incident
                i = incident("dionaea.service.shell.connect")
                i.set("host", server)
                i.set("port", int(port))
                if con:
                    i.set("con", con)
                i.report()

            elif conn_type == 'bind' and port:
                logger.info("Network bind: %s on port %d", proto, port)

                # Emit bind shell incident
                i = incident("dionaea.service.shell.listen")
                i.set("port", int(port))
                if con:
                    i.set("con", con)
                i.report()
