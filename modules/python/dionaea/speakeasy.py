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
        self.config = config or {}
        self.max_instructions = self.config.get('max_instructions', 1000000)
        self.timeout = self.config.get('timeout', 60)  # seconds

    def handle_incident_dionaea_shellcode_detected(self, icd: incident) -> None:
        """
        Handle shellcode detection incident.

        Receives incident with:
        - data: shellcode bytes
        - offset: detected shellcode offset
        - con: connection object
        """

        if not self.speakeasy_available:
            logger.debug("Speakeasy not available, skipping analysis")
            return

        # Extract incident data
        try:
            shellcode_data = icd.get("data")
            con: connection | None = icd.get("con")
        except (AttributeError, KeyError) as e:
            logger.error("Missing required incident data: %s", e)
            return

        # Offset may not be present
        try:
            offset = icd.get("offset")
        except (AttributeError, KeyError):
            offset = 0

        logger.info("Analyzing shellcode at offset %d (%d bytes total)",
                    offset, len(shellcode_data))

        # Analyze with Speakeasy
        try:
            results = self._analyze_shellcode(shellcode_data, offset)
            if results:
                self._process_results(results, con)
        except Exception as e:
            logger.error("Speakeasy analysis failed: %s", e, exc_info=True)

    def _analyze_shellcode(self, data: bytes, offset: int) -> dict[str, Any] | None:
        """
        Run Speakeasy emulation on shellcode.

        Returns emulation results with API calls, network activity, file operations, etc.
        """
        try:
            import speakeasy
        except ImportError:
            return None

        logger.debug("Starting Speakeasy emulation")

        # Create Speakeasy emulator instance
        se = speakeasy.Speakeasy()

        # Run shellcode emulation
        try:
            # Adjust data to start from detected offset
            shellcode_data = data[offset:] if offset > 0 else data

            # Load shellcode into emulation space
            sc_addr = se.load_shellcode(
                'shellcode',
                'x86',  # TODO: Support amd64 when C detector adds 64-bit support
                data=shellcode_data
            )

            # Execute shellcode from loaded address
            se.run_shellcode(sc_addr)

            # Get emulation report
            report = se.get_report()

            logger.info("Speakeasy emulation completed: %d API calls recorded",
                       len(report.get('apis', [])))

            return report

        except Exception as e:
            logger.error("Speakeasy emulation error: %s", e)
            return None

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

        apis = results.get('apis', [])
        if not apis:
            logger.debug("No API calls captured")
            return

        # Log full API trace
        logger.debug("API trace: %s", json.dumps(apis, indent=2))

        # Analyze for specific behaviors
        self._detect_downloads(apis, con)
        self._detect_bind_shell(apis, con)
        self._detect_reverse_shell(apis, con)
        self._detect_command_execution(apis, con)

        # Emit generic profile incident (compatible with existing handlers)
        i = incident("dionaea.module.emu.profile")
        i.set("profile", json.dumps(apis))
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
