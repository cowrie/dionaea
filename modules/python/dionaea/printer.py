# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2019 Michael Neu (inquiries@michaeln.eu)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# The following code is based on github.com/michaelneu/pjl-honeypot
# MIT licensed code, GPL compatible
# Copyright (c) 2019 Michael Neu

# pjl/pcl server (printer)
from __future__ import annotations

from dionaea import ServiceLoader
from dionaea.core import connection, g_dionaea, incident
from dionaea.exception import ServiceConfigError
import logging
import os
from pathlib import Path
import re
import time

logger = logging.getLogger("printer")
logger.setLevel(logging.DEBUG)


class PrinterService(ServiceLoader):
    name = "printer"

    @classmethod
    def start(cls, addr, iface=None, config=None):
        daemon = Printerd()
        try:
            daemon.apply_config(config or {})
        except ServiceConfigError as e:
            logger.error(e.msg, *e.args)
            return
        daemon.bind(addr, 9100, iface=iface)
        daemon.listen()
        return daemon


def convert_pjl_command_to_regex(command):
    """Converts an underscore separated PJL command to a regex pattern.

    The generated regex pattern captures the command's arguments in the first group.
    """
    command_bytes = bytes(command, "utf-8")
    return re.compile(
        rb"^\@pjl\s+" + command_bytes.replace(b"_", rb"\s+") + rb"\s*(.*)", re.IGNORECASE
    )


def convert_pjl_responses_to_regex(responses_dict):
    """Converts all dictionary items to a (regex, command, response) triple.

    The regex is generated using `convert_pjl_command_to_regex`, thus it can be used to capture arguements.
    """
    return [
        (
            convert_pjl_command_to_regex(command),
            command,
            response,
        )
        for command, response in responses_dict.items()
    ]


def cut_bytes_before_last_crlf(text):
    """Cuts the given text before the last line break.

    Example:
        cut_bytes_before_last_crlf(b"foo\r\nbar") => b"foo\r\n"
        cut_bytes_before_last_crlf(b"foo\r\nbar\r\n") => b"foo\r\nbar\r\n"
    """
    try:
        last_crlf_index = text.rindex(b"\r\n")
        return text[0 : last_crlf_index + 2]
    except ValueError:
        return text


pjl_default_responses = {
    "comment": "",
    "enter_language_pcl": "E . . . . PCL Job . . . . E",
    "enter_language_postscript": "%!PS-ADOBE ... PostScript print job ...",
    "job": "",
    "eoj": "",
    "default": "",
    "set": "",
    "initialize": "",
    "reset": "",
    "inquire_ret": "MEDIUM",
    "inquire_pageprotect": "OFF",
    "inquire_resolution": "600",
    "inquire_personality": "AUTO",
    "inquire_timeout": "15",
    "inquire_lparm:pcl_pitch": "10.00",
    "inquire_lparm:pcl_ptsize": "12.00",
    "inquire_lparm:pcl_symset": "ROMAN8",
    "dinquire_ret": "MEDIUM",
    "dinquire_pageprotect": "OFF",
    "dinquire_resolution": "600",
    "dinquire_personality": "AUTO",
    "dinquire_timeout": "15",
    "dinquire_lparm:pcl_pitch": "10.00",
    "dinquire_lparm:pcl_ptsize": "12.00",
    "dinquire_lparm:pcl_symset": "ROMAN8",
    "info_id": "HP LASERJET 4ML",
    "info_config": "IN TRAYS [3 ENUMERATED]\n"
    "\tINTRAY1 MP\n"
    "\tINTRAY2 PC\n"
    "\tINTRAY3 LC\n"
    "ENVELOPE TRAY\n"
    "OUT TRAYS [1 ENUMERATED]\n"
    "\tNORMAL FACEDOWN\n"
    "PAPERS [9 ENUMERATED]\n"
    "\tLETTER\n"
    "\tLEGAL\n"
    "\tA4\n"
    "\tEXECUTIVE\n"
    "\tMONARCH\n"
    "\tCOM10\n"
    "\tDL\n"
    "\tC5\n"
    "\tB5\n"
    "LANGUAGES [2 ENUMERATED]\n"
    "\tPCL\n"
    "\tPOSTSCRIPT\n"
    "USTATUS [4 ENUMERATED]\n"
    "\tDEVICE\n"
    "\tJOB\n"
    "\tPAGE\n"
    "\tTIMED\n"
    "FONT CARTRIDGE SLOTS [1 ENUMERATED]\n"
    "\tCARTRIDGE\n"
    "MEMORY=2097152\n"
    "DISPLAY LINES=1\n"
    "DISPLAY CHARACTER SIZE=16",
    "info_filesys": "VOLUME TOTAL SIZE FREE SPACE LOCATION LABEL STATUS\n"
    "0:     1755136    1718272    <HT>     <HT>  READ-WRITE",
    "info_memory": "TOTAL=1494416\nLARGEST=1494176",
    "info_pagecount": "PAGECOUNT=183933",
    "info_status": 'CODE=10001\nDISPLAY="Non HP supply in use"\nONLINE=TRUE',
    "info_variables": "COPIES=1 [2 RANGE]\n"
    "\t1\n"
    "\t999\n"
    "PAPER=LETTER [3 ENUMERATED]\n"
    "\tLETTER\n"
    "\tLEGAL\n"
    "\tA4\n"
    "ORIENTATION=PORTRAIT [2 ENUMERATED]\n"
    "\tPORTRAIT\n"
    "\tLANDSCAPE\n"
    "FORMLINES=60 [2 RANGE]\n"
    "\t5\n"
    "\t128\n"
    "MANUALFEED=OFF [2 ENUMERATED]\n"
    "\tOFF\n"
    "\tON\n"
    "RET=MEDIUM [4 ENUMERATED]\n"
    "\tOFF\n"
    "\tLIGHT\n"
    "\tMEDIUM\n"
    "\tDARK\n"
    "PAGEPROTECT=OFF [4 ENUMERATED]\n"
    "\tOFF\n"
    "\tLETTER\n"
    "\tLEGAL\n"
    "\tA4\n"
    "RESOLUTION=600 [2 ENUMERATED]\n"
    "\t300\n"
    "\t600\n"
    "PERSONALITY=AUTO [3 ENUMERATED]\n"
    "\tAUTO\n"
    "\tPCL\n"
    "\tPOSTSCRIPT\n"
    "TIMEOUT=15 [2 RANGE]\n"
    "\t5\n"
    "\t300\n"
    "MPTRAY=CASSETTE [3 ENUMERATED]\n"
    "\tMANUAL\n"
    "\tCASSETTE\n"
    "\tFIRST\n"
    "INTRAY1=UNLOCKED [2 ENUMERATED]\n"
    "\tUNLOCKED\n"
    "\tLOCKED\n"
    "INTRAY2=UNLOCKED [2 ENUMERATED]\n"
    "\tUNLOCKED\n"
    "\tLOCKED\n"
    "INTRAY3=UNLOCKED [2 ENUMERATED]\n"
    "\tUNLOCKED\n"
    "\tLOCKED\n"
    "CLEARABLEWARNINGS=ON [2 ENUMERATED READONLY]\n"
    "\tJOB\n"
    "\tON\n"
    "AUTOCONT=OFF [2 ENUMERATED READONLY]\n"
    "\tOFF\n"
    "\tON\n"
    "\n"
    "DENSITY=3 [2 RANGE READONLY]\n"
    "\t1\n"
    "\t5\n"
    "LOWTONER=ON [2 ENUMERATED READONLY]\n"
    "\tOFF\n"
    "\tON\n"
    "INTRAY1SIZE=LETTER [9 ENUMERATED READONLY]\n"
    "\tLETTER\n"
    "\tLEGAL\n"
    "\tA4\n"
    "\tEXECUTIVE\n"
    "\tCOM10\n"
    "\tMONARCH\n"
    "\tC5\n"
    "\tDL\n"
    "\tB5\n"
    "INTRAY2SIZE=LETTER [4 ENUMERATED READONLY]\n"
    "\tLETTER\n"
    "\tLEGAL\n"
    "\tA4\n"
    "\tEXECUTIVE\n"
    "INTRAY3SIZE=LETTER [4 ENUMERATED READONLY]\n"
    "\tLETTER\n"
    "\tLEGAL\n"
    "\tA4\n"
    "\tEXECUTIVE\n"
    "INTRAY4SIZE=COM10 [5 ENUMERATED READONLY]\n"
    "\tCOM10\n"
    "\tMONARCH\n"
    "\tC5\n"
    "\tDL\n"
    "\tB5\n"
    "LPARM:PCL FONTSOURCE=I [1 ENUMERATED]\n"
    "\tI\n"
    "LPARM:PCL FONTNUMBER=0 [2 RANGE]\n"
    "\t0\n"
    "\t50\n"
    "LPARM:PCL PITCH=10.00 [2 RANGE]\n"
    "\t0.44\n"
    "\t99.99\n"
    "LPARM:PCL PTSIZE=12.00 [2 RANGE]\n"
    "\t4.00\n"
    "\t999.75\n"
    "LPARM:PCL SYMSET=ROMAN8 [4 ENUMERATED]\n"
    "\tROMAN8\n"
    "\tISOL1\n"
    "\tISOL2\n"
    "\tWIN30\n"
    "LPARM:POSTSCRIPT PRTPSERRS=OFF [2 ENUMERATED]\n"
    "\tOFF\n"
    "\tON",
    "info_ustatus": "DEVICE=OFF [3 ENUMERATED]\n"
    "\tOFF\n"
    "\tON\n"
    "\tVERBOSE\n"
    "JOB=OFF [2 ENUMERATED]\n"
    "\tOFF\n"
    "\tON\n"
    "PAGE=OFF [2 ENUMERATED]\n"
    "\tOFF\n"
    "\tON\n"
    "TIMED=0 [2 RANGE]\n"
    "\t5\n"
    "\t300",
    "ustatusoff": "",
    "ustatus_device": 'CODE=10001\nDISPLAY="Non HP supply in use"\nONLINE=TRUE',
    "ustatus_job": "",
    "ustatus_page": "",
    "ustatus_timed": 'CODE=10001\nDISPLAY="Non HP supply in use"\nONLINE=TRUE',
    "rdymsg": "",
    "opmsg": "",
    "stmsg": "",
    "fsappend": "",
    "fsdelete": "",
    "fsdownload": "",
    "fsinit": "",
    "fsmkdir": "",
    "fsupload": "",
}

echo_command_regex = convert_pjl_command_to_regex("echo")
fsdirlist_command_regex = convert_pjl_command_to_regex("fsdirlist")
fsquery_command_regex = convert_pjl_command_to_regex("fsquery")
info_command_regex = convert_pjl_command_to_regex("info")
path_regex = re.compile(r"\"([^\"]+)\"")


class Printerd(connection):
    """A PJL/PCL based printer daemon"""

    STATE_INIT, STATE_PJL, STATE_PCL = range(3)

    protocol_name = "printerd"
    shared_config_values = [
        "download_dir",
        "pjl_response_regexes",
        "root",
    ]

    def __init__(self, proto="tcp"):
        connection.__init__(self, proto)
        self.download_dir = None
        self.root = None

        self.pjl_response_regexes = []
        self.pjl_responses = dict(pjl_default_responses.items())

        self.state = self.STATE_INIT
        self.pjl_program_delimiter = None
        self.pcl_file_handle = None

    def reply(self, msg):
        """Sends the given message back to the client."""
        msg_lf = f"{msg}\n"
        msg_crlf = msg_lf.replace("\n", "\r\n")

        logger.debug("sending %s", bytes(msg_crlf, "utf-8"))
        self.send(msg_crlf)

    def apply_config(self, config):
        """Applies the given configuration to this daemon"""
        dionaea_config = g_dionaea.config().get("dionaea", {})
        self.download_dir = dionaea_config.get("download.dir")

        if self.download_dir is None:
            raise ServiceConfigError("download_dir not defined")
        if not Path(self.download_dir).is_dir():
            raise ServiceConfigError(
                f"The PCL output directory '{self.download_dir}' is not a directory"
            )
        if not os.access(self.download_dir, os.W_OK):
            raise ServiceConfigError(
                f"Unable to write files in '{self.download_dir}'"
            )

        self.root = config.get("root")

        if self.root is None:
            raise ServiceConfigError("root not defined")
        if not Path(self.root).is_dir():
            raise ServiceConfigError(
                f"The PJL filesystem '{self.root}' is not a directory"
            )
        if not os.access(self.root, os.R_OK):
            raise ServiceConfigError(f"Unable to read files in '{self.root}'")

        self.pjl_responses.update(config.get("pjl_msgs", {}))
        self.pjl_response_regexes = convert_pjl_responses_to_regex(self.pjl_responses)

    def chroot(self, p):
        self.root = p

    def handle_origin(self, parent):
        logger.debug(f"setting download_dir to '{parent.download_dir}' from parent")
        self.download_dir = parent.download_dir

        logger.debug("setting pjl_response_regexes from parent")
        self.pjl_response_regexes = parent.pjl_response_regexes

        logger.debug("setting root from parent")
        self.root = parent.root

    def handle_established(self):
        self.processors()

    def handle_disconnect(self):
        if self.pcl_file_handle is not None:
            self.pcl_file_handle.close()

    def handle_io_in(self, data: bytes) -> int:
        logger.debug("received %s", data.decode(errors="replace"))

        if self.state == self.STATE_INIT:
            if data.startswith(b"\x1bE"):
                logger.debug("entering PCL mode")
                self.state = self.STATE_PCL
            else:
                logger.debug("entering PJL mode")
                self.state = self.STATE_PJL

        if self.state == self.STATE_PJL:
            return self.process_pjl_program(data)
        elif self.state == self.STATE_PCL:
            return self.process_pcl(data)
        return len(data)

    def process_pjl_program(self, program):
        """Parses a PJL program, taking delimiters and chunk-split programs into account.

        If the program starts with a delimiter, it will be removed and be expected in each
        follow up chunk, until it appears. If a previous chunk started with a delimiter,
        but the current chunk doesn't end with one, the last line will be preserved, to
        wait for more data.
        """
        processed_bytes = 0
        reset_delimiter = False

        if self.pjl_program_delimiter is None:
            try:
                program_start = program.index(b"@")
            except ValueError:
                program_start = 0

            if program_start != 0:
                self.pjl_program_delimiter = program[0:program_start]
                program = program[len(self.pjl_program_delimiter) :]
                processed_bytes += len(self.pjl_program_delimiter)

        if self.pjl_program_delimiter:
            if program.endswith(self.pjl_program_delimiter):
                program = program[0 : -len(self.pjl_program_delimiter)]
                processed_bytes += len(self.pjl_program_delimiter)
                reset_delimiter = True
            else:
                program = cut_bytes_before_last_crlf(program)

        if not program.endswith(b"\r\n"):
            program = cut_bytes_before_last_crlf(program)

        lines = program.strip().split(b"\r\n")
        processed_bytes += len(program)

        for line in lines:
            while self.pjl_program_delimiter and line.startswith(
                self.pjl_program_delimiter
            ):
                line = line[len(self.pjl_program_delimiter) :]

            self.process_pjl_line(line)

        if reset_delimiter:
            self.pjl_program_delimiter = None

        return processed_bytes

    def process_pjl_line(self, line):
        """Executes a line of PJL code.

        Static PJL commands, as defined in `pjl_default_responses`, will be sent as is, whereas
        "dynamic" commands like ECHO or FSQUERY will take their arguments into account.

        If no matching command could be found, "?" will be sent.
        """
        for regex, command, response in self.pjl_response_regexes:
            match = regex.match(line)

            if match:
                logger.debug("input matches command '%s'", command)
                self.reply(response)
                return

        echo_match = echo_command_regex.match(line)
        if echo_match:
            command = echo_match.group(0).decode("utf-8")
            self.pjl_ECHO(command)
            return

        fsdirlist_match = fsdirlist_command_regex.match(line)
        if fsdirlist_match:
            arguments = fsdirlist_match.group(1).decode("utf-8")
            self.pjl_FSDIRLIST(arguments)
            return

        fsquery_match = fsquery_command_regex.match(line)
        if fsquery_match:
            arguments = fsquery_match.group(1).decode("utf-8")
            self.pjl_FSQUERY(arguments)
            return

        info_match = info_command_regex.match(line)
        if info_match:
            arguments = info_match.group(1).decode("utf-8")
            self.pjl_INFO(arguments)
            return

        logger.warning("unable to find command for '%s'", str(line))
        self.reply("?")

    def pjl_ECHO(self, command):
        """@PJL ECHO COMMAND"""
        logger.debug("echo %s", command)
        stripped_command = command.strip()
        self.reply(stripped_command)

    def pjl_INFO(self, arguments):
        """@PJL INFO <category>"""
        category = arguments.strip().upper()
        logger.debug("info %s", category)

        if category == "PRODINFO":
            self.reply(
                "@PJL INFO PRODINFO\r\n"
                'PRODUCT NAME="HP LaserJet 4250"\r\n'
                'PRODUCT NUMBER="Q5400A"\r\n'
                'SERIAL NUMBER="CNBRF17839"\r\n'
                'SERVICE ID="21074"\r\n'
                'FIRMWARE DATECODE="20051014"'
            )
        elif category == "ID":
            self.reply('@PJL INFO ID\r\n"HP LaserJet 4250"')
        elif category == "STATUS":
            self.reply(
                '@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY="Ready"\r\nONLINE=TRUE'
            )
        else:
            logger.info("unhandled INFO category: %s", category)
            self.reply("?")

    def extract_path_from_arguments(self, arguments):
        """Extracts a path string from a command's arguments."""
        paths = path_regex.findall(arguments)

        if len(paths) > 0:
            path = paths[0]
            return self.normalize_path(path)

    def normalize_path(self, path):
        """Normalizes the given PJL path to a regular path.

        Example:
            normalize_path(r"0:\\foo\\bar") => "0/foo/bar"
        """
        if ":" not in path:
            path = "0:" + path

        volume, rest = path.split(":", 1)
        path_parts = [volume] + [
            part
            for part in re.split(r"(\\|/)", rest)
            if part.strip() not in ["", "/", "\\"]
            and part.replace(".", " ").strip() != ""
        ]
        full_path = str(Path(*path_parts))

        while "../" in full_path:
            full_path = full_path.replace("../", "")

        return full_path

    def listdir(self, path):
        """Sends the result similar to an `ls` call.

        If the file doesn't exist, "FILEERROR=1" will be sent. If the path is a
        directory, a directory listing will be sent, whereas a file will only yield
        its name and size according to the PJL specification.
        """
        actual_path = str(Path(self.root) / path)

        if not Path(actual_path).exists():
            self.reply("FILEERROR=1")
            return

        if Path(actual_path).is_file():
            stat = Path(actual_path).stat()
            basename = Path(actual_path).name

            self.reply(f"{basename} TYPE=FILE SIZE={stat.st_size}")
        elif Path(actual_path).is_dir():
            directory_entries = sorted([f.name for f in Path(actual_path).iterdir()])

            files = []
            directories = [". TYPE=DIR"]

            if "/" in path:
                directories.append(".. TYPE=DIR")

            for entry in directory_entries:
                entry_path = str(Path(actual_path) / entry)

                if Path(entry_path).is_file():
                    stat = Path(entry_path).stat()
                    files.append(f"{entry} TYPE=FILE SIZE={stat.st_size}")
                elif Path(entry_path).is_dir():
                    directories.append(f"{entry} TYPE=DIR")

            listing = directories + files
            self.reply("\n".join(listing))

    def pjl_FSDIRLIST(self, arguments):
        """@PJL FSDIRLIST NAME="PATH" """
        path = self.extract_path_from_arguments(arguments)
        logger.debug("listdir '%s'", path)
        self.listdir(path)

    def pjl_FSQUERY(self, arguments):
        """@PJL FSQUERY NAME="PATH" """
        path = self.extract_path_from_arguments(arguments)
        logger.debug("fsquery '%s'", path)
        self.listdir(path)

    def process_pcl(self, data):
        """Starts "printing" the given PCL to a new file.

        The file name will be created using the current time, e.g. "print-1547056738.pcl".
        Additionally, an incident "dionaea.modules.python.printer.print" will be created.
        """
        if self.pcl_file_handle is None:
            filename = f"print-{int(time.time())}.pcl"
            path = str(Path(self.download_dir) / filename)
            logger.info("printing to '%s'", path)
            self.pcl_file_handle = open(path, "wb")

            icd = incident("dionaea.modules.python.printer.print")
            icd.con = self
            icd.path = path
            icd.report()

        self.pcl_file_handle.write(data)
        return len(data)
