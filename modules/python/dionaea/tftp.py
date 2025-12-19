# ABOUTME: TFTP server implementation for dionaea honeypot with RFC compliance
# ABOUTME: Supports file downloads (RRQ) and uploads (WRQ) using Construct parser
#
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2006-2009 Michael P. Soulier
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
# SPDX-FileCopyrightText: 2009-2011 Markus Koetter
# SPDX-FileCopyrightText: 2015-2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# The whole logic is taken from tftpy - http://tftpy.sourceforge.net/
# tftpy is licensed using CNRI Python License which is claimed to be incompatible with the GPL
# http://www.gnu.org/philosophy/license-list.html
#
# Nevertheless, the tftpy author Michael P. Soulier
# gave us a non exclusive permission to use his code in
# our gpl project

import tempfile
import struct
import logging
import os
import hashlib
import shutil
from typing import Any
from urllib import parse

from construct import (
    Struct, Int16ub, CString, GreedyRange,
    Computed, Switch, this, Pass, GreedyBytes,
    Adapter, ConstructError, Default
)

from dionaea import IHandlerLoader, ServiceLoader
from dionaea.core import connection, ihandler, g_dionaea, incident
from dionaea.exception import ServiceConfigError

DEF_BLKSIZE = 512
MIN_BLKSIZE = 8
MAX_BLKSIZE = 65464

# Upload limits (configurable)
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB default
MIN_FREE_DISK_SPACE = 1024 * 1024 * 1024  # 1GB minimum free space

logger = logging.getLogger('tftp')
logger.setLevel(logging.INFO)


# ============================================================================
# Construct-based TFTP Parser (replaces manual parsing)
# ============================================================================

# TFTP Opcodes
OPCODE_RRQ = 1   # Read request
OPCODE_WRQ = 2   # Write request
OPCODE_DATA = 3  # Data packet
OPCODE_ACK = 4   # Acknowledgment
OPCODE_ERROR = 5 # Error
OPCODE_OACK = 6  # Option acknowledgment


class TFTPOptionsAdapter(Adapter):
    """Adapter to convert TFTP options to/from dictionary"""
    def _decode(self, obj: list[str], context: Any, path: Any) -> dict[str, str]:
        if not obj:
            return {}
        result: dict[str, str] = {}
        try:
            for i in range(0, len(obj), 2):
                if i + 1 < len(obj):
                    key = obj[i].lower()
                    value = obj[i + 1]
                    result[key] = value
                else:
                    logger.debug(f"Odd number of option items, ignoring last: {obj[i]}")
        except Exception as e:
            logger.debug(f"Error parsing TFTP options: {e}")
            return {}
        return result

    def _encode(self, obj: dict[str, Any], context: Any, path: Any) -> list[str]:
        result: list[str] = []
        for key, value in obj.items():
            result.append(key)
            result.append(str(value))
        return result


# TFTP packet structure definitions
TFTPOptions = TFTPOptionsAdapter(GreedyRange(CString("utf8")))

TFTPRequestPacket = Struct(
    "filename" / Default(CString("utf8"), ""),
    "mode" / Default(CString("utf8"), "octet"),
    "options" / Default(TFTPOptions, {})
)

TFTPDataPacket = Struct(
    "block_number" / Int16ub,
    "data" / GreedyBytes
)

TFTPAckPacket = Struct(
    "block_number" / Int16ub
)

TFTPErrorPacket = Struct(
    "error_code" / Int16ub,
    "error_msg" / Default(CString("utf8"), "")
)

TFTPOackPacket = Struct(
    "options" / Default(TFTPOptions, {})
)


def _opcode_to_name(opcode: int) -> str:
    """Convert opcode to human-readable name"""
    names = {
        OPCODE_RRQ: "RRQ",
        OPCODE_WRQ: "WRQ",
        OPCODE_DATA: "DATA",
        OPCODE_ACK: "ACK",
        OPCODE_ERROR: "ERROR",
        OPCODE_OACK: "OACK"
    }
    return names.get(opcode, f"UNKNOWN({opcode})")


# Main TFTP packet structure
TFTPPacketStruct = Struct(
    "opcode" / Int16ub,
    "payload" / Switch(
        this.opcode,
        {
            OPCODE_RRQ: TFTPRequestPacket,
            OPCODE_WRQ: TFTPRequestPacket,
            OPCODE_DATA: TFTPDataPacket,
            OPCODE_ACK: TFTPAckPacket,
            OPCODE_ERROR: TFTPErrorPacket,
            OPCODE_OACK: TFTPOackPacket,
        },
        default=Pass
    ),
    "packet_type" / Computed(lambda ctx: _opcode_to_name(ctx.opcode))
)


def parse_tftp_packet(data: bytes) -> dict | None:
    """
    Parse TFTP packet using Construct.
    Returns dictionary with parsed fields, or None if parsing fails.
    """
    try:
        packet = TFTPPacketStruct.parse(data)
        return packet
    except ConstructError as e:
        logger.debug(f"Failed to parse TFTP packet: {e}")
        return None
    except Exception as e:
        logger.warning(f"Unexpected error parsing TFTP packet: {e}")
        return None


# ============================================================================
# End of Construct Parser
# ============================================================================


class TFTPDownloadHandlerLoader(IHandlerLoader):
    name = "tftp_download"

    @classmethod
    def start(cls, config: dict[str, Any] | None = None) -> 'tftpdownloadhandler':
        return tftpdownloadhandler("dionaea.download.offer")


class TFTPService(ServiceLoader):
    name = "tftp"

    @classmethod
    def start(cls, addr: str, iface: str | None = None, config: dict[str, Any] | None = None) -> 'TftpServer':
        daemon = TftpServer()
        if config is not None:
            try:
                daemon.apply_config(config)
            except ServiceConfigError as e:
                logger.error(e.msg, *e.args)
        daemon.bind(addr, 69, iface=iface)
        return daemon


def tftpassert(condition: Any, msg: str) -> None:
    """This function is a simple utility that will check the condition
    passed for a false state. If it finds one, it throws a TftpException
    with the message passed. This just makes the code throughout cleaner
    by refactoring."""
    if not condition:
        raise TftpException(msg)

class TftpException(Exception):
    """This class is the parent class of all exceptions regarding the handling
    of the TFTP protocol."""
    pass


class TftpErrors:
    """This class is a convenience for defining the common tftp error codes,
    and making them more readable in the code."""
    NotDefined = 0
    FileNotFound = 1
    AccessViolation = 2
    DiskFull = 3
    IllegalTftpOp = 4
    UnknownTID = 5
    FileAlreadyExists = 6
    NoSuchUser = 7
    FailedNegotiation = 8


class TftpState:
    """This class represents a particular state for a TFTP Session. It encapsulates a
    state, kind of like an enum. The states mean the following:
    nil - Client/Server - Session not yet established
    rrq - Client - Just sent RRQ in a download, waiting for response
          Server - Just received an RRQ
    wrq - Client - Just sent WRQ in an upload, waiting for response
          Server - Just received a WRQ
    dat - Client/Server - Transferring data
    oack - Client - Just received oack
           Server - Just sent OACK
    ack - Client - Acknowledged oack, awaiting response
          Server - Just received ACK to OACK
    err - Client/Server - Fatal problems, giving up
    fin - Client/Server - Transfer completed
    """
    states = ['nil',
              'rrq',
              'wrq',
              'dat',
              'oack',
              'ack',
              'err',
              'fin']

    def __init__(self, state: str = 'nil') -> None:
        self.state = state

    def getState(self) -> str:
        return self.__state

    def setState(self, state: str) -> None:
        if state in TftpState.states:
            self.__state = state

    state = property(getState, setState)

class TftpSession(connection):
    """This class is the base class for the tftp client and server. Any shared
    code should be in this class."""

    def __init__(self) -> None:
        """Class constructor. Note that the state property must be a TftpState
        object."""
        self.options: dict[str, Any] | None = None
        self.state: TftpState = TftpState()
        self.dups: int = 0
        self.errors: int = 0
        connection.__init__(self, 'udp')

#    def __del__(self):
#        print('__del__' + str(self))


    def senderror(self, errorcode: int) -> None:
        """This method uses the socket passed, and uses the errorcode, address
        and port to compose and send an error packet."""
        try:
            logger.debug("In senderror, being asked to send error %d to %s:%i", errorcode, self.remote.host, self.remote.port)
        except (ReferenceError, AttributeError):
            logger.debug("In senderror, being asked to send error %d (connection closed)", errorcode)
        errpkt = TftpPacketERR()
        errpkt.errorcode = errorcode
        self.send(errpkt.encode().buffer)

class TftpPacketWithOptions:
    """This class exists to permit some TftpPacket subclasses to share code
    regarding options handling. It does not inherit from TftpPacket, as the
    goal is just to share code here, and not cause diamond inheritance."""

    def __init__(self) -> None:
        self.options: list | dict[str, str] = []

    def setoptions(self, options: dict[str, Any]) -> None:
        logger.debug("in TftpPacketWithOptions.setoptions")
        logger.debug("options: %s", str(options))
        myoptions: dict[str, str] = {}
        for key in options:
            newkey = str(key)
            myoptions[newkey] = str(options[key])
            logger.debug("populated myoptions with %s = %s", newkey, myoptions[newkey])

        logger.debug("setting options hash to: " + str(myoptions))
        self._options = myoptions

    def getoptions(self) -> dict[str, str]:
        logger.debug("in TftpPacketWithOptions.getoptions")
        return self._options

    # Set up getter and setter on options to ensure that they are the proper
    # type. They should always be strings, but we don't need to force the
    # client to necessarily enter strings if we can avoid it.
    options = property(getoptions, setoptions)


class TftpPacket:
    """This class is the parent class of all tftp packet classes. It is an
    abstract class, providing an interface, and should not be instantiated
    directly."""
    def __init__(self) -> None:
        self.opcode: int = 0
        self.buffer: bytes = b""

    def encode(self) -> 'TftpPacket':
        """The encode method of a TftpPacket takes keyword arguments specific
        to the type of packet, and packs an appropriate buffer in network-byte
        order suitable for sending over the wire.

        This is an abstract method."""
        raise NotImplementedError("Abstract method")


class TftpPacketInitial(TftpPacket, TftpPacketWithOptions):
    """This class is a common parent class for the RRQ and WRQ packets, as
    they share quite a bit of code."""
    def __init__(self) -> None:
        TftpPacket.__init__(self)
        TftpPacketWithOptions.__init__(self)
        self.filename: str | None = None
        self.mode: str | None = None

    def encode(self) -> 'TftpPacketInitial':
        """Encode the packet's buffer from the instance variables."""
        tftpassert(self.filename, "filename required in initial packet")
        tftpassert(self.mode, "mode required in initial packet")
        assert self.filename is not None  # For mypy
        assert self.mode is not None  # For mypy

        ptype = None
        if self.opcode == 1:
            ptype = "RRQ"
        else:
            ptype = "WRQ"
        logger.debug("Encoding %s packet, filename = %s, mode = %s"
                     % (ptype, self.filename, self.mode))
        for key in self.options:
            logger.debug(f"    Option {key} = {self.options[key]}")

        format = "!H"
        format += "%dsx" % len(self.filename)
        if self.mode == "octet":
            format += "5sx"
        else:
            raise AssertionError("Unsupported mode: %s" % self.mode)
        # Add options.
        options_list = []
        if len(self.options.keys()) > 0:
            logger.debug("there are options to encode")
            for key in self.options:
                # Populate the option name
                format += "%dsx" % len(key)
                options_list.append(key.encode("utf-8"))
                # Populate the option value
                format += "%dsx" % len(str(self.options[key]))
                options_list.append(str(self.options[key]).encode("utf-8"))

        logger.debug("format is %s" % format)
        logger.debug("options_list is %s" % options_list)
        logger.debug("size of struct is %d" % struct.calcsize(format))

        self.buffer = struct.pack(format,
                                  self.opcode,
                                  self.filename.encode('utf-8'),
                                  self.mode.encode('utf-8'),
                                  *options_list)

        logger.debug("buffer is " + repr(self.buffer))
        return self


class TftpPacketRRQ(TftpPacketInitial):
    """
        2 bytes    string   1 byte     string   1 byte
        -----------------------------------------------
RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
WRQ     -----------------------------------------------
    """
    def __init__(self) -> None:
        TftpPacketInitial.__init__(self)
        self.opcode = 1

    def __str__(self) -> str:
        s = 'RRQ packet: filename = %s' % self.filename
        s += ' mode = %s' % self.mode
        if self.options:
            s += '\n    options = %s' % self.options
        return s

class TftpPacketWRQ(TftpPacketInitial):
    """
        2 bytes    string   1 byte     string   1 byte
        -----------------------------------------------
RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
WRQ     -----------------------------------------------
    """
    def __init__(self) -> None:
        TftpPacketInitial.__init__(self)
        self.opcode = 2

    def __str__(self) -> str:
        s = 'WRQ packet: filename = %s' % self.filename
        s += ' mode = %s' % self.mode
        if self.options:
            s += '\n    options = %s' % self.options
        return s

class TftpPacketDAT(TftpPacket):
    """
        2 bytes    2 bytes       n bytes
        ---------------------------------
DATA  | 03    |   Block #  |    Data    |
        ---------------------------------
    """
    def __init__(self) -> None:
        TftpPacket.__init__(self)
        self.opcode: int = 3
        self.blocknumber: int = 0
        self.data: bytes | None = None

    def __str__(self) -> str:
        s = 'DAT packet: block %s' % self.blocknumber
        if self.data:
            s += '\n    data: %d bytes' % len(self.data)
        return s

    def encode(self) -> 'TftpPacketDAT':
        """Encode the DAT packet. This method populates self.buffer, and
        returns self for easy method chaining."""
        assert self.data is not None  # For mypy
        if len(self.data) == 0:
            logger.debug("Encoding an empty DAT packet")
        format = "!HH%ds" % len(self.data)
        self.buffer = struct.pack(format,
                                  self.opcode,
                                  self.blocknumber,
                                  self.data)
        return self


class TftpPacketACK(TftpPacket):
    """
        2 bytes    2 bytes
        -------------------
ACK   | 04    |   Block #  |
        --------------------
    """
    def __init__(self) -> None:
        TftpPacket.__init__(self)
        self.opcode: int = 4
        self.blocknumber: int = 0

    def __str__(self) -> str:
        return 'ACK packet: block %d' % self.blocknumber

    def encode(self) -> 'TftpPacketACK':
        logger.debug("encoding ACK: opcode = %d, block = %d"
                     % (self.opcode, self.blocknumber))
        self.buffer = struct.pack("!HH", self.opcode, self.blocknumber)
        return self


class TftpPacketERR(TftpPacket):
    """
        2 bytes  2 bytes        string    1 byte
        ----------------------------------------
ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
        ----------------------------------------
    Error Codes

    Value     Meaning

    0         Not defined, see error message (if any).
    1         File not found.
    2         Access violation.
    3         Disk full or allocation exceeded.
    4         Illegal TFTP operation.
    5         Unknown transfer ID.
    6         File already exists.
    7         No such user.
    8         Failed to negotiate options
    """
    def __init__(self) -> None:
        TftpPacket.__init__(self)
        self.opcode: int = 5
        self.errorcode: int = 0
        self.errmsg: str | None = None
        # FIXME - integrate in TftpErrors references?
        self.errmsgs: dict[int, str] = {
            1: "File not found",
            2: "Access violation",
            3: "Disk full or allocation exceeded",
            4: "Illegal TFTP operation",
            5: "Unknown transfer ID",
            6: "File already exists",
            7: "No such user",
            8: "Failed to negotiate options"
        }

    def __str__(self) -> str:
        s = 'ERR packet: errorcode = %d' % self.errorcode
        s += '\n    msg = %s' % self.errmsgs.get(self.errorcode, '')
        return s

    def encode(self) -> 'TftpPacketERR':
        """Encode the DAT packet based on instance variables, populating
        self.buffer, returning self."""
        format = "!HH%dsx" % len(self.errmsgs[self.errorcode])
        logger.debug("encoding ERR packet with format %s" % format)
        self.buffer = struct.pack(format,
                                  self.opcode,
                                  self.errorcode,
                                  self.errmsgs[self.errorcode].encode("utf-8"))
        return self


class TftpPacketOACK(TftpPacket, TftpPacketWithOptions):
    """
    #  +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
    #  |  opc  |  opt1  | 0 | value1 | 0 |  optN  | 0 | valueN | 0 |
    #  +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
    """
    def __init__(self) -> None:
        TftpPacket.__init__(self)
        TftpPacketWithOptions.__init__(self)
        self.opcode: int = 6

    def __str__(self) -> str:
        return 'OACK packet:\n    options = %s' % self.options

    def encode(self) -> 'TftpPacketOACK':
        format = "!H" # opcode
        options_list: list[bytes] = []
        logger.debug("in TftpPacketOACK.encode")
        for key in self.options:
            logger.debug("looping on option key %s" % key)
            logger.debug("value is %s" % self.options[key])
            format += "%dsx" % len(key)
            format += "%dsx" % len(self.options[key])
            options_list.append(key.encode("utf-8"))
            options_list.append(self.options[key].encode("utf-8"))
        self.buffer = struct.pack(format, self.opcode, *options_list)
        return self

    def match_options(self, options: dict[str, Any]) -> bool:
        """This method takes a set of options, and tries to match them with
        its own. It can accept some changes in those options from the server as
        part of a negotiation. Changed or unchanged, it will return a dict of
        the options so that the session can update itself to the negotiated
        options."""
        for name in self.options:
            if name in options:
                if name == 'blksize':
                    # We can accept anything between the min and max values.
                    size = int(self.options[name])
                    if size >= MIN_BLKSIZE and size <= MAX_BLKSIZE:
                        logger.debug("negotiated blksize of %d bytes" % size)
                        options[name] = size
                else:
                    raise TftpException("Unsupported option: %s" % name)
        return True


class TftpPacketFactory:
    """This class generates TftpPacket objects. It is responsible for parsing
    raw buffers off of the wire and returning objects representing them, via
    the parse() method."""
    def __init__(self) -> None:
        self.classes: dict[int, type] = {
            1: TftpPacketRRQ,
            2: TftpPacketWRQ,
            3: TftpPacketDAT,
            4: TftpPacketACK,
            5: TftpPacketERR,
            6: TftpPacketOACK
        }

    def parse(self, buffer: bytes) -> TftpPacket:
        """This method is used to parse an existing datagram into its
        corresponding TftpPacket object. The buffer is the raw bytes off of
        the network."""
        logger.debug("parsing a %d byte packet" % len(buffer))

        # Use construct-based parser
        result = parse_tftp_packet(buffer)
        if result is None:
            raise TftpException("Failed to parse TFTP packet")

        opcode = result['opcode']
        logger.debug("opcode is %d" % opcode)

        # Create packet object
        packet = self.__create(opcode)
        packet.buffer = buffer

        # Populate packet from parsed result
        packet_type = result['packet_type']
        payload = result['payload']

        # Check for unknown packet types
        if 'UNKNOWN' in packet_type or payload is None:
            raise TftpException(f"Unknown or malformed TFTP packet: {packet_type}")

        if packet_type in ('RRQ', 'WRQ'):
            packet.filename = payload['filename']
            packet.mode = payload['mode']
            packet.options = payload['options']
        elif packet_type == 'DATA':
            packet.blocknumber = payload['block_number']
            packet.data = payload['data']
        elif packet_type == 'ACK':
            packet.blocknumber = payload['block_number']
        elif packet_type == 'ERROR':
            packet.errorcode = payload['error_code']
            packet.errmsg = payload['error_msg']
        elif packet_type == 'OACK':
            packet.options = payload['options']

        return packet

    def __create(self, opcode: int) -> TftpPacket:
        """This method returns the appropriate class object corresponding to
        the passed opcode."""
        tftpassert( opcode in self.classes,
                    "Unsupported opcode: %d" % opcode)
        packet: TftpPacket
        if opcode == 1:
            packet = TftpPacketRRQ()
        elif opcode == 2:
            packet = TftpPacketWRQ()
        elif opcode == 3:
            packet = TftpPacketDAT()
        elif opcode == 4:
            packet = TftpPacketACK()
        elif opcode == 5:
            packet = TftpPacketERR()
        elif opcode == 6:
            packet = TftpPacketOACK()
        else:
            raise TftpException("Unsupported opcode: %d" % opcode)

        logger.debug("packet is %s" % packet)
        return packet


class TftpServerHandler(TftpSession):
    def __init__(self, state: Any = None, root: str | None = None, localhost: str | None = None,
                 remotehost: str | None = None, remoteport: int | None = None, packet: Any = None) -> None:
        TftpSession.__init__(self)
        self.bind(localhost, 0)
        self.connect(remotehost, remoteport)
        self.packet: Any = packet
        self.state: Any = state
        self.root: str | None = root
        self.mode: str | None = None
        self.filename: str | None = None
        self.original_filename: str | None = None  # Store client's requested filename
        self.options: dict[str, Any] = {'blksize': DEF_BLKSIZE}
        self.blocknumber: int = 0
        self.buffer: bytes = b""
        self.fileobj: Any = None
        self.timeouts.idle = 3
        self.timeouts.sustain = 120
        # Upload tracking
        self.bytes_uploaded: int = 0
        self.upload_hash: Any = hashlib.sha256()  # For computing file hash during upload

    def handle_timeout_idle(self) -> bool:
        return False

    def handle_timeout_sustain(self) -> bool:
        return False

    def _handle_rrq(self, recvpkt: Any, data: bytes) -> int:
        """Handle RRQ (Read Request) packet."""
        assert self.root is not None  # Root must be set for handler
        logger.debug("Handler %s received RRQ packet" % self)
        logger.debug("Requested file is %s, mode is %s" %
                     (recvpkt.filename, recvpkt.mode))

        # Accept both octet (binary) and netascii (text) modes
        # For honeypot purposes, we serve raw bytes in both cases
        if recvpkt.mode not in ['octet', 'netascii']:
            self.senderror(TftpErrors.IllegalTftpOp)
            logger.warn("Unsupported mode: %s" % recvpkt.mode)
            self.close()
            return len(data)

        if self.state.state == 'rrq':
            logger.debug("Received RRQ. Composing response.")
            self.filename = self.root + os.sep + recvpkt.filename
            logger.debug("The path to the desired file is %s" %
                         self.filename)
            self.filename = os.path.abspath(self.filename)
            logger.debug("The absolute path is %s" % self.filename)
            # Security check. Make sure it's prefixed by the tftproot.
            if self.filename.startswith(os.path.abspath(self.root)):
                logger.debug("The path appears to be safe: %s" %
                             self.filename)
            else:
                self.errors += 1
                self.senderror(TftpErrors.AccessViolation)
                logger.warn("Insecure path: %s" % self.filename)
                self.close()
                return len(data)

            # Does the file exist?
            if os.path.exists(self.filename):
                logger.debug("File %s exists." % self.filename)

                # Check options
                if 'blksize' in recvpkt.options:
                    logger.debug("RRQ includes a blksize option")
                    blksize = int(recvpkt.options['blksize'])
                    del recvpkt.options['blksize']
                    if blksize >= MIN_BLKSIZE and blksize <= MAX_BLKSIZE:
                        logger.info("Client requested blksize = %d"
                                    % blksize)
                        self.options['blksize'] = blksize
                    else:
                        logger.warning("Client %s requested invalid "
                                       "blocksize %d, responding with default"
                                       % (self.remote.host, blksize))
                        self.options['blksize'] = DEF_BLKSIZE

                if 'tsize' in recvpkt.options:
                    logger.info('RRQ includes tsize option')
                    self.options['tsize'] = os.stat(self.filename).st_size
                    del recvpkt.options['tsize']

                if 'rollover' in recvpkt.options:
                    rollover_val = recvpkt.options['rollover']
                    logger.debug('RRQ includes rollover option: %s' % rollover_val)
                    # We support block number rollover (see send_dat)
                    # Only acknowledge non-standard rollover values in OACK
                    # rollover:0 is standard TFTP (no rollover), doesn't need OACK
                    if rollover_val != '0':
                        logger.debug('Non-zero rollover value, will acknowledge in OACK')
                        self.options['rollover'] = rollover_val
                    else:
                        logger.debug('rollover:0 is standard behavior, no OACK needed')
                    del recvpkt.options['rollover']

                if len(list(recvpkt.options.keys())) > 0:
                    logger.warning("Client %s requested unsupported options: %s"
                                   % (self.remote.host, recvpkt.options))

                if self.options['blksize'] != DEF_BLKSIZE or 'tsize' in self.options or 'rollover' in self.options:
                    logger.info("Options requested, sending OACK")
                    self.send_oack()
                else:
                    logger.debug("Client %s requested no options."
                                 % self.remote.host)
                    self.start_download()

            else:
                logger.warn("Requested file %s does not exist." %
                            self.filename)
                self.senderror(TftpErrors.FileNotFound)
                self.close()
                return len(data)

        else:
            # We're receiving an RRQ when we're not expecting one.
            logger.warn("Received an RRQ in handler %s "
                        "but we're in state %s" % (self.remote.host, self.state))
            self.errors += 1

        return len(data)

    def _handle_wrq(self, recvpkt: Any, data: bytes) -> int:
        """Handle WRQ (Write Request) packet."""
        assert self.root is not None  # Root must be set for handler
        logger.info(f"Handler {self} received WRQ packet in state {self.state.state}")
        logger.info("Client wants to upload file %s, mode is %s" %
                    (recvpkt.filename, recvpkt.mode))

        # Accept both octet (binary) and netascii (text) modes
        # For honeypot purposes, we save raw bytes in both cases
        if recvpkt.mode not in ['octet', 'netascii']:
            self.senderror(TftpErrors.IllegalTftpOp)
            logger.warn("Unsupported mode: %s" % recvpkt.mode)
            self.close()
            return len(data)

        if self.state.state == 'wrq':
            logger.debug("Received WRQ. Preparing to receive file.")

            # Store original filename for logging
            self.original_filename = recvpkt.filename

            # Check disk space
            upload_dir = self.root + os.sep + "uploads"
            if os.path.exists(upload_dir):
                free_space = shutil.disk_usage(upload_dir).free
                if free_space < MIN_FREE_DISK_SPACE:
                    logger.error("Insufficient disk space: %d bytes free" % free_space)
                    self.senderror(TftpErrors.DiskFull)
                    self.close()
                    return len(data)

            # Create uploads directory if it doesn't exist
            if not os.path.exists(upload_dir):
                try:
                    os.makedirs(upload_dir)
                except OSError as e:
                    logger.error("Failed to create uploads directory: %s" % e)
                    self.senderror(TftpErrors.AccessViolation)
                    self.close()
                    return len(data)

            # We'll use a temporary filename until we compute the final hash
            # For now, create a temp file to write to
            safe_filename = os.path.basename(recvpkt.filename)
            temp_filename = os.path.join(upload_dir, ".tmp_" + safe_filename)
            self.filename = temp_filename
            logger.debug("Will save uploaded file to temporary location: %s" % self.filename)

            # Security check - make sure it's in uploads directory
            self.filename = os.path.abspath(self.filename)
            if not self.filename.startswith(os.path.abspath(upload_dir)):
                logger.warn("Insecure upload path: %s" % self.filename)
                self.senderror(TftpErrors.AccessViolation)
                self.close()
                return len(data)

            # Handle options
            if 'blksize' in recvpkt.options:
                logger.debug("WRQ includes a blksize option")
                blksize = int(recvpkt.options['blksize'])
                del recvpkt.options['blksize']
                if blksize >= MIN_BLKSIZE and blksize <= MAX_BLKSIZE:
                    logger.info("Client requested blksize = %d" % blksize)
                    self.options['blksize'] = blksize
                else:
                    logger.warning("Client %s requested invalid blocksize %d, using default"
                                   % (self.remote.host, blksize))
                    self.options['blksize'] = DEF_BLKSIZE

            if 'tsize' in recvpkt.options:
                tsize_val = recvpkt.options['tsize']
                logger.info('WRQ includes tsize option: %s bytes' % tsize_val)
                # Check if upload would exceed maximum size
                if tsize_val != '0':
                    try:
                        size = int(tsize_val)
                        if size > MAX_UPLOAD_SIZE:
                            logger.error("Upload size %d exceeds maximum %d" % (size, MAX_UPLOAD_SIZE))
                            self.senderror(TftpErrors.DiskFull)
                            self.close()
                            return len(data)
                        logger.debug('Non-zero tsize, will acknowledge in OACK')
                        self.options['tsize'] = tsize_val
                    except ValueError:
                        logger.warning("Invalid tsize value: %s" % tsize_val)
                else:
                    logger.debug('tsize:0 in WRQ is meaningless, ignoring')
                del recvpkt.options['tsize']

            if 'rollover' in recvpkt.options:
                rollover_val = recvpkt.options['rollover']
                logger.debug('WRQ includes rollover option: %s' % rollover_val)
                # We support block number rollover
                # Only acknowledge non-standard rollover values in OACK
                # rollover:0 is standard TFTP (no rollover), doesn't need OACK
                if rollover_val != '0':
                    logger.debug('Non-zero rollover value, will acknowledge in OACK')
                    self.options['rollover'] = rollover_val
                else:
                    logger.debug('rollover:0 is standard behavior, no OACK needed')
                del recvpkt.options['rollover']

            if len(list(recvpkt.options.keys())) > 0:
                logger.warning("Client %s requested unsupported options: %s"
                               % (self.remote.host, recvpkt.options))

            # Open file for writing
            try:
                self.fileobj = open(self.filename, "wb")
            except OSError as e:
                logger.error("Failed to open file for writing: %s" % e)
                self.senderror(TftpErrors.AccessViolation)
                self.close()
                return len(data)

            # Send OACK only if we negotiated options beyond defaults
            # Don't send OACK with just default values - confuses clients
            has_negotiated_options = (
                self.options.get('blksize', DEF_BLKSIZE) != DEF_BLKSIZE or
                'rollover' in self.options or
                'tsize' in self.options
            )

            if has_negotiated_options:
                logger.info("WRQ: Options negotiated, sending OACK: %s" % self.options)
                self.send_oack()
            else:
                logger.info("WRQ: No options to negotiate, sending ACK 0 to start upload")
                self.send_ack(0)
                self.state.state = 'dat'
                logger.info("WRQ: ACK 0 sent, state now 'dat', ready to receive DATA")
        else:
            logger.warn("Received WRQ in unexpected state %s" % self.state.state)
            self.errors += 1

        return len(data)

    def _handle_ack(self, recvpkt: Any, data: bytes) -> int:
        """Handle ACK packet."""
        logger.debug("Received an ACK from the client.")
        if recvpkt.blocknumber == 0 and self.state.state == 'oack':
            logger.debug(
                "Received ACK with 0 blocknumber, starting download")
            self.start_download()
        else:
            if self.state.state == 'dat' or self.state.state == 'fin':
                if self.blocknumber == recvpkt.blocknumber:
                    logger.debug("Received ACK for block %d"
                                 % recvpkt.blocknumber)
                    if self.state.state == 'fin':
                        self.close()
                    else:
                        self.send_dat()
                elif recvpkt.blocknumber < self.blocknumber:
                    # Don't resend a DAT due to an old ACK. Fixes the
                    # sorceror's apprentice problem.
                    logger.warn("Received old ACK for block number %d"
                                % recvpkt.blocknumber)
                else:
                    logger.warn("Received ACK for block number "
                                "%d, apparently from the future"
                                % recvpkt.blocknumber)
            else:
                logger.warn("Received ACK with block number %d "
                            "while in state %s"
                            % (recvpkt.blocknumber,
                                self.state.state))

        return len(data)

    def _handle_data(self, recvpkt: Any, data: bytes) -> int:
        """Handle DATA packet (client uploading to us)."""
        assert self.filename is not None  # Filename must be set during WRQ
        if self.state.state not in ['dat', 'oack', 'fin']:
            logger.warn("Received DATA packet in unexpected state %s" % self.state.state)
            return len(data)

        logger.debug("Received DATA packet %d from client" % recvpkt.blocknumber)

        # Handle ACK to OACK transition
        if self.state.state == 'oack':
            logger.debug("Transitioning from oack to dat state")
            self.state.state = 'dat'
            self.blocknumber = 0

        # Check if this is the expected block
        expected_block = self.blocknumber + 1
        if expected_block > 65535:
            expected_block = 0

        if recvpkt.blocknumber == expected_block:
            # Check upload size limit
            if self.bytes_uploaded + len(recvpkt.data) > MAX_UPLOAD_SIZE:
                logger.error("Upload exceeds maximum size of %d bytes" % MAX_UPLOAD_SIZE)
                self.senderror(TftpErrors.DiskFull)
                if self.fileobj:
                    self.fileobj.close()
                    # Clean up temp file
                    try:
                        os.unlink(self.filename)
                    except OSError:
                        pass
                self.close()
                return len(data)

            # Write data to file and update hash
            try:
                self.fileobj.write(recvpkt.data)
                self.upload_hash.update(recvpkt.data)
                self.bytes_uploaded += len(recvpkt.data)
                self.blocknumber = recvpkt.blocknumber
                logger.debug("Wrote %d bytes to file, block %d (total: %d bytes)" %
                             (len(recvpkt.data), self.blocknumber, self.bytes_uploaded))
            except OSError as e:
                logger.error("Failed to write to file: %s" % e)
                self.senderror(TftpErrors.AccessViolation)
                self.close()
                return len(data)

            # Send ACK
            self.send_ack(self.blocknumber)

            # Check if this was the last packet (less than blksize)
            if len(recvpkt.data) < int(self.options['blksize']):
                logger.info("Upload complete: %s (%d blocks, %d bytes total)" %
                            (self.filename, self.blocknumber, self.bytes_uploaded))
                self.fileobj.close()

                # Compute final hash
                file_hash = self.upload_hash.hexdigest()
                logger.info("Upload SHA256: %s" % file_hash)

                # Determine final filename based on hash
                upload_dir = os.path.dirname(self.filename)
                hash_filename = os.path.join(upload_dir, file_hash)

                # Check if file with this hash already exists
                if os.path.exists(hash_filename):
                    logger.info("File with hash %s already exists, discarding duplicate" % file_hash)
                    # Remove temp file
                    try:
                        os.unlink(self.filename)
                    except OSError as e:
                        logger.warning("Failed to remove temp file: %s" % e)
                    final_path = hash_filename
                else:
                    # Rename temp file to hash
                    try:
                        os.rename(self.filename, hash_filename)
                        logger.info(f"Renamed {self.filename} to {hash_filename}")
                        final_path = hash_filename
                    except OSError as e:
                        logger.error("Failed to rename temp file: %s" % e)
                        final_path = self.filename

                # Create incident for upload
                icd = incident("dionaea.upload.complete")
                icd.path = final_path
                icd.con = self
                icd.url = "tftp://{}/{}".format(self.local.host, self.original_filename or "unknown")
                # Add custom fields for hash and original filename
                icd.sha256 = file_hash
                icd.origin_filename = self.original_filename or os.path.basename(final_path)
                icd.report()

                # Set state to 'fin' instead of closing immediately
                # This allows final ACK to be transmitted and handles retransmissions
                # Connection will close via idle timeout (3 seconds)
                self.state.state = 'fin'
                logger.debug("Upload finished, state set to 'fin', waiting for idle timeout")

        elif recvpkt.blocknumber < expected_block:
            logger.warn("Received old DATA block %d, expected %d" %
                        (recvpkt.blocknumber, expected_block))
            # Resend ACK for old block
            self.send_ack(recvpkt.blocknumber)
        else:
            logger.warn("Received DATA block %d from future, expected %d" %
                        (recvpkt.blocknumber, expected_block))

        return len(data)

    def handle_io_in(self, data: bytes) -> int:
        """This method informs a handler instance that it has data waiting on
        its socket that it must read and process.

        Dispatches to packet-specific handlers for cleaner code organization.
        """
        recvpkt = self.packet.parse(data)

        # Dispatch to appropriate handler based on packet type
        if isinstance(recvpkt, TftpPacketRRQ):
            return self._handle_rrq(recvpkt, data)

        elif isinstance(recvpkt, TftpPacketWRQ):
            return self._handle_wrq(recvpkt, data)

        elif isinstance(recvpkt, TftpPacketACK):
            return self._handle_ack(recvpkt, data)

        elif isinstance(recvpkt, TftpPacketDAT):
            return self._handle_data(recvpkt, data)

        elif isinstance(recvpkt, TftpPacketERR):
            logger.warn("Received error packet from client: %s" % recvpkt)
            self.state.state = 'err'
            logger.warn("Received error from client")
            self.close()
            return len(data)

        else:
            logger.warn("Received unexpected packet type %s" % recvpkt)
            self.senderror(TftpErrors.IllegalTftpOp)
            logger.warn("Invalid packet received")
            self.close()
            return len(data)

        return len(data)

    def start_download(self) -> None:
        """This method opens self.filename, stores the resulting file object
        in self.fileobj, and calls send_dat()."""
        assert self.filename is not None  # Filename set during RRQ handling
        self.state.state = 'dat'
        self.fileobj = open(self.filename, "rb")
        self.send_dat()

    def send_dat(self, resend: bool = False) -> None:
        """This method reads sends a DAT packet based on what is in self.buffer."""
        if not resend:
            blksize = int(self.options['blksize'])
            self.buffer = self.fileobj.read(blksize)
            logger.debug("Read %d bytes into buffer" % len(self.buffer))
            if len(self.buffer) < blksize:
                logger.info("Reached EOF on file %s" % self.filename)
                self.state.state = 'fin'
            self.blocknumber += 1
            if self.blocknumber > 65535:
                logger.debug("Blocknumber rolled over to zero")
                self.blocknumber = 0
        else:
            logger.warn("Resending block number %d" % self.blocknumber)
        dat = TftpPacketDAT()
        dat.data = self.buffer
        dat.blocknumber = self.blocknumber
        logger.debug("Sending DAT packet %d" % self.blocknumber)
        self.send(dat.encode().buffer)


    # FIXME - should these be factored-out into the session class?
    def send_oack(self) -> None:
        """This method sends an OACK packet based on current params."""
        logger.debug("Composing and sending OACK packet")
        oack = TftpPacketOACK()
        # Only send options that differ from defaults
        negotiated_opts: dict[str, str] = {}
        for key, value in self.options.items():
            if key == 'blksize' and value == DEF_BLKSIZE:
                # Skip default blksize unless explicitly negotiated
                continue
            negotiated_opts[key] = str(value)
        oack.options = negotiated_opts
        logger.info("Sending OACK with options: %s" % negotiated_opts)
        self.send(oack.encode().buffer)
        self.state.state = 'oack'
        logger.debug("state %s" % self.state.state)

    def send_ack(self, blocknumber: int) -> None:
        """Send an ACK packet for the given block number."""
        logger.info("Sending ACK for block %d to %s:%d" % (blocknumber, self.remote.host, self.remote.port))
        ack = TftpPacketACK()
        ack.blocknumber = blocknumber
        encoded_ack = ack.encode()
        assert encoded_ack.buffer is not None  # Buffer set by encode()
        logger.debug("ACK packet encoded, sending %d bytes" % len(encoded_ack.buffer))
        self.send(encoded_ack.buffer)


class TftpServer(TftpSession):
    shared_config_values = [
        "root",
        "allow_uploads"
    ]

    def __init__(self) -> None:
        TftpSession.__init__(self)
        self.packet: TftpPacketFactory = TftpPacketFactory()
        self.root: str = ''
        self.allow_uploads: bool = True  # Default: allow uploads

    def apply_config(self, config: dict[str, Any]) -> None:
        self.root = config.get("root", self.root)
        if self.root is None:
            raise ServiceConfigError("Root path not defined")
        if not os.path.isdir(self.root):
            raise ServiceConfigError("Root path '%s' is not a directory", self.root)
        if not os.access(self.root, os.R_OK):
            raise ServiceConfigError("Unable to list files in the '%s' directory", self.root)

        # Configure upload support (default: enabled)
        self.allow_uploads = config.get("allow_uploads", self.allow_uploads)

    def handle_io_in(self, data: bytes) -> int:
        logger.debug("Data ready on our main socket")
        buffer = data
        logger.debug("Read %d bytes" % len(buffer))
        recvpkt: TftpPacket | None = None
        try:
            recvpkt = self.packet.parse(buffer)
        except TftpException as e:
            logger.debug(f"TFTP packet parse error: {e}")
            return len(data)

        if isinstance(recvpkt, TftpPacketRRQ):
            logger.debug("RRQ packet from %s:%i" %
                         (self.remote.host, self.remote.port))
            t = TftpServerHandler(TftpState(
                'rrq'), self.root, self.local.host, self.remote.host, self.remote.port, self.packet)
            t.handle_io_in(data)
        elif isinstance(recvpkt, TftpPacketWRQ):
            if not self.allow_uploads:
                logger.warn("WRQ packet from %s:%i rejected - uploads disabled" %
                           (self.remote.host, self.remote.port))
                # Send access violation error
                errpkt = TftpPacketERR()
                errpkt.errorcode = TftpErrors.AccessViolation
                self.send(errpkt.encode().buffer)
            else:
                logger.info("WRQ packet from %s:%i, file: %s" %
                            (self.remote.host, self.remote.port, recvpkt.filename))
                t = TftpServerHandler(TftpState(
                    'wrq'), self.root, self.local.host, self.remote.host, self.remote.port, self.packet)
                logger.debug("Created WRQ handler, processing request...")
                t.handle_io_in(data)
        return len(data)


class TftpClient(TftpSession):
    """This class is an implementation of a tftp client. Once instantiated, a
    download can be initiated via the download() method."""
    def __init__(self) -> None:
        TftpSession.__init__(self)
        self.timeouts.idle=5
        self.timeouts.sustain = 120
        self.options: dict[str, Any] = {}
        self.packet: TftpPacketFactory = TftpPacketFactory()
        self.expected_block: int = 0
        self.curblock: int = 0
        self.bytes: int = 0
        self.filename: str | None = None
        self.port: int = 0
        self.connected: bool = False
        self.idlecount: int = 0

    def __del__(self) -> None:
        if self.con is not None:
            self.con.unref()
            self.con = None

    def download(self, con: Any, host: str, port: int, filename: str, url: str) -> None:
        logger.info("Connecting to %s to download" % host)
        logger.info("    filename -> %s" % filename)

        if 'blksize' in self.options:
            size = self.options['blksize']
            if size < MIN_BLKSIZE or size > MAX_BLKSIZE:
                raise TftpException("Invalid blksize: %d" % size)
        else:
            self.options['blksize'] = DEF_BLKSIZE

        self.filename = filename
        self.port = port
        self.con = con
        self.url = url
        if con is not None:
            self.bind(con.local.host, 0)
            self.con.ref()

        self.connect(host,0)
        if con is not None:
            i = incident("dionaea.connection.link")
            i.parent = con
            i.child = self
            i.report()


    def handle_established(self) -> None:
        logger.info("connection to %s established" % self.remote.host)
        logger.info("port %i established" % self.port)
        self.remote.port = self.port
        pkt = TftpPacketRRQ()
        pkt.filename = self.filename
        pkt.mode = "octet" # FIXME - shouldn't hardcode this
        pkt.options = self.options
        self.last_packet = pkt.encode().buffer
        self.send(self.last_packet)
        self.state.state = 'rrq'
        self.fileobj = tempfile.NamedTemporaryFile(delete=False, prefix='tftp-', suffix=g_dionaea.config(
        )['downloads']['tmp-suffix'], dir=g_dionaea.config()['downloads']['dir'])

#    def handle_disconnect(self):
#        if self.con:
#            self.con.unref()
#        return False

    def handle_io_in(self, data: bytes) -> int:
        logger.debug('Received packet from server %s:%i' %
                     (self.remote.host, self.remote.port))

        if not self.connected:
            self.connect(self.remote.host, self.remote.port)
            self.connected = True
            if self.con is not None:
                i = incident("dionaea.connection.link")
                i.parent = self.con
                i.child = self
                i.report()


        recvpkt = self.packet.parse(data)
        if isinstance(recvpkt, TftpPacketDAT):
            assert recvpkt.data is not None  # DAT packets always have data
            logger.debug("recvpkt.blocknumber = %d" % recvpkt.blocknumber)
            logger.debug("curblock = %d" % self.curblock)

            if self.state.state == 'rrq' and self.options:
                logger.info("no OACK, our options were ignored")
                self.options = { 'blksize': DEF_BLKSIZE }
                self.state.state = 'ack'

            self.expected_block = self.curblock + 1
            if self.expected_block > 65535:
                logger.debug("block number rollover to 0 again")
                self.expected_block = 0
            if recvpkt.blocknumber == self.expected_block:
                logger.debug("good, received block %d in sequence"
                             % recvpkt.blocknumber)
                self.curblock = self.expected_block


                # ACK the packet, and save the data.
                logger.info("sending ACK to block %d" % self.curblock)
                logger.debug("ip = %s, port = %i" %
                             (self.remote.host, self.remote.port))
                ackpkt = TftpPacketACK()
                ackpkt.blocknumber = self.curblock
                self.last_packet = ackpkt.encode().buffer
                self.send(self.last_packet)

                logger.debug("writing %d bytes to output file"
                             % len(recvpkt.data))
                self.fileobj.write(recvpkt.data)
                self.bytes += len(recvpkt.data)
                # Check for end-of-file, any less than full data packet.
                if len(recvpkt.data) < int(self.options['blksize']):
                    logger.info("end of file detected")
                    self.fileobj.close()
                    icd = incident("dionaea.download.complete")
                    icd.url = self.url
                    icd.path = self.fileobj.name
                    icd.con = self
                    icd.report()
                    self.close()
                    self.fileobj.unlink(self.fileobj.name)


            elif recvpkt.blocknumber == self.curblock:
                logger.warn("dropping duplicate block %d" % self.curblock)
                logger.debug(
                    "ACKing block %d again, just in case" % self.curblock)
                ackpkt = TftpPacketACK()
                ackpkt.blocknumber = self.curblock
                self.send(ackpkt.encode().buffer)

            else:
                msg = "Whoa! Received block %d but expected %d" % (recvpkt.blocknumber,
                                                                   self.curblock+1)
                logger.warn(msg)

        # Check other packet types.
        elif isinstance(recvpkt, TftpPacketOACK):
            if not self.state.state == 'rrq':
                self.errors += 1
                logger.warn("Received OACK in state %s" % self.state.state)
#                continue
            self.state.state = 'oack'
            logger.info("Received OACK from server.")
            if len(recvpkt.options.keys()) > 0:
                if recvpkt.match_options(self.options):
                    logger.info("Successful negotiation of options")
                    # Set options to OACK options
                    self.options = recvpkt.options
                    for key in self.options:
                        logger.info(f"    {key} = {self.options[key]}")
                    logger.debug("sending ACK to OACK")
                    ackpkt = TftpPacketACK()
                    ackpkt.blocknumber = 0
                    self.last_packet = ackpkt.encode().buffer
                    self.send(self.last_packet)
                    self.state.state = 'ack'
                else:
                    logger.warn("failed to negotiate options")
                    self.senderror(TftpErrors.FailedNegotiation)
                    self.state.state = 'err'
#                    raise TftpException("Failed to negotiate options")
                    self.fail()

        elif isinstance(recvpkt, TftpPacketACK):
            # Umm, we ACK, the server doesn't.
            self.state.state = 'err'
#            self.senderror(TftpErrors.IllegalTftpOp)
            logger.warn("Received ACK from server while in download")
#            tftpassert(False, "Received ACK from server while in download")
            self.fail()

        elif isinstance(recvpkt, TftpPacketERR):
            self.state.state = 'err'
#            self.senderror(TftpErrors.IllegalTftpOp)
            logger.warn("Received ERR from server: " + str(recvpkt))
            self.fail()

        elif isinstance(recvpkt, TftpPacketWRQ):
            self.state.state = 'err'
#            self.senderror(TftpErrors.IllegalTftpOp)
#            tftpassert(False, "Received WRQ from server: " + str(recvpkt))
            logger.warn("Received WRQ from server: " + str(recvpkt))
            self.fail()
        else:
            self.state.state = 'err'
#            self.senderror(TftpErrors.IllegalTftpOp)
#            tftpassert(False, "Received unknown packet type from server: " + str(recvpkt))
            logger.warn(
                "Received unknown packet type from server: " + str(recvpkt))
            self.fail()

        return len(data)

    def handle_error(self, err: Any) -> None:
        pass

    def handle_timeout_sustain(self) -> bool:
        logger.debug("tftp sustain timeout!")
        self.fail()
        return False

    def handle_timeout_idle(self) -> bool:
        logger.debug("tftp idle timeout!")
        if self.idlecount > 10:
            self.fail()
            return False
        self.idlecount+=1
        self.send(self.last_packet)
        return True

    def fail(self) -> None:
        if self.fileobj:
            self.fileobj.close()
            self.fileobj.unlink(self.fileobj.name)
        self.close()



class tftpdownloadhandler(ihandler):
    def __init__(self, path: str) -> None:
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, path)

    def handle_incident(self, icd: Any) -> None:
        url = icd.get("url")
        if isinstance(url, bytes):
            try:
                url = url.decode(encoding="utf-8")
            except UnicodeEncodeError:
                logger.warning("Error decoding URL %s", url, exc_info=True)
                return

        if url.startswith('tftp://'):
            # python fails parsing tftp://, ftp:// works, so ...
            logger.info("do download")
            x = parse.urlsplit(url[1:])
            if x.netloc == '0.0.0.0':
                logger.info("Discarding download from INADDR_ANY")
                return
            try:
                con = icd.con
            except AttributeError:
                con = None
            t=TftpClient()
            t.download(con, x.netloc, 69, x.path[1:], url)
