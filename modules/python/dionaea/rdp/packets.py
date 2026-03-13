# ABOUTME: RDP protocol packet structures for TPKT, X.224, and MCS layers.
# ABOUTME: Used by the RDP honeypot to parse and construct RDP protocol messages.

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2025 Cowrie <cowrie@cowrie.org>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial

"""
RDP packet structures based on:
- MS-RDPBCGR specification
- WithSecureLabs doublepulsar-detection-script (BSD 3-Clause)
- Rapid7 DOUBLEPULSAR RDP analysis
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum


class TPKTVersion(IntEnum):
    """TPKT protocol version."""
    VERSION_3 = 3


class X224Type(IntEnum):
    """X.224 TPDU types."""
    CONNECTION_REQUEST = 0xe0
    CONNECTION_CONFIRM = 0xd0
    DATA = 0xf0
    DISCONNECT_REQUEST = 0x80


class RDPNegotiationType(IntEnum):
    """RDP Negotiation Request/Response types."""
    NEG_REQ = 0x01  # RDP_NEG_REQ
    NEG_RSP = 0x02  # RDP_NEG_RSP
    NEG_FAILURE = 0x03  # RDP_NEG_FAILURE


class RDPProtocol(IntEnum):
    """RDP Security Protocol flags."""
    PROTOCOL_RDP = 0x00000000
    PROTOCOL_SSL = 0x00000001
    PROTOCOL_HYBRID = 0x00000002  # CredSSP (NLA)
    PROTOCOL_RDSTLS = 0x00000004
    PROTOCOL_HYBRID_EX = 0x00000008


class MCSType(IntEnum):
    """MCS PDU types (from T.125)."""
    CONNECT_INITIAL = 0x7f65
    CONNECT_RESPONSE = 0x7f66
    ERECT_DOMAIN_REQUEST = 0x04
    ATTACH_USER_REQUEST = 0x28
    ATTACH_USER_CONFIRM = 0x2e
    CHANNEL_JOIN_REQUEST = 0x38
    CHANNEL_JOIN_CONFIRM = 0x3e
    SEND_DATA_REQUEST = 0x64
    SEND_DATA_INDICATION = 0x68


class DoublePulsarOpcode(IntEnum):
    """DOUBLEPULSAR RDP opcodes."""
    EXEC = 0x01
    PING = 0x02
    BURN = 0x03


# DOUBLEPULSAR magic value (big-endian: 0x19283744, little-endian: 0x44372819)
DOUBLEPULSAR_MAGIC = 0x19283744
DOUBLEPULSAR_MAGIC_BYTES = struct.pack('>I', DOUBLEPULSAR_MAGIC)

# DOUBLEPULSAR ping response size
DOUBLEPULSAR_PING_RESPONSE_SIZE = 288


@dataclass
class TPKTPacket:
    """TPKT packet (RFC 2126)."""
    version: int
    reserved: int
    length: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes) -> 'TPKTPacket | None':
        """Parse a TPKT packet from raw bytes."""
        if len(data) < 4:
            return None
        version, reserved, length = struct.unpack('>BBH', data[:4])
        if version != TPKTVersion.VERSION_3:
            return None
        if len(data) < length:
            return None
        return cls(version, reserved, length, data[4:length])

    def build(self) -> bytes:
        """Build TPKT packet bytes."""
        length = 4 + len(self.payload)
        return struct.pack('>BBH', self.version, self.reserved, length) + self.payload


@dataclass
class X224Packet:
    """X.224 TPDU packet."""
    length: int
    pdu_type: int
    dst_ref: int
    src_ref: int
    class_options: int
    payload: bytes

    @classmethod
    def parse_connection_request(cls, data: bytes) -> 'X224Packet | None':
        """Parse X.224 Connection Request."""
        if len(data) < 7:
            return None
        length = data[0]
        pdu_type = data[1]
        if pdu_type != X224Type.CONNECTION_REQUEST:
            return None
        dst_ref = struct.unpack('>H', data[2:4])[0]
        src_ref = struct.unpack('>H', data[4:6])[0]
        class_options = data[6]
        payload = data[7:] if len(data) > 7 else b''
        return cls(length, pdu_type, dst_ref, src_ref, class_options, payload)

    @classmethod
    def parse_data(cls, data: bytes) -> 'X224Packet | None':
        """Parse X.224 Data TPDU."""
        if len(data) < 3:
            return None
        length = data[0]
        pdu_type = data[1]
        if pdu_type != X224Type.DATA:
            return None
        # Data TPDU has EOT flag at byte 2
        payload = data[3:] if len(data) > 3 else b''
        return cls(length, pdu_type, 0, 0, data[2], payload)

    @staticmethod
    def build_connection_confirm(use_ssl: bool = True) -> bytes:
        """Build X.224 Connection Confirm with RDP Negotiation Response."""
        # X.224 CC header
        x224_header = bytes([
            0x0e,  # Length (14 bytes following)
            X224Type.CONNECTION_CONFIRM,
            0x00, 0x00,  # DST-REF
            0x00, 0x00,  # SRC-REF
            0x00,  # Class 0
        ])

        # RDP Negotiation Response
        protocol = RDPProtocol.PROTOCOL_SSL if use_ssl else RDPProtocol.PROTOCOL_RDP
        neg_rsp = bytes([
            RDPNegotiationType.NEG_RSP,
            0x00,  # flags
            0x08, 0x00,  # length (8 bytes)
        ]) + struct.pack('<I', protocol)

        return x224_header + neg_rsp

    @staticmethod
    def build_data_header() -> bytes:
        """Build X.224 Data TPDU header."""
        return bytes([
            0x02,  # Length
            X224Type.DATA,
            0x80,  # EOT flag
        ])


@dataclass
class RDPNegotiationRequest:
    """RDP Negotiation Request from client."""
    neg_type: int
    flags: int
    length: int
    requested_protocols: int
    cookie: str | None = None

    @classmethod
    def parse(cls, x224_payload: bytes) -> 'RDPNegotiationRequest | None':
        """Parse RDP Negotiation Request from X.224 payload."""
        cookie = None
        offset = 0

        # Check for routing token or cookie
        if x224_payload.startswith(b'Cookie:'):
            # Find end of cookie (CR LF)
            end = x224_payload.find(b'\r\n')
            if end != -1:
                cookie = x224_payload[:end].decode('ascii', errors='replace')
                offset = end + 2

        # Parse RDP_NEG_REQ if present
        remaining = x224_payload[offset:]
        if len(remaining) >= 8 and remaining[0] == RDPNegotiationType.NEG_REQ:
            neg_type = remaining[0]
            flags = remaining[1]
            length = struct.unpack('<H', remaining[2:4])[0]
            requested_protocols = struct.unpack('<I', remaining[4:8])[0]
            return cls(neg_type, flags, length, requested_protocols, cookie)

        # No negotiation request, client wants standard RDP
        return cls(0, 0, 0, RDPProtocol.PROTOCOL_RDP, cookie)


@dataclass
class MCSConnectInitial:
    """MCS Connect-Initial PDU (simplified parsing)."""
    calling_domain: bytes
    called_domain: bytes
    upward_flag: bool
    target_params: bytes
    min_params: bytes
    max_params: bytes
    user_data: bytes

    @classmethod
    def parse(cls, data: bytes) -> 'MCSConnectInitial | None':
        """Parse MCS Connect-Initial (simplified - just extract user data)."""
        # MCS Connect-Initial is BER encoded
        # We just need to find the GCC Conference Create Request in user data
        # For simplicity, we look for the "Duca" (0x44756361) signature
        duca_offset = data.find(b'Duca')
        if duca_offset == -1:
            return None

        # User data starts after "Duca" marker
        user_data = data[duca_offset:]
        return cls(b'', b'', True, b'', b'', b'', user_data)


@dataclass
class GCCClientData:
    """GCC Conference Create Request client data (simplified)."""
    client_name: str
    client_build: int
    keyboard_layout: int
    client_product_id: int
    requested_color_depth: int
    desktop_width: int = 0
    desktop_height: int = 0
    requested_channels: list[str] | None = None

    def __post_init__(self):
        if self.requested_channels is None:
            self.requested_channels = []

    @classmethod
    def parse(cls, user_data: bytes) -> 'GCCClientData | None':
        """Parse GCC client data to extract client info."""
        # Skip "Duca" key (4 bytes) and PER length determinant
        offset = 4
        if offset >= len(user_data):
            return None
        if user_data[offset] & 0x80:
            offset += 2  # 2-byte PER length
        else:
            offset += 1  # 1-byte PER length

        if len(user_data) < offset + 4:
            return None

        # Scan TS_UD blocks: type (2 bytes LE), length (2 bytes LE), data
        result = None
        channels = []

        while offset + 4 <= len(user_data):
            block_type = struct.unpack('<H', user_data[offset:offset+2])[0]
            block_len = struct.unpack('<H', user_data[offset+2:offset+4])[0]

            if block_type == 0xc001:  # CS_CORE
                core_data = user_data[offset+4:offset+block_len]
                if len(core_data) >= 134:
                    desktop_width = struct.unpack('<H', core_data[4:6])[0]
                    desktop_height = struct.unpack('<H', core_data[6:8])[0]
                    color_depth = struct.unpack('<H', core_data[8:10])[0]
                    kb_layout = struct.unpack('<I', core_data[12:16])[0]
                    client_build = struct.unpack('<I', core_data[16:20])[0]
                    client_name_raw = core_data[20:52]
                    client_name = client_name_raw.decode('utf-16-le', errors='replace').rstrip('\x00')
                    product_id = struct.unpack('<H', core_data[132:134])[0]

                    result = cls(
                        client_name, client_build, kb_layout, product_id,
                        color_depth, desktop_width, desktop_height,
                    )

            elif block_type == 0xc003:  # CS_NET
                net_data = user_data[offset+4:offset+block_len]
                if len(net_data) >= 4:
                    channel_count = struct.unpack('<I', net_data[0:4])[0]
                    chan_offset = 4
                    for _ in range(channel_count):
                        if chan_offset + 12 > len(net_data):
                            break
                        # CHANNEL_DEF: name (8 bytes, null-padded) + options (4 bytes)
                        name = net_data[chan_offset:chan_offset+8].split(b'\x00')[0].decode('ascii', errors='replace')
                        channels.append(name)
                        chan_offset += 12

            offset += block_len
            if block_len == 0:
                break

        if result is not None:
            result.requested_channels = channels
        return result


@dataclass
class DoublePulsarPacket:
    """DOUBLEPULSAR RDP packet."""
    magic: int
    opcode: int
    body: bytes

    @classmethod
    def parse(cls, data: bytes) -> 'DoublePulsarPacket | None':
        """Parse DOUBLEPULSAR packet from MCS data."""
        # DOUBLEPULSAR uses channelJoinConfirm (0x3c) as carrier
        # Format: 0x3c, magic (4 bytes), opcode (2 bytes), [body]
        if len(data) < 7:
            return None

        # Check for channelJoinConfirm type
        if data[0] != 0x3c:
            return None

        magic = struct.unpack('>I', data[1:5])[0]
        if magic != DOUBLEPULSAR_MAGIC:
            return None

        opcode = struct.unpack('>H', data[5:7])[0]
        body = data[7:] if len(data) > 7 else b''

        return cls(magic, opcode, body)

    @staticmethod
    def build_ping_response(
        major: int = 6,
        minor: int = 1,
        build: int = 7601,
        service_pack: int = 1,
        product_type: int = 1,
        arch: int = 64
    ) -> bytes:
        """
        Build DOUBLEPULSAR ping response with OSVERSIONINFOEXW.

        Args:
            major: OS major version (6 for Vista/7/8/10)
            minor: OS minor version (1 for 7, 2 for 8, 3 for 8.1)
            build: OS build number
            service_pack: Service pack level
            product_type: 1=Workstation, 2=Domain Controller, 3=Server
            arch: 32 or 64 bit
        """
        # Build OSVERSIONINFOEXW structure (284 bytes + padding = 288)
        # struct OSVERSIONINFOEXW {
        #   DWORD dwOSVersionInfoSize;  // 284
        #   DWORD dwMajorVersion;
        #   DWORD dwMinorVersion;
        #   DWORD dwBuildNumber;
        #   DWORD dwPlatformId;         // VER_PLATFORM_WIN32_NT = 2
        #   WCHAR szCSDVersion[128];    // 256 bytes
        #   WORD  wServicePackMajor;
        #   WORD  wServicePackMinor;
        #   WORD  wSuiteMask;
        #   BYTE  wProductType;
        #   BYTE  wReserved;
        # }

        os_info = struct.pack('<I', 284)  # dwOSVersionInfoSize
        os_info += struct.pack('<I', major)  # dwMajorVersion
        os_info += struct.pack('<I', minor)  # dwMinorVersion
        os_info += struct.pack('<I', build)  # dwBuildNumber
        os_info += struct.pack('<I', 2)  # dwPlatformId (VER_PLATFORM_WIN32_NT)

        # szCSDVersion - "Service Pack N" as UTF-16LE
        sp_string = f"Service Pack {service_pack}" if service_pack > 0 else ""
        sp_bytes = sp_string.encode('utf-16-le')
        os_info += sp_bytes.ljust(256, b'\x00')  # Pad to 256 bytes

        os_info += struct.pack('<H', service_pack)  # wServicePackMajor
        os_info += struct.pack('<H', 0)  # wServicePackMinor
        os_info += struct.pack('<H', 0)  # wSuiteMask

        os_info += struct.pack('<B', product_type)  # wProductType
        os_info += struct.pack('<B', 0)  # wReserved

        # Add architecture flag and padding to reach 288 bytes
        arch_flag = 0x01 if arch == 64 else 0x00
        padding_needed = DOUBLEPULSAR_PING_RESPONSE_SIZE - len(os_info) - 1
        os_info += struct.pack('<B', arch_flag)
        os_info += b'\x00' * padding_needed

        return os_info[:DOUBLEPULSAR_PING_RESPONSE_SIZE]

    @staticmethod
    def build_response_packet(opcode: int, body: bytes = b'') -> bytes:
        """Build DOUBLEPULSAR response packet wrapped in TPKT/X.224."""
        # MCS-style response with channelJoinConfirm type
        mcs_data = bytes([0x3e])  # channelJoinConfirm response type
        mcs_data += struct.pack('>I', DOUBLEPULSAR_MAGIC)
        mcs_data += struct.pack('>H', opcode)
        mcs_data += body

        # Wrap in X.224 Data
        x224 = X224Packet.build_data_header() + mcs_data

        # Wrap in TPKT
        tpkt = TPKTPacket(TPKTVersion.VERSION_3, 0, 0, x224)
        return tpkt.build()


# ---------------------------------------------------------------------------
# CredSSP TSRequest / NTLMSSP Negotiate
# ---------------------------------------------------------------------------

NTLMSSP_SIGNATURE = b"NTLMSSP\x00"

# NTLMSSP Negotiate flags relevant to domain/workstation/version presence
NTLMSSP_NEGOTIATE_VERSION = 0x02000000


def _der_read_tlv(data: bytes, offset: int) -> tuple[int, bytes] | None:
    """Read a DER tag-length-value at offset. Returns (new_offset, value) or None."""
    if offset >= len(data):
        return None
    offset += 1  # skip tag byte
    if offset >= len(data):
        return None
    length_byte = data[offset]
    offset += 1
    if length_byte < 0x80:
        length = length_byte
    elif length_byte == 0x81:
        if offset >= len(data):
            return None
        length = data[offset]
        offset += 1
    elif length_byte == 0x82:
        if offset + 1 >= len(data):
            return None
        length = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
    else:
        return None
    if offset + length > len(data):
        return None
    return offset + length, data[offset:offset + length]


def der_sequence_length(data: bytes) -> int | None:
    """Return total byte length of a DER SEQUENCE starting at data[0], or None if incomplete/invalid."""
    if len(data) < 2 or data[0] != 0x30:
        return None
    result = _der_read_tlv(data, 0)
    if result is None:
        return None
    end_offset, _ = result
    return end_offset


@dataclass
class TSRequest:
    """CredSSP TSRequest (RFC 4178 / MS-CSSP)."""
    version: int
    nego_tokens: list[bytes]


def parse_tsrequest(data: bytes) -> TSRequest | None:
    """Parse a CredSSP TSRequest, extracting version and negoTokens."""
    if len(data) < 2 or data[0] != 0x30:
        return None

    result = _der_read_tlv(data, 0)
    if result is None:
        return None
    _, seq_value = result

    version = 0
    nego_tokens: list[bytes] = []
    pos = 0

    while pos < len(seq_value):
        tag = seq_value[pos]
        result = _der_read_tlv(seq_value, pos)
        if result is None:
            break
        pos, field_value = result

        if tag == 0xA0:
            # [0] version — contains an INTEGER
            inner = _der_read_tlv(field_value, 0)
            if inner is not None:
                _, int_bytes = inner
                version = int.from_bytes(int_bytes, "big")

        elif tag == 0xA1:
            # [1] negoTokens — SEQUENCE OF SEQUENCE { [0] negoToken OCTET STRING }
            outer = _der_read_tlv(field_value, 0)  # outer SEQUENCE
            if outer is None:
                continue
            _, outer_value = outer
            # Iterate inner SEQUENCEs
            inner_pos = 0
            while inner_pos < len(outer_value):
                inner = _der_read_tlv(outer_value, inner_pos)
                if inner is None:
                    break
                inner_pos, inner_value = inner
                # Each inner SEQUENCE has [0] OCTET STRING
                token_wrapper = _der_read_tlv(inner_value, 0)
                if token_wrapper is None:
                    continue
                _, wrapper_value = token_wrapper
                octet = _der_read_tlv(wrapper_value, 0)
                if octet is not None:
                    _, token = octet
                    nego_tokens.append(token)

    return TSRequest(version=version, nego_tokens=nego_tokens)


@dataclass
class NTLMSSPNegotiate:
    """NTLMSSP Negotiate (Type 1) message fields."""
    flags: int
    domain_name: str
    workstation_name: str
    os_version: tuple[int, int, int, int] | None  # (major, minor, build, revision)


def parse_ntlmssp_negotiate(data: bytes) -> NTLMSSPNegotiate | None:
    """Parse NTLMSSP Negotiate (Type 1) message."""
    # Minimum: 8 (sig) + 4 (type) + 4 (flags) + 8 (domain) + 8 (workstation) = 32
    if len(data) < 32:
        return None
    if data[:8] != NTLMSSP_SIGNATURE:
        return None
    msg_type = struct.unpack("<I", data[8:12])[0]
    if msg_type != 1:
        return None

    flags = struct.unpack("<I", data[12:16])[0]

    domain_len = struct.unpack("<H", data[16:18])[0]
    domain_offset = struct.unpack("<I", data[20:24])[0]
    workstation_len = struct.unpack("<H", data[24:26])[0]
    workstation_offset = struct.unpack("<I", data[28:32])[0]

    os_version = None
    if flags & NTLMSSP_NEGOTIATE_VERSION and len(data) >= 40:
        major = data[32]
        minor = data[33]
        build = struct.unpack("<H", data[34:36])[0]
        revision = data[39]
        os_version = (major, minor, build, revision)

    domain_name = ""
    if domain_len > 0 and domain_offset + domain_len <= len(data):
        domain_name = data[domain_offset:domain_offset + domain_len].decode(
            "ascii", errors="replace"
        )

    workstation_name = ""
    if workstation_len > 0 and workstation_offset + workstation_len <= len(data):
        workstation_name = data[
            workstation_offset:workstation_offset + workstation_len
        ].decode("ascii", errors="replace")

    return NTLMSSPNegotiate(
        flags=flags,
        domain_name=domain_name,
        workstation_name=workstation_name,
        os_version=os_version,
    )
