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
    """TPKT packet (RFC 1006)."""
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
# BER encoding utilities
# ---------------------------------------------------------------------------


def ber_encode_length(length: int) -> bytes:
    """Encode a BER length field."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82]) + struct.pack('!H', length)


def ber_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode BER length. Returns (length, new_offset)."""
    if data[offset] < 0x80:
        return data[offset], offset + 1
    num_bytes = data[offset] & 0x7F
    offset += 1
    length = int.from_bytes(data[offset:offset + num_bytes], 'big')
    return length, offset + num_bytes


# ---------------------------------------------------------------------------
# GCC User Data Block parsing/building
# ---------------------------------------------------------------------------

# GCC Conference Create Request user data block types
CS_CORE = 0xC001
CS_SECURITY = 0xC002
CS_NET = 0xC003
CS_CLUSTER = 0xC004

SC_CORE = 0x0C01
SC_SECURITY = 0x0C02
SC_NET = 0x0C03

# X.224 Data TPDU header (precedes MCS in later stages)
X224_DATA_HEADER = bytes([0x02, 0xF0, 0x80])

# GCC Conference Create Request/Response magic
GCC_CCR_KEY = b"\x00\x05\x00\x14\x7c\x00\x01"

# RDP version for SC_CORE
RDP_VERSION_5_PLUS = 0x00080004

# IO channel (always 1003)
MCS_IO_CHANNEL_ID = 0x03EB


@dataclass
class GCCClientCoreData:
    """Key fields from GCC Client Core Data (TS_UD_CS_CORE)."""
    version_major: int
    version_minor: int
    desktop_width: int
    desktop_height: int
    color_depth: int
    sas_sequence: int
    keyboard_layout: int
    client_build: int
    client_name: str
    keyboard_type: int
    keyboard_subtype: int
    keyboard_function_keys: int


def parse_gcc_client_core_data(data: bytes) -> GCCClientCoreData | None:
    """Parse TS_UD_CS_CORE from raw client core data block (after header type+length)."""
    if len(data) < 128:
        return None

    (version_major, version_minor,
     desktop_width, desktop_height,
     color_depth, sas_sequence,
     keyboard_layout, client_build) = struct.unpack_from('<HHHHHHII', data, 0)

    client_name_raw = data[20:52]
    client_name = client_name_raw.decode('utf-16-le', errors='replace').rstrip('\x00')

    keyboard_type, keyboard_subtype, keyboard_function_keys = struct.unpack_from('<III', data, 52)

    return GCCClientCoreData(
        version_major=version_major, version_minor=version_minor,
        desktop_width=desktop_width, desktop_height=desktop_height,
        color_depth=color_depth, sas_sequence=sas_sequence,
        keyboard_layout=keyboard_layout, client_build=client_build,
        client_name=client_name, keyboard_type=keyboard_type,
        keyboard_subtype=keyboard_subtype, keyboard_function_keys=keyboard_function_keys,
    )


def parse_cs_net_channels(data: bytes) -> list[str]:
    """Parse channel names from CS_NET block payload (after type+length header).

    Each channel is a CHANNEL_DEF: name (8 bytes, null-padded) + options (4 bytes).
    """
    if len(data) < 4:
        return []
    channel_count = struct.unpack('<I', data[0:4])[0]
    channels: list[str] = []
    offset = 4
    for _ in range(channel_count):
        if offset + 12 > len(data):
            break
        name = data[offset:offset + 8].split(b'\x00')[0].decode('ascii', errors='replace')
        channels.append(name)
        offset += 12
    return channels


def parse_gcc_user_data_blocks(data: bytes) -> dict[int, bytes]:
    """Parse a sequence of GCC user data blocks (type:u16LE, length:u16LE, data).

    Returns dict mapping block type -> block payload (excluding header).
    """
    blocks: dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(data):
        block_type, block_length = struct.unpack_from('<HH', data, offset)
        if block_length < 4 or offset + block_length > len(data):
            break
        blocks[block_type] = data[offset + 4:offset + block_length]
        offset += block_length
    return blocks


def parse_mcs_connect_initial(data: bytes) -> dict[int, bytes] | None:
    """Parse MCS Connect-Initial, extract GCC user data blocks.

    Input: BER-encoded MCS Connect-Initial (starts with 0x7f 0x65).
    Returns dict of GCC client data blocks, or None on failure.
    """
    if len(data) < 2:
        return None
    pos = 0

    # BER: Application[101] CONNECT-INITIAL
    if data[pos] != 0x7F or data[pos + 1] != 0x65:
        return None
    pos += 2

    _ci_len, pos = ber_decode_length(data, pos)

    # Skip three BER OCTET STRINGs: callingDomainSelector, calledDomainSelector, upwardFlag
    for _ in range(3):
        if pos >= len(data):
            return None
        pos += 1  # tag
        field_len, pos = ber_decode_length(data, pos)
        pos += field_len

    # Skip targetParameters, minimumParameters, maximumParameters (three SEQUENCE)
    for _ in range(3):
        if pos >= len(data):
            return None
        pos += 1  # tag
        field_len, pos = ber_decode_length(data, pos)
        pos += field_len

    # userData OCTET STRING
    if pos >= len(data) or data[pos] != 0x04:
        return None
    pos += 1
    user_data_len, pos = ber_decode_length(data, pos)
    user_data = data[pos:pos + user_data_len]

    # GCC Conference Create Request header — look for T.124 key
    gcc_start = user_data.find(GCC_CCR_KEY)
    if gcc_start < 0:
        return None

    p = gcc_start + len(GCC_CCR_KEY)
    if p + 1 > len(user_data):
        return None
    # PER length prefix
    if user_data[p] & 0x80:
        p += 2
    else:
        p += 1

    p += 2  # conference name PER encoded

    # h221NonStandard key "Duca"
    duca_pos = user_data.find(b'Duca', p)
    if duca_pos < 0:
        return None

    ud_start = duca_pos + 4
    if ud_start < len(user_data):
        if user_data[ud_start] & 0x80:
            ud_start += 2
        else:
            ud_start += 2  # Always 2 in practice

    return parse_gcc_user_data_blocks(user_data[ud_start:])


# ---------------------------------------------------------------------------
# Server-side GCC / MCS Connect-Response builders
# ---------------------------------------------------------------------------


def build_gcc_server_data(
    selected_protocol: int = 0,
    channel_ids: list[int] | None = None,
    server_security_data: bytes | None = None,
) -> bytes:
    """Build GCC server user data blocks (SC_CORE + SC_SECURITY + SC_NET)."""
    if channel_ids is None:
        channel_ids = []

    sc_core_payload = struct.pack('<II', RDP_VERSION_5_PLUS, selected_protocol)
    sc_core = struct.pack('<HH', SC_CORE, 4 + len(sc_core_payload)) + sc_core_payload

    if server_security_data is not None:
        sc_sec = struct.pack('<HH', SC_SECURITY, 4 + len(server_security_data)) + server_security_data
    else:
        sc_sec_payload = struct.pack('<II', 0x00000001, 0x00000003)
        sc_sec = struct.pack('<HH', SC_SECURITY, 4 + len(sc_sec_payload)) + sc_sec_payload

    sc_net_payload = struct.pack('<HH', MCS_IO_CHANNEL_ID, len(channel_ids))
    for ch_id in channel_ids:
        sc_net_payload += struct.pack('<H', ch_id)
    if len(sc_net_payload) % 4 != 0:
        sc_net_payload += b'\x00' * (4 - len(sc_net_payload) % 4)
    sc_net = struct.pack('<HH', SC_NET, 4 + len(sc_net_payload)) + sc_net_payload

    return sc_core + sc_sec + sc_net


def build_mcs_connect_response(
    selected_protocol: int = 0,
    channel_ids: list[int] | None = None,
    server_security_data: bytes | None = None,
) -> bytes:
    """Build complete MCS Connect-Response with GCC Conference Create Response.

    Returns TPKT payload (X.224 Data header + BER-encoded MCS).
    """
    gcc_user_data = build_gcc_server_data(selected_protocol, channel_ids, server_security_data)

    # GCC Conference Create Response wrapper
    gcc_inner = b'\x21'  # nodeID (PER)
    gcc_inner += b'\x80'  # result = success
    gcc_inner += struct.pack('!H', len(gcc_user_data) | 0x8000)
    gcc_inner += b'\x04\x01\x01'  # ConnectGCCPDU choice + key
    gcc_inner += b'McDn'
    gcc_inner += struct.pack('!H', len(gcc_user_data) | 0x8000)
    gcc_inner += gcc_user_data

    gcc_data = b'\x04' + ber_encode_length(len(gcc_inner)) + gcc_inner

    result = b'\x0a\x01\x00'
    connect_id = b'\x02\x01\x00'
    domain_params = bytes([
        0x30, 0x1a,
        0x02, 0x01, 0x22,
        0x02, 0x01, 0x03,
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x01,
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x01,
        0x02, 0x03, 0x00, 0xff, 0xff,
        0x02, 0x01, 0x02,
    ])

    inner = result + connect_id + domain_params + gcc_data
    mcs_pdu = bytes([0x7F, 0x66]) + ber_encode_length(len(inner)) + inner

    return X224_DATA_HEADER + mcs_pdu


# ---------------------------------------------------------------------------
# Client Info PDU (TS_INFO_PACKET) parsing
# ---------------------------------------------------------------------------


@dataclass
class ClientInfo:
    """Parsed credentials from TS_INFO_PACKET."""
    domain: str
    username: str
    password: str
    alt_shell: str
    working_dir: str


def parse_client_info_pdu(data: bytes) -> ClientInfo | None:
    """Parse TS_INFO_PACKET to extract credentials.

    Input: raw info packet data (after security header).
    """
    if len(data) < 18:
        return None

    (_code_page, flags,
     cb_domain, cb_user, cb_password,
     cb_shell, cb_dir) = struct.unpack_from('<II HHHHH', data, 0)

    is_unicode = bool(flags & 0x00000010)  # INFO_UNICODE
    encoding = 'utf-16-le' if is_unicode else 'ascii'
    null_term_len = 2 if is_unicode else 1

    offset = 18

    def read_field(length: int) -> str:
        nonlocal offset
        field_data = data[offset:offset + length]
        offset += length + null_term_len
        return field_data.decode(encoding, errors='replace')

    try:
        domain = read_field(cb_domain)
        username = read_field(cb_user)
        password = read_field(cb_password)
        alt_shell = read_field(cb_shell)
        working_dir = read_field(cb_dir)
    except Exception:
        return None

    return ClientInfo(
        domain=domain, username=username, password=password,
        alt_shell=alt_shell, working_dir=working_dir,
    )


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
    try:
        length, offset = ber_decode_length(data, offset)
    except (IndexError, ValueError):
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


# ---------------------------------------------------------------------------
# NTLMSSP Challenge (Type 2) building
# ---------------------------------------------------------------------------

# Flags for our Type 2 challenge message
_CHALLENGE_FLAGS = (
    0x00000001  # NEGOTIATE_UNICODE
    | 0x00000002  # NEGOTIATE_NTLM
    | 0x00000004  # REQUEST_TARGET
    | 0x00008000  # NEGOTIATE_ALWAYS_SIGN
    | 0x00080000  # NEGOTIATE_NTLM2 (extended session security)
    | 0x00800000  # NEGOTIATE_TARGET_INFO
)


def _build_av_pairs(target_name: str) -> bytes:
    """Build AV_PAIR target info structures for the NTLMSSP challenge."""
    pairs = b""
    # MsvAvNbDomainName (type 2)
    name_bytes = target_name.encode("utf-16-le")
    pairs += struct.pack("<HH", 2, len(name_bytes)) + name_bytes
    # MsvAvNbComputerName (type 1)
    pairs += struct.pack("<HH", 1, len(name_bytes)) + name_bytes
    # MsvAvEOL (type 0, length 0)
    pairs += struct.pack("<HH", 0, 0)
    return pairs


def build_ntlmssp_challenge(
    server_challenge: bytes,
    target_name: str = "WORKGROUP",
) -> bytes:
    """Build an NTLMSSP Challenge (Type 2) message.

    Args:
        server_challenge: 8-byte random nonce.
        target_name: NetBIOS domain name to present to client.
    """
    target_name_bytes = target_name.encode("utf-16-le")
    av_pairs = _build_av_pairs(target_name)

    # Fixed header: sig(8) + type(4) + target_name_fields(8) + flags(4) +
    #               server_challenge(8) + reserved(8) + target_info_fields(8)
    header_size = 8 + 4 + 8 + 4 + 8 + 8 + 8  # = 48

    target_name_offset = header_size
    target_info_offset = target_name_offset + len(target_name_bytes)

    msg = NTLMSSP_SIGNATURE
    msg += struct.pack("<I", 2)  # Message type
    # TargetNameFields
    msg += struct.pack("<HHI", len(target_name_bytes), len(target_name_bytes), target_name_offset)
    msg += struct.pack("<I", _CHALLENGE_FLAGS)
    msg += server_challenge  # 8 bytes
    msg += b"\x00" * 8  # Reserved
    # TargetInfoFields
    msg += struct.pack("<HHI", len(av_pairs), len(av_pairs), target_info_offset)

    msg += target_name_bytes + av_pairs
    return msg


# ---------------------------------------------------------------------------
# TSRequest response building (server → client)
# ---------------------------------------------------------------------------


def _der_encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode a DER tag-length-value triple."""
    return bytes([tag]) + ber_encode_length(len(value)) + value


def build_tsrequest_response(nego_token: bytes, version: int = 2) -> bytes:
    """Build a CredSSP TSRequest containing a single negoToken (server → client)."""
    # [0] version INTEGER
    version_tlv = _der_encode_tlv(0xA0, _der_encode_tlv(0x02, bytes([version])))
    # negoToken wrapped: OCTET STRING → [0] → SEQUENCE → SEQUENCE → [1]
    octet = _der_encode_tlv(0x04, nego_token)
    inner = _der_encode_tlv(0xA0, octet)
    inner_seq = _der_encode_tlv(0x30, inner)
    outer_seq = _der_encode_tlv(0x30, inner_seq)
    nego_tokens = _der_encode_tlv(0xA1, outer_seq)
    return _der_encode_tlv(0x30, version_tlv + nego_tokens)


# SEC_E_LOGON_DENIED (0x8009030C) — NTSTATUS for "logon denied"
CREDSSP_ERROR_LOGON_DENIED = 0x8009030C


def build_tsrequest_error(error_code: int = CREDSSP_ERROR_LOGON_DENIED, version: int = 2) -> bytes:
    """Build a CredSSP TSRequest with errorCode (server → client, logon denied)."""
    version_tlv = _der_encode_tlv(0xA0, _der_encode_tlv(0x02, bytes([version])))
    # [3] errorCode INTEGER (4 bytes, unsigned → encode as signed per DER)
    error_bytes = error_code.to_bytes(4, "big")
    # Strip leading zero bytes for minimal DER INTEGER encoding, but keep sign byte
    while len(error_bytes) > 1 and error_bytes[0] == 0:
        error_bytes = error_bytes[1:]
    # If high bit set, prepend 0x00 for positive representation
    if error_bytes[0] & 0x80:
        error_bytes = b"\x00" + error_bytes
    error_tlv = _der_encode_tlv(0xA3, _der_encode_tlv(0x02, error_bytes))
    return _der_encode_tlv(0x30, version_tlv + error_tlv)


# ---------------------------------------------------------------------------
# NTLMSSP Authenticate (Type 3) parsing
# ---------------------------------------------------------------------------


@dataclass
class NTLMSSPAuthenticate:
    """NTLMSSP Authenticate (Type 3) message fields."""
    domain: str
    username: str
    workstation: str
    nt_response: bytes
    lm_response: bytes


def parse_ntlmssp_authenticate(data: bytes) -> NTLMSSPAuthenticate | None:
    """Parse NTLMSSP Authenticate (Type 3) message."""
    # Minimum: sig(8) + type(4) + lm(8) + nt(8) + domain(8) + user(8) + ws(8) + enc(8) + flags(4) = 64
    if len(data) < 64:
        return None
    if data[:8] != NTLMSSP_SIGNATURE:
        return None
    msg_type = struct.unpack("<I", data[8:12])[0]
    if msg_type != 3:
        return None

    def _read_fields(offset: int) -> tuple[int, int]:
        """Read security buffer fields (length, offset)."""
        length = struct.unpack("<H", data[offset:offset + 2])[0]
        buf_offset = struct.unpack("<I", data[offset + 4:offset + 8])[0]
        return length, buf_offset

    lm_len, lm_off = _read_fields(12)
    nt_len, nt_off = _read_fields(20)
    dom_len, dom_off = _read_fields(28)
    user_len, user_off = _read_fields(36)
    ws_len, ws_off = _read_fields(44)

    def _extract(off: int, length: int) -> bytes:
        if length == 0:
            return b""
        if off + length > len(data):
            return b""
        return data[off:off + length]

    lm_response = _extract(lm_off, lm_len)
    nt_response = _extract(nt_off, nt_len)
    domain = _extract(dom_off, dom_len).decode("utf-16-le", errors="replace")
    username = _extract(user_off, user_len).decode("utf-16-le", errors="replace")
    workstation = _extract(ws_off, ws_len).decode("utf-16-le", errors="replace")

    return NTLMSSPAuthenticate(
        domain=domain,
        username=username,
        workstation=workstation,
        nt_response=nt_response,
        lm_response=lm_response,
    )


# ---------------------------------------------------------------------------
# NTLMv2 hash formatting (hashcat mode 5600)
# ---------------------------------------------------------------------------


def format_ntlmv2_hash(
    username: str,
    domain: str,
    server_challenge: bytes,
    nt_response: bytes,
) -> str | None:
    """Format NTLMv2 hash for offline cracking (hashcat mode 5600).

    Returns: username::domain:server_challenge:nt_proof:ntv2_blob
    Or None if nt_response is too short (must be > 16 bytes).
    """
    if len(nt_response) <= 16:
        return None
    nt_proof = nt_response[:16]
    ntv2_blob = nt_response[16:]
    return "%s::%s:%s:%s:%s" % (
        username,
        domain,
        server_challenge.hex(),
        nt_proof.hex(),
        ntv2_blob.hex(),
    )
