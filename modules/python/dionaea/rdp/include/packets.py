# ABOUTME: RDP protocol wire format parsers and builders.
# ABOUTME: Handles TPKT, X.224, MCS/GCC, and security PDU construction/parsing.

import struct
from typing import NamedTuple


# ---------------------------------------------------------------------------
# TPKT (RFC 1006) -- 4-byte transport framing
# ---------------------------------------------------------------------------

TPKT_VERSION = 3
TPKT_HEADER_LEN = 4


def parse_tpkt(data: bytes) -> tuple[int, int] | None:
    """Parse a TPKT header. Returns (version, total_length) or None if incomplete."""
    if len(data) < TPKT_HEADER_LEN:
        return None
    version, reserved, length = struct.unpack("!BBH", data[:TPKT_HEADER_LEN])
    return version, length


def build_tpkt(payload: bytes) -> bytes:
    """Wrap payload in a TPKT header."""
    length = TPKT_HEADER_LEN + len(payload)
    return struct.pack("!BBH", TPKT_VERSION, 0, length) + payload


# ---------------------------------------------------------------------------
# X.224 (ISO 8073) -- Connection Request / Connection Confirm
# ---------------------------------------------------------------------------

# X.224 TPDU type codes (high nibble of the type byte)
X224_TYPE_CR = 0xE0  # Connection Request
X224_TYPE_CC = 0xD0  # Connection Confirm

# RDP Negotiation Request/Response types
RDP_NEG_REQ = 0x01
RDP_NEG_RSP = 0x02

# Protocol flags
PROTOCOL_RDP = 0x00000000
PROTOCOL_SSL = 0x00000001
PROTOCOL_HYBRID = 0x00000002  # CredSSP (NLA)
PROTOCOL_RDSTLS = 0x00000004
PROTOCOL_HYBRID_EX = 0x00000008


class X224ConnectionRequest(NamedTuple):
    """Parsed X.224 Connection Request."""
    cookie: str
    requested_protocols: int


def parse_x224_cr(data: bytes) -> X224ConnectionRequest | None:
    """Parse X.224 Connection Request from the TPKT payload.

    The payload starts with:
      [length_indicator:1] [type:1] [dst_ref:2] [src_ref:2] [class:1]
    followed by optional cookie and RDP Negotiation Request.
    """
    if len(data) < 7:
        return None

    length_indicator = data[0]
    tpdu_type = data[1]

    if tpdu_type & 0xF0 != X224_TYPE_CR:
        return None

    # Variable data starts after the 7-byte fixed header
    variable = data[7:]

    cookie = ""
    requested_protocols = PROTOCOL_RDP

    # Parse cookie: "Cookie: mstshash=...\r\n"
    if variable.startswith(b"Cookie:"):
        cr_lf = variable.find(b"\r\n")
        if cr_lf >= 0:
            cookie = variable[:cr_lf].decode("ascii", errors="replace")
            variable = variable[cr_lf + 2:]

    # Parse RDP Negotiation Request (type 0x01, flags, length=8, protocols)
    if len(variable) >= 8 and variable[0] == RDP_NEG_REQ:
        requested_protocols = struct.unpack("<I", variable[4:8])[0]

    return X224ConnectionRequest(cookie=cookie, requested_protocols=requested_protocols)


def build_x224_cc(selected_protocol: int = PROTOCOL_RDP) -> bytes:
    """Build X.224 Connection Confirm with RDP Negotiation Response.

    Returns the TPKT payload (without the TPKT header).
    """
    # Fixed header: [length_indicator] [type=CC] [dst_ref=0] [src_ref=0] [class=0]
    # RDP Neg Response: [type=0x02] [flags=0] [length=8] [selected_protocol:LE32]
    neg_rsp = struct.pack("<BBH I", RDP_NEG_RSP, 0x00, 8, selected_protocol)

    # length_indicator = fixed_header_size(6) + neg_rsp_size(8)
    header = struct.pack("!BBHHB", 6 + len(neg_rsp), X224_TYPE_CC, 0, 0, 0)

    return header + neg_rsp


# ---------------------------------------------------------------------------
# MCS/T.125 -- BER-encoded multi-channel service
# ---------------------------------------------------------------------------

# MCS PDU types (application tags in BER encoding)
MCS_CONNECT_INITIAL = 0x65   # Application[101], CONNECT-INITIAL
MCS_CONNECT_RESPONSE = 0x66  # Application[102], CONNECT-RESPONSE
MCS_ERECT_DOMAIN = 0x04      # Domain-MCS-PDU choice 1
MCS_ATTACH_USER_REQ = 0x28   # Application[10]
MCS_ATTACH_USER_CONFIRM = 0x2E  # Application[11]
MCS_CHANNEL_JOIN_REQ = 0x38  # Application[14]
MCS_CHANNEL_JOIN_CONFIRM = 0x3E  # Application[15]

# X.224 Data TPDU header (precedes MCS in later stages)
X224_DATA_HEADER = bytes([0x02, 0xF0, 0x80])

# GCC Conference Create Request/Response magic
GCC_CCR_KEY = b"\x00\x05\x00\x14\x7c\x00\x01"  # T.124 key for RDP


def ber_encode_length(length: int) -> bytes:
    """Encode a BER length field."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82]) + struct.pack("!H", length)


def ber_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode BER length. Returns (length, new_offset)."""
    if data[offset] < 0x80:
        return data[offset], offset + 1
    num_bytes = data[offset] & 0x7F
    offset += 1
    length = int.from_bytes(data[offset:offset + num_bytes], "big")
    return length, offset + num_bytes


class GCCClientCoreData(NamedTuple):
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
    """Parse TS_UD_CS_CORE from GCC Conference Create Request user data.

    Input: raw client core data block (after the header type+length fields).
    """
    if len(data) < 128:
        return None

    (version_major, version_minor,
     desktop_width, desktop_height,
     color_depth, sas_sequence,
     keyboard_layout, client_build) = struct.unpack_from("<HHHHHHII", data, 0)

    # Client name: 32 bytes at offset 20, null-terminated UTF-16LE
    # (struct format HHHHHHII = 2+2+2+2+2+2+4+4 = 20 bytes)
    client_name_raw = data[20:52]
    client_name = client_name_raw.decode("utf-16-le", errors="replace").rstrip("\x00")

    # Keyboard type at offset 52 (20 + 32 bytes client name)
    keyboard_type, keyboard_subtype, keyboard_function_keys = struct.unpack_from("<III", data, 52)

    return GCCClientCoreData(
        version_major=version_major,
        version_minor=version_minor,
        desktop_width=desktop_width,
        desktop_height=desktop_height,
        color_depth=color_depth,
        sas_sequence=sas_sequence,
        keyboard_layout=keyboard_layout,
        client_build=client_build,
        client_name=client_name,
        keyboard_type=keyboard_type,
        keyboard_subtype=keyboard_subtype,
        keyboard_function_keys=keyboard_function_keys,
    )


# GCC Conference Create Request user data block types
CS_CORE = 0xC001
CS_SECURITY = 0xC002
CS_NET = 0xC003
CS_CLUSTER = 0xC004

SC_CORE = 0x0C01
SC_SECURITY = 0x0C02
SC_NET = 0x0C03


def parse_gcc_user_data_blocks(data: bytes) -> dict[int, bytes]:
    """Parse a sequence of GCC user data blocks (type:u16LE, length:u16LE, data).

    Returns dict mapping block type -> block payload (excluding header).
    """
    blocks: dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(data):
        block_type, block_length = struct.unpack_from("<HH", data, offset)
        if block_length < 4 or offset + block_length > len(data):
            break
        blocks[block_type] = data[offset + 4:offset + block_length]
        offset += block_length
    return blocks


def parse_mcs_connect_initial(payload: bytes) -> dict[int, bytes] | None:
    """Parse MCS Connect-Initial, extract GCC user data blocks.

    Input: TPKT payload (starts with X.224 Data header, then BER-encoded MCS).
    Returns dict of GCC client data blocks, or None on failure.
    """
    # Skip X.224 Data header (3 bytes: 0x02, 0xF0, 0x80)
    if len(payload) < 3:
        return None
    pos = 3

    # BER: Application[101] CONNECT-INITIAL
    if payload[pos] != 0x7F or payload[pos + 1] != MCS_CONNECT_INITIAL:
        return None
    pos += 2

    # BER length of Connect-Initial
    _ci_len, pos = ber_decode_length(payload, pos)

    # Skip three BER OCTET STRINGs: callingDomainSelector, calledDomainSelector, upwardFlag
    for _ in range(3):
        if pos >= len(payload):
            return None
        pos += 1  # tag
        field_len, pos = ber_decode_length(payload, pos)
        pos += field_len

    # Skip targetParameters, minimumParameters, maximumParameters (three SEQUENCE)
    for _ in range(3):
        if pos >= len(payload):
            return None
        pos += 1  # tag
        field_len, pos = ber_decode_length(payload, pos)
        pos += field_len

    # Now we should be at the userData OCTET STRING
    if pos >= len(payload) or payload[pos] != 0x04:
        return None
    pos += 1
    user_data_len, pos = ber_decode_length(payload, pos)
    user_data = payload[pos:pos + user_data_len]

    # GCC Conference Create Request header
    # Skip: T.124 ConnectData + key (variable, look for the magic)
    gcc_start = user_data.find(GCC_CCR_KEY)
    if gcc_start < 0:
        return None

    # Skip the T.124 header to get to user data
    # The structure is: key(7) + connectPDU length encoding + h221NonStandard("Duca") + userData
    p = gcc_start + len(GCC_CCR_KEY)
    # Skip ConnectData::connectPDU (PER length + header)
    if p + 1 > len(user_data):
        return None
    # PER length prefix
    if user_data[p] & 0x80:
        p += 2  # 2-byte PER length
    else:
        p += 1  # 1-byte PER length

    # Skip conference name (PER encoded) - 2 bytes + 2 bytes for userData header
    p += 2  # per choice + selection

    # Look for h221NonStandard key "Duca"
    duca_pos = user_data.find(b"Duca", p)
    if duca_pos < 0:
        return None

    # User data starts 4 bytes after "Duca" + 2 bytes for PER length
    ud_start = duca_pos + 4
    # Skip PER length (1 or 2 bytes)
    if ud_start < len(user_data):
        if user_data[ud_start] & 0x80:
            ud_start += 2
        else:
            ud_start += 2  # Always seems to be 2 in practice

    return parse_gcc_user_data_blocks(user_data[ud_start:])


class ChannelJoinRequest(NamedTuple):
    """Parsed MCS Channel Join Request."""
    user_id: int
    channel_id: int


def parse_mcs_erect_domain(payload: bytes) -> bool:
    """Check if payload is an MCS ErectDomainRequest. Returns True if valid."""
    if len(payload) < 3:
        return False
    # X.224 Data header + MCS ErectDomainRequest (PER encoded, tag = 0x04)
    return payload[3] == MCS_ERECT_DOMAIN if len(payload) > 3 else False


def parse_mcs_attach_user_request(payload: bytes) -> bool:
    """Check if payload is an MCS AttachUserRequest. Returns True if valid."""
    if len(payload) < 4:
        return False
    return payload[3] == MCS_ATTACH_USER_REQ


def build_mcs_attach_user_confirm(user_id: int) -> bytes:
    """Build MCS AttachUserConfirm (PER encoded)."""
    # X.224 Data header + AttachUserConfirm
    # PER: result=rt-successful(0), initiator present + value
    return X224_DATA_HEADER + bytes([MCS_ATTACH_USER_CONFIRM, 0x00]) + struct.pack("!H", user_id)


def parse_mcs_channel_join_request(payload: bytes) -> ChannelJoinRequest | None:
    """Parse MCS ChannelJoinRequest. Returns (user_id, channel_id)."""
    # X.224 Data header (3 bytes) + tag (1 byte) + user_id (2 bytes) + channel_id (2 bytes)
    if len(payload) < 8:
        return None
    if payload[3] != MCS_CHANNEL_JOIN_REQ:
        return None
    user_id, channel_id = struct.unpack("!HH", payload[4:8])
    return ChannelJoinRequest(user_id=user_id, channel_id=channel_id)


def build_mcs_channel_join_confirm(user_id: int, channel_id: int) -> bytes:
    """Build MCS ChannelJoinConfirm (PER encoded)."""
    return X224_DATA_HEADER + struct.pack("!BBHHH",
        MCS_CHANNEL_JOIN_CONFIRM,
        0x00,  # result = rt-successful (1 byte)
        user_id,
        channel_id,  # requested
        channel_id,  # channelId (same as requested on success)
    )


# ---------------------------------------------------------------------------
# Server-side GCC / MCS Connect-Response builders
# ---------------------------------------------------------------------------

# RDP version for SC_CORE
RDP_VERSION_5_PLUS = 0x00080004

# IO channel (always 1003)
MCS_IO_CHANNEL_ID = 0x03EB


def build_gcc_server_data(
    selected_protocol: int = PROTOCOL_RDP,
    channel_ids: list[int] | None = None,
    server_security_data: bytes | None = None,
) -> bytes:
    """Build GCC server user data blocks (SC_CORE + SC_SECURITY + SC_NET).

    If server_security_data is provided, it replaces the default SC_SECURITY payload.
    Returns raw concatenated user data blocks.
    """
    if channel_ids is None:
        channel_ids = []

    # SC_CORE: version(4) + clientRequestedProtocols(4)
    sc_core_payload = struct.pack("<II", RDP_VERSION_5_PLUS, selected_protocol)
    sc_core = struct.pack("<HH", SC_CORE, 4 + len(sc_core_payload)) + sc_core_payload

    # SC_SECURITY
    if server_security_data is not None:
        sc_sec = struct.pack("<HH", SC_SECURITY, 4 + len(server_security_data)) + server_security_data
    else:
        sc_sec_payload = struct.pack("<II",
            0x00000001,  # ENCRYPTION_METHOD_40BIT
            0x00000003,  # ENCRYPTION_LEVEL_HIGH (forces encryption)
        )
        sc_sec = struct.pack("<HH", SC_SECURITY, 4 + len(sc_sec_payload)) + sc_sec_payload

    # SC_NET: MCSChannelId(2) + channelCount(2) + channelId[](2 each) + pad
    sc_net_payload = struct.pack("<HH", MCS_IO_CHANNEL_ID, len(channel_ids))
    for ch_id in channel_ids:
        sc_net_payload += struct.pack("<H", ch_id)
    # Pad to 4-byte boundary
    if len(sc_net_payload) % 4 != 0:
        sc_net_payload += b"\x00" * (4 - len(sc_net_payload) % 4)
    sc_net = struct.pack("<HH", SC_NET, 4 + len(sc_net_payload)) + sc_net_payload

    return sc_core + sc_sec + sc_net


def build_mcs_connect_response(
    selected_protocol: int = PROTOCOL_RDP,
    channel_ids: list[int] | None = None,
    server_security_data: bytes | None = None,
) -> bytes:
    """Build complete MCS Connect-Response with GCC Conference Create Response.

    Returns TPKT payload (X.224 Data header + BER-encoded MCS).
    """
    gcc_user_data = build_gcc_server_data(selected_protocol, channel_ids, server_security_data)

    # GCC Conference Create Response wrapper
    # PER: ConferenceCreateResponse
    gcc_inner = b"\x21"  # nodeID = 0x79F3 (PER encoded as 1 byte for short form)
    gcc_inner += b"\x80"  # result = success
    # userData: key "McDn" (h221NonStandard)
    gcc_inner += struct.pack("!H", len(gcc_user_data) | 0x8000)  # PER length with high bit
    gcc_inner += b"\x04\x01\x01"  # ConnectGCCPDU choice + key
    gcc_inner += b"McDn"
    gcc_inner += struct.pack("!H", len(gcc_user_data) | 0x8000)
    gcc_inner += gcc_user_data

    # BER: OCTET STRING wrapping GCC data
    gcc_data = b"\x04" + ber_encode_length(len(gcc_inner)) + gcc_inner

    # MCS Connect-Response fields (BER encoded):
    # result: ENUMERATED rt-successful (0)
    result = b"\x0a\x01\x00"
    # calledConnectId: INTEGER 0
    connect_id = b"\x02\x01\x00"
    # domainParameters: SEQUENCE { maxChannelIds=34, maxUserIds=3, ... }
    domain_params = bytes([
        0x30, 0x1a,              # SEQUENCE, length 26
        0x02, 0x01, 0x22,        # maxChannelIds = 34
        0x02, 0x01, 0x03,        # maxUserIds = 3
        0x02, 0x01, 0x00,        # maxTokenIds = 0
        0x02, 0x01, 0x01,        # numPriorities = 1
        0x02, 0x01, 0x00,        # minThroughput = 0
        0x02, 0x01, 0x01,        # maxHeight = 1
        0x02, 0x03, 0x00, 0xff, 0xff,  # maxMCSPDUsize = 65535
        0x02, 0x01, 0x02,        # protocolVersion = 2
    ])

    # userData: OCTET STRING
    inner = result + connect_id + domain_params + gcc_data

    # BER: Application[102] CONNECT-RESPONSE
    mcs_pdu = bytes([0x7F, MCS_CONNECT_RESPONSE]) + ber_encode_length(len(inner)) + inner

    return X224_DATA_HEADER + mcs_pdu
