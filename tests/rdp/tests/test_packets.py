# ABOUTME: Unit tests for RDP packet parsing.
# ABOUTME: Tests TPKT, X.224, MCS, and DOUBLEPULSAR packet structures.

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2025 Cowrie <cowrie@cowrie.org>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial

"""
Unit tests for RDP packet parsing.

Packet hex values are derived from the BSD 3-Clause licensed
WithSecureLabs doublepulsar-detection-script.
"""

import struct
import pytest
import sys
from pathlib import Path

# Add modules path for imports - insert at start to avoid dionaea __init__ issues
rdp_module_path = str(Path(__file__).parent.parent.parent.parent / "modules" / "python" / "dionaea" / "rdp")
sys.path.insert(0, rdp_module_path)

from packets import (
    CS_CORE,
    CS_NET,
    DOUBLEPULSAR_MAGIC,
    DOUBLEPULSAR_PING_RESPONSE_SIZE,
    SC_CORE,
    SC_NET,
    SC_SECURITY,
    DoublePulsarOpcode,
    DoublePulsarPacket,
    RDPNegotiationRequest,
    RDPProtocol,
    TPKTPacket,
    X224Packet,
    X224Type,
    ber_decode_length,
    ber_encode_length,
    build_gcc_server_data,
    build_mcs_connect_response,
    parse_client_info_pdu,
    parse_cs_net_channels,
    parse_gcc_client_core_data,
    parse_gcc_user_data_blocks,
)


class TestTPKTPacket:
    """Tests for TPKT packet parsing."""

    def test_parse_valid_tpkt(self):
        """Test parsing a valid TPKT packet."""
        # TPKT version 3, length 19
        data = bytes.fromhex("030000130ee000000000000100080001000000")
        tpkt = TPKTPacket.parse(data)

        assert tpkt is not None
        assert tpkt.version == 3
        assert tpkt.length == 19
        assert len(tpkt.payload) == 15  # 19 - 4 header bytes

    def test_parse_incomplete_header(self):
        """Test parsing with incomplete header returns None."""
        data = bytes.fromhex("0300")  # Only 2 bytes
        tpkt = TPKTPacket.parse(data)
        assert tpkt is None

    def test_parse_incomplete_payload(self):
        """Test parsing with incomplete payload returns None."""
        # TPKT version 3, length 19, but only 10 bytes total
        data = bytes.fromhex("03000013" + "00" * 6)
        tpkt = TPKTPacket.parse(data)
        assert tpkt is None

    def test_parse_wrong_version(self):
        """Test parsing with wrong version returns None."""
        data = bytes.fromhex("040000130ee000000000000100080001000000")
        tpkt = TPKTPacket.parse(data)
        assert tpkt is None

    def test_build_tpkt(self):
        """Test building a TPKT packet."""
        payload = b"\x01\x02\x03\x04"
        tpkt = TPKTPacket(3, 0, 0, payload)
        result = tpkt.build()

        # Should be: version(1) + reserved(1) + length(2) + payload(4) = 8 bytes
        assert len(result) == 8
        assert result[0] == 3  # Version
        assert result[1] == 0  # Reserved
        assert struct.unpack(">H", result[2:4])[0] == 8  # Length
        assert result[4:] == payload


class TestX224Packet:
    """Tests for X.224 packet parsing."""

    def test_parse_connection_request(self):
        """Test parsing X.224 Connection Request."""
        # X.224 CR: length=14, type=0xe0, dst_ref=0, src_ref=0, class=0
        x224_data = bytes.fromhex("0ee000000000000100080001000000")
        x224 = X224Packet.parse_connection_request(x224_data)

        assert x224 is not None
        assert x224.pdu_type == X224Type.CONNECTION_REQUEST
        assert x224.dst_ref == 0
        assert x224.src_ref == 0

    def test_parse_data_tpdu(self):
        """Test parsing X.224 Data TPDU."""
        # X.224 Data: length=2, type=0xf0, EOT=0x80
        x224_data = bytes.fromhex("02f080" + "1234567890")
        x224 = X224Packet.parse_data(x224_data)

        assert x224 is not None
        assert x224.pdu_type == X224Type.DATA
        assert x224.class_options == 0x80  # EOT flag

    def test_build_connection_confirm_ssl(self):
        """Test building X.224 Connection Confirm with SSL."""
        response = X224Packet.build_connection_confirm(use_ssl=True)

        # Should contain NEG_RSP (0x02) with SSL protocol (0x00000001)
        assert response[7] == 0x02  # NEG_RSP type
        protocol = struct.unpack("<I", response[11:15])[0]
        assert protocol == RDPProtocol.PROTOCOL_SSL

    def test_build_connection_confirm_no_ssl(self):
        """Test building X.224 Connection Confirm without SSL."""
        response = X224Packet.build_connection_confirm(use_ssl=False)

        # Should contain NEG_RSP (0x02) with RDP protocol (0x00000000)
        assert response[7] == 0x02  # NEG_RSP type
        protocol = struct.unpack("<I", response[11:15])[0]
        assert protocol == RDPProtocol.PROTOCOL_RDP


class TestRDPNegotiationRequest:
    """Tests for RDP Negotiation Request parsing."""

    def test_parse_with_ssl_request(self):
        """Test parsing negotiation request with SSL."""
        # NEG_REQ type=1, flags=0, length=8, protocols=1 (SSL)
        payload = bytes.fromhex("01000800" + "01000000")
        neg_req = RDPNegotiationRequest.parse(payload)

        assert neg_req is not None
        assert neg_req.requested_protocols & RDPProtocol.PROTOCOL_SSL

    def test_parse_with_nla_request(self):
        """Test parsing negotiation request with NLA (CredSSP)."""
        # NEG_REQ type=1, flags=0, length=8, protocols=3 (SSL|HYBRID)
        payload = bytes.fromhex("01000800" + "03000000")
        neg_req = RDPNegotiationRequest.parse(payload)

        assert neg_req is not None
        assert neg_req.requested_protocols & RDPProtocol.PROTOCOL_HYBRID

    def test_parse_with_cookie(self):
        """Test parsing negotiation request with cookie."""
        cookie = b"Cookie: mstshash=TestUser\r\n"
        neg_data = bytes.fromhex("01000800" + "01000000")  # NEG_REQ
        payload = cookie + neg_data
        neg_req = RDPNegotiationRequest.parse(payload)

        assert neg_req is not None
        assert neg_req.cookie == "Cookie: mstshash=TestUser"

    def test_parse_no_negotiation(self):
        """Test parsing without negotiation request (legacy RDP)."""
        payload = b""
        neg_req = RDPNegotiationRequest.parse(payload)

        assert neg_req is not None
        assert neg_req.requested_protocols == RDPProtocol.PROTOCOL_RDP


class TestDoublePulsarPacket:
    """Tests for DOUBLEPULSAR packet parsing and building."""

    def test_magic_value(self):
        """Test DOUBLEPULSAR magic value."""
        assert DOUBLEPULSAR_MAGIC == 0x19283744

    def test_parse_ping_packet(self):
        """Test parsing DOUBLEPULSAR ping packet."""
        # channelJoinConfirm (0x3c) + magic + opcode (ping=0x02)
        data = bytes.fromhex("3c" + "19283744" + "0002")
        dp = DoublePulsarPacket.parse(data)

        assert dp is not None
        assert dp.magic == DOUBLEPULSAR_MAGIC
        assert dp.opcode == DoublePulsarOpcode.PING

    def test_parse_exec_packet(self):
        """Test parsing DOUBLEPULSAR exec packet."""
        # channelJoinConfirm (0x3c) + magic + opcode (exec=0x01) + body
        data = bytes.fromhex("3c" + "19283744" + "0001" + "deadbeef")
        dp = DoublePulsarPacket.parse(data)

        assert dp is not None
        assert dp.magic == DOUBLEPULSAR_MAGIC
        assert dp.opcode == DoublePulsarOpcode.EXEC
        assert dp.body == bytes.fromhex("deadbeef")

    def test_parse_burn_packet(self):
        """Test parsing DOUBLEPULSAR burn packet."""
        # channelJoinConfirm (0x3c) + magic + opcode (burn=0x03)
        data = bytes.fromhex("3c" + "19283744" + "0003")
        dp = DoublePulsarPacket.parse(data)

        assert dp is not None
        assert dp.magic == DOUBLEPULSAR_MAGIC
        assert dp.opcode == DoublePulsarOpcode.BURN

    def test_parse_wrong_type(self):
        """Test parsing with wrong packet type returns None."""
        # Wrong type byte (not 0x3c)
        data = bytes.fromhex("3e" + "19283744" + "0002")
        dp = DoublePulsarPacket.parse(data)
        assert dp is None

    def test_parse_wrong_magic(self):
        """Test parsing with wrong magic returns None."""
        # Wrong magic value
        data = bytes.fromhex("3c" + "12345678" + "0002")
        dp = DoublePulsarPacket.parse(data)
        assert dp is None

    def test_build_ping_response(self):
        """Test building DOUBLEPULSAR ping response."""
        response = DoublePulsarPacket.build_ping_response(
            major=6,
            minor=1,
            build=7601,
            service_pack=1,
            product_type=1,
            arch=64,
        )

        # Response should be exactly 288 bytes
        assert len(response) == DOUBLEPULSAR_PING_RESPONSE_SIZE

        # Check OSVERSIONINFOEXW fields
        size = struct.unpack("<I", response[0:4])[0]
        assert size == 284  # dwOSVersionInfoSize

        major = struct.unpack("<I", response[4:8])[0]
        assert major == 6

        minor = struct.unpack("<I", response[8:12])[0]
        assert minor == 1

        build = struct.unpack("<I", response[12:16])[0]
        assert build == 7601

        platform = struct.unpack("<I", response[16:20])[0]
        assert platform == 2  # VER_PLATFORM_WIN32_NT

    def test_build_response_packet(self):
        """Test building complete DOUBLEPULSAR response with TPKT wrapper."""
        body = b"\x01\x02\x03\x04"
        response = DoublePulsarPacket.build_response_packet(
            DoublePulsarOpcode.PING,
            body,
        )

        # Should be TPKT wrapped
        assert response[0] == 3  # TPKT version
        assert response[1] == 0  # Reserved

        # X.224 Data header
        assert response[4] == 2  # X.224 length
        assert response[5] == X224Type.DATA
        assert response[6] == 0x80  # EOT

        # MCS/DOUBLEPULSAR data
        assert response[7] == 0x3e  # channelJoinConfirm response
        magic = struct.unpack(">I", response[8:12])[0]
        assert magic == DOUBLEPULSAR_MAGIC


class TestDetectionScriptPackets:
    """Tests using actual packet data from detection script."""

    # These are the exact packets from the BSD-licensed detection script
    SSL_NEGOTIATION_REQUEST = bytes.fromhex(
        "030000130ee000000000000100080001000000"
    )

    NON_SSL_NEGOTIATION_REQUEST = bytes.fromhex(
        "030000130ee000000000000100080000000000"
    )

    PING_PACKET = bytes.fromhex(
        "0300000e02f0803c443728190200"
    )

    def test_parse_ssl_negotiation_request(self):
        """Test parsing SSL negotiation request from detection script."""
        tpkt = TPKTPacket.parse(self.SSL_NEGOTIATION_REQUEST)
        assert tpkt is not None
        assert tpkt.version == 3
        assert tpkt.length == 19

    def test_parse_non_ssl_negotiation_request(self):
        """Test parsing non-SSL negotiation request from detection script."""
        tpkt = TPKTPacket.parse(self.NON_SSL_NEGOTIATION_REQUEST)
        assert tpkt is not None
        assert tpkt.version == 3
        assert tpkt.length == 19

    def test_parse_ping_packet(self):
        """Test parsing DOUBLEPULSAR ping from detection script."""
        tpkt = TPKTPacket.parse(self.PING_PACKET)
        assert tpkt is not None
        assert tpkt.version == 3

        # The X.224 Data header is at the start of payload
        x224 = X224Packet.parse_data(tpkt.payload)
        assert x224 is not None

        # After X.224, we have the DOUBLEPULSAR packet
        # Note: detection script uses little-endian magic 0x44372819
        # which is the same bytes as big-endian 0x19283744
        dp_data = x224.payload
        assert dp_data[0] == 0x3c  # channelJoinConfirm

        # Magic is stored differently in detection script (LE vs BE)
        # 0x44372819 LE = bytes [19 28 37 44] = 0x19283744 BE
        magic_bytes = dp_data[1:5]
        assert magic_bytes == bytes.fromhex("44372819")


class TestCSNetChannels:
    """Tests for CS_NET channel name parsing."""

    @staticmethod
    def _build_cs_net_data(channel_names):
        """Build raw CS_NET block payload (after type+length header)."""
        body = struct.pack('<I', len(channel_names))
        for name in channel_names:
            # CHANNEL_DEF: name (8 bytes, null-padded) + options (4 bytes)
            name_bytes = name.encode('ascii')[:7].ljust(8, b'\x00')
            body += name_bytes + struct.pack('<I', 0)  # options=0
        return body

    def test_parse_channel_names(self):
        data = self._build_cs_net_data(["cliprdr", "rdpdr", "rdpsnd"])
        channels = parse_cs_net_channels(data)
        assert channels == ["cliprdr", "rdpdr", "rdpsnd"]

    def test_parse_no_channels(self):
        data = self._build_cs_net_data([])
        channels = parse_cs_net_channels(data)
        assert channels == []

    def test_parse_single_channel(self):
        data = self._build_cs_net_data(["cliprdr"])
        channels = parse_cs_net_channels(data)
        assert channels == ["cliprdr"]

    def test_parse_too_short(self):
        channels = parse_cs_net_channels(b"\x00")
        assert channels == []

    def test_parse_truncated_channel_data(self):
        """Count says 3 channels but data only has 1."""
        body = struct.pack('<I', 3)
        name_bytes = b"cliprdr\x00"
        body += name_bytes + struct.pack('<I', 0)
        channels = parse_cs_net_channels(body)
        assert channels == ["cliprdr"]


class TestBER:
    """Tests for BER encoding/decoding utilities."""

    def test_encode_short_length(self):
        assert ber_encode_length(0) == b"\x00"
        assert ber_encode_length(127) == b"\x7f"

    def test_encode_medium_length(self):
        assert ber_encode_length(128) == b"\x81\x80"
        assert ber_encode_length(255) == b"\x81\xff"

    def test_encode_long_length(self):
        assert ber_encode_length(256) == b"\x82\x01\x00"
        assert ber_encode_length(1000) == b"\x82\x03\xe8"

    def test_decode_short_length(self):
        length, offset = ber_decode_length(b"\x42rest", 0)
        assert length == 0x42
        assert offset == 1

    def test_decode_medium_length(self):
        length, offset = ber_decode_length(b"\x81\x80rest", 0)
        assert length == 128
        assert offset == 2

    def test_decode_long_length(self):
        length, offset = ber_decode_length(b"\x82\x01\x00rest", 0)
        assert length == 256
        assert offset == 3

    def test_round_trip(self):
        for n in [0, 1, 127, 128, 255, 256, 1000, 65535]:
            encoded = ber_encode_length(n)
            decoded, end = ber_decode_length(encoded, 0)
            assert decoded == n
            assert end == len(encoded)


class TestGCCUserDataBlocks:
    """Tests for GCC user data block parsing."""

    def test_parse_blocks(self):
        block1 = struct.pack('<HH', CS_CORE, 8) + b"\x01\x02\x03\x04"
        block2 = struct.pack('<HH', CS_NET, 6) + b"\xAA\xBB"
        blocks = parse_gcc_user_data_blocks(block1 + block2)
        assert CS_CORE in blocks
        assert CS_NET in blocks
        assert blocks[CS_CORE] == b"\x01\x02\x03\x04"
        assert blocks[CS_NET] == b"\xAA\xBB"

    def test_parse_empty(self):
        assert parse_gcc_user_data_blocks(b"") == {}

    def test_parse_truncated_block(self):
        data = struct.pack('<HH', CS_CORE, 100) + b"\x00" * 10
        assert parse_gcc_user_data_blocks(data) == {}


class TestGCCClientCoreDataParsing:
    """Tests for TS_UD_CS_CORE parsing."""

    @staticmethod
    def _build_core_data(
        width=1920, height=1080,
        keyboard_layout=0x0409, client_build=19041,
        client_name="WIN-TEST123",
    ) -> bytes:
        name_bytes = client_name.encode('utf-16-le')[:32].ljust(32, b'\x00')
        buf = struct.pack('<HHHHHHII', 4, 8, width, height, 0xCA01, 0xAA03, keyboard_layout, client_build)
        buf += name_bytes
        buf += struct.pack('<III', 4, 0, 12)  # keyboard type/subtype/function_keys
        buf = buf.ljust(128, b'\x00')
        return buf

    def test_parse_core_data(self):
        data = self._build_core_data()
        result = parse_gcc_client_core_data(data)
        assert result is not None
        assert result.desktop_width == 1920
        assert result.desktop_height == 1080
        assert result.client_build == 19041
        assert result.client_name == "WIN-TEST123"
        assert result.keyboard_layout == 0x0409

    def test_parse_core_data_too_short(self):
        assert parse_gcc_client_core_data(b"\x00" * 50) is None


class TestMCSConnectResponse:
    """Tests for MCS Connect-Response building."""

    def test_build_gcc_server_data_contains_all_blocks(self):
        channels = [1004, 1005]
        data = build_gcc_server_data(channel_ids=channels)
        blocks = parse_gcc_user_data_blocks(data)
        assert SC_CORE in blocks
        assert SC_SECURITY in blocks
        assert SC_NET in blocks
        net_data = blocks[SC_NET]
        mcs_channel_id, channel_count = struct.unpack_from('<HH', net_data, 0)
        assert mcs_channel_id == 0x03EB
        assert channel_count == 2

    def test_build_mcs_connect_response_structure(self):
        response = build_mcs_connect_response(channel_ids=[1004])
        # X.224 Data header
        assert response[:3] == bytes([0x02, 0xF0, 0x80])
        # BER Application[102] tag
        assert response[3] == 0x7F
        assert response[4] == 0x66

    def test_build_mcs_connect_response_ber_length_valid(self):
        """BER outer length matches actual content."""
        response = build_mcs_connect_response(channel_ids=[1004, 1005])
        # Skip X.224 header (3 bytes) + tag (2 bytes)
        _length, end = ber_decode_length(response, 5)
        assert end + _length == len(response)

    def test_build_mcs_connect_response_no_channels(self):
        response = build_mcs_connect_response(channel_ids=[])
        assert response[3] == 0x7F
        assert response[4] == 0x66


class TestClientInfoPDU:
    """Tests for TS_INFO_PACKET parsing."""

    @staticmethod
    def _build_client_info(
        domain="WORKGROUP", username="administrator",
        password="P@ssw0rd", alt_shell="", working_dir="",
    ) -> bytes:
        domain_bytes = domain.encode("utf-16-le") + b"\x00\x00"
        user_bytes = username.encode("utf-16-le") + b"\x00\x00"
        pass_bytes = password.encode("utf-16-le") + b"\x00\x00"
        shell_bytes = alt_shell.encode("utf-16-le") + b"\x00\x00"
        dir_bytes = working_dir.encode("utf-16-le") + b"\x00\x00"

        flags = 0x00000033  # INFO_MOUSE | INFO_UNICODE | INFO_LOGONNOTIFY | INFO_MAXIMIZESHELL
        header = struct.pack("<II HHHHH",
            0, flags,
            len(domain_bytes) - 2, len(user_bytes) - 2, len(pass_bytes) - 2,
            len(shell_bytes) - 2, len(dir_bytes) - 2,
        )
        return header + domain_bytes + user_bytes + pass_bytes + shell_bytes + dir_bytes

    def test_parse_client_info(self):
        data = self._build_client_info()
        info = parse_client_info_pdu(data)
        assert info is not None
        assert info.domain == "WORKGROUP"
        assert info.username == "administrator"
        assert info.password == "P@ssw0rd"

    def test_parse_different_credentials(self):
        data = self._build_client_info(domain="CORP", username="admin", password="secret123")
        info = parse_client_info_pdu(data)
        assert info is not None
        assert info.domain == "CORP"
        assert info.username == "admin"
        assert info.password == "secret123"

    def test_parse_empty_password(self):
        data = self._build_client_info(password="")
        info = parse_client_info_pdu(data)
        assert info is not None
        assert info.password == ""

    def test_parse_too_short(self):
        assert parse_client_info_pdu(b"\x00" * 10) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
