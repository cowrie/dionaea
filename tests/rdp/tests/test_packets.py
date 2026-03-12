# ABOUTME: Unit tests for RDP packet parsing.
# ABOUTME: Tests TPKT, X.224, MCS, and DOUBLEPULSAR packet structures.

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2025 Michel
#
# SPDX-License-Identifier: GPL-2.0-or-later

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
    DOUBLEPULSAR_MAGIC,
    DOUBLEPULSAR_PING_RESPONSE_SIZE,
    DoublePulsarOpcode,
    DoublePulsarPacket,
    RDPNegotiationRequest,
    RDPProtocol,
    TPKTPacket,
    X224Packet,
    X224Type,
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


class TestGCCClientData:
    """Tests for GCC Client Data parsing."""

    @staticmethod
    def _build_cs_core(
        desktop_width=1920,
        desktop_height=1080,
        color_depth=0xca01,
        keyboard_layout=0x0409,
        client_build=2600,
        client_name="TESTPC",
    ):
        """Build a CS_CORE (0xc001) block for testing."""
        core = struct.pack('<I', 0x00080004)  # version (RDP 5.0+)
        core += struct.pack('<H', desktop_width)
        core += struct.pack('<H', desktop_height)
        core += struct.pack('<H', color_depth)
        core += struct.pack('<H', 0)  # SASSequence
        core += struct.pack('<I', keyboard_layout)
        core += struct.pack('<I', client_build)
        name_bytes = client_name.encode('utf-16-le')
        core += name_bytes.ljust(32, b'\x00')  # clientName (32 bytes)
        # Pad remaining fields to reach at least 134 bytes of core data
        # After clientName (offset 52): keyboardType(4), keyboardSubType(4),
        # keyboardFunctionKey(4), imeFileName(64), postBeta2ColorDepth(2),
        # clientProductId(2)
        core += b'\x00' * 4  # keyboardType
        core += b'\x00' * 4  # keyboardSubType
        core += b'\x00' * 4  # keyboardFunctionKey
        core += b'\x00' * 64  # imeFileName
        core += struct.pack('<H', 0)  # postBeta2ColorDepth
        core += struct.pack('<H', 1)  # clientProductId
        core += struct.pack('<I', 0)  # serialNumber
        # Total core_data is now 136 bytes (>= 134 required by parser)
        header = struct.pack('<HH', 0xc001, 4 + len(core))
        return header + core

    @staticmethod
    def _build_cs_net(channel_names):
        """Build a CS_NET (0xc003) block with channel names."""
        body = struct.pack('<I', len(channel_names))
        for name in channel_names:
            # CHANNEL_DEF: name (8 bytes, null-padded) + options (4 bytes)
            name_bytes = name.encode('ascii')[:7].ljust(8, b'\x00')
            body += name_bytes + struct.pack('<I', 0)  # options=0
        header = struct.pack('<HH', 0xc003, 4 + len(body))
        return header + body

    @staticmethod
    def _wrap_gcc(blocks_data):
        """Wrap block data with 'Duca' header and PER length for GCC user data."""
        length = len(blocks_data)
        if length < 128:
            per_len = bytes([length])
        else:
            per_len = bytes([0x80 | (length >> 8), length & 0xFF])
        return b'Duca' + per_len + blocks_data

    def test_parse_desktop_dimensions(self):
        """Test extracting desktop width and height from CS_CORE."""
        from packets import GCCClientData

        cs_core = self._build_cs_core(desktop_width=1920, desktop_height=1080)
        user_data = self._wrap_gcc(cs_core)
        gcc = GCCClientData.parse(user_data)

        assert gcc is not None
        assert gcc.desktop_width == 1920
        assert gcc.desktop_height == 1080

    def test_parse_channel_names(self):
        """Test extracting virtual channel names from CS_NET."""
        from packets import GCCClientData

        cs_core = self._build_cs_core()
        cs_net = self._build_cs_net(["cliprdr", "rdpdr", "rdpsnd"])
        user_data = self._wrap_gcc(cs_core + cs_net)
        gcc = GCCClientData.parse(user_data)

        assert gcc is not None
        assert "cliprdr" in gcc.requested_channels
        assert "rdpdr" in gcc.requested_channels
        assert "rdpsnd" in gcc.requested_channels

    def test_parse_no_cs_net(self):
        """Test parsing without CS_NET block returns empty channels."""
        from packets import GCCClientData

        cs_core = self._build_cs_core()
        user_data = self._wrap_gcc(cs_core)
        gcc = GCCClientData.parse(user_data)

        assert gcc is not None
        assert gcc.requested_channels == []

    def test_parse_empty_cs_net(self):
        """Test parsing CS_NET with zero channels."""
        from packets import GCCClientData

        cs_core = self._build_cs_core()
        cs_net = self._build_cs_net([])
        user_data = self._wrap_gcc(cs_core + cs_net)
        gcc = GCCClientData.parse(user_data)

        assert gcc is not None
        assert gcc.requested_channels == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
