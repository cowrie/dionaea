# ABOUTME: Unit tests for RDP wire format parsers and builders.
# ABOUTME: Verifies TPKT, X.224, and MCS packet handling against known byte sequences.

from __future__ import annotations

import struct
import pytest

from dionaea.rdp.include.packets import (
    TPKT_VERSION,
    parse_tpkt,
    build_tpkt,
    X224_TYPE_CR,
    X224_TYPE_CC,
    PROTOCOL_RDP,
    PROTOCOL_SSL,
    PROTOCOL_HYBRID,
    RDP_NEG_REQ,
    parse_x224_cr,
    build_x224_cc,
    ber_encode_length,
    ber_decode_length,
    parse_gcc_client_core_data,
    parse_gcc_user_data_blocks,
    CS_CORE,
    CS_SECURITY,
    CS_NET,
    SC_CORE,
    SC_SECURITY,
    SC_NET,
    MCS_CONNECT_RESPONSE,
    MCS_ERECT_DOMAIN,
    MCS_ATTACH_USER_REQ,
    X224_DATA_HEADER,
    parse_mcs_erect_domain,
    parse_mcs_attach_user_request,
    build_mcs_attach_user_confirm,
    parse_mcs_channel_join_request,
    build_mcs_channel_join_confirm,
    build_mcs_connect_response,
    build_gcc_server_data,
)


# ---------------------------------------------------------------------------
# TPKT tests
# ---------------------------------------------------------------------------

class TestTPKT:
    def test_parse_tpkt_valid(self):
        data = struct.pack("!BBH", 3, 0, 42)
        result = parse_tpkt(data)
        assert result == (3, 42)

    def test_parse_tpkt_incomplete(self):
        assert parse_tpkt(b"\x03\x00") is None
        assert parse_tpkt(b"") is None

    def test_build_tpkt(self):
        payload = b"\xAB\xCD"
        pkt = build_tpkt(payload)
        assert pkt[:4] == struct.pack("!BBH", 3, 0, 6)
        assert pkt[4:] == payload

    def test_round_trip(self):
        payload = b"hello"
        pkt = build_tpkt(payload)
        version, length = parse_tpkt(pkt)
        assert version == TPKT_VERSION
        assert length == len(pkt)
        assert pkt[4:] == payload


# ---------------------------------------------------------------------------
# X.224 tests
# ---------------------------------------------------------------------------

class TestX224:
    def _build_cr(self, cookie: bytes = b"", requested_protocols: int = 0) -> bytes:
        """Build a raw X.224 Connection Request payload (without TPKT)."""
        variable = b""
        if cookie:
            variable += cookie + b"\r\n"

        # RDP Negotiation Request
        neg_req = struct.pack("<BBH I", RDP_NEG_REQ, 0x00, 8, requested_protocols)
        variable += neg_req

        # Fixed header: length_indicator, type=CR, dst_ref=0, src_ref=0, class=0
        li = 6 + len(variable)
        header = struct.pack("!BBHHB", li, X224_TYPE_CR, 0, 0, 0)
        return header + variable

    def test_parse_cr_with_cookie_and_nla(self):
        cr = self._build_cr(
            cookie=b"Cookie: mstshash=administrator",
            requested_protocols=PROTOCOL_HYBRID | PROTOCOL_SSL,
        )
        result = parse_x224_cr(cr)
        assert result is not None
        assert result.cookie == "Cookie: mstshash=administrator"
        assert result.requested_protocols == (PROTOCOL_HYBRID | PROTOCOL_SSL)

    def test_parse_cr_no_cookie(self):
        cr = self._build_cr(requested_protocols=PROTOCOL_RDP)
        result = parse_x224_cr(cr)
        assert result is not None
        assert result.cookie == ""
        assert result.requested_protocols == PROTOCOL_RDP

    def test_parse_cr_cookie_only_no_neg(self):
        # Cookie but no negotiation request
        cookie = b"Cookie: mstshash=test"
        variable = cookie + b"\r\n"
        li = 6 + len(variable)
        header = struct.pack("!BBHHB", li, X224_TYPE_CR, 0, 0, 0)
        cr = header + variable
        result = parse_x224_cr(cr)
        assert result is not None
        assert result.cookie == "Cookie: mstshash=test"
        assert result.requested_protocols == PROTOCOL_RDP  # default

    def test_parse_cr_too_short(self):
        assert parse_x224_cr(b"\x00\x01\x02") is None

    def test_parse_cr_wrong_type(self):
        # Build with CC type instead of CR
        header = struct.pack("!BBHHB", 6, X224_TYPE_CC, 0, 0, 0)
        assert parse_x224_cr(header) is None

    def test_build_cc(self):
        cc = build_x224_cc(PROTOCOL_RDP)
        # Should start with length indicator, type CC
        assert cc[1] == X224_TYPE_CC
        # Should contain neg response with PROTOCOL_RDP
        assert struct.unpack("<I", cc[-4:])[0] == PROTOCOL_RDP

    def test_build_cc_ssl(self):
        cc = build_x224_cc(PROTOCOL_SSL)
        assert struct.unpack("<I", cc[-4:])[0] == PROTOCOL_SSL


# ---------------------------------------------------------------------------
# BER encoding tests
# ---------------------------------------------------------------------------

class TestBER:
    def test_encode_short_length(self):
        assert ber_encode_length(0) == b"\x00"
        assert ber_encode_length(127) == b"\x7f"

    def test_encode_medium_length(self):
        result = ber_encode_length(128)
        assert result == b"\x81\x80"
        result = ber_encode_length(255)
        assert result == b"\x81\xff"

    def test_encode_long_length(self):
        result = ber_encode_length(256)
        assert result == b"\x82\x01\x00"
        result = ber_encode_length(1000)
        assert result == b"\x82\x03\xe8"

    def test_decode_short_length(self):
        data = b"\x42rest"
        length, offset = ber_decode_length(data, 0)
        assert length == 0x42
        assert offset == 1

    def test_decode_medium_length(self):
        data = b"\x81\x80rest"
        length, offset = ber_decode_length(data, 0)
        assert length == 128
        assert offset == 2

    def test_decode_long_length(self):
        data = b"\x82\x01\x00rest"
        length, offset = ber_decode_length(data, 0)
        assert length == 256
        assert offset == 3

    def test_round_trip(self):
        for n in [0, 1, 127, 128, 255, 256, 1000, 65535]:
            encoded = ber_encode_length(n)
            decoded, end = ber_decode_length(encoded, 0)
            assert decoded == n
            assert end == len(encoded)


# ---------------------------------------------------------------------------
# GCC User Data Block tests
# ---------------------------------------------------------------------------

class TestGCCUserData:
    def test_parse_blocks(self):
        # Build two blocks: CS_CORE with 4 bytes, CS_NET with 2 bytes
        block1 = struct.pack("<HH", CS_CORE, 8) + b"\x01\x02\x03\x04"
        block2 = struct.pack("<HH", CS_NET, 6) + b"\xAA\xBB"
        data = block1 + block2

        blocks = parse_gcc_user_data_blocks(data)
        assert CS_CORE in blocks
        assert CS_NET in blocks
        assert blocks[CS_CORE] == b"\x01\x02\x03\x04"
        assert blocks[CS_NET] == b"\xAA\xBB"

    def test_parse_empty(self):
        assert parse_gcc_user_data_blocks(b"") == {}

    def test_parse_truncated_block(self):
        # Block claims 100 bytes but data is shorter
        data = struct.pack("<HH", CS_CORE, 100) + b"\x00" * 10
        blocks = parse_gcc_user_data_blocks(data)
        assert blocks == {}


class TestGCCClientCoreData:
    def _build_core_data(
        self,
        version_major=4,
        version_minor=8,
        width=1920,
        height=1080,
        color_depth=0xCA01,
        sas_sequence=0xAA03,
        keyboard_layout=0x00000409,
        client_build=19041,
        client_name="WIN-TEST123",
        keyboard_type=4,
        keyboard_subtype=0,
        keyboard_function_keys=12,
    ) -> bytes:
        """Build a TS_UD_CS_CORE data block."""
        name_bytes = client_name.encode("utf-16-le")
        # Pad/truncate to 32 bytes
        name_bytes = name_bytes[:32].ljust(32, b"\x00")

        buf = struct.pack("<HHHHHHII",
            version_major, version_minor,
            width, height,
            color_depth, sas_sequence,
            keyboard_layout, client_build,
        )
        buf += name_bytes
        buf += struct.pack("<III", keyboard_type, keyboard_subtype, keyboard_function_keys)
        # Pad to minimum 128 bytes
        buf = buf.ljust(128, b"\x00")
        return buf

    def test_parse_core_data(self):
        data = self._build_core_data()
        result = parse_gcc_client_core_data(data)
        assert result is not None
        assert result.desktop_width == 1920
        assert result.desktop_height == 1080
        assert result.client_build == 19041
        assert result.client_name == "WIN-TEST123"
        assert result.keyboard_type == 4
        assert result.keyboard_layout == 0x0409

    def test_parse_core_data_different_name(self):
        data = self._build_core_data(client_name="ATTACKER-PC", width=1024, height=768)
        result = parse_gcc_client_core_data(data)
        assert result is not None
        assert result.client_name == "ATTACKER-PC"
        assert result.desktop_width == 1024
        assert result.desktop_height == 768

    def test_parse_core_data_too_short(self):
        assert parse_gcc_client_core_data(b"\x00" * 50) is None


# ---------------------------------------------------------------------------
# MCS PDU tests
# ---------------------------------------------------------------------------

class TestMCSPDUs:
    def test_parse_erect_domain(self):
        payload = X224_DATA_HEADER + bytes([MCS_ERECT_DOMAIN, 0x00, 0x01, 0x00, 0x01])
        assert parse_mcs_erect_domain(payload) is True

    def test_parse_erect_domain_wrong_type(self):
        payload = X224_DATA_HEADER + bytes([0x99, 0x00])
        assert parse_mcs_erect_domain(payload) is False

    def test_parse_attach_user_request(self):
        payload = X224_DATA_HEADER + bytes([MCS_ATTACH_USER_REQ])
        assert parse_mcs_attach_user_request(payload) is True

    def test_build_attach_user_confirm(self):
        result = build_mcs_attach_user_confirm(1007)
        assert result[:3] == X224_DATA_HEADER
        user_id = struct.unpack("!H", result[5:7])[0]
        assert user_id == 1007

    def test_parse_channel_join_request(self):
        payload = X224_DATA_HEADER + struct.pack("!BHH", 0x38, 1007, 1003)
        result = parse_mcs_channel_join_request(payload)
        assert result is not None
        assert result.user_id == 1007
        assert result.channel_id == 1003

    def test_parse_channel_join_request_too_short(self):
        assert parse_mcs_channel_join_request(b"\x02\xF0\x80\x38") is None

    def test_build_channel_join_confirm(self):
        result = build_mcs_channel_join_confirm(1007, 1003)
        assert result[:3] == X224_DATA_HEADER
        # Parse it back: tag(B) + result(B) + initiator(H) + requested(H) + channelId(H)
        tag, res, user_id, requested, channel_id = struct.unpack("!BBHHH", result[3:12])
        assert tag == 0x3E
        assert res == 0x00
        assert user_id == 1007
        assert requested == 1003
        assert channel_id == 1003


# ---------------------------------------------------------------------------
# MCS Connect-Response / GCC Server Data tests
# ---------------------------------------------------------------------------

class TestMCSConnectResponse:
    def test_build_gcc_server_data(self):
        channels = [1004, 1005, 1006]
        data = build_gcc_server_data(
            selected_protocol=PROTOCOL_RDP,
            channel_ids=channels,
        )
        # Should contain SC_CORE, SC_SECURITY, SC_NET blocks
        blocks = parse_gcc_user_data_blocks(data)
        assert SC_CORE in blocks
        assert SC_SECURITY in blocks
        assert SC_NET in blocks
        # SC_NET should contain the channel count and channel IDs
        net_data = blocks[SC_NET]
        mcs_channel_id, channel_count = struct.unpack_from("<HH", net_data, 0)
        assert mcs_channel_id == 0x03EB  # IO channel = 1003
        assert channel_count == len(channels)

    def test_build_mcs_connect_response(self):
        channels = [1004, 1005]
        response = build_mcs_connect_response(
            selected_protocol=PROTOCOL_RDP,
            channel_ids=channels,
        )
        # Should start with X.224 Data header
        assert response[:3] == X224_DATA_HEADER
        # Next bytes: BER Application[102] tag
        assert response[3] == 0x7F
        assert response[4] == MCS_CONNECT_RESPONSE

    def test_build_mcs_connect_response_no_channels(self):
        response = build_mcs_connect_response(
            selected_protocol=PROTOCOL_RDP,
            channel_ids=[],
        )
        assert response[:3] == X224_DATA_HEADER
        assert response[3] == 0x7F
        assert response[4] == MCS_CONNECT_RESPONSE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
