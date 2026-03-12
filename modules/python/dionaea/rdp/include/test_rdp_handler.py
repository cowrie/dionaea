# ABOUTME: Unit tests for the RDP protocol state machine.
# ABOUTME: Tests TPKT framing, X.224 handshake, and MCS negotiation flow.

import struct
import pytest

from dionaea.rdp.include.packets import (
    TPKT_HEADER_LEN,
    PROTOCOL_RDP,
    PROTOCOL_SSL,
    PROTOCOL_HYBRID,
    RDP_NEG_REQ,
    X224_TYPE_CR,
    X224_TYPE_CC,
    X224_DATA_HEADER,
    MCS_ERECT_DOMAIN,
    MCS_ATTACH_USER_REQ,
    MCS_ATTACH_USER_CONFIRM,
    MCS_CHANNEL_JOIN_REQ,
    MCS_CHANNEL_JOIN_CONFIRM,
    MCS_CONNECT_RESPONSE,
    build_tpkt,
    parse_tpkt,
    parse_x224_cr,
)
from dionaea.rdp.rdp import RdpStateMachine, RdpState


# ---------------------------------------------------------------------------
# Helpers for building client messages
# ---------------------------------------------------------------------------

def build_x224_cr_packet(
    cookie: bytes = b"",
    requested_protocols: int = PROTOCOL_RDP,
) -> bytes:
    """Build a complete TPKT + X.224 Connection Request."""
    variable = b""
    if cookie:
        variable += cookie + b"\r\n"
    neg_req = struct.pack("<BBH I", RDP_NEG_REQ, 0x00, 8, requested_protocols)
    variable += neg_req
    li = 6 + len(variable)
    header = struct.pack("!BBHHB", li, X224_TYPE_CR, 0, 0, 0)
    return build_tpkt(header + variable)


def build_mcs_connect_initial_packet() -> bytes:
    """Build a minimal MCS Connect-Initial with GCC client data.

    This is a simplified version — enough to trigger the state machine
    transition without being a fully valid MCS PDU.
    """
    # We need: X.224 Data header + BER Application[101] + GCC with "Duca" key
    # Build a minimal client core data block
    core_data = struct.pack("<HHHHHHII",
        4, 8,          # version
        1920, 1080,    # desktop size
        0xCA01, 0xAA03,  # color depth, SAS sequence
        0x00000409, 19041,  # keyboard layout, client build
    )
    # Client name (32 bytes) + keyboard info (12 bytes)
    core_data += b"W\x00I\x00N\x00-\x00T\x00E\x00S\x00T\x00" + b"\x00" * 16
    core_data += struct.pack("<III", 4, 0, 12)
    core_data = core_data.ljust(128, b"\x00")

    # Wrap in CS_CORE block
    cs_core = struct.pack("<HH", 0xC001, 4 + len(core_data)) + core_data

    # GCC user data with "Duca" key
    gcc_user_data = cs_core
    per_length = struct.pack("!H", len(gcc_user_data) | 0x8000)
    gcc = b"\x00\x05\x00\x14\x7c\x00\x01"  # T.124 key
    gcc += b"\x81\x00"  # PER length (placeholder, 2 bytes)
    gcc += b"\x00\x08"  # conference name + selection
    gcc += b"\x00\x10\x00\x01\x04\x01\x01"  # h221NonStandard header
    gcc += b"Duca"
    gcc += per_length
    gcc += gcc_user_data

    # BER: OCTET STRING wrapping gcc
    user_data_ber = b"\x04" + _ber_len(len(gcc)) + gcc

    # Three OCTET STRINGS (callingDomainSelector, calledDomainSelector, upwardFlag)
    octet_strings = b""
    for _ in range(3):
        octet_strings += b"\x04\x01\x01"

    # Three SEQUENCEs (target, minimum, maximum domain parameters)
    seq = bytes([
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
    sequences = seq * 3

    # Combine into Connect-Initial body
    ci_body = octet_strings + sequences + user_data_ber

    # BER: Application[101] (0x7F 0x65) + length
    mcs_ci = b"\x7f\x65" + _ber_len(len(ci_body)) + ci_body

    return build_tpkt(X224_DATA_HEADER + mcs_ci)


def build_erect_domain_packet() -> bytes:
    """Build MCS ErectDomainRequest."""
    payload = X224_DATA_HEADER + bytes([MCS_ERECT_DOMAIN, 0x00, 0x01, 0x00, 0x01])
    return build_tpkt(payload)


def build_attach_user_request_packet() -> bytes:
    """Build MCS AttachUserRequest."""
    payload = X224_DATA_HEADER + bytes([MCS_ATTACH_USER_REQ])
    return build_tpkt(payload)


def build_channel_join_request_packet(user_id: int, channel_id: int) -> bytes:
    """Build MCS ChannelJoinRequest."""
    payload = X224_DATA_HEADER + struct.pack("!BHH", MCS_CHANNEL_JOIN_REQ, user_id, channel_id)
    return build_tpkt(payload)


def _ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82]) + struct.pack("!H", length)


# ---------------------------------------------------------------------------
# State Machine tests
# ---------------------------------------------------------------------------

class TestRdpStateMachine:
    def test_initial_state(self):
        sm = RdpStateMachine()
        assert sm.state == RdpState.X224_NEGOTIATION

    def test_x224_cr_produces_cc(self):
        sm = RdpStateMachine()
        pkt = build_x224_cr_packet(
            cookie=b"Cookie: mstshash=admin",
            requested_protocols=PROTOCOL_RDP,
        )
        consumed, responses = sm.feed(pkt)
        assert consumed == len(pkt)
        assert len(responses) == 1
        # Response should be a TPKT-wrapped X.224 CC
        version, length = parse_tpkt(responses[0])
        assert version == 3
        assert length == len(responses[0])
        # X.224 CC type byte at offset 5 (TPKT=4, skip LI byte)
        assert responses[0][5] == X224_TYPE_CC
        # State should advance
        assert sm.state == RdpState.MCS_CONNECT

    def test_x224_cr_captures_cookie(self):
        sm = RdpStateMachine()
        pkt = build_x224_cr_packet(cookie=b"Cookie: mstshash=administrator")
        sm.feed(pkt)
        assert sm.cookie == "Cookie: mstshash=administrator"

    def test_x224_cr_captures_requested_protocols(self):
        sm = RdpStateMachine()
        pkt = build_x224_cr_packet(requested_protocols=PROTOCOL_HYBRID | PROTOCOL_SSL)
        sm.feed(pkt)
        assert sm.requested_protocols == (PROTOCOL_HYBRID | PROTOCOL_SSL)

    def test_incomplete_tpkt_returns_zero(self):
        sm = RdpStateMachine()
        # Send only 2 bytes of a 4-byte TPKT header
        consumed, responses = sm.feed(b"\x03\x00")
        assert consumed == 0
        assert responses == []

    def test_partial_tpkt_payload_returns_zero(self):
        sm = RdpStateMachine()
        # TPKT header says length=100 but only 10 bytes total
        data = struct.pack("!BBH", 3, 0, 100) + b"\x00" * 6
        consumed, responses = sm.feed(data)
        assert consumed == 0
        assert responses == []

    def test_mcs_connect_initial_produces_response(self):
        sm = RdpStateMachine()
        # First: X.224 handshake
        cr = build_x224_cr_packet()
        sm.feed(cr)
        assert sm.state == RdpState.MCS_CONNECT

        # Now: MCS Connect-Initial
        ci = build_mcs_connect_initial_packet()
        consumed, responses = sm.feed(ci)
        assert consumed == len(ci)
        assert len(responses) == 1
        # Should be TPKT-wrapped MCS Connect-Response
        version, length = parse_tpkt(responses[0])
        assert version == 3
        assert sm.state == RdpState.MCS_ERECT_DOMAIN

    def test_erect_domain_accepted(self):
        sm = RdpStateMachine()
        sm.feed(build_x224_cr_packet())
        sm.feed(build_mcs_connect_initial_packet())
        assert sm.state == RdpState.MCS_ERECT_DOMAIN

        consumed, responses = sm.feed(build_erect_domain_packet())
        assert consumed > 0
        assert responses == []  # No response for ErectDomain
        assert sm.state == RdpState.MCS_ATTACH_USER

    def test_attach_user_produces_confirm(self):
        sm = RdpStateMachine()
        sm.feed(build_x224_cr_packet())
        sm.feed(build_mcs_connect_initial_packet())
        sm.feed(build_erect_domain_packet())
        assert sm.state == RdpState.MCS_ATTACH_USER

        consumed, responses = sm.feed(build_attach_user_request_packet())
        assert consumed > 0
        assert len(responses) == 1
        # Response should contain AttachUserConfirm
        resp_payload = responses[0][TPKT_HEADER_LEN:]
        assert resp_payload[:3] == X224_DATA_HEADER
        assert resp_payload[3] == MCS_ATTACH_USER_CONFIRM
        assert sm.state == RdpState.MCS_CHANNEL_JOIN
        assert sm.user_id is not None

    def test_channel_join_produces_confirms(self):
        sm = RdpStateMachine()
        sm.feed(build_x224_cr_packet())
        sm.feed(build_mcs_connect_initial_packet())
        sm.feed(build_erect_domain_packet())
        sm.feed(build_attach_user_request_packet())
        assert sm.state == RdpState.MCS_CHANNEL_JOIN

        user_id = sm.user_id
        # Join the user channel
        consumed, responses = sm.feed(
            build_channel_join_request_packet(user_id, user_id)
        )
        assert consumed > 0
        assert len(responses) == 1
        # Should still be in channel join state (IO channel not yet joined)
        assert sm.state == RdpState.MCS_CHANNEL_JOIN

        # Join the IO channel (1003)
        consumed, responses = sm.feed(
            build_channel_join_request_packet(user_id, 0x03EB)
        )
        assert consumed > 0
        assert len(responses) == 1
        # After joining IO channel, advance to security exchange
        assert sm.state == RdpState.SECURITY_EXCHANGE

    def test_multiple_tpkt_in_one_buffer(self):
        sm = RdpStateMachine()
        # Concatenate two packets
        pkt1 = build_x224_cr_packet()
        pkt2 = build_mcs_connect_initial_packet()
        data = pkt1 + pkt2
        consumed, responses = sm.feed(data)
        # Should consume both
        assert consumed == len(data)
        assert len(responses) == 2  # CC + Connect-Response
        assert sm.state == RdpState.MCS_ERECT_DOMAIN


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
