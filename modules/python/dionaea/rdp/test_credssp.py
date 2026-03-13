# ABOUTME: Tests for CredSSP TSRequest and NTLMSSP Negotiate parsers.
# ABOUTME: Validates extraction of client workstation, domain, and version from NLA data.

# SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial

from __future__ import annotations

import struct

import pytest

from dionaea.rdp.packets import (
    NTLMSSPNegotiate,
    TSRequest,
    parse_ntlmssp_negotiate,
    parse_tsrequest,
)


def _build_ntlmssp_negotiate(
    flags: int = 0x00088207,
    domain: bytes = b"",
    workstation: bytes = b"",
    version: tuple[int, int, int, int] | None = None,
) -> bytes:
    """Build an NTLMSSP Negotiate (Type 1) message."""
    signature = b"NTLMSSP\x00"
    msg_type = struct.pack("<I", 1)
    negotiate_flags = struct.pack("<I", flags)

    has_version = version is not None
    base_offset = 40 if has_version else 32

    domain_offset = base_offset
    workstation_offset = base_offset + len(domain)

    domain_fields = struct.pack("<HHI", len(domain), len(domain), domain_offset)
    workstation_fields = struct.pack(
        "<HHI", len(workstation), len(workstation), workstation_offset
    )

    msg = signature + msg_type + negotiate_flags + domain_fields + workstation_fields

    if has_version:
        major, minor, build, revision = version
        msg += struct.pack("<BBHBBBB", major, minor, build, 0, 0, 0, revision)

    msg += domain + workstation
    return msg


def _build_tsrequest(nego_token: bytes, version: int = 2) -> bytes:
    """Build a CredSSP TSRequest wrapping a single negoToken."""
    # negoToken OCTET STRING
    octet = _der_tlv(0x04, nego_token)
    # [0] EXPLICIT wrapper
    inner = _der_tlv(0xA0, octet)
    # Inner SEQUENCE (one element in the SEQUENCE OF)
    inner_seq = _der_tlv(0x30, inner)
    # Outer SEQUENCE (negoTokens)
    outer_seq = _der_tlv(0x30, inner_seq)
    # [1] EXPLICIT wrapper for negoTokens
    nego_tokens = _der_tlv(0xA1, outer_seq)
    # [0] EXPLICIT INTEGER for version
    version_tlv = _der_tlv(0xA0, _der_tlv(0x02, bytes([version])))
    # TSRequest SEQUENCE
    return _der_tlv(0x30, version_tlv + nego_tokens)


def _der_tlv(tag: int, value: bytes) -> bytes:
    """Build a DER tag-length-value triple."""
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    elif length < 0x100:
        return bytes([tag, 0x81, length]) + value
    else:
        return bytes([tag, 0x82]) + struct.pack(">H", length) + value


# ---------------------------------------------------------------------------
# TSRequest parsing
# ---------------------------------------------------------------------------


class TestParseTSRequest:
    def test_basic(self):
        ntlmssp = _build_ntlmssp_negotiate()
        data = _build_tsrequest(ntlmssp)
        result = parse_tsrequest(data)
        assert result is not None
        assert result.version == 2
        assert len(result.nego_tokens) == 1
        assert result.nego_tokens[0] == ntlmssp

    def test_version_3(self):
        ntlmssp = _build_ntlmssp_negotiate()
        data = _build_tsrequest(ntlmssp, version=3)
        result = parse_tsrequest(data)
        assert result is not None
        assert result.version == 3

    def test_not_sequence(self):
        assert parse_tsrequest(b"\x31\x00") is None

    def test_too_short(self):
        assert parse_tsrequest(b"") is None
        assert parse_tsrequest(b"\x30") is None

    def test_no_nego_tokens(self):
        # TSRequest with just version, no [1] negoTokens
        version_tlv = _der_tlv(0xA0, _der_tlv(0x02, b"\x02"))
        data = _der_tlv(0x30, version_tlv)
        result = parse_tsrequest(data)
        assert result is not None
        assert result.version == 2
        assert result.nego_tokens == []

    def test_real_wire_data(self):
        """Parse the 57-byte TSRequest captured from a real NLA client."""
        wire = bytes.fromhex(
            "3037a003020106a130302e302ca02a0428"
            "4e544c4d53535000010000003782084200"
            "0000000028000000000000002800000006"
            "0072170000000f"
        )
        result = parse_tsrequest(wire)
        assert result is not None
        assert result.version == 6
        assert len(result.nego_tokens) == 1
        assert result.nego_tokens[0].startswith(b"NTLMSSP\x00")


# ---------------------------------------------------------------------------
# NTLMSSP Negotiate parsing
# ---------------------------------------------------------------------------


class TestParseNTLMSSPNegotiate:
    def test_minimal(self):
        msg = _build_ntlmssp_negotiate()
        result = parse_ntlmssp_negotiate(msg)
        assert result is not None
        assert result.flags == 0x00088207
        assert result.domain_name == ""
        assert result.workstation_name == ""
        assert result.os_version is None

    def test_with_domain_and_workstation(self):
        msg = _build_ntlmssp_negotiate(
            domain=b"TESTDOM",
            workstation=b"DESKTOP-ABC",
        )
        result = parse_ntlmssp_negotiate(msg)
        assert result is not None
        assert result.domain_name == "TESTDOM"
        assert result.workstation_name == "DESKTOP-ABC"

    def test_with_version(self):
        flags = 0x02088207  # NTLMSSP_NEGOTIATE_VERSION set
        msg = _build_ntlmssp_negotiate(
            flags=flags,
            version=(10, 0, 19041, 15),
        )
        result = parse_ntlmssp_negotiate(msg)
        assert result is not None
        assert result.os_version == (10, 0, 19041, 15)
        assert result.flags == flags

    def test_with_version_and_strings(self):
        flags = 0x02088207
        msg = _build_ntlmssp_negotiate(
            flags=flags,
            domain=b"CORP",
            workstation=b"WIN-HUNTER",
            version=(6, 1, 7601, 15),
        )
        result = parse_ntlmssp_negotiate(msg)
        assert result is not None
        assert result.domain_name == "CORP"
        assert result.workstation_name == "WIN-HUNTER"
        assert result.os_version == (6, 1, 7601, 15)

    def test_bad_signature(self):
        msg = b"XXXXXXXX" + b"\x00" * 24
        assert parse_ntlmssp_negotiate(msg) is None

    def test_wrong_type(self):
        # Type 2 (Challenge) instead of Type 1 (Negotiate)
        msg = b"NTLMSSP\x00" + struct.pack("<I", 2) + b"\x00" * 20
        assert parse_ntlmssp_negotiate(msg) is None

    def test_too_short(self):
        assert parse_ntlmssp_negotiate(b"NTLMSSP\x00\x01") is None

    def test_real_wire_data(self):
        """Parse the NTLMSSP token from a real NLA client."""
        token = bytes.fromhex(
            "4e544c4d53535000010000003782084200"
            "0000000028000000000000002800000006"
            "0072170000000f"
        )
        result = parse_ntlmssp_negotiate(token)
        assert result is not None
        assert result.flags == 0x42088237
        # This token has NEGOTIATE_VERSION set (0x02000000 in flags)
        assert result.os_version is not None
        assert result.domain_name == ""
        assert result.workstation_name == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
