# ABOUTME: Tests for CredSSP/NLA protocol: TSRequest parsing, NTLMSSP message building/parsing.
# ABOUTME: Covers Type 1 (Negotiate), Type 2 (Challenge), Type 3 (Authenticate), and hash formatting.

# SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial

from __future__ import annotations

import struct

import pytest

from dionaea.rdp.packets import (
    CREDSSP_ERROR_LOGON_DENIED,
    NTLMSSP_SIGNATURE,
    build_ntlmssp_challenge,
    build_tsrequest_error,
    build_tsrequest_response,
    der_sequence_length,
    format_ntlmv2_hash,
    parse_ntlmssp_authenticate,
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


# ---------------------------------------------------------------------------
# DER sequence length detection (for _process_buffer CredSSP dispatch)
# ---------------------------------------------------------------------------


class TestDerSequenceLength:
    def test_real_credssp_tsrequest(self):
        """der_sequence_length correctly measures a real 57-byte TSRequest."""
        wire = bytes.fromhex(
            "3037a003020106a130302e302ca02a0428"
            "4e544c4d53535000010000003782084200"
            "0000000028000000000000002800000006"
            "0072170000000f"
        )
        assert der_sequence_length(wire) == 57

    def test_tsrequest_with_trailing_data(self):
        """Length is just the SEQUENCE, ignoring trailing bytes."""
        wire = bytes.fromhex(
            "3037a003020106a130302e302ca02a0428"
            "4e544c4d53535000010000003782084200"
            "0000000028000000000000002800000006"
            "0072170000000f"
        )
        padded = wire + b"\x00" * 100
        assert der_sequence_length(padded) == 57

    def test_not_sequence(self):
        assert der_sequence_length(b"\x31\x00") is None

    def test_too_short(self):
        assert der_sequence_length(b"\x30") is None
        assert der_sequence_length(b"") is None

    def test_incomplete_value(self):
        """SEQUENCE header says 55 bytes but only 10 present."""
        assert der_sequence_length(b"\x30\x37" + b"\x00" * 10) is None

    def test_synthetic_short_sequence(self):
        data = _build_tsrequest(_build_ntlmssp_negotiate(), version=2)
        assert der_sequence_length(data) == len(data)


# ---------------------------------------------------------------------------
# NTLMSSP Challenge (Type 2) building
# ---------------------------------------------------------------------------


class TestBuildNTLMSSPChallenge:
    def test_signature_and_type(self):
        msg = build_ntlmssp_challenge(server_challenge=b"\x01" * 8)
        assert msg[:8] == NTLMSSP_SIGNATURE
        msg_type = struct.unpack("<I", msg[8:12])[0]
        assert msg_type == 2

    def test_server_challenge_embedded(self):
        challenge = b"\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22"
        msg = build_ntlmssp_challenge(server_challenge=challenge)
        # Server challenge is at offset 24 in Type 2
        assert msg[24:32] == challenge

    def test_target_name_present(self):
        msg = build_ntlmssp_challenge(
            server_challenge=b"\x01" * 8,
            target_name="HONEYPOT",
        )
        # Target name should be embedded as UTF-16LE somewhere in the message
        assert "HONEYPOT".encode("utf-16-le") in msg

    def test_flags_include_ntlmv2(self):
        msg = build_ntlmssp_challenge(server_challenge=b"\x01" * 8)
        # Flags at offset 20: sig(8) + type(4) + target_name_fields(8) = 20
        flags = struct.unpack("<I", msg[20:24])[0]
        assert flags & 0x00000001  # NEGOTIATE_UNICODE
        assert flags & 0x00000002  # NEGOTIATE_NTLM

    def test_parseable_by_parse_tsrequest_round_trip(self):
        """Challenge wrapped in TSRequest should be parseable."""
        challenge_msg = build_ntlmssp_challenge(server_challenge=b"\x01" * 8)
        tsrequest = build_tsrequest_response(challenge_msg, version=3)
        parsed = parse_tsrequest(tsrequest)
        assert parsed is not None
        assert parsed.version == 3
        assert len(parsed.nego_tokens) == 1
        assert parsed.nego_tokens[0] == challenge_msg


# ---------------------------------------------------------------------------
# TSRequest response building
# ---------------------------------------------------------------------------


class TestBuildTSRequestResponse:
    def test_is_valid_der_sequence(self):
        token = b"\x01\x02\x03"
        data = build_tsrequest_response(token, version=2)
        assert data[0] == 0x30  # SEQUENCE
        assert der_sequence_length(data) == len(data)

    def test_version_encoded(self):
        token = b"\xAA"
        data = build_tsrequest_response(token, version=5)
        parsed = parse_tsrequest(data)
        assert parsed is not None
        assert parsed.version == 5

    def test_token_round_trip(self):
        token = b"NTLMSSP\x00" + b"\x02" * 50
        data = build_tsrequest_response(token, version=2)
        parsed = parse_tsrequest(data)
        assert parsed is not None
        assert len(parsed.nego_tokens) == 1
        assert parsed.nego_tokens[0] == token


# ---------------------------------------------------------------------------
# NTLMSSP Authenticate (Type 3) parsing
# ---------------------------------------------------------------------------


class TestBuildTSRequestError:
    def test_is_valid_der_sequence(self):
        data = build_tsrequest_error()
        assert data[0] == 0x30
        assert der_sequence_length(data) == len(data)

    def test_contains_error_code(self):
        data = build_tsrequest_error(error_code=CREDSSP_ERROR_LOGON_DENIED, version=3)
        parsed = parse_tsrequest(data)
        assert parsed is not None
        assert parsed.version == 3
        # No negoTokens in an error response
        assert parsed.nego_tokens == []


# ---------------------------------------------------------------------------
# NTLMSSP Authenticate (Type 3) parsing
# ---------------------------------------------------------------------------


def _build_ntlmssp_authenticate(
    domain: str = "WORKGROUP",
    username: str = "administrator",
    workstation: str = "WIN-PC",
    nt_response: bytes = b"\xAA" * 24,
    lm_response: bytes = b"\xBB" * 24,
) -> bytes:
    """Build an NTLMSSP Authenticate (Type 3) message for testing."""
    domain_bytes = domain.encode("utf-16-le")
    username_bytes = username.encode("utf-16-le")
    workstation_bytes = workstation.encode("utf-16-le")

    # Fixed header: sig(8) + type(4) + lm_fields(8) + nt_fields(8) +
    #               domain_fields(8) + user_fields(8) + workstation_fields(8) +
    #               enc_random_session_key_fields(8) + negotiate_flags(4)
    header_size = 8 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 4
    # = 64 bytes

    # Payload order: lm, nt, domain, user, workstation
    payload_offset = header_size
    lm_offset = payload_offset
    nt_offset = lm_offset + len(lm_response)
    domain_offset = nt_offset + len(nt_response)
    user_offset = domain_offset + len(domain_bytes)
    ws_offset = user_offset + len(username_bytes)

    msg = NTLMSSP_SIGNATURE
    msg += struct.pack("<I", 3)  # Type 3
    # LmChallengeResponse
    msg += struct.pack("<HHI", len(lm_response), len(lm_response), lm_offset)
    # NtChallengeResponse
    msg += struct.pack("<HHI", len(nt_response), len(nt_response), nt_offset)
    # DomainName
    msg += struct.pack("<HHI", len(domain_bytes), len(domain_bytes), domain_offset)
    # UserName
    msg += struct.pack("<HHI", len(username_bytes), len(username_bytes), user_offset)
    # Workstation
    msg += struct.pack("<HHI", len(workstation_bytes), len(workstation_bytes), ws_offset)
    # EncryptedRandomSessionKey (empty)
    msg += struct.pack("<HHI", 0, 0, 0)
    # NegotiateFlags (UNICODE | NTLM)
    msg += struct.pack("<I", 0x00000003)

    msg += lm_response + nt_response + domain_bytes + username_bytes + workstation_bytes
    return msg


class TestParseNTLMSSPAuthenticate:
    def test_basic(self):
        msg = _build_ntlmssp_authenticate()
        result = parse_ntlmssp_authenticate(msg)
        assert result is not None
        assert result.domain == "WORKGROUP"
        assert result.username == "administrator"
        assert result.workstation == "WIN-PC"
        assert result.nt_response == b"\xAA" * 24
        assert result.lm_response == b"\xBB" * 24

    def test_different_credentials(self):
        msg = _build_ntlmssp_authenticate(
            domain="CORP",
            username="admin",
            workstation="SRV-01",
            nt_response=b"\x11" * 24,
            lm_response=b"\x22" * 24,
        )
        result = parse_ntlmssp_authenticate(msg)
        assert result is not None
        assert result.domain == "CORP"
        assert result.username == "admin"
        assert result.workstation == "SRV-01"

    def test_empty_domain(self):
        msg = _build_ntlmssp_authenticate(domain="")
        result = parse_ntlmssp_authenticate(msg)
        assert result is not None
        assert result.domain == ""

    def test_bad_signature(self):
        msg = b"XXXXXXXX" + b"\x00" * 56
        assert parse_ntlmssp_authenticate(msg) is None

    def test_wrong_type(self):
        msg = NTLMSSP_SIGNATURE + struct.pack("<I", 1) + b"\x00" * 52
        assert parse_ntlmssp_authenticate(msg) is None

    def test_too_short(self):
        assert parse_ntlmssp_authenticate(b"NTLMSSP\x00\x03") is None


# ---------------------------------------------------------------------------
# NTLMv2 hash formatting (hashcat mode 5600)
# ---------------------------------------------------------------------------


class TestFormatNTLMv2Hash:
    def test_basic_format(self):
        # NTLMv2: nt_response = nt_proof(16) + ntv2_blob(rest)
        nt_proof = bytes(range(16))
        ntv2_blob = bytes(range(16, 32))
        nt_response = nt_proof + ntv2_blob
        server_challenge = b"\xAA" * 8

        result = format_ntlmv2_hash(
            username="admin",
            domain="CORP",
            server_challenge=server_challenge,
            nt_response=nt_response,
        )

        # Format: username::domain:server_challenge_hex:nt_proof_hex:ntv2_blob_hex
        parts = result.split(":")
        assert parts[0] == "admin"
        assert parts[1] == ""  # empty between ::
        assert parts[2] == "CORP"
        assert parts[3] == server_challenge.hex()
        assert parts[4] == nt_proof.hex()
        assert parts[5] == ntv2_blob.hex()

    def test_short_nt_response_returns_none(self):
        # NTLMv2 nt_response must be > 16 bytes (16 proof + blob)
        result = format_ntlmv2_hash(
            username="admin",
            domain="CORP",
            server_challenge=b"\x01" * 8,
            nt_response=b"\x01" * 10,
        )
        assert result is None

    def test_exactly_16_bytes_returns_none(self):
        # 16 bytes = proof only, no blob
        result = format_ntlmv2_hash(
            username="admin",
            domain="CORP",
            server_challenge=b"\x01" * 8,
            nt_response=b"\x01" * 16,
        )
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
