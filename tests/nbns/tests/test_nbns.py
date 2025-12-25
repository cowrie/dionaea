# ABOUTME: NBNS protocol unit tests for packet parsing and threat detection
# ABOUTME: Tests encoding/decoding, anomaly detection, and attack pattern recognition
#
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import struct
import importlib.util
import os

import pytest

# Load the nbns module directly without triggering dionaea package dependencies
_nbns_path = os.path.join(
    os.path.dirname(__file__),
    '..', '..', '..', 'modules', 'python', 'dionaea', 'nbns', 'nbns.py'
)
_nbns_path = os.path.abspath(_nbns_path)

# Create a mock for dionaea imports
import sys
from unittest.mock import MagicMock
sys.modules['dionaea'] = MagicMock()
sys.modules['dionaea.core'] = MagicMock()

# Now load the module
spec = importlib.util.spec_from_file_location("nbns", _nbns_path)
nbns_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nbns_module)

# Import what we need
decode_netbios_name = nbns_module.decode_netbios_name
encode_netbios_name = nbns_module.encode_netbios_name
get_suffix_name = nbns_module.get_suffix_name
get_qtype_name = nbns_module.get_qtype_name
analyze_query_threat = nbns_module.analyze_query_threat
NBNSPacket = nbns_module.NBNSPacket
NBNSResponse = nbns_module.NBNSResponse
QTYPE_NB = nbns_module.QTYPE_NB
QTYPE_NBSTAT = nbns_module.QTYPE_NBSTAT
NBNS_SUFFIX_WORKSTATION = nbns_module.NBNS_SUFFIX_WORKSTATION
NBNS_SUFFIX_FILE_SERVER = nbns_module.NBNS_SUFFIX_FILE_SERVER
NBNS_SUFFIX_DOMAIN_CONTROLLER = nbns_module.NBNS_SUFFIX_DOMAIN_CONTROLLER
OPCODE_QUERY = nbns_module.OPCODE_QUERY
OPCODE_REGISTRATION = nbns_module.OPCODE_REGISTRATION


class TestNetBIOSNameEncoding:
    """Test NetBIOS name first-level encoding/decoding."""

    def test_encode_simple_name(self):
        """Test encoding a simple name."""
        encoded = encode_netbios_name("TEST")
        # TEST + 11 spaces + suffix 0x00
        # T=0x54 -> 0x45 0x45 = 'EE', E=0x45 -> 'EF', S=0x53 -> 'FD', T=0x54 -> 'EE'
        assert len(encoded) == 32
        # Verify round-trip
        name, suffix = decode_netbios_name(encoded)
        assert name == "TEST"
        assert suffix == 0x00

    def test_encode_wpad(self):
        """Test encoding WPAD name."""
        encoded = encode_netbios_name("WPAD")
        name, suffix = decode_netbios_name(encoded)
        assert name == "WPAD"
        assert suffix == 0x00

    def test_encode_with_suffix(self):
        """Test encoding with different suffix bytes."""
        encoded = encode_netbios_name("SERVER", suffix=NBNS_SUFFIX_FILE_SERVER)
        name, suffix = decode_netbios_name(encoded)
        assert name == "SERVER"
        assert suffix == NBNS_SUFFIX_FILE_SERVER

    def test_encode_max_length_name(self):
        """Test encoding 15-character name."""
        encoded = encode_netbios_name("ABCDEFGHIJKLMNO")
        name, suffix = decode_netbios_name(encoded)
        assert name == "ABCDEFGHIJKLMNO"

    def test_encode_truncates_long_name(self):
        """Test that names longer than 15 chars are truncated."""
        encoded = encode_netbios_name("VERYLONGNAMETHATEXCEEDS15CHARS")
        name, suffix = decode_netbios_name(encoded)
        assert name == "VERYLONGNAMETHA"  # Truncated to 15 chars and upper-cased

    def test_decode_short_data_raises(self):
        """Test that decoding short data raises ValueError."""
        with pytest.raises(ValueError, match="too short"):
            decode_netbios_name(b"SHORT")


class TestSuffixAndTypeNames:
    """Test human-readable name lookups."""

    def test_known_suffixes(self):
        assert get_suffix_name(0x00) == "Workstation"
        assert get_suffix_name(0x20) == "FileServer"
        assert get_suffix_name(0x1C) == "DomainController"
        assert get_suffix_name(0x1D) == "MasterBrowser"

    def test_unknown_suffix(self):
        assert "Unknown" in get_suffix_name(0xFF)

    def test_known_qtypes(self):
        assert get_qtype_name(QTYPE_NB) == "NB"
        assert get_qtype_name(QTYPE_NBSTAT) == "NBSTAT"

    def test_unknown_qtype(self):
        assert "Unknown" in get_qtype_name(0x9999)


class TestThreatAnalysis:
    """Test attack pattern detection."""

    def test_wpad_is_attack(self):
        """WPAD queries should be flagged as attack."""
        level, desc = analyze_query_threat("WPAD", 0x00, QTYPE_NB, OPCODE_QUERY)
        assert level == "attack"
        assert "WPAD" in desc or "Hot Potato" in desc

    def test_wpad_case_insensitive(self):
        """WPAD detection should be case-insensitive."""
        level, _ = analyze_query_threat("wpad", 0x00, QTYPE_NB, OPCODE_QUERY)
        assert level == "attack"
        level, _ = analyze_query_threat("Wpad", 0x00, QTYPE_NB, OPCODE_QUERY)
        assert level == "attack"

    def test_isatap_is_suspicious(self):
        """ISATAP queries should be suspicious."""
        level, desc = analyze_query_threat("ISATAP", 0x00, QTYPE_NB, OPCODE_QUERY)
        assert level == "suspicious"
        assert "tunnel" in desc.lower()

    def test_nbstat_is_suspicious(self):
        """NBSTAT queries are reconnaissance."""
        level, desc = analyze_query_threat("ANYHOST", 0x00, QTYPE_NBSTAT, OPCODE_QUERY)
        assert level == "suspicious"
        assert "reconnaissance" in desc.lower() or "enumeration" in desc.lower()

    def test_registration_is_suspicious(self):
        """Registration attempts could be poisoning."""
        level, desc = analyze_query_threat("MYHOST", 0x00, QTYPE_NB, OPCODE_REGISTRATION)
        assert level == "suspicious"
        assert "poisoning" in desc.lower() or "registration" in desc.lower()

    def test_domain_controller_query_is_suspicious(self):
        """Domain controller queries indicate AD reconnaissance."""
        level, desc = analyze_query_threat("DOMAIN", NBNS_SUFFIX_DOMAIN_CONTROLLER, QTYPE_NB, OPCODE_QUERY)
        assert level == "suspicious"

    def test_normal_query_is_info(self):
        """Normal workstation queries are just info."""
        level, desc = analyze_query_threat("WORKSTATION1", NBNS_SUFFIX_WORKSTATION, QTYPE_NB, OPCODE_QUERY)
        assert level == "info"


class TestNBNSPacketParsing:
    """Test NBNS packet parsing."""

    def build_nbns_query(self, name: str, suffix: int = 0x00,
                         qtype: int = QTYPE_NB, qclass: int = 0x0001,
                         transaction_id: int = 0x1234) -> bytes:
        """Build a valid NBNS query packet."""
        # Header
        flags = 0x0110  # Query, recursion desired, broadcast
        header = struct.pack('!HHHHHH',
            transaction_id,
            flags,
            1,  # 1 question
            0,  # 0 answers
            0,  # 0 authority
            0   # 0 additional
        )

        # Question section
        encoded_name = encode_netbios_name(name, suffix)
        question = bytes([len(encoded_name)]) + encoded_name + b'\x00'
        question += struct.pack('!HH', qtype, qclass)

        return header + question

    def test_parse_simple_query(self):
        """Test parsing a simple name query."""
        packet_data = self.build_nbns_query("TEST")
        packet = NBNSPacket(packet_data)

        assert packet.transaction_id == 0x1234
        assert packet.is_response == False
        assert packet.opcode == 0
        assert packet.qdcount == 1
        assert len(packet.questions) == 1

        name, suffix, qtype, qclass = packet.questions[0]
        assert name == "TEST"
        assert suffix == 0x00
        assert qtype == QTYPE_NB

    def test_parse_wpad_query(self):
        """Test parsing WPAD query."""
        packet_data = self.build_nbns_query("WPAD")
        packet = NBNSPacket(packet_data)

        name, suffix, qtype, qclass = packet.questions[0]
        assert name == "WPAD"

    def test_parse_nbstat_query(self):
        """Test parsing NBSTAT query."""
        packet_data = self.build_nbns_query("HOST", qtype=QTYPE_NBSTAT)
        packet = NBNSPacket(packet_data)

        name, suffix, qtype, qclass = packet.questions[0]
        assert qtype == QTYPE_NBSTAT

    def test_short_packet_raises(self):
        """Test that short packets raise ValueError."""
        with pytest.raises(ValueError, match="too short"):
            NBNSPacket(b"\x00" * 10)

    def test_truncated_packet_has_anomalies(self):
        """Test that truncated packets are detected."""
        # Build a packet with claimed 2 questions but only provide 1
        flags = 0x0110
        header = struct.pack('!HHHHHH', 0x1234, flags, 2, 0, 0, 0)  # Claims 2 questions
        encoded_name = encode_netbios_name("TEST")
        question = bytes([len(encoded_name)]) + encoded_name + b'\x00'
        question += struct.pack('!HH', QTYPE_NB, 0x0001)

        packet = NBNSPacket(header + question)
        assert packet.has_anomalies()
        assert len(packet.questions) == 1  # Only parsed 1

    def test_unusual_qtype_has_anomalies(self):
        """Test that unusual query types are flagged."""
        packet_data = self.build_nbns_query("TEST", qtype=0x9999)
        packet = NBNSPacket(packet_data)
        assert packet.has_anomalies()
        assert any("query type" in err.lower() for err in packet.parse_errors)

    def test_opcode_name(self):
        """Test opcode name lookup."""
        packet_data = self.build_nbns_query("TEST")
        packet = NBNSPacket(packet_data)
        assert packet.get_opcode_name() == "Query"


class TestNBNSResponse:
    """Test NBNS response building."""

    def test_build_positive_response(self):
        """Test building a positive name query response."""
        response = NBNSResponse.build_positive_name_query_response(
            transaction_id=0x1234,
            name="TEST",
            suffix=0x00,
            ip_address="192.168.1.1"
        )

        # Parse the response
        assert len(response) > 12  # At least header size

        # Check header
        tid, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', response[:12])
        assert tid == 0x1234
        assert flags & 0x8000  # Is response
        assert qdcount == 0
        assert ancount == 1
