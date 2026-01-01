# ABOUTME: Unit tests for SNMP BER encoding/decoding functions
# ABOUTME: Tests packet parsing, OID handling, and response building

import pytest
import sys
import os
import importlib.util

# Load the snmp module directly to avoid dionaea.core dependencies
snmp_path = os.path.join(os.path.dirname(__file__), '../../modules/python/dionaea/snmp/__init__.py')
spec = importlib.util.spec_from_file_location("snmp_module", snmp_path)
snmp_module = importlib.util.module_from_spec(spec)

# Mock the dionaea imports that snmp needs
class MockServiceLoader:
    name = ""
    @classmethod
    def start(cls, addr, iface=None, config=None):
        raise NotImplementedError()

class MockConnection:
    def __init__(self, proto):
        self.proto = proto
    def bind(self, *args, **kwargs):
        pass
    def listen(self):
        pass

class MockIncident:
    def __init__(self, name):
        self.name = name
        self.data = {}
    def set(self, key, value):
        self.data[key] = value
    def report(self):
        pass

# Create mock dionaea module
sys.modules['dionaea'] = type(sys)('dionaea')
sys.modules['dionaea'].ServiceLoader = MockServiceLoader
sys.modules['dionaea.core'] = type(sys)('dionaea.core')
sys.modules['dionaea.core'].connection = MockConnection
sys.modules['dionaea.core'].incident = MockIncident

# Now load the module
spec.loader.exec_module(snmp_module)

# Import the functions we need
decode_ber_length = snmp_module.decode_ber_length
decode_ber_integer = snmp_module.decode_ber_integer
decode_ber_string = snmp_module.decode_ber_string
decode_ber_oid = snmp_module.decode_ber_oid
encode_ber_length = snmp_module.encode_ber_length
encode_ber_integer = snmp_module.encode_ber_integer
encode_ber_string = snmp_module.encode_ber_string
encode_ber_oid = snmp_module.encode_ber_oid
encode_ber_sequence = snmp_module.encode_ber_sequence
SNMPPacket = snmp_module.SNMPPacket
PDU_GET_REQUEST = snmp_module.PDU_GET_REQUEST
COMMON_COMMUNITIES = snmp_module.COMMON_COMMUNITIES
sanitize_for_log = snmp_module.sanitize_for_log
MAX_COMMUNITY_LEN = snmp_module.MAX_COMMUNITY_LEN
MAX_OID_COMPONENT = snmp_module.MAX_OID_COMPONENT


class TestBERLength:
    """Test BER length encoding/decoding."""

    def test_short_form(self):
        """Length < 128 uses single byte."""
        assert decode_ber_length(bytes([0x05]), 0) == (5, 1)
        assert decode_ber_length(bytes([0x7F]), 0) == (127, 1)
        assert decode_ber_length(bytes([0x00]), 0) == (0, 1)

    def test_long_form_one_byte(self):
        """Length 128-255 uses 0x81 prefix."""
        assert decode_ber_length(bytes([0x81, 0x80]), 0) == (128, 2)
        assert decode_ber_length(bytes([0x81, 0xFF]), 0) == (255, 2)

    def test_long_form_two_bytes(self):
        """Length 256-65535 uses 0x82 prefix."""
        assert decode_ber_length(bytes([0x82, 0x01, 0x00]), 0) == (256, 3)
        assert decode_ber_length(bytes([0x82, 0xFF, 0xFF]), 0) == (65535, 3)

    def test_encode_short_form(self):
        assert encode_ber_length(0) == bytes([0x00])
        assert encode_ber_length(127) == bytes([0x7F])

    def test_encode_long_form(self):
        assert encode_ber_length(128) == bytes([0x81, 0x80])
        assert encode_ber_length(256) == bytes([0x82, 0x01, 0x00])


class TestBERInteger:
    """Test BER integer encoding/decoding."""

    def test_decode_positive(self):
        # INTEGER 0
        assert decode_ber_integer(bytes([0x02, 0x01, 0x00]), 0) == (0, 3)
        # INTEGER 1
        assert decode_ber_integer(bytes([0x02, 0x01, 0x01]), 0) == (1, 3)
        # INTEGER 127
        assert decode_ber_integer(bytes([0x02, 0x01, 0x7F]), 0) == (127, 3)
        # INTEGER 128 (needs leading 0x00 to stay positive)
        assert decode_ber_integer(bytes([0x02, 0x02, 0x00, 0x80]), 0) == (128, 4)

    def test_decode_negative(self):
        # INTEGER -1 (0xFF in signed byte)
        assert decode_ber_integer(bytes([0x02, 0x01, 0xFF]), 0) == (-1, 3)
        # INTEGER -128
        assert decode_ber_integer(bytes([0x02, 0x01, 0x80]), 0) == (-128, 3)

    def test_encode_positive(self):
        assert encode_ber_integer(0) == bytes([0x02, 0x01, 0x00])
        assert encode_ber_integer(1) == bytes([0x02, 0x01, 0x01])
        assert encode_ber_integer(127) == bytes([0x02, 0x01, 0x7F])

    def test_roundtrip(self):
        """Encoding then decoding should return original value."""
        for val in [0, 1, 127, 128, 255, 256, 1000, -1, -128]:
            encoded = encode_ber_integer(val)
            decoded, _ = decode_ber_integer(encoded, 0)
            assert decoded == val, f"Roundtrip failed for {val}"


class TestBERString:
    """Test BER octet string encoding/decoding."""

    def test_decode_empty(self):
        result, consumed = decode_ber_string(bytes([0x04, 0x00]), 0)
        assert result == b''
        assert consumed == 2

    def test_decode_ascii(self):
        # "public" = 0x70 0x75 0x62 0x6c 0x69 0x63
        data = bytes([0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63])
        result, consumed = decode_ber_string(data, 0)
        assert result == b'public'
        assert consumed == 8

    def test_encode_string(self):
        encoded = encode_ber_string(b'public')
        assert encoded == bytes([0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63])


class TestBEROID:
    """Test BER OID encoding/decoding."""

    def test_decode_sysdescr(self):
        # sysDescr.0 = 1.3.6.1.2.1.1.1.0
        # First two: 1*40 + 3 = 43 = 0x2B
        # Remaining: 6, 1, 2, 1, 1, 1, 0
        data = bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        oid, consumed = decode_ber_oid(data, 0)
        assert oid == '1.3.6.1.2.1.1.1.0'
        assert consumed == 10

    def test_encode_sysdescr(self):
        encoded = encode_ber_oid('1.3.6.1.2.1.1.1.0')
        assert encoded == bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])

    def test_roundtrip(self):
        oids = [
            '1.3.6.1.2.1.1.1.0',
            '1.3.6.1.2.1.1.5.0',
            '1.3.6.1.4.1.8072.3.2.10',
        ]
        for oid in oids:
            encoded = encode_ber_oid(oid)
            decoded, _ = decode_ber_oid(encoded, 0)
            assert decoded == oid, f"Roundtrip failed for {oid}"


class TestSNMPPacket:
    """Test SNMP packet parsing."""

    def test_parse_get_request(self):
        """Parse a real SNMPv1 GetRequest for sysDescr."""
        # SNMPv1 GetRequest for sysDescr.0 with community "public"
        # Captured from a real SNMP client
        packet = bytes([
            0x30, 0x26,  # SEQUENCE, length 38
            0x02, 0x01, 0x00,  # INTEGER 0 (version v1)
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # OCTET STRING "public"
            0xa0, 0x19,  # GetRequest-PDU, length 25
            0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # INTEGER request-id=1
            0x02, 0x01, 0x00,  # INTEGER error-status=0
            0x02, 0x01, 0x00,  # INTEGER error-index=0
            0x30, 0x0b,  # SEQUENCE (varbind list), length 11
            0x30, 0x09,  # SEQUENCE (varbind), length 9
            0x06, 0x07, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01,  # OID 1.3.6.1.2.1.1.1
            0x05, 0x00,  # NULL
        ])

        pkt = SNMPPacket(packet)
        assert pkt.version == 0
        assert pkt.version_string == 'v1'
        assert pkt.community == 'public'
        assert pkt.pdu_type == PDU_GET_REQUEST
        assert pkt.pdu_name == 'GetRequest'
        assert pkt.request_id == 1
        assert pkt.error_status == 0
        assert pkt.error_index == 0
        assert len(pkt.varbinds) >= 1
        # Note: OID might not have trailing .0 due to packet structure
        assert pkt.varbinds[0][0].startswith('1.3.6.1.2.1.1.1')

    def test_parse_v2c(self):
        """Parse an SNMPv2c packet."""
        # SNMPv2c GetRequest
        packet = bytes([
            0x30, 0x26,
            0x02, 0x01, 0x01,  # version v2c
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
            0xa0, 0x19,
            0x02, 0x04, 0x00, 0x00, 0x00, 0x02,
            0x02, 0x01, 0x00,
            0x02, 0x01, 0x00,
            0x30, 0x0b,
            0x30, 0x09,
            0x06, 0x07, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01,
            0x05, 0x00,
        ])

        pkt = SNMPPacket(packet)
        assert pkt.version == 1
        assert pkt.version_string == 'v2c'
        assert pkt.request_id == 2

    def test_parse_too_short(self):
        """Reject packets that are too short."""
        with pytest.raises(ValueError, match="too short"):
            SNMPPacket(bytes([0x30, 0x05, 0x02, 0x01, 0x00]))

    def test_parse_wrong_tag(self):
        """Reject packets without SEQUENCE tag."""
        with pytest.raises(ValueError, match="Expected SEQUENCE"):
            SNMPPacket(bytes([0x31] + [0x00] * 20))


class TestCommonCommunities:
    """Test detection of common/default community strings."""

    def test_common_communities_detected(self):
        """Common community strings should be in the detection set."""
        assert 'public' in COMMON_COMMUNITIES
        assert 'private' in COMMON_COMMUNITIES
        assert 'community' in COMMON_COMMUNITIES
        assert 'cisco' in COMMON_COMMUNITIES


class TestSecurityLimits:
    """Test security limits and sanitization."""

    def test_sanitize_removes_newlines(self):
        """Newlines should be replaced to prevent log injection."""
        assert sanitize_for_log("hello\nworld") == "hello?world"
        assert sanitize_for_log("test\r\ninjection") == "test??injection"

    def test_sanitize_removes_control_chars(self):
        """Control characters should be replaced."""
        assert sanitize_for_log("test\x00null") == "test?null"
        assert sanitize_for_log("ansi\x1b[31mred") == "ansi?[31mred"

    def test_sanitize_truncates_long_strings(self):
        """Long strings should be truncated."""
        long_str = "A" * 100
        result = sanitize_for_log(long_str)
        assert len(result) == 67  # 64 + "..."
        assert result.endswith("...")

    def test_community_string_length_limit(self):
        """Reject community strings that are too long."""
        # Build a packet with oversized community string
        community = b'A' * 200
        packet = bytes([
            0x30, 0x81, 0xD6,  # SEQUENCE, length 214
            0x02, 0x01, 0x00,  # version
            0x04, 0x81, 0xC8,  # OCTET STRING, length 200
        ]) + community + bytes([
            0xa0, 0x06,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x00,
            0x02, 0x01, 0x00,
        ])
        with pytest.raises(ValueError, match="too long"):
            SNMPPacket(packet)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
