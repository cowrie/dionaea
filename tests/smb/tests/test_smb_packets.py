# ABOUTME: Unit tests for SMB packet classes
# ABOUTME: Tests packet parsing for TRANSACTION_SECONDARY and related packets

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import sys
import os
import types

# Set up path to load include modules as a package
_base = os.path.dirname(__file__)
_dionaea_path = os.path.join(_base, "../../../modules/python")
_dionaea_path = os.path.abspath(_dionaea_path)

# Add to path so that the dionaea.smb.include package can be found
if _dionaea_path not in sys.path:
    sys.path.insert(0, _dionaea_path)

# Create stub modules to avoid loading dionaea/__init__.py which requires yaml
_dionaea_stub = types.ModuleType("dionaea")
_dionaea_stub.__path__ = [os.path.join(_dionaea_path, "dionaea")]
sys.modules["dionaea"] = _dionaea_stub

_smb_stub = types.ModuleType("dionaea.smb")
_smb_stub.__path__ = [os.path.join(_dionaea_path, "dionaea/smb")]
sys.modules["dionaea.smb"] = _smb_stub

_include_stub = types.ModuleType("dionaea.smb.include")
_include_stub.__path__ = [os.path.join(_dionaea_path, "dionaea/smb/include")]
sys.modules["dionaea.smb.include"] = _include_stub

# Import smbfields to populate sys.modules (must be after stub setup)
__import__("dionaea.smb.include.smbfields")  # noqa: E402


def test_trans_secondary_request_import():
    """Test that SMB_Trans_Secondary_Request can be imported."""
    from dionaea.smb.include.smbfields import SMB_Trans_Secondary_Request

    assert SMB_Trans_Secondary_Request is not None


def test_trans_secondary_request_fields():
    """Test SMB_Trans_Secondary_Request field structure."""
    from dionaea.smb.include.smbfields import (
        SMB_Trans_Secondary_Request,
        SMB_COM_TRANSACTION_SECONDARY,
    )

    # Verify command code
    assert SMB_Trans_Secondary_Request.smb_cmd == SMB_COM_TRANSACTION_SECONDARY
    assert SMB_COM_TRANSACTION_SECONDARY == 0x26

    # Create packet and verify default fields
    pkt = SMB_Trans_Secondary_Request()
    assert pkt.WordCount == 8
    assert pkt.TotalParamCount == 0
    assert pkt.TotalDataCount == 0
    assert pkt.ParamCount == 0
    assert pkt.ParamOffset == 0
    assert pkt.ParamDisplacement == 0
    assert pkt.DataCount == 0
    assert pkt.DataOffset == 0
    assert pkt.DataDisplacement == 0


def test_trans_secondary_request_parse():
    """Test parsing a raw SMB_Trans_Secondary_Request packet."""
    from dionaea.smb.include.smbfields import SMB_Trans_Secondary_Request

    # Build a raw packet with known values:
    # WordCount=8, TotalParamCount=100, TotalDataCount=200,
    # ParamCount=50, ParamOffset=60, ParamDisplacement=0,
    # DataCount=75, DataOffset=120, DataDisplacement=25,
    # ByteCount=125, followed by params and data
    raw = bytes(
        [
            0x08,  # WordCount
            0x64,
            0x00,  # TotalParamCount = 100
            0xC8,
            0x00,  # TotalDataCount = 200
            0x32,
            0x00,  # ParamCount = 50
            0x3C,
            0x00,  # ParamOffset = 60
            0x00,
            0x00,  # ParamDisplacement = 0
            0x4B,
            0x00,  # DataCount = 75
            0x78,
            0x00,  # DataOffset = 120
            0x19,
            0x00,  # DataDisplacement = 25
            0x7D,
            0x00,  # ByteCount = 125
        ]
    )
    # Add 50 bytes of params (0xAA pattern)
    raw += bytes([0xAA] * 50)
    # Add 75 bytes of data (0xBB pattern)
    raw += bytes([0xBB] * 75)

    pkt = SMB_Trans_Secondary_Request(raw)

    assert pkt.WordCount == 8
    assert pkt.TotalParamCount == 100
    assert pkt.TotalDataCount == 200
    assert pkt.ParamCount == 50
    assert pkt.ParamOffset == 60
    assert pkt.ParamDisplacement == 0
    assert pkt.DataCount == 75
    assert pkt.DataOffset == 120
    assert pkt.DataDisplacement == 25
    assert pkt.ByteCount == 125

    # Verify params and data were parsed
    assert len(pkt.Params) == 50
    assert pkt.Params == bytes([0xAA] * 50)
    assert len(pkt.Data) == 75
    assert pkt.Data == bytes([0xBB] * 75)


def test_trans_secondary_bind():
    """Test that SMB_Trans_Secondary_Request is bound to SMB_Header for command 0x26."""
    from dionaea.smb.include.smbfields import (
        NBTSession,
        SMB_Header,
        SMB_Trans_Secondary_Request,
    )

    # Build a complete SMB packet with TRANSACTION_SECONDARY command
    nbt = NBTSession(TYPE=0x00, LENGTH=0)
    smb_hdr = SMB_Header(
        Command=0x26, Flags=0x00
    )  # 0x26 = TRANSACTION_SECONDARY, Flags=0 (request)
    trans_sec = SMB_Trans_Secondary_Request(
        WordCount=8,
        TotalParamCount=10,
        TotalDataCount=20,
        ParamCount=5,
        DataCount=10,
        ByteCount=15,
        Params=bytes([0x41] * 5),
        Data=bytes([0x42] * 10),
    )

    # Build complete packet
    pkt = nbt / smb_hdr / trans_sec

    # Serialize and deserialize
    raw = pkt.build()

    # Parse it back
    parsed = NBTSession(raw)

    # Verify the layers are present
    assert parsed.haslayer(SMB_Header)
    smb = parsed.getlayer(SMB_Header)
    assert smb.Command == 0x26

    # The parsed packet should have SMB_Trans_Secondary_Request layer
    assert parsed.haslayer(SMB_Trans_Secondary_Request)
    trans = parsed.getlayer(SMB_Trans_Secondary_Request)
    assert trans.TotalParamCount == 10
    assert trans.TotalDataCount == 20


class TestDCERPCByteOrder:
    """Test UUID parsing with different DCE/RPC byte orders."""

    def test_parse_uuid_little_endian(self):
        """Test that UUIDs are correctly parsed from little-endian data."""
        from uuid import UUID

        # NDR32 transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
        # In little-endian wire format (bytes_le):
        # First 4 bytes reversed: 04 5d 88 8a
        # Next 2 bytes reversed: eb 1c
        # Next 2 bytes reversed: c9 11
        # Last 8 bytes as-is: 9f e8 08 00 2b 10 48 60
        wire_bytes = bytes([
            0x04, 0x5d, 0x88, 0x8a,  # 8a885d04 in LE
            0xeb, 0x1c,              # 1ceb in LE
            0xc9, 0x11,              # 11c9 in LE
            0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60
        ])

        # Parse as little-endian (standard Windows/DCE-RPC format)
        parsed = UUID(bytes_le=wire_bytes)
        assert str(parsed) == '8a885d04-1ceb-11c9-9fe8-08002b104860'

    def test_parse_uuid_big_endian(self):
        """Test that UUIDs are correctly parsed from big-endian data."""
        from uuid import UUID

        # NDR32 transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
        # In big-endian wire format (bytes):
        # All bytes in network order (no swapping)
        wire_bytes = bytes([
            0x8a, 0x88, 0x5d, 0x04,  # 8a885d04 in BE
            0x1c, 0xeb,              # 1ceb in BE
            0x11, 0xc9,              # 11c9 in BE
            0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60
        ])

        # Parse as big-endian
        parsed = UUID(bytes=wire_bytes)
        assert str(parsed) == '8a885d04-1ceb-11c9-9fe8-08002b104860'

    def test_wrong_byte_order_gives_wrong_uuid(self):
        """Test that using wrong byte order gives incorrect UUID."""
        from uuid import UUID

        # Big-endian wire bytes for NDR32
        be_wire_bytes = bytes([
            0x8a, 0x88, 0x5d, 0x04,
            0x1c, 0xeb,
            0x11, 0xc9,
            0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60
        ])

        # If we incorrectly parse big-endian bytes as little-endian,
        # we get the byte-swapped UUID that was in the warning
        wrong_parsed = UUID(bytes_le=be_wire_bytes)
        assert str(wrong_parsed) == '045d888a-eb1c-c911-9fe8-08002b104860'

        # This is NOT the correct NDR32 UUID
        assert str(wrong_parsed) != '8a885d04-1ceb-11c9-9fe8-08002b104860'

    def test_data_representation_byte_order_flag(self):
        """Test interpreting DataRepresentation byte order field."""
        # DataRepresentation is a 4-byte field:
        # Byte 0: Integer representation (0x00=BE, 0x10=LE)
        # Byte 1: Character (0=ASCII)
        # Byte 2: Floating-point (0=IEEE)
        # Byte 3: Reserved

        # Little-endian (standard Windows): 0x10 in byte 0
        le_data_rep = 0x00000010  # As stored in little-endian
        le_byte_order = le_data_rep & 0xFF
        assert le_byte_order == 0x10
        assert le_byte_order != 0x00  # Not big-endian

        # Big-endian: 0x00 in byte 0
        be_data_rep = 0x00000000
        be_byte_order = be_data_rep & 0xFF
        assert be_byte_order == 0x00

    def test_parse_uuid_with_byte_order_flag(self):
        """Test helper function for parsing UUIDs based on byte order."""
        from uuid import UUID

        def parse_dcerpc_uuid(uuid_bytes, big_endian):
            """Parse UUID bytes according to DCE/RPC byte order."""
            if big_endian:
                return UUID(bytes=uuid_bytes)
            else:
                return UUID(bytes_le=uuid_bytes)

        # NDR32 UUID
        expected = '8a885d04-1ceb-11c9-9fe8-08002b104860'

        # Little-endian wire bytes
        le_bytes = bytes([
            0x04, 0x5d, 0x88, 0x8a,
            0xeb, 0x1c,
            0xc9, 0x11,
            0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60
        ])
        assert str(parse_dcerpc_uuid(le_bytes, False)) == expected

        # Big-endian wire bytes
        be_bytes = bytes([
            0x8a, 0x88, 0x5d, 0x04,
            0x1c, 0xeb,
            0x11, 0xc9,
            0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60
        ])
        assert str(parse_dcerpc_uuid(be_bytes, True)) == expected

    def test_swap16(self):
        """Test 16-bit byte swapping."""
        def _swap16(value):
            return ((value & 0xFF) << 8) | ((value >> 8) & 0xFF)

        assert _swap16(0x1234) == 0x3412
        assert _swap16(0xABCD) == 0xCDAB
        assert _swap16(0x0100) == 0x0001
        assert _swap16(0xFF00) == 0x00FF
        # Swapping twice returns original
        assert _swap16(_swap16(0x1234)) == 0x1234

    def test_swap32(self):
        """Test 32-bit byte swapping."""
        def _swap32(value):
            return (
                ((value & 0xFF) << 24) |
                ((value & 0xFF00) << 8) |
                ((value >> 8) & 0xFF00) |
                ((value >> 24) & 0xFF)
            )

        assert _swap32(0x12345678) == 0x78563412
        assert _swap32(0xAABBCCDD) == 0xDDCCBBAA
        assert _swap32(0x01000000) == 0x00000001
        # Swapping twice returns original
        assert _swap32(_swap32(0x12345678)) == 0x12345678

    def test_dcerpc_is_big_endian(self):
        """Test detection of big-endian DCE/RPC packets."""
        def dcerpc_is_big_endian(data_representation):
            return (data_representation & 0xFF) == 0x00

        # Little-endian (standard Windows)
        assert dcerpc_is_big_endian(0x00000010) is False
        assert dcerpc_is_big_endian(0x10) is False

        # Big-endian
        assert dcerpc_is_big_endian(0x00000000) is True
        assert dcerpc_is_big_endian(0x00) is True

        # Other bytes don't affect byte order detection
        assert dcerpc_is_big_endian(0x00FF0010) is False
        assert dcerpc_is_big_endian(0x00FF0000) is True
