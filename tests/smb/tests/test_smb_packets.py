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
_dionaea_path = os.path.join(_base, '../../../modules/python')
_dionaea_path = os.path.abspath(_dionaea_path)

# Add to path so that the dionaea.smb.include package can be found
if _dionaea_path not in sys.path:
    sys.path.insert(0, _dionaea_path)

# Create stub modules to avoid loading dionaea/__init__.py which requires yaml
_dionaea_stub = types.ModuleType('dionaea')
_dionaea_stub.__path__ = [os.path.join(_dionaea_path, 'dionaea')]
sys.modules['dionaea'] = _dionaea_stub

_smb_stub = types.ModuleType('dionaea.smb')
_smb_stub.__path__ = [os.path.join(_dionaea_path, 'dionaea/smb')]
sys.modules['dionaea.smb'] = _smb_stub

_include_stub = types.ModuleType('dionaea.smb.include')
_include_stub.__path__ = [os.path.join(_dionaea_path, 'dionaea/smb/include')]
sys.modules['dionaea.smb.include'] = _include_stub

# Now we can import the include submodules
from dionaea.smb.include import smbfields

import pytest


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
    raw = bytes([
        0x08,  # WordCount
        0x64, 0x00,  # TotalParamCount = 100
        0xc8, 0x00,  # TotalDataCount = 200
        0x32, 0x00,  # ParamCount = 50
        0x3c, 0x00,  # ParamOffset = 60
        0x00, 0x00,  # ParamDisplacement = 0
        0x4b, 0x00,  # DataCount = 75
        0x78, 0x00,  # DataOffset = 120
        0x19, 0x00,  # DataDisplacement = 25
        0x7d, 0x00,  # ByteCount = 125
    ])
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
    smb_hdr = SMB_Header(Command=0x26, Flags=0x00)  # 0x26 = TRANSACTION_SECONDARY, Flags=0 (request)
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
