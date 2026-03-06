# ABOUTME: Unit tests for Modbus TCP protocol parsing and response generation
# ABOUTME: Tests MBAP framing, function code handlers, device state, and error responses

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import struct


def _build_mbap(transaction_id, unit_id, pdu):
    """Build an MBAP frame: [txn:2][proto:2][len:2][unit:1] + pdu"""
    length = len(pdu) + 1  # includes unit_id byte
    return struct.pack('>HHHB', transaction_id, 0, length, unit_id) + pdu


class TestMbapParsing:
    """Test MBAP header parsing and frame extraction."""

    def test_parse_valid_frame(self):
        from dionaea.modbus import parse_mbap_frame
        # FC 3 Read Holding Registers: addr=0, qty=1
        pdu = bytes([0x03, 0x00, 0x00, 0x00, 0x01])
        frame = _build_mbap(1, 1, pdu)
        result = parse_mbap_frame(frame)
        assert result is not None
        txn_id, proto_id, unit_id, pdu_out, consumed = result
        assert txn_id == 1
        assert proto_id == 0
        assert unit_id == 1
        assert pdu_out == pdu
        assert consumed == len(frame)

    def test_parse_incomplete_header(self):
        from dionaea.modbus import parse_mbap_frame
        # Only 5 bytes, need at least 7 for header
        result = parse_mbap_frame(b'\x00\x01\x00\x00\x00')
        assert result is None

    def test_parse_incomplete_pdu(self):
        from dionaea.modbus import parse_mbap_frame
        # Header says length=5 but only 1 byte of PDU present
        header = struct.pack('>HHH', 1, 0, 5)  # txn=1, proto=0, len=5
        result = parse_mbap_frame(header + b'\x01')
        assert result is None

    def test_parse_non_modbus_protocol(self):
        from dionaea.modbus import parse_mbap_frame
        # Protocol ID != 0 is not Modbus TCP
        pdu = bytes([0x03, 0x00, 0x00, 0x00, 0x01])
        frame = struct.pack('>HHH', 1, 1, len(pdu) + 1) + bytes([1]) + pdu
        result = parse_mbap_frame(frame)
        assert result is None

    def test_parse_multiple_frames(self):
        from dionaea.modbus import parse_mbap_frame
        pdu1 = bytes([0x03, 0x00, 0x00, 0x00, 0x01])
        pdu2 = bytes([0x03, 0x00, 0x0A, 0x00, 0x02])
        frame1 = _build_mbap(1, 1, pdu1)
        frame2 = _build_mbap(2, 1, pdu2)
        buf = frame1 + frame2
        result = parse_mbap_frame(buf)
        assert result is not None
        txn_id, _, _, pdu_out, consumed = result
        assert txn_id == 1
        assert consumed == len(frame1)
        # Remaining buffer should parse as second frame
        result2 = parse_mbap_frame(buf[consumed:])
        assert result2 is not None
        assert result2[0] == 2


class TestBuildMbapResponse:
    """Test MBAP response frame construction."""

    def test_build_response(self):
        from dionaea.modbus import build_mbap_response
        pdu = bytes([0x03, 0x02, 0x00, 0x64])
        frame = build_mbap_response(42, 1, pdu)
        txn, proto, length, unit = struct.unpack('>HHHB', frame[:7])
        assert txn == 42
        assert proto == 0
        assert length == len(pdu) + 1
        assert unit == 1
        assert frame[7:] == pdu


class TestDeviceState:
    """Test simulated PLC device state."""

    def test_initial_state(self):
        from dionaea.modbus import DeviceState
        state = DeviceState()
        assert len(state.coils) == 65536
        assert len(state.discrete_inputs) == 65536
        assert len(state.holding_registers) == 65536
        assert len(state.input_registers) == 65536

    def test_prepopulated_registers(self):
        from dionaea.modbus import DeviceState
        state = DeviceState()
        # Some holding registers should be non-zero (plausible PLC values)
        has_nonzero = any(v != 0 for v in state.holding_registers[:100])
        assert has_nonzero, "Expected some pre-populated holding register values"


class TestReadCoils:
    """Test FC 1: Read Coils."""

    def test_read_coils_basic(self):
        from dionaea.modbus import DeviceState, handle_read_coils
        state = DeviceState()
        state.coils[0] = 1
        state.coils[1] = 0
        state.coils[2] = 1
        pdu = handle_read_coils(state, address=0, quantity=3)
        assert pdu[0] == 0x01  # FC
        assert pdu[1] == 1     # byte count
        assert pdu[2] == 0b00000101  # coils 0,2 on

    def test_read_coils_spanning_bytes(self):
        from dionaea.modbus import DeviceState, handle_read_coils
        state = DeviceState()
        for i in range(10):
            state.coils[i] = 1
        pdu = handle_read_coils(state, address=0, quantity=10)
        assert pdu[0] == 0x01
        assert pdu[1] == 2     # 10 coils = 2 bytes
        assert pdu[2] == 0xFF  # first 8 coils all on
        assert pdu[3] == 0x03  # bits 0,1 of second byte

    def test_read_coils_address_out_of_range(self):
        from dionaea.modbus import DeviceState, handle_read_coils
        state = DeviceState()
        pdu = handle_read_coils(state, address=65535, quantity=2)
        # Should return exception: illegal data address (0x02)
        assert pdu[0] == 0x81  # FC + 0x80
        assert pdu[1] == 0x02

    def test_read_coils_quantity_zero(self):
        from dionaea.modbus import DeviceState, handle_read_coils
        state = DeviceState()
        pdu = handle_read_coils(state, address=0, quantity=0)
        assert pdu[0] == 0x81
        assert pdu[1] == 0x03  # illegal data value

    def test_read_coils_quantity_over_2000(self):
        from dionaea.modbus import DeviceState, handle_read_coils
        state = DeviceState()
        pdu = handle_read_coils(state, address=0, quantity=2001)
        assert pdu[0] == 0x81
        assert pdu[1] == 0x03


class TestReadDiscreteInputs:
    """Test FC 2: Read Discrete Inputs."""

    def test_read_discrete_inputs(self):
        from dionaea.modbus import DeviceState, handle_read_discrete_inputs
        state = DeviceState()
        # Clear prepopulated values for a clean test
        state.discrete_inputs[0] = 0
        state.discrete_inputs[3] = 1
        pdu = handle_read_discrete_inputs(state, address=0, quantity=8)
        assert pdu[0] == 0x02
        assert pdu[1] == 1
        assert pdu[2] == 0b00001000


class TestReadHoldingRegisters:
    """Test FC 3: Read Holding Registers."""

    def test_read_holding_registers(self):
        from dionaea.modbus import DeviceState, handle_read_holding_registers
        state = DeviceState()
        state.holding_registers[0] = 100
        state.holding_registers[1] = 200
        pdu = handle_read_holding_registers(state, address=0, quantity=2)
        assert pdu[0] == 0x03
        assert pdu[1] == 4  # 2 registers * 2 bytes
        assert struct.unpack('>H', pdu[2:4])[0] == 100
        assert struct.unpack('>H', pdu[4:6])[0] == 200

    def test_read_holding_registers_out_of_range(self):
        from dionaea.modbus import DeviceState, handle_read_holding_registers
        state = DeviceState()
        pdu = handle_read_holding_registers(state, address=65535, quantity=2)
        assert pdu[0] == 0x83
        assert pdu[1] == 0x02

    def test_read_holding_registers_quantity_over_125(self):
        from dionaea.modbus import DeviceState, handle_read_holding_registers
        state = DeviceState()
        pdu = handle_read_holding_registers(state, address=0, quantity=126)
        assert pdu[0] == 0x83
        assert pdu[1] == 0x03


class TestReadInputRegisters:
    """Test FC 4: Read Input Registers."""

    def test_read_input_registers(self):
        from dionaea.modbus import DeviceState, handle_read_input_registers
        state = DeviceState()
        state.input_registers[5] = 0xBEEF
        pdu = handle_read_input_registers(state, address=5, quantity=1)
        assert pdu[0] == 0x04
        assert pdu[1] == 2
        assert struct.unpack('>H', pdu[2:4])[0] == 0xBEEF


class TestWriteSingleCoil:
    """Test FC 5: Write Single Coil."""

    def test_write_coil_on(self):
        from dionaea.modbus import DeviceState, handle_write_single_coil
        state = DeviceState()
        pdu = handle_write_single_coil(state, address=10, value=0xFF00)
        assert state.coils[10] == 1
        assert pdu[0] == 0x05
        # Echo back address and value
        assert struct.unpack('>H', pdu[1:3])[0] == 10
        assert struct.unpack('>H', pdu[3:5])[0] == 0xFF00

    def test_write_coil_off(self):
        from dionaea.modbus import DeviceState, handle_write_single_coil
        state = DeviceState()
        state.coils[10] = 1
        pdu = handle_write_single_coil(state, address=10, value=0x0000)
        assert state.coils[10] == 0

    def test_write_coil_invalid_value(self):
        from dionaea.modbus import DeviceState, handle_write_single_coil
        state = DeviceState()
        pdu = handle_write_single_coil(state, address=10, value=0x1234)
        assert pdu[0] == 0x85
        assert pdu[1] == 0x03


class TestWriteSingleRegister:
    """Test FC 6: Write Single Register."""

    def test_write_single_register(self):
        from dionaea.modbus import DeviceState, handle_write_single_register
        state = DeviceState()
        pdu = handle_write_single_register(state, address=0, value=1234)
        assert state.holding_registers[0] == 1234
        assert pdu[0] == 0x06
        assert struct.unpack('>H', pdu[1:3])[0] == 0
        assert struct.unpack('>H', pdu[3:5])[0] == 1234


class TestWriteMultipleCoils:
    """Test FC 15: Write Multiple Coils."""

    def test_write_multiple_coils(self):
        from dionaea.modbus import DeviceState, handle_write_multiple_coils
        state = DeviceState()
        # Write 10 coils starting at address 20, first 8 on, then 2 more
        pdu = handle_write_multiple_coils(state, address=20, quantity=10,
                                          values=bytes([0xFF, 0x03]))
        assert pdu[0] == 0x0F
        assert struct.unpack('>H', pdu[1:3])[0] == 20
        assert struct.unpack('>H', pdu[3:5])[0] == 10
        for i in range(10):
            assert state.coils[20 + i] == 1

    def test_write_multiple_coils_out_of_range(self):
        from dionaea.modbus import DeviceState, handle_write_multiple_coils
        state = DeviceState()
        pdu = handle_write_multiple_coils(state, address=65530, quantity=10,
                                          values=bytes([0xFF, 0x03]))
        assert pdu[0] == 0x8F
        assert pdu[1] == 0x02


class TestWriteMultipleRegisters:
    """Test FC 16: Write Multiple Registers."""

    def test_write_multiple_registers(self):
        from dionaea.modbus import DeviceState, handle_write_multiple_registers
        state = DeviceState()
        values = struct.pack('>HH', 1111, 2222)
        pdu = handle_write_multiple_registers(state, address=0, quantity=2, values=values)
        assert pdu[0] == 0x10
        assert struct.unpack('>H', pdu[1:3])[0] == 0
        assert struct.unpack('>H', pdu[3:5])[0] == 2
        assert state.holding_registers[0] == 1111
        assert state.holding_registers[1] == 2222

    def test_write_multiple_registers_out_of_range(self):
        from dionaea.modbus import DeviceState, handle_write_multiple_registers
        state = DeviceState()
        values = struct.pack('>HH', 1111, 2222)
        pdu = handle_write_multiple_registers(state, address=65535, quantity=2, values=values)
        assert pdu[0] == 0x90
        assert pdu[1] == 0x02


class TestDeviceIdentification:
    """Test FC 43: Read Device Identification (MEI)."""

    def test_device_identification(self):
        from dionaea.modbus import handle_device_identification
        pdu = handle_device_identification(
            vendor="Schneider Electric",
            product="Modicon M340",
            version="2.0",
        )
        assert pdu[0] == 0x2B  # FC 43
        assert pdu[1] == 0x0E  # MEI type
        # Should contain vendor, product, version as objects
        # Parse the response to verify
        assert b'Schneider Electric' in pdu
        assert b'Modicon M340' in pdu
        assert b'2.0' in pdu


class TestExceptionResponse:
    """Test Modbus exception response generation."""

    def test_exception_response(self):
        from dionaea.modbus import make_exception
        pdu = make_exception(0x03, 0x02)
        assert pdu[0] == 0x83  # FC | 0x80
        assert pdu[1] == 0x02  # exception code

    def test_illegal_function(self):
        from dionaea.modbus import make_exception
        pdu = make_exception(0x07, 0x01)
        assert pdu[0] == 0x87
        assert pdu[1] == 0x01


class TestDispatchPdu:
    """Test PDU dispatch to correct function code handler."""

    def test_dispatch_read_holding_registers(self):
        from dionaea.modbus import DeviceState, dispatch_pdu
        state = DeviceState()
        state.holding_registers[0] = 42
        # FC 3, addr=0, qty=1
        pdu = struct.pack('>BHH', 0x03, 0, 1)
        result = dispatch_pdu(state, pdu, vendor="V", product="P", version="1")
        assert result[0] == 0x03
        assert struct.unpack('>H', result[2:4])[0] == 42

    def test_dispatch_unsupported_fc(self):
        from dionaea.modbus import DeviceState, dispatch_pdu
        state = DeviceState()
        pdu = bytes([0x07, 0x00, 0x00])  # FC 7 not supported
        result = dispatch_pdu(state, pdu, vendor="V", product="P", version="1")
        assert result[0] == 0x87  # 0x07 | 0x80
        assert result[1] == 0x01  # illegal function

    def test_dispatch_write_single_register(self):
        from dionaea.modbus import DeviceState, dispatch_pdu
        state = DeviceState()
        pdu = struct.pack('>BHH', 0x06, 5, 999)
        result = dispatch_pdu(state, pdu, vendor="V", product="P", version="1")
        assert result[0] == 0x06
        assert state.holding_registers[5] == 999

    def test_dispatch_fc43_device_id(self):
        from dionaea.modbus import DeviceState, dispatch_pdu
        state = DeviceState()
        # FC 43, MEI type 0x0E, Read Device ID code 1, Object ID 0
        pdu = bytes([0x2B, 0x0E, 0x01, 0x00])
        result = dispatch_pdu(state, pdu, vendor="TestVendor", product="TestProd", version="3.0")
        assert result[0] == 0x2B
        assert b'TestVendor' in result

    def test_dispatch_write_multiple_coils(self):
        from dionaea.modbus import DeviceState, dispatch_pdu
        state = DeviceState()
        # FC 15, addr=0, qty=8, byte_count=1, values=0xFF
        pdu = struct.pack('>BHH', 0x0F, 0, 8) + bytes([1, 0xFF])
        result = dispatch_pdu(state, pdu, vendor="V", product="P", version="1")
        assert result[0] == 0x0F
        for i in range(8):
            assert state.coils[i] == 1

    def test_dispatch_write_multiple_registers(self):
        from dionaea.modbus import DeviceState, dispatch_pdu
        state = DeviceState()
        # FC 16, addr=0, qty=2, byte_count=4, values
        reg_data = struct.pack('>HH', 100, 200)
        pdu = struct.pack('>BHH', 0x10, 0, 2) + bytes([4]) + reg_data
        result = dispatch_pdu(state, pdu, vendor="V", product="P", version="1")
        assert result[0] == 0x10
        assert state.holding_registers[0] == 100
        assert state.holding_registers[1] == 200
