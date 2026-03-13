# ABOUTME: Modbus TCP honeypot protocol module for dionaea
# ABOUTME: Emulates a Modbus PLC (coils, registers, device ID) on port 502

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2025 Cowrie <cowrie@cowrie.org>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial

from __future__ import annotations

import logging
import struct
from typing import Any

from dionaea import ServiceLoader
from dionaea.core import connection, incident

logger = logging.getLogger('modbus')

# Modbus exception codes
ILLEGAL_FUNCTION = 0x01
ILLEGAL_DATA_ADDRESS = 0x02
ILLEGAL_DATA_VALUE = 0x03

# Max quantities per Modbus spec
MAX_COIL_READ = 2000
MAX_REGISTER_READ = 125
MAX_COIL_WRITE = 1968
MAX_REGISTER_WRITE = 123

MBAP_HEADER_SIZE = 7


def make_exception(function_code: int, exception_code: int) -> bytes:
    """Build a Modbus exception response PDU."""
    return bytes([function_code | 0x80, exception_code])


def parse_mbap_frame(data: bytes) -> tuple[int, int, int, bytes, int] | None:
    """Parse one MBAP frame from buffer.

    Returns (transaction_id, protocol_id, unit_id, pdu, bytes_consumed)
    or None if not enough data or invalid protocol.
    """
    if len(data) < MBAP_HEADER_SIZE:
        return None
    txn_id, proto_id, length = struct.unpack('>HHH', data[:6])
    if proto_id != 0:
        return None
    total = 6 + length  # header (6 bytes before length field) + length
    if len(data) < total:
        return None
    unit_id = data[6]
    pdu = data[7:total]
    return (txn_id, proto_id, unit_id, pdu, total)


def build_mbap_response(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    """Wrap a response PDU in an MBAP header."""
    length = len(pdu) + 1  # +1 for unit_id
    return struct.pack('>HHHB', transaction_id, 0, length, unit_id) + pdu


class DeviceState:
    """Simulated PLC memory: coils, discrete inputs, holding/input registers."""

    def __init__(self) -> None:
        self.coils = bytearray(65536)
        self.discrete_inputs = bytearray(65536)
        self.holding_registers: list[int] = [0] * 65536
        self.input_registers: list[int] = [0] * 65536
        self._prepopulate()

    def _prepopulate(self) -> None:
        """Set plausible PLC values so the device looks real."""
        # Firmware version-ish values
        self.holding_registers[0] = 2
        self.holding_registers[1] = 0
        # Some typical sensor-range values
        self.holding_registers[10] = 2350   # e.g. temperature * 100
        self.holding_registers[11] = 5012   # e.g. pressure * 100
        self.holding_registers[12] = 60     # e.g. speed RPM
        self.holding_registers[20] = 1      # running status
        self.holding_registers[30] = 4800   # e.g. voltage * 10
        # Input registers: some read-only sensor values
        self.input_registers[0] = 2347
        self.input_registers[1] = 5008
        self.input_registers[2] = 59
        # A few coils on
        self.coils[0] = 1   # run
        self.coils[1] = 1   # enable
        self.discrete_inputs[0] = 1  # input power OK


def _read_bits(bits: bytearray, address: int, quantity: int,
               function_code: int, max_qty: int) -> bytes:
    """Shared logic for FC 1 (coils) and FC 2 (discrete inputs)."""
    if quantity < 1 or quantity > max_qty:
        return make_exception(function_code, ILLEGAL_DATA_VALUE)
    if address + quantity > 65536:
        return make_exception(function_code, ILLEGAL_DATA_ADDRESS)
    byte_count = (quantity + 7) // 8
    result = bytearray(byte_count)
    for i in range(quantity):
        if bits[address + i]:
            result[i // 8] |= 1 << (i % 8)
    return bytes([function_code, byte_count]) + bytes(result)


def handle_read_coils(state: DeviceState, address: int, quantity: int) -> bytes:
    """FC 1: Read Coils."""
    return _read_bits(state.coils, address, quantity, 0x01, MAX_COIL_READ)


def handle_read_discrete_inputs(state: DeviceState, address: int, quantity: int) -> bytes:
    """FC 2: Read Discrete Inputs."""
    return _read_bits(state.discrete_inputs, address, quantity, 0x02, MAX_COIL_READ)


def _read_registers(registers: list[int], address: int, quantity: int,
                    function_code: int) -> bytes:
    """Shared logic for FC 3 (holding) and FC 4 (input) registers."""
    if quantity < 1 or quantity > MAX_REGISTER_READ:
        return make_exception(function_code, ILLEGAL_DATA_VALUE)
    if address + quantity > 65536:
        return make_exception(function_code, ILLEGAL_DATA_ADDRESS)
    byte_count = quantity * 2
    data = struct.pack('>' + 'H' * quantity,
                       *registers[address:address + quantity])
    return bytes([function_code, byte_count]) + data


def handle_read_holding_registers(state: DeviceState, address: int, quantity: int) -> bytes:
    """FC 3: Read Holding Registers."""
    return _read_registers(state.holding_registers, address, quantity, 0x03)


def handle_read_input_registers(state: DeviceState, address: int, quantity: int) -> bytes:
    """FC 4: Read Input Registers."""
    return _read_registers(state.input_registers, address, quantity, 0x04)


def handle_write_single_coil(state: DeviceState, address: int, value: int) -> bytes:
    """FC 5: Write Single Coil. Value must be 0xFF00 (on) or 0x0000 (off)."""
    if value not in (0xFF00, 0x0000):
        return make_exception(0x05, ILLEGAL_DATA_VALUE)
    if address >= 65536:
        return make_exception(0x05, ILLEGAL_DATA_ADDRESS)
    state.coils[address] = 1 if value == 0xFF00 else 0
    return struct.pack('>BHH', 0x05, address, value)


def handle_write_single_register(state: DeviceState, address: int, value: int) -> bytes:
    """FC 6: Write Single Register."""
    if address >= 65536:
        return make_exception(0x06, ILLEGAL_DATA_ADDRESS)
    if value < 0 or value > 0xFFFF:
        return make_exception(0x06, ILLEGAL_DATA_VALUE)
    state.holding_registers[address] = value
    return struct.pack('>BHH', 0x06, address, value)


def handle_write_multiple_coils(state: DeviceState, address: int,
                                quantity: int, values: bytes) -> bytes:
    """FC 15: Write Multiple Coils."""
    if quantity < 1 or quantity > MAX_COIL_WRITE:
        return make_exception(0x0F, ILLEGAL_DATA_VALUE)
    if address + quantity > 65536:
        return make_exception(0x0F, ILLEGAL_DATA_ADDRESS)
    for i in range(quantity):
        byte_idx = i // 8
        bit_idx = i % 8
        state.coils[address + i] = 1 if (values[byte_idx] >> bit_idx) & 1 else 0
    return struct.pack('>BHH', 0x0F, address, quantity)


def handle_write_multiple_registers(state: DeviceState, address: int,
                                    quantity: int, values: bytes) -> bytes:
    """FC 16: Write Multiple Registers."""
    if quantity < 1 or quantity > MAX_REGISTER_WRITE:
        return make_exception(0x10, ILLEGAL_DATA_VALUE)
    if address + quantity > 65536:
        return make_exception(0x10, ILLEGAL_DATA_ADDRESS)
    for i in range(quantity):
        state.holding_registers[address + i] = struct.unpack('>H', values[i*2:i*2+2])[0]
    return struct.pack('>BHH', 0x10, address, quantity)


def handle_device_identification(vendor: str, product: str, version: str) -> bytes:
    """FC 43 / MEI 0x0E: Read Device Identification (basic, stream access)."""
    objects = [
        (0x00, vendor.encode()),   # VendorName
        (0x01, product.encode()),  # ProductCode
        (0x02, version.encode()),  # MajorMinorRevision
    ]
    obj_data = bytearray()
    for obj_id, val in objects:
        obj_data.append(obj_id)
        obj_data.append(len(val))
        obj_data.extend(val)
    return bytes([
        0x2B,           # FC 43
        0x0E,           # MEI type: Read Device Identification
        0x01,           # conformity level: basic
        0x00,           # more follows: no
        0x00,           # next object id
        len(objects),   # number of objects
    ]) + bytes(obj_data)


def dispatch_pdu(state: DeviceState, pdu: bytes,
                 vendor: str, product: str, version: str) -> bytes:
    """Route a Modbus PDU to the correct function code handler."""
    if len(pdu) < 1:
        return make_exception(0x00, ILLEGAL_FUNCTION)
    fc = pdu[0]
    try:
        if fc in (0x01, 0x02, 0x03, 0x04):
            if len(pdu) < 5:
                return make_exception(fc, ILLEGAL_DATA_VALUE)
            address, quantity = struct.unpack('>HH', pdu[1:5])
            if fc == 0x01:
                return handle_read_coils(state, address, quantity)
            elif fc == 0x02:
                return handle_read_discrete_inputs(state, address, quantity)
            elif fc == 0x03:
                return handle_read_holding_registers(state, address, quantity)
            else:
                return handle_read_input_registers(state, address, quantity)
        elif fc in (0x05, 0x06):
            if len(pdu) < 5:
                return make_exception(fc, ILLEGAL_DATA_VALUE)
            address, value = struct.unpack('>HH', pdu[1:5])
            if fc == 0x05:
                return handle_write_single_coil(state, address, value)
            else:
                return handle_write_single_register(state, address, value)
        elif fc == 0x0F:
            if len(pdu) < 6:
                return make_exception(fc, ILLEGAL_DATA_VALUE)
            address, quantity = struct.unpack('>HH', pdu[1:5])
            byte_count = pdu[5]
            values = pdu[6:6 + byte_count]
            return handle_write_multiple_coils(state, address, quantity, values)
        elif fc == 0x10:
            if len(pdu) < 6:
                return make_exception(fc, ILLEGAL_DATA_VALUE)
            address, quantity = struct.unpack('>HH', pdu[1:5])
            byte_count = pdu[5]
            values = pdu[6:6 + byte_count]
            return handle_write_multiple_registers(state, address, quantity, values)
        elif fc == 0x2B:
            return handle_device_identification(vendor, product, version)
        else:
            return make_exception(fc, ILLEGAL_FUNCTION)
    except Exception:
        logger.exception("Error handling FC %d", fc)
        return make_exception(fc, ILLEGAL_FUNCTION)


class ModbusService(ServiceLoader):
    name = "modbus"

    @classmethod
    def start(cls, addr: str, iface: str | None = None,
              config: dict[str, Any] | None = None) -> 'Modbusd':
        if config is None:
            config = {}
        port = config.get("port", 502)
        daemon = Modbusd(proto='tcp')
        daemon.apply_config(config)
        daemon.bind(addr, port, iface=iface)
        daemon.listen()
        return daemon


class Modbusd(connection):
    shared_config_values = ["vendor", "product", "version"]

    def __init__(self, proto: str | None = None) -> None:
        connection.__init__(self, proto)
        self.buf = b''
        self.state = DeviceState()
        self.vendor = "Schneider Electric"
        self.product = "Modicon M340"
        self.version = "2.0"

    def apply_config(self, config: dict[str, Any] | None) -> None:
        if config is None:
            return
        self.vendor = config.get("vendor", self.vendor)
        self.product = config.get("product", self.product)
        self.version = config.get("version", self.version)

    def handle_established(self) -> None:
        self.timeouts.idle = 120
        self.processors()

    def handle_io_in(self, data: bytes) -> int:
        self.buf += data
        while True:
            result = parse_mbap_frame(self.buf)
            if result is None:
                break
            txn_id, _proto_id, unit_id, pdu, consumed = result
            self.buf = self.buf[consumed:]
            response_pdu = dispatch_pdu(
                self.state, pdu,
                self.vendor, self.product, self.version,
            )
            self._emit_incident(pdu, unit_id)
            response = build_mbap_response(txn_id, unit_id, response_pdu)
            self.send(response)
        return len(data)

    def _emit_incident(self, pdu: bytes, unit_id: int) -> None:
        if len(pdu) < 1:
            return
        fc = pdu[0]
        i = incident("dionaea.modules.python.modbus.command")
        i.con = self
        i.function_code = fc
        i.unit_id = unit_id
        if len(pdu) >= 5:
            address, quantity = struct.unpack('>HH', pdu[1:5])
            i.address = address
            i.quantity = quantity
        i.report()

    def handle_timeout_idle(self) -> bool:
        return False

    def handle_disconnect(self) -> bool:
        return False
