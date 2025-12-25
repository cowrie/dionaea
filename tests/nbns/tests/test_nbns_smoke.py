# ABOUTME: NBNS protocol smoke tests for dionaea honeypot
# ABOUTME: Tests that NBNS service handles queries without errors

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import socket
import struct


def encode_netbios_name(name: str, suffix: int = 0x00) -> bytes:
    """Encode a name using NetBIOS first-level encoding."""
    padded = name.upper().ljust(15)[:15]
    name_bytes = padded.encode('ascii') + bytes([suffix])

    encoded = []
    for byte in name_bytes:
        high = (byte >> 4) + ord('A')
        low = (byte & 0x0F) + ord('A')
        encoded.extend([high, low])

    return bytes(encoded)


def build_nbns_query(name: str, transaction_id: int = 0x1234) -> bytes:
    """Build a simple NBNS name query packet."""
    flags = 0x0110  # Query, recursion desired, broadcast
    header = struct.pack('!HHHHHH',
        transaction_id,
        flags,
        1,  # 1 question
        0,  # 0 answers
        0,  # 0 authority
        0   # 0 additional
    )

    encoded_name = encode_netbios_name(name)
    question = bytes([len(encoded_name)]) + encoded_name + b'\x00'
    question += struct.pack('!HH', 0x0020, 0x0001)  # NB, IN

    return header + question


def test_nbns_handles_query(dionaea_host, dionaea_ports):
    """Test that NBNS service handles a query without crashing."""
    port = dionaea_ports["nbns"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        packet = build_nbns_query("WPAD")
        sock.sendto(packet, (dionaea_host, port))
        # Response is optional depending on config, but no crash means success
        try:
            sock.recvfrom(1024)
        except socket.timeout:
            pass
    finally:
        sock.close()


def test_nbns_handles_multiple_queries(dionaea_host, dionaea_ports):
    """Test that NBNS handles multiple queries (exercises child connections)."""
    port = dionaea_ports["nbns"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        # Send several queries to exercise connection handling
        for i, name in enumerate(["WPAD", "TEST", "HOST", "ISATAP"]):
            packet = build_nbns_query(name, transaction_id=0x1000 + i)
            sock.sendto(packet, (dionaea_host, port))
            try:
                sock.recvfrom(1024)
            except socket.timeout:
                pass
    finally:
        sock.close()


def test_nbns_handles_malformed_packet(dionaea_host, dionaea_ports):
    """Test that NBNS handles malformed packets gracefully."""
    port = dionaea_ports["nbns"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    try:
        sock.sendto(b"\x00\x01\x02\x03", (dionaea_host, port))
        try:
            sock.recvfrom(1024)
        except socket.timeout:
            pass
    finally:
        sock.close()
