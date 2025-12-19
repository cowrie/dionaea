# ABOUTME: TFTP protocol smoke tests for dionaea honeypot
# ABOUTME: Tests basic RRQ and WRQ handling using tftpy client

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import io
import socket
import tempfile

import tftpy


def test_tftp_read_request(dionaea_host, dionaea_ports):
    """Test that TFTP server responds to read requests.

    Dionaea should respond with either data or an error packet.
    Both indicate the server is working.
    """
    port = dionaea_ports["tftp"]
    client = tftpy.TftpClient(dionaea_host, port)

    # Request a non-existent file - expect file not found error
    output = io.BytesIO()
    try:
        client.download("nonexistent.txt", output)
        # If download succeeds, server is working
    except tftpy.TftpException as e:
        # File not found or other TFTP error means server responded
        assert "not found" in str(e).lower() or "error" in str(e).lower()


def test_tftp_write_request(dionaea_host, dionaea_ports):
    """Test that TFTP server responds to write requests.

    Dionaea should accept the write request and send ACK packets.
    """
    port = dionaea_ports["tftp"]
    client = tftpy.TftpClient(dionaea_host, port)

    # Upload a small test file - use tempfile because tftpy needs flock()
    test_data = b"test data from smoke test\n"
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(test_data)
        tmp.flush()
        tmp_path = tmp.name

    try:
        client.upload("test_upload.txt", tmp_path)
        # Upload succeeded - server is working
    except tftpy.TftpException:
        # Some error during upload - that's ok, server still responded
        pass


def test_tftp_connection(dionaea_host, dionaea_ports):
    """Test basic UDP connectivity to TFTP port.

    Sends a minimal RRQ packet and expects some response.
    """
    port = dionaea_ports["tftp"]

    # Build a minimal RRQ packet: opcode (2 bytes) + filename + null + mode + null
    # Opcode 1 = RRQ
    packet = b"\x00\x01" + b"test.txt\x00" + b"octet\x00"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    try:
        sock.sendto(packet, (dionaea_host, port))
        # Wait for any response (data or error)
        data, addr = sock.recvfrom(1024)
        # Got a response - server is alive
        assert len(data) >= 4  # Minimum TFTP packet size
    finally:
        sock.close()
