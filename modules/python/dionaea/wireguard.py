# ABOUTME: WireGuard VPN honeypot - detects scanning on UDP 51820
# ABOUTME: Logs connection attempts and extracts ephemeral keys from handshakes

# SPDX-FileCopyrightText: 2025 Cowrie <cowrie@cowrie.org>
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial

from __future__ import annotations

import logging
import os
import struct
from typing import Any

from dionaea import ServiceLoader
from dionaea.core import connection, incident

logger = logging.getLogger("wireguard")
logger.setLevel(logging.DEBUG)

# WireGuard message types
MSG_HANDSHAKE_INITIATION = 0x01
MSG_HANDSHAKE_RESPONSE = 0x02
MSG_COOKIE_REPLY = 0x03
MSG_TRANSPORT_DATA = 0x04

MSG_TYPES = {
    MSG_HANDSHAKE_INITIATION: "handshake_initiation",
    MSG_HANDSHAKE_RESPONSE: "handshake_response",
    MSG_COOKIE_REPLY: "cookie_reply",
    MSG_TRANSPORT_DATA: "transport_data",
}

# Expected message sizes
MSG_SIZES = {
    MSG_HANDSHAKE_INITIATION: 148,
    MSG_HANDSHAKE_RESPONSE: 92,
    MSG_COOKIE_REPLY: 64,
}


class WireGuardService(ServiceLoader):
    """Service loader for WireGuard honeypot on UDP 51820."""

    name = "wireguard"

    @classmethod
    def start(
        cls, addr: str, iface: str | None = None, config: dict[str, Any] | None = None
    ) -> list["WireGuardd"]:
        if config is None:
            config = {}

        daemon = WireGuardd(proto="udp")
        daemon.send_fake_response = config.get("send_fake_response", False)
        daemon.bind(addr, 51820, iface=iface)
        daemon.listen()
        logger.info("WireGuard honeypot listening on %s:51820", addr)
        return [daemon]


class WireGuardd(connection):
    """WireGuard honeypot daemon - logs VPN scanning attempts."""

    def __init__(self, proto: str = "udp"):
        logger.debug("WireGuard honeypot starting")
        connection.__init__(self, proto)
        self.send_fake_response = False

    def handle_established(self) -> None:
        self.timeouts.idle = 30
        self.timeouts.sustain = 60
        self.processors()

        # Report UDP connection
        i = incident("dionaea.connection.udp.connect")
        i.con = self
        i.report()

    def handle_io_in(self, data: bytes) -> int:
        """Handle incoming WireGuard packet."""
        if len(data) < 4:
            logger.debug(
                "Short packet from %s:%s (%d bytes)",
                self.remote.host,
                self.remote.port,
                len(data),
            )
            return len(data)

        # Parse message type (first byte)
        msg_type = data[0]
        msg_name = MSG_TYPES.get(msg_type, f"unknown(0x{msg_type:02x})")

        logger.info(
            "WireGuard %s from %s:%s (%d bytes)",
            msg_name,
            self.remote.host,
            self.remote.port,
            len(data),
        )

        # Parse handshake initiation for more details
        handshake_info: dict[str, Any] = {}
        if msg_type == MSG_HANDSHAKE_INITIATION and len(data) >= 148:
            handshake_info = self._parse_handshake_initiation(data)

            # Optionally send fake response to trigger more scanner behavior
            if self.send_fake_response and "sender_index" in handshake_info:
                self._send_fake_response(handshake_info["sender_index"])

        # Report the scan
        i = incident("dionaea.modules.python.wireguard.scan")
        i.con = self
        i.msg_type = msg_name
        if handshake_info.get("ephemeral_pubkey"):
            i.ephemeral_pubkey = handshake_info["ephemeral_pubkey"]
        i.report()

        return len(data)

    def _parse_handshake_initiation(self, data: bytes) -> dict[str, Any]:
        """Parse WireGuard handshake initiation message.

        Structure (148 bytes):
        - type: 1 byte (0x01)
        - reserved: 3 bytes (zeros)
        - sender_index: 4 bytes (LE uint32)
        - unencrypted_ephemeral: 32 bytes (Curve25519 public key)
        - encrypted_static: 48 bytes (encrypted)
        - encrypted_timestamp: 28 bytes (encrypted)
        - mac1: 16 bytes
        - mac2: 16 bytes
        """
        info: dict[str, Any] = {}
        try:
            sender_index = struct.unpack("<I", data[4:8])[0]
            ephemeral_pubkey = data[8:40]  # 32-byte Curve25519 public key

            info["sender_index"] = sender_index
            info["ephemeral_pubkey"] = ephemeral_pubkey.hex()

            logger.info(
                "  sender_index=%d ephemeral_key=%s",
                sender_index,
                ephemeral_pubkey.hex(),
            )
        except (struct.error, IndexError):
            pass
        return info

    def _send_fake_response(self, sender_index: int) -> None:
        """Send a fake handshake response.

        This won't complete the handshake (we don't have proper keys),
        but may trigger additional behavior from scanners/attackers.
        """
        # Build fake response (92 bytes)
        # type(1) + reserved(3) + sender_index(4) + receiver_index(4) +
        # unencrypted_ephemeral(32) + encrypted_nothing(16) + mac1(16) + mac2(16)
        response = bytearray(92)
        response[0] = MSG_HANDSHAKE_RESPONSE
        # receiver_index = their sender_index
        struct.pack_into("<I", response, 4, sender_index)
        # our sender_index = random
        struct.pack_into("<I", response, 8, struct.unpack("<I", os.urandom(4))[0])
        # Fill rest with random (won't decrypt correctly, but looks like a response)
        response[12:] = os.urandom(80)

        self.send(bytes(response))
        logger.debug("Sent fake handshake response")

    def handle_timeout_idle(self) -> bool:
        logger.debug("WireGuard connection idle timeout")
        return False
