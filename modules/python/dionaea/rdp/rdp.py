# ABOUTME: RDP honeypot protocol handler for detecting DOUBLEPULSAR attacks.
# ABOUTME: Implements minimal RDP negotiation to capture login attempts and shellcode payloads.

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2025 Cowrie <cowrie@cowrie.org>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial

"""
RDP honeypot with DOUBLEPULSAR detection.

Based on:
- MS-RDPBCGR specification
- WithSecureLabs doublepulsar-detection-script (BSD 3-Clause)
- Rapid7 DOUBLEPULSAR RDP analysis
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import struct
import tempfile
from dataclasses import dataclass
from enum import IntEnum

from dionaea.core import connection, incident, g_dionaea
from dionaea.util import xor

from .packets import (
    DOUBLEPULSAR_MAGIC,
    NTLMSSP_SIGNATURE,
    DoublePulsarOpcode,
    DoublePulsarPacket,
    GCCClientData,
    MCSConnectInitial,
    MCSType,
    RDPNegotiationRequest,
    RDPProtocol,
    TPKTPacket,
    X224Packet,
    der_sequence_length,
    parse_ntlmssp_negotiate,
    parse_tsrequest,
)

rdplog = logging.getLogger("RDP")
rdplog.setLevel(logging.DEBUG)


class State(IntEnum):
    """RDP connection state machine."""
    NEGOTIATION = 0      # Waiting for X.224 Connection Request
    TLS_UPGRADE = 1      # Upgrading to TLS
    MCS_CONNECT = 2      # Waiting for MCS Connect Initial
    MCS_CHANNELS = 3     # Channel setup (ErectDomain, AttachUser, ChannelJoin)
    SECURE_SETTINGS = 4  # Waiting for Client Info PDU
    DOUBLEPULSAR = 5     # Detected DOUBLEPULSAR, handling commands
    DONE = 6             # Connection complete


@dataclass
class RDPConfig:
    """RDP service configuration."""
    port: int = 3389
    os_major: int = 6
    os_minor: int = 1
    os_build: int = 7601
    os_service_pack: int = 1
    os_product_type: int = 1  # VER_NT_WORKSTATION
    os_arch: int = 64


@dataclass
class ConnectionInfo:
    """Information gathered about the connecting client."""
    client_name: str = ""
    client_build: int = 0
    keyboard_layout: int = 0
    desktop_width: int = 0
    desktop_height: int = 0
    requested_channels: list[str] | None = None
    username: str = ""
    domain: str = ""
    password: str = ""
    cookie: str = ""

    def __post_init__(self):
        if self.requested_channels is None:
            self.requested_channels = []


class rdpd(connection):
    """RDP honeypot daemon."""

    shared_config_values = ["config"]

    # DOUBLEPULSAR signature - random per process to avoid fingerprinting
    doublepulsar_signature = secrets.randbits(32)

    @staticmethod
    def _calculate_xor_key_from_signature(sig: int) -> int:
        """Calculate XOR key from signature per DOUBLEPULSAR protocol."""
        x = (2 * sig) ^ (
            (((sig & 0xFF00) | (sig << 16)) << 8)
            | (((sig >> 16) | (sig & 0xFF0000)) >> 8)
        )
        return x & 0xFFFFFFFF

    doublepulsar_xor_key = _calculate_xor_key_from_signature(doublepulsar_signature)

    @classmethod
    def get_doublepulsar_xor_key_bytes(cls) -> bytearray:
        """Convert XOR key to bytearray for XOR operations (little-endian)."""
        key = cls.doublepulsar_xor_key
        return bytearray([
            key & 0xFF,
            (key >> 8) & 0xFF,
            (key >> 16) & 0xFF,
            (key >> 24) & 0xFF,
        ])

    def __init__(self, proto: str = "tcp") -> None:
        connection.__init__(self, proto)
        self.state = State.NEGOTIATION
        self.config = RDPConfig()
        self.client_info = ConnectionInfo()
        self.use_ssl = False
        self.buffer = b""
        self.doublepulsar_payload_buffer = b""
        self.user_channel_id = 0
        self.io_channel_id = 1003  # Standard I/O channel

    def apply_config(self, config: dict | None = None) -> None:
        """Apply configuration from YAML."""
        if config is None:
            config = {}
        self.config.port = config.get("port", 3389)

        os_config = config.get("os_version", {})
        self.config.os_major = os_config.get("major", 6)
        self.config.os_minor = os_config.get("minor", 1)
        self.config.os_build = os_config.get("build", 7601)
        self.config.os_service_pack = os_config.get("service_pack", 1)
        self.config.os_product_type = os_config.get("product_type", 1)
        self.config.os_arch = os_config.get("arch", 64)

    def handle_established(self) -> None:
        """Handle new connection."""
        rdplog.info(
            "RDP connection from %s:%d",
            self.remote.host,
            self.remote.port,
        )
        self.timeouts.idle = 30.0
        self.timeouts.sustain = 120.0
        try:
            self.processors()
        except Exception as e:
            rdplog.error("Error calling processors(): %s", e)

    def handle_disconnect(self) -> bool:
        """Handle disconnection."""
        rdplog.debug(
            "RDP disconnect from %s:%d (state=%s)",
            self.remote.host,
            self.remote.port,
            State(self.state).name,
        )
        return True

    def handle_timeout_idle(self) -> bool:
        """Handle idle timeout."""
        rdplog.debug("RDP idle timeout")
        return False

    def handle_timeout_sustain(self) -> bool:
        """Handle sustain timeout."""
        rdplog.debug("RDP sustain timeout")
        return False

    def handle_io_in(self, data: bytes) -> int:
        """Handle incoming data."""
        rdplog.debug("handle_io_in: received %d bytes: %s", len(data), data[:20].hex())
        self.buffer += data

        while True:
            consumed = self._process_buffer()
            if consumed == 0:
                break

        return len(data)

    def _process_buffer(self) -> int:
        """Process buffered data based on current state."""
        rdplog.debug("_process_buffer: buffer=%d bytes, state=%s", len(self.buffer), State(self.state).name)
        if len(self.buffer) < 4:
            return 0

        # Parse TPKT header to get packet length
        tpkt = TPKTPacket.parse(self.buffer)
        if tpkt is None:
            # Check for DOUBLEPULSAR without TPKT wrapper
            if self._check_doublepulsar_raw():
                return len(self.buffer)
            # CredSSP TSRequest (ASN.1 SEQUENCE) arrives without TPKT wrapper
            if self.state == State.MCS_CONNECT and self.buffer[0] == 0x30:
                return self._handle_raw_credssp()
            rdplog.warning(
                "Unparseable data in buffer (%d bytes, first=0x%02x, state=%s)",
                len(self.buffer), self.buffer[0], State(self.state).name,
            )
            return 0

        packet_len = tpkt.length
        if len(self.buffer) < packet_len:
            return 0

        # Remove complete packet from buffer
        self.buffer = self.buffer[packet_len:]

        self._handle_packet(tpkt)
        return packet_len

    def _check_doublepulsar_raw(self) -> bool:
        """Check for DOUBLEPULSAR magic without TPKT wrapper."""
        if len(self.buffer) >= 7:
            # Look for channelJoinConfirm (0x3c) followed by magic
            if self.buffer[0] == 0x3c:
                magic = struct.unpack('>I', self.buffer[1:5])[0]
                if magic == DOUBLEPULSAR_MAGIC:
                    self.state = State.DOUBLEPULSAR
                    self._handle_doublepulsar_command(self.buffer)
                    return True
        return False

    def _handle_raw_credssp(self) -> int:
        """Handle a CredSSP TSRequest that arrived without TPKT framing."""
        seq_len = der_sequence_length(self.buffer)
        if seq_len is None:
            # Incomplete — wait for more data
            return 0
        raw = self.buffer[:seq_len]
        self.buffer = self.buffer[seq_len:]
        self._handle_credssp(raw)
        return seq_len

    def _handle_packet(self, tpkt: TPKTPacket) -> None:
        """Route packet to appropriate handler based on state."""
        payload = tpkt.payload
        rdplog.debug("_handle_packet: state=%s, payload=%d bytes", State(self.state).name, len(payload))

        if self.state == State.NEGOTIATION:
            self._handle_negotiation(payload)
        elif self.state == State.MCS_CONNECT:
            self._handle_mcs_connect(payload)
        elif self.state == State.MCS_CHANNELS:
            self._handle_mcs_channels(payload)
        elif self.state == State.SECURE_SETTINGS:
            self._handle_secure_settings(payload)
        elif self.state == State.DOUBLEPULSAR:
            self._handle_doublepulsar(payload)
        else:
            rdplog.debug("Unhandled state %s, data: %s", State(self.state).name, payload.hex())

    def _handle_negotiation(self, data: bytes) -> None:
        """Handle X.224 Connection Request."""
        x224 = X224Packet.parse_connection_request(data)
        if x224 is None:
            rdplog.warning("Invalid X.224 Connection Request")
            return

        # Parse RDP negotiation request
        neg_req = RDPNegotiationRequest.parse(x224.payload)
        if neg_req:
            if neg_req.cookie:
                self.client_info.cookie = neg_req.cookie
                rdplog.debug("RDP cookie: %s", neg_req.cookie)

            # Check requested protocols
            if neg_req.requested_protocols & RDPProtocol.PROTOCOL_HYBRID:
                # Client wants NLA - we don't support it, offer SSL instead
                rdplog.debug("Client requested NLA, offering SSL")
                self.use_ssl = True
            elif neg_req.requested_protocols & RDPProtocol.PROTOCOL_SSL:
                self.use_ssl = True
            else:
                self.use_ssl = False

        # Send Connection Confirm
        response = X224Packet.build_connection_confirm(use_ssl=self.use_ssl)
        self._send_tpkt(response)

        if self.use_ssl:
            rdplog.debug("Upgrading connection to TLS")
            self.start_tls()
        self.state = State.MCS_CONNECT

    def _handle_mcs_connect(self, data: bytes) -> None:
        """Handle MCS Connect-Initial."""
        rdplog.debug("_handle_mcs_connect: received %d bytes: %s", len(data), data[:20].hex())

        # Skip X.224 Data header
        x224 = X224Packet.parse_data(data)
        if x224 is None:
            # Try parsing raw MCS data
            mcs_data = data
            rdplog.debug("_handle_mcs_connect: X.224 parse failed, using raw data")
        else:
            mcs_data = x224.payload
            rdplog.debug("_handle_mcs_connect: X.224 payload (%d bytes): %s", len(mcs_data), mcs_data[:20].hex() if mcs_data else "empty")

        # Check for MCS Connect-Initial
        if len(mcs_data) < 2:
            rdplog.debug("_handle_mcs_connect: mcs_data too short (%d bytes)", len(mcs_data))
            return

        rdplog.debug("_handle_mcs_connect: first byte = 0x%02x", mcs_data[0])

        # Check for DOUBLEPULSAR first - can arrive at any state
        if mcs_data[0] == 0x3c:  # channelJoinConfirm carrier
            rdplog.debug("_handle_mcs_connect: detected 0x3c, checking DOUBLEPULSAR")
            dp = DoublePulsarPacket.parse(mcs_data)
            if dp:
                rdplog.debug("DOUBLEPULSAR detected in MCS_CONNECT state: opcode=%s", dp.opcode)
                self.state = State.DOUBLEPULSAR
                self._handle_doublepulsar_command(mcs_data)
                return
            else:
                rdplog.debug("_handle_mcs_connect: DoublePulsarPacket.parse returned None")

        # CredSSP TSRequest (ASN.1 SEQUENCE) — NLA clients send this instead of MCS
        if mcs_data[0] == 0x30:
            self._handle_credssp(mcs_data)
            return

        # BER-encoded Connect-Initial starts with 0x7f 0x65
        if mcs_data[0:2] == bytes([0x7f, 0x65]):
            mcs = MCSConnectInitial.parse(mcs_data)
            if mcs:
                # Extract client information from GCC data
                gcc_data = GCCClientData.parse(mcs.user_data)
                if gcc_data:
                    self.client_info.client_name = gcc_data.client_name
                    self.client_info.client_build = gcc_data.client_build
                    self.client_info.keyboard_layout = gcc_data.keyboard_layout
                    self.client_info.desktop_width = gcc_data.desktop_width
                    self.client_info.desktop_height = gcc_data.desktop_height
                    self.client_info.requested_channels = gcc_data.requested_channels
                    rdplog.debug(
                        "RDP client: name=%s, build=%d, kb_layout=0x%x, desktop=%dx%d",
                        gcc_data.client_name,
                        gcc_data.client_build,
                        gcc_data.keyboard_layout,
                        gcc_data.desktop_width,
                        gcc_data.desktop_height,
                    )
                    if gcc_data.requested_channels:
                        rdplog.debug("RDP requested channels: %s", gcc_data.requested_channels)
                        i = incident("dionaea.connection.rdp.channels")
                        i.con = self
                        i.set("channels", ",".join(gcc_data.requested_channels))
                        i.report()

            # Send MCS Connect-Response
            self._send_mcs_connect_response()
            self.state = State.MCS_CHANNELS
        else:
            rdplog.debug("Unexpected MCS data: %s", mcs_data[:20].hex())

    def _handle_credssp(self, data: bytes) -> None:
        """Extract client info from CredSSP TSRequest containing NTLMSSP Negotiate."""
        ts = parse_tsrequest(data)
        if ts is None:
            rdplog.debug("CredSSP TSRequest parse failed")
            return

        for token in ts.nego_tokens:
            if not token.startswith(NTLMSSP_SIGNATURE):
                continue
            ntlm = parse_ntlmssp_negotiate(token)
            if ntlm is None:
                continue

            parts = []
            if ntlm.workstation_name:
                self.client_info.client_name = ntlm.workstation_name
                parts.append("workstation=%s" % ntlm.workstation_name)
            if ntlm.domain_name:
                self.client_info.domain = ntlm.domain_name
                parts.append("domain=%s" % ntlm.domain_name)
            if ntlm.os_version:
                major, minor, build, _rev = ntlm.os_version
                parts.append("os=%d.%d.%d" % (major, minor, build))

            rdplog.info(
                "RDP NLA (CredSSP v%d): %s",
                ts.version,
                ", ".join(parts) if parts else "no client details",
            )

            i = incident("dionaea.connection.rdp.credssp")
            i.con = self
            if ntlm.workstation_name:
                i.set("workstation", ntlm.workstation_name)
            if ntlm.domain_name:
                i.set("domain", ntlm.domain_name)
            if ntlm.os_version:
                i.set("os_version", "%d.%d.%d" % ntlm.os_version[:3])
            i.set("negotiate_flags", "0x%08x" % ntlm.flags)
            i.report()
            return

        rdplog.debug("CredSSP TSRequest v%d with no NTLMSSP token", ts.version)

    def _send_mcs_connect_response(self) -> None:
        """Send MCS Connect-Response with GCC Conference Create Response."""
        # Simplified MCS Connect-Response
        # This is a minimal response to keep the connection alive
        mcs_response = bytes.fromhex(
            "7f66"  # BER: Connect-Response
            "8201be"  # Length
            "0a0100"  # Result: rt-successful
            "0201"  # CalledConnectId
            "00"
            "3081b7"  # DomainParameters
            "0201"  # maxChannelIds
            "22"
            "0201"  # maxUserIds
            "03"
            "0201"  # maxTokenIds
            "00"
            "0201"  # numPriorities
            "01"
            "0201"  # minThroughput
            "00"
            "0201"  # maxHeight
            "01"
            "0202"  # maxMCSPDUsize
            "ffff"
            "0202"  # protocolVersion
            "0002"
            "0481a7"  # UserData (GCC Conference Create Response)
        )

        # SC_CORE (Server Core Data)
        sc_core = bytes.fromhex("0c00")  # Type: SC_CORE (0x0c01 LE -> 0c 01)
        sc_core = struct.pack('<H', 0x0c01)
        sc_core += struct.pack('<H', 16)  # Length
        sc_core += struct.pack('<I', 0x00080004)  # Version (RDP 5.0+)
        sc_core += struct.pack('<I', 0)  # clientRequestedProtocols
        sc_core += struct.pack('<I', 0)  # earlyCapabilityFlags

        # SC_NET (Server Network Data)
        sc_net = struct.pack('<H', 0x0c03)  # Type: SC_NET
        sc_net += struct.pack('<H', 12)  # Length
        sc_net += struct.pack('<H', self.io_channel_id)  # MCSChannelId
        sc_net += struct.pack('<H', 1)  # channelCount
        sc_net += struct.pack('<H', self.io_channel_id + 1)  # channel[0]
        sc_net += struct.pack('<H', 0)  # Pad

        # Combine server data
        server_data = sc_core + sc_net

        # Build full response (simplified - using prebuilt header)
        # In production, this should be properly BER-encoded
        full_response = mcs_response + server_data

        x224_data = X224Packet.build_data_header() + full_response
        self._send_tpkt(x224_data)

    def _handle_mcs_channels(self, data: bytes) -> None:
        """Handle MCS channel setup (ErectDomain, AttachUser, ChannelJoin)."""
        x224 = X224Packet.parse_data(data)
        mcs_data = x224.payload if x224 else data

        if len(mcs_data) < 1:
            return

        pdu_type = mcs_data[0]

        # Check for DOUBLEPULSAR first
        if pdu_type == 0x3c:  # channelJoinConfirm carrier
            dp = DoublePulsarPacket.parse(mcs_data)
            if dp:
                self.state = State.DOUBLEPULSAR
                self._handle_doublepulsar_command(mcs_data)
                return

        if pdu_type == MCSType.ERECT_DOMAIN_REQUEST:
            rdplog.debug("MCS Erect Domain Request")
            # No response needed

        elif pdu_type == MCSType.ATTACH_USER_REQUEST:
            rdplog.debug("MCS Attach User Request")
            # Send Attach User Confirm
            self.user_channel_id = 1001 + secrets.randbelow(100)
            self._send_attach_user_confirm()

        elif pdu_type == MCSType.CHANNEL_JOIN_REQUEST:
            rdplog.debug("MCS Channel Join Request")
            # Parse channel ID and send confirm
            if len(mcs_data) >= 5:
                initiator = struct.unpack('>H', mcs_data[1:3])[0]
                channel_id = struct.unpack('>H', mcs_data[3:5])[0]
                self._send_channel_join_confirm(initiator, channel_id)

        elif pdu_type == MCSType.SEND_DATA_REQUEST:
            # Client is sending data - transition to secure settings
            self.state = State.SECURE_SETTINGS
            self._handle_secure_settings(data)

        else:
            rdplog.debug("Unknown MCS PDU type: 0x%02x", pdu_type)

    def _send_attach_user_confirm(self) -> None:
        """Send MCS Attach User Confirm."""
        # AttachUserConfirm ::= [APPLICATION 11] IMPLICIT SEQUENCE {
        #   result      Result,
        #   initiator   UserId OPTIONAL
        # }
        confirm = bytes([
            MCSType.ATTACH_USER_CONFIRM,
            0x00,  # Result: rt-successful
        ])
        # UserId encoded as PER (user_channel_id - 1001)
        user_offset = self.user_channel_id - 1001
        confirm += struct.pack('>H', user_offset)

        x224_data = X224Packet.build_data_header() + confirm
        self._send_tpkt(x224_data)

    def _send_channel_join_confirm(self, initiator: int, channel_id: int) -> None:
        """Send MCS Channel Join Confirm."""
        confirm = bytes([
            MCSType.CHANNEL_JOIN_CONFIRM,
            0x00,  # Result: rt-successful
        ])
        confirm += struct.pack('>H', initiator)
        confirm += struct.pack('>H', channel_id)
        confirm += struct.pack('>H', channel_id)  # Requested = Joined

        x224_data = X224Packet.build_data_header() + confirm
        self._send_tpkt(x224_data)

    def _handle_secure_settings(self, data: bytes) -> None:
        """Handle Security Exchange and Client Info PDU."""
        x224 = X224Packet.parse_data(data)
        mcs_data = x224.payload if x224 else data

        # Check for DOUBLEPULSAR
        if len(mcs_data) >= 7 and mcs_data[0] == 0x3c:
            dp = DoublePulsarPacket.parse(mcs_data)
            if dp:
                self.state = State.DOUBLEPULSAR
                self._handle_doublepulsar_command(mcs_data)
                return

        # Look for SendDataRequest with client info
        if len(mcs_data) > 0 and mcs_data[0] == MCSType.SEND_DATA_REQUEST:
            self._parse_client_info_pdu(mcs_data)

    def _parse_client_info_pdu(self, mcs_data: bytes) -> None:
        """Parse Client Info PDU to extract username/domain/password."""
        # SendDataRequest header: type(1), initiator(2), channelId(2), priority(1), segmentation(1), len(2+)
        if len(mcs_data) < 8:
            return

        # Skip MCS header to get to security header
        offset = 8
        if len(mcs_data) <= offset:
            return

        # Look for InfoPacket signature
        # The actual parsing depends on whether encryption is enabled
        # For non-encrypted (basic RDP), we can try to find credentials

        # Try to find domain\username pattern
        try:
            # Look for null-terminated UTF-16LE strings
            remaining = mcs_data[offset:]

            # Client Info Packet structure (simplified):
            # CodePage (4), Flags (4), cbDomain (2), cbUserName (2), cbPassword (2), ...
            if len(remaining) < 18:
                return

            _ = struct.unpack('<I', remaining[4:8])[0]  # flags (unused)
            cb_domain = struct.unpack('<H', remaining[8:10])[0]
            cb_username = struct.unpack('<H', remaining[10:12])[0]
            cb_password = struct.unpack('<H', remaining[12:14])[0]

            data_offset = 18  # Fixed header size

            if cb_domain > 0 and len(remaining) >= data_offset + cb_domain:
                domain_bytes = remaining[data_offset:data_offset + cb_domain]
                self.client_info.domain = domain_bytes.decode('utf-16-le', errors='replace').rstrip('\x00')
                data_offset += cb_domain + 2  # +2 for null terminator

            if cb_username > 0 and len(remaining) >= data_offset + cb_username:
                username_bytes = remaining[data_offset:data_offset + cb_username]
                self.client_info.username = username_bytes.decode('utf-16-le', errors='replace').rstrip('\x00')
                data_offset += cb_username + 2

            if cb_password > 0 and len(remaining) >= data_offset + cb_password:
                password_bytes = remaining[data_offset:data_offset + cb_password]
                self.client_info.password = password_bytes.decode('utf-16-le', errors='replace').rstrip('\x00')

            if self.client_info.username or self.client_info.domain:
                rdplog.info(
                    "RDP login attempt: domain=%s, username=%s, password=%s",
                    self.client_info.domain or "(none)",
                    self.client_info.username or "(none)",
                    "***" if self.client_info.password else "(none)",
                )

                # Create incident for login attempt
                i = incident("dionaea.connection.rdp.login")
                i.con = self
                i.set("domain", self.client_info.domain)
                i.set("username", self.client_info.username)
                i.set("password", self.client_info.password)
                i.set("hostname", self.client_info.client_name)
                i.set("client_build", self.client_info.client_build)
                i.set("keyboard_layout", self.client_info.keyboard_layout)
                i.set("desktop_width", self.client_info.desktop_width)
                i.set("desktop_height", self.client_info.desktop_height)
                i.set("cookie", self.client_info.cookie)
                i.report()

        except Exception as e:
            rdplog.debug("Failed to parse client info: %s", e)

    def _handle_doublepulsar(self, data: bytes) -> None:
        """Handle data in DOUBLEPULSAR state."""
        x224 = X224Packet.parse_data(data)
        mcs_data = x224.payload if x224 else data
        self._handle_doublepulsar_command(mcs_data)

    def _handle_doublepulsar_command(self, data: bytes) -> None:
        """Handle DOUBLEPULSAR command."""
        dp = DoublePulsarPacket.parse(data)
        if dp is None:
            # Could be payload continuation
            if self.doublepulsar_payload_buffer:
                self.doublepulsar_payload_buffer += data
                rdplog.debug("DOUBLEPULSAR payload chunk: %d bytes", len(data))
            return

        rdplog.info(
            "DOUBLEPULSAR command detected: opcode=0x%02x from %s:%d",
            dp.opcode,
            self.remote.host,
            self.remote.port,
        )

        if dp.opcode == DoublePulsarOpcode.PING:
            self._handle_doublepulsar_ping()
        elif dp.opcode == DoublePulsarOpcode.EXEC:
            self._handle_doublepulsar_exec(dp.body)
        elif dp.opcode == DoublePulsarOpcode.BURN:
            self._handle_doublepulsar_burn()
        else:
            rdplog.warning("Unknown DOUBLEPULSAR opcode: 0x%02x", dp.opcode)

    def _handle_doublepulsar_ping(self) -> None:
        """Handle DOUBLEPULSAR ping command."""
        rdplog.info(
            "DOUBLEPULSAR PING from %s:%d - responding with OS info",
            self.remote.host,
            self.remote.port,
        )

        # Build ping response with configured OS version
        os_info = DoublePulsarPacket.build_ping_response(
            major=self.config.os_major,
            minor=self.config.os_minor,
            build=self.config.os_build,
            service_pack=self.config.os_service_pack,
            product_type=self.config.os_product_type,
            arch=self.config.os_arch,
        )

        response = DoublePulsarPacket.build_response_packet(
            DoublePulsarOpcode.PING,
            os_info,
        )
        self.send(response)

        # Create incident
        i = incident("dionaea.connection.rdp.doublepulsar.ping")
        i.con = self
        i.report()

    def _handle_doublepulsar_exec(self, body: bytes) -> None:
        """Handle DOUBLEPULSAR exec command with shellcode."""
        rdplog.info(
            "DOUBLEPULSAR EXEC from %s:%d - capturing shellcode (%d bytes)",
            self.remote.host,
            self.remote.port,
            len(body),
        )

        if len(body) == 0:
            # Exec command without body - expecting payload in next packets
            self.doublepulsar_payload_buffer = b""
            return

        # Store payload
        self.doublepulsar_payload_buffer += body

        # Try to decode payload
        self._process_doublepulsar_payload()

    def _process_doublepulsar_payload(self) -> None:
        """Process captured DOUBLEPULSAR payload."""
        if len(self.doublepulsar_payload_buffer) < 16:
            return

        raw_payload = self.doublepulsar_payload_buffer

        # Calculate hashes
        hash_raw = hashlib.sha256(raw_payload).hexdigest()

        # XOR decode the payload
        xor_key = self.get_doublepulsar_xor_key_bytes()
        decoded_payload = xor(raw_payload, xor_key)
        hash_decoded = hashlib.sha256(decoded_payload).hexdigest()

        rdplog.info(
            "DOUBLEPULSAR payload: raw_size=%d, raw_sha256=%s, decoded_sha256=%s",
            len(raw_payload),
            hash_raw,
            hash_decoded,
        )

        # Save payloads to temp files
        try:
            # Raw payload
            with tempfile.NamedTemporaryFile(
                prefix="rdp_doublepulsar_raw_",
                suffix=".bin",
                delete=False,
                dir=g_dionaea.config().get("dionaea", {}).get("download.dir", "/tmp"),
            ) as f:
                f.write(raw_payload)
                raw_path = f.name

            # Decoded payload
            with tempfile.NamedTemporaryFile(
                prefix="rdp_doublepulsar_decoded_",
                suffix=".bin",
                delete=False,
                dir=g_dionaea.config().get("dionaea", {}).get("download.dir", "/tmp"),
            ) as f:
                f.write(decoded_payload)
                decoded_path = f.name

            rdplog.info(
                "DOUBLEPULSAR payloads saved: raw=%s, decoded=%s",
                raw_path,
                decoded_path,
            )

            # Create incident for payload
            i = incident("dionaea.connection.rdp.doublepulsar.exec")
            i.con = self
            i.set("raw_path", raw_path)
            i.set("decoded_path", decoded_path)
            i.set("raw_sha256", hash_raw)
            i.set("decoded_sha256", hash_decoded)
            i.set("size", len(raw_payload))
            i.report()

            # Also report as download for further processing
            i = incident("dionaea.download.complete")
            i.con = self
            i.set("path", decoded_path)
            i.set("url", f"rdp-doublepulsar://{self.remote.host}:{self.remote.port}/")
            i.report()

        except Exception as e:
            rdplog.error("Failed to save DOUBLEPULSAR payload: %s", e)

        # Clear buffer
        self.doublepulsar_payload_buffer = b""

    def _handle_doublepulsar_burn(self) -> None:
        """Handle DOUBLEPULSAR burn (neutralize) command."""
        rdplog.info(
            "DOUBLEPULSAR BURN from %s:%d - implant neutralization requested",
            self.remote.host,
            self.remote.port,
        )

        # Respond with success
        response = DoublePulsarPacket.build_response_packet(
            DoublePulsarOpcode.BURN,
            b'',
        )
        self.send(response)

        # Create incident
        i = incident("dionaea.connection.rdp.doublepulsar.burn")
        i.con = self
        i.report()

    def _send_tpkt(self, payload: bytes) -> None:
        """Send data wrapped in TPKT."""
        tpkt = TPKTPacket(3, 0, 0, payload)
        self.send(tpkt.build())


# Log DOUBLEPULSAR signature at module load
rdplog.debug(
    "DOUBLEPULSAR signature: 0x%08x, XOR key: 0x%08x",
    rdpd.doublepulsar_signature,
    rdpd.doublepulsar_xor_key,
)
