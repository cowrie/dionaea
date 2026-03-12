# ABOUTME: RDP honeypot protocol handler with state machine for connection negotiation.
# ABOUTME: Handles TPKT framing, X.224, MCS/GCC handshake, and channel setup.

import enum
import logging

from .include.packets import (
    TPKT_HEADER_LEN,
    PROTOCOL_RDP,
    MCS_IO_CHANNEL_ID,
    parse_tpkt,
    build_tpkt,
    parse_x224_cr,
    build_x224_cc,
    parse_mcs_connect_initial,
    parse_mcs_erect_domain,
    parse_mcs_attach_user_request,
    build_mcs_attach_user_confirm,
    parse_mcs_channel_join_request,
    build_mcs_channel_join_confirm,
    build_mcs_connect_response,
    parse_gcc_client_core_data,
    CS_CORE,
)

logger = logging.getLogger('RDP')


class RdpState(enum.Enum):
    X224_NEGOTIATION = "x224_negotiation"
    MCS_CONNECT = "mcs_connect"
    MCS_ERECT_DOMAIN = "mcs_erect_domain"
    MCS_ATTACH_USER = "mcs_attach_user"
    MCS_CHANNEL_JOIN = "mcs_channel_join"
    SECURITY_EXCHANGE = "security_exchange"
    ESTABLISHED = "established"
    CLOSED = "closed"


# Default user ID assigned by the server
DEFAULT_USER_ID = 1007


class RdpStateMachine:
    """RDP protocol state machine, independent of the dionaea connection class.

    Call feed(data) with incoming bytes. Returns (bytes_consumed, list_of_response_packets).
    Each response packet is a complete TPKT-wrapped message ready to send.
    """

    def __init__(self) -> None:
        self.state = RdpState.X224_NEGOTIATION
        self.cookie: str = ""
        self.requested_protocols: int = PROTOCOL_RDP
        self.selected_protocol: int = PROTOCOL_RDP
        self.user_id: int | None = None
        self.client_core = None  # GCCClientCoreData, set after MCS Connect-Initial
        self.channel_ids: list[int] = []
        self._joined_channels: set[int] = set()

    def feed(self, data: bytes) -> tuple[int, list[bytes]]:
        """Process incoming data. Returns (bytes_consumed, response_packets)."""
        total_consumed = 0
        all_responses: list[bytes] = []

        while total_consumed < len(data):
            remaining = data[total_consumed:]

            # Parse TPKT frame
            tpkt = parse_tpkt(remaining)
            if tpkt is None:
                break
            version, length = tpkt
            if len(remaining) < length:
                break  # Incomplete packet

            # Extract TPKT payload
            payload = remaining[TPKT_HEADER_LEN:length]
            total_consumed += length

            responses = self._dispatch(payload)
            all_responses.extend(responses)

        return total_consumed, all_responses

    def _dispatch(self, payload: bytes) -> list[bytes]:
        """Route a single TPKT payload to the appropriate state handler."""
        handler = {
            RdpState.X224_NEGOTIATION: self._handle_x224_cr,
            RdpState.MCS_CONNECT: self._handle_mcs_connect_initial,
            RdpState.MCS_ERECT_DOMAIN: self._handle_mcs_erect_domain,
            RdpState.MCS_ATTACH_USER: self._handle_mcs_attach_user,
            RdpState.MCS_CHANNEL_JOIN: self._handle_mcs_channel_join,
        }.get(self.state)

        if handler is None:
            logger.warning("Unexpected data in state %s", self.state)
            return []

        return handler(payload)

    def _handle_x224_cr(self, payload: bytes) -> list[bytes]:
        cr = parse_x224_cr(payload)
        if cr is None:
            logger.warning("Invalid X.224 Connection Request")
            return []

        self.cookie = cr.cookie
        self.requested_protocols = cr.requested_protocols

        # Always select standard RDP security (no TLS/NLA) to get plaintext credentials
        self.selected_protocol = PROTOCOL_RDP

        logger.info("X.224 CR: cookie=%r protocols=0x%x", self.cookie, self.requested_protocols)

        cc = build_x224_cc(self.selected_protocol)
        self.state = RdpState.MCS_CONNECT
        return [build_tpkt(cc)]

    def _handle_mcs_connect_initial(self, payload: bytes) -> list[bytes]:
        blocks = parse_mcs_connect_initial(payload)
        if blocks is None:
            logger.warning("Invalid MCS Connect-Initial")
            # Some clients send malformed packets; advance state anyway
            self.state = RdpState.MCS_ERECT_DOMAIN
            response = build_mcs_connect_response(self.selected_protocol, self.channel_ids)
            return [build_tpkt(response)]

        # Extract client info from CS_CORE
        if CS_CORE in blocks:
            self.client_core = parse_gcc_client_core_data(blocks[CS_CORE])
            if self.client_core:
                logger.info(
                    "Client: name=%r build=%d desktop=%dx%d keyboard=0x%x",
                    self.client_core.client_name,
                    self.client_core.client_build,
                    self.client_core.desktop_width,
                    self.client_core.desktop_height,
                    self.client_core.keyboard_layout,
                )

        response = build_mcs_connect_response(self.selected_protocol, self.channel_ids)
        self.state = RdpState.MCS_ERECT_DOMAIN
        return [build_tpkt(response)]

    def _handle_mcs_erect_domain(self, payload: bytes) -> list[bytes]:
        if not parse_mcs_erect_domain(payload):
            logger.warning("Expected MCS ErectDomainRequest")
            return []
        self.state = RdpState.MCS_ATTACH_USER
        return []  # No response needed

    def _handle_mcs_attach_user(self, payload: bytes) -> list[bytes]:
        if not parse_mcs_attach_user_request(payload):
            logger.warning("Expected MCS AttachUserRequest")
            return []
        self.user_id = DEFAULT_USER_ID
        self.state = RdpState.MCS_CHANNEL_JOIN

        confirm = build_mcs_attach_user_confirm(self.user_id)
        return [build_tpkt(confirm)]

    def _handle_mcs_channel_join(self, payload: bytes) -> list[bytes]:
        join_req = parse_mcs_channel_join_request(payload)
        if join_req is None:
            logger.warning("Expected MCS ChannelJoinRequest")
            return []

        logger.debug("Channel join: user=%d channel=%d", join_req.user_id, join_req.channel_id)
        self._joined_channels.add(join_req.channel_id)

        confirm = build_mcs_channel_join_confirm(join_req.user_id, join_req.channel_id)

        # Transition to security exchange once the IO channel is joined
        if MCS_IO_CHANNEL_ID in self._joined_channels:
            self.state = RdpState.SECURITY_EXCHANGE

        return [build_tpkt(confirm)]
