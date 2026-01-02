# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2015 Tan Kean Siong
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea.core import connection, incident

import traceback
import logging

from dionaea.mqtt.include.packets import (
    MQTT_CONTROLMESSAGE_TYPE_CONNECT,
    MQTT_CONTROLMESSAGE_TYPE_DISCONNECT,
    MQTT_CONTROLMESSAGE_TYPE_PINGREQ,
    MQTT_CONTROLMESSAGE_TYPE_PUBLISH,
    MQTT_CONTROLMESSAGE_TYPE_PUBLISHCOM,
    MQTT_CONTROLMESSAGE_TYPE_PUBLISHRCV,
    MQTT_CONTROLMESSAGE_TYPE_PUBLISHREL,
    MQTT_CONTROLMESSAGE_TYPE_QoS1,
    MQTT_CONTROLMESSAGE_TYPE_QoS2,
    MQTT_CONTROLMESSAGE_TYPE_SUBSCRIBE,
    MQTT_Connect,
    MQTT_ConnectACK,
    MQTT_ControlMessage_Type,
    MQTT_DisconnectReq,
    MQTT_PingRequest,
    MQTT_PingResponse,
    MQTT_Publish,
    MQTT_PublishACK_Identifier,
    MQTT_Publish_Release,
    MQTT_Subscribe,
    MQTT_SubscribeACK_Identifier,
)

logger = logging.getLogger('mqtt')

class mqttd(connection):
	def __init__ (self):
		connection.__init__(self,"tcp")
		self.buf = b''

	def handle_established(self):
		self.timeouts.idle = 120
		self.processors()

	def handle_io_in(self, data: bytes) -> int:
		offset=0

		if len(data) > offset:
			p = None
			x = None
			try:

				if len(data) > 0:
					p = MQTT_ControlMessage_Type(data)
					p.show()

					self.pendingPacketType = p.ControlPacketType
					logger.debug(f"MQTT Control Packet Type {self.pendingPacketType}")

				if len(data) == 0:
					logger.warn("Bad MQTT Packet, Length = 0")

			except Exception:
				t = traceback.format_exc()
				logger.error(t)
				return offset

			x = None
			if self.pendingPacketType == MQTT_CONTROLMESSAGE_TYPE_CONNECT:
				x = MQTT_Connect(data)

				i = incident("dionaea.modules.python.mqtt.connect")
				i.con = self
				i.clientid = x.ClientID
				i.willtopic = x.WillTopic
				i.willmessage = x.WillMessage
				i.username = x.Username
				i.password = x.Password
				i.report()

			elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISH) == 48) &
				((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_QoS1) > 0) ) :
				x = MQTT_Publish(data)

				i = incident("dionaea.modules.python.mqtt.publish")
				i.con = self
				i.publishtopic = x.Topic
				i.publishmessage = x.Message
				i.report()

			elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISH) == 48) &
				((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_QoS2) > 0) ) :
				x = MQTT_Publish(data)

				i = incident("dionaea.modules.python.mqtt.publish")
				i.con = self
				i.publishtopic = x.Topic
				i.publishmessage = x.Message
				i.report()

			elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISHREL) == 96) &
				((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_QoS1) > 0) ) :
				x = MQTT_Publish_Release(data)

			elif self.pendingPacketType == MQTT_CONTROLMESSAGE_TYPE_PUBLISH:
				x = MQTT_Publish(data)

				i = incident("dionaea.modules.python.mqtt.publish")
				i.con = self
				i.publishtopic = x.Topic
				i.publishmessage = x.Message
				i.report()

			elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_SUBSCRIBE) == 128) &
				((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_QoS1) > 0) ) :
				x = MQTT_Subscribe(data)

				i = incident("dionaea.modules.python.mqtt.subscribe")
				i.con = self
				i.subscribemessageid = x.PacketIdentifier
				i.subscribetopic = x.Topic
				i.report()

			elif self.pendingPacketType == MQTT_CONTROLMESSAGE_TYPE_SUBSCRIBE:
				x = MQTT_Subscribe(data)

				i = incident("dionaea.modules.python.mqtt.subscribe")
				i.con = self
				i.subscribemessageid = x.PacketIdentifier
				i.subscribetopic = x.Topic
				i.report()

			elif self.pendingPacketType == MQTT_CONTROLMESSAGE_TYPE_PINGREQ:
				x = MQTT_PingRequest(data)

			elif self.pendingPacketType == MQTT_CONTROLMESSAGE_TYPE_DISCONNECT:
				x = MQTT_DisconnectReq(data)
			else:
				logger.warning(f"Unknown MQTT packet type: {self.pendingPacketType}")

			self.buf = b''

			if x is not None:
				x.show()

				r = None
				r = self.process( self.pendingPacketType, x)

				if r:
					r.show()
					self.send(r.build())

		return len(data)

	def process(self, PacketType, p):
		r =''

		if PacketType == MQTT_CONTROLMESSAGE_TYPE_CONNECT:
			r = MQTT_ConnectACK()

		elif PacketType == MQTT_CONTROLMESSAGE_TYPE_DISCONNECT:
			r = ''

		elif PacketType == MQTT_CONTROLMESSAGE_TYPE_PINGREQ:
			r = MQTT_PingResponse()

		elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_SUBSCRIBE) == 128) &
			((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_QoS1) > 0) ) :
			layer = p.getlayer(MQTT_Subscribe)
			packetidentifier = layer.PacketIdentifier
			GrantedQoS = layer.GrantedQoS
			r = MQTT_SubscribeACK_Identifier()
			if (packetidentifier is not None):
				r.PacketIdentifier = packetidentifier
			if (GrantedQoS is not None):
				r.GrantedQoS = GrantedQoS

		# mqtt-v3.1.1-os.pdf - page 36
		# For "Publish" Packet, the Response will be varied with the QoS level:
		# - QoS level 0 - No response packet
		# - QoS level 1 - PUBACK packet
		# - QoS level 2 - PUBREC packet

		elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISH) == 48) &
			((PacketType & MQTT_CONTROLMESSAGE_TYPE_QoS1) == 2) ) :
			layer = p.getlayer(MQTT_Publish)
			packetidentifier = layer.PacketIdentifier
			if (packetidentifier is not None):
				r = MQTT_PublishACK_Identifier()
				r.PacketIdentifier = packetidentifier

		elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISH) == 48) &
			((PacketType & MQTT_CONTROLMESSAGE_TYPE_QoS2) == 4) ) :
			layer = p.getlayer(MQTT_Publish)
			packetidentifier = layer.PacketIdentifier
			if (packetidentifier is not None):
				r = MQTT_PublishACK_Identifier()
				r.HeaderFlags = MQTT_CONTROLMESSAGE_TYPE_PUBLISHRCV
				r.PacketIdentifier = packetidentifier

		elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISH) == 48) &
			((PacketType & MQTT_CONTROLMESSAGE_TYPE_QoS1) == 0) ) :
			r = ''

		elif (PacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISHREL) == 96:
			layer = p.getlayer(MQTT_Publish_Release)
			packetidentifier = layer.PacketIdentifier
			if (packetidentifier is not None):
				r = MQTT_PublishACK_Identifier()
				r.PacketIdentifier = packetidentifier
				r.HeaderFlags = MQTT_CONTROLMESSAGE_TYPE_PUBLISHCOM
		else:
			logger.warn(f"Unknown Packet Type for MQTT {PacketType}")

		return r

	def handle_timeout_idle(self):
		return False

	def handle_disconnect(self):
		return False
