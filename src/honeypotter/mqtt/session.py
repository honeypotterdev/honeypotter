import logging
from typing import Any

from honeypotter.core import Context, Layer
from honeypotter.mqtt.protocol import ConnectionEvent, MqttConnection
from honeypotter.mqtt.values import ConnectPacket, PublishPacket, SubscribePacket
from honeypotter.transport import DataEvent, DisconnectRequestEvent

_logger = logging.getLogger(__name__)


class MqttSession(Layer):
    def __init__(self, context: Context) -> None:
        super().__init__(context)
        self._connection = MqttConnection()

    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            events = self._connection.receive_data(event.data)

            _logger.debug(f"Received events: {events!r}")

            for connection_event in events:
                self._handle_event(connection_event)

            return

        super().handle_inbound(event)

    def _handle_event(self, event: ConnectionEvent) -> None:
        match event:
            case ConnectPacket():
                self.ctx.send_outbound(DataEvent(data=self._connection.send_conn_ack_packet()))
            case (
                PublishPacket(qos=1, message_identifier=message_identifier)
                | PublishPacket(qos=2, message_identifier=message_identifier)
            ):
                assert message_identifier is not None

                self.ctx.send_outbound(
                    DataEvent(data=self._connection.send_pub_ack_packet(message_identifier=message_identifier))
                )
            case SubscribePacket(message_identifier=message_identifier, subscriptions=subscriptions):
                self.ctx.send_outbound(
                    DataEvent(
                        data=self._connection.send_sub_ack_packet(
                            message_identifier=message_identifier,
                            return_codes=[subscription.qos for subscription in subscriptions],
                        )
                    )
                )
            case _:
                self.ctx.send_outbound(DisconnectRequestEvent())
