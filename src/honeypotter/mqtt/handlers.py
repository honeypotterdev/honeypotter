import logging
from typing import Any

from honeypotter.core import Handler, HandlerContext
from honeypotter.mqtt.connection import MqttConnection
from honeypotter.mqtt.events import ConnectReceived, DisconnectReceived, Event, PublishReceived, SubscribeReceived
from honeypotter.transport import DataEvent, DisconnectRequestEvent

_logger = logging.getLogger(__name__)


class MqttHandler(Handler):
    def __init__(self) -> None:
        super().__init__()

        self._connection = MqttConnection()

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case DataEvent():
                self._handle_data_event(context, event)
            case _:
                super().handle_inbound(context, event)

    def _handle_data_event(self, context: HandlerContext, event: DataEvent) -> None:
        events = self._connection.receive_data(event.data)

        _logger.debug(f"Received events: {events!r}")

        for connection_event in events:
            self._handle_connection_event(context, connection_event)

    def _handle_connection_event(self, context: HandlerContext, event: Event) -> None:
        match event:
            case ConnectReceived():
                context.send_outbound(DataEvent(data=self._connection.send_conn_ack_packet()))
            case DisconnectReceived():
                context.send_outbound(DisconnectRequestEvent())
            case PublishReceived(qos=0):
                pass
            case PublishReceived(message_identifier=message_identifier):
                assert message_identifier is not None

                context.send_outbound(
                    DataEvent(data=self._connection.send_pub_ack_packet(message_identifier=message_identifier))
                )
            case SubscribeReceived():
                self._handle_subscribe_event(context, event)
            case _:
                context.send_outbound(DisconnectRequestEvent())

    def _handle_subscribe_event(self, context: HandlerContext, event: SubscribeReceived) -> None:
        context.send_outbound(
            DataEvent(
                data=self._connection.send_sub_ack_packet(
                    message_identifier=event.message_identifier,
                    return_codes=[subscription.qos for subscription in event.subscriptions],
                )
            )
        )

        for subscription in event.subscriptions:
            if subscription.topic_filter == "$SYS/#":
                self._publish_sys_topics(context)

    def _publish_sys_topics(self, context: HandlerContext) -> None:
        output = [
            ("$SYS/broker/version", b"mosquitto version 2.1.2"),
            ("$SYS/broker/uptime", b"18590 seconds"),
            ("$SYS/broker/clients/total", b"0"),
            ("$SYS/broker/clients/disconnected", b"0"),
            ("$SYS/broker/clients/inactive", b"0"),
            ("$SYS/broker/clients/connected", b"0"),
            ("$SYS/broker/clients/active", b"0"),
            ("$SYS/broker/clients/expired", b"0"),
            ("$SYS/broker/messages/stored", b"55"),
            ("$SYS/broker/messages/received", b"12"),
            ("$SYS/broker/messages/sent", b"232"),
            ("$SYS/broker/store/messages/count", b"55"),
            ("$SYS/broker/store/messages/bytes", b"197"),
            ("$SYS/broker/subscriptions/count", b"0"),
            ("$SYS/broker/shared_subscriptions/count", b"0"),
            ("$SYS/broker/retained messages/count", b"55"),
            ("$SYS/broker/heap/current", b"835168"),
            ("$SYS/broker/heap/maximum", b"849472"),
            ("$SYS/broker/bytes/received", b"113"),
            ("$SYS/broker/bytes/sent", b"8951"),
            ("$SYS/broker/publish/bytes/received", b"0"),
            ("$SYS/broker/publish/bytes/sent", b"858"),
            ("$SYS/broker/publish/messages/dropped", b"0"),
            ("$SYS/broker/publish/messages/received", b"0"),
            ("$SYS/broker/publish/messages/sent", b"224"),
            ("$SYS/broker/packet/out/count", b"0"),
            ("$SYS/broker/packet/out/bytes", b"0"),
            ("$SYS/broker/connections/socket/count", b"4"),
            ("$SYS/broker/load/messages/received/1min", b"0.06"),
            ("$SYS/broker/load/messages/received/5min", b"0.30"),
            ("$SYS/broker/load/messages/received/15min", b"0.54"),
            ("$SYS/broker/load/messages/sent/1min", b"0.06"),
            ("$SYS/broker/load/messages/sent/5min", b"0.30"),
            ("$SYS/broker/load/messages/sent/15min", b"0.90"),
            ("$SYS/broker/load/publish/dropped/1min", b"0.00"),
            ("$SYS/broker/load/publish/dropped/5min", b"0.00"),
            ("$SYS/broker/load/publish/dropped/15min", b"0.00"),
            ("$SYS/broker/load/publish/received/1min", b"0.00"),
            ("$SYS/broker/load/publish/received/5min", b"0.00"),
            ("$SYS/broker/load/publish/received/15min", b"0.00"),
            ("$SYS/broker/load/publish/sent/1min", b"0.06"),
            ("$SYS/broker/load/publish/sent/5min", b"0.30"),
            ("$SYS/broker/load/publish/sent/15min", b"0.90"),
            ("$SYS/broker/load/bytes/received/1min", b"0.06"),
            ("$SYS/broker/load/bytes/received/5min", b"0.30"),
            ("$SYS/broker/load/bytes/received/15min", b"0.90"),
            ("$SYS/broker/load/bytes/sent/1min", b"0.06"),
            ("$SYS/broker/load/bytes/sent/5min", b"0.30"),
            ("$SYS/broker/load/bytes/sent/15min", b"3.24"),
            ("$SYS/broker/load/sockets/1min", b"0.06"),
            ("$SYS/broker/load/sockets/5min", b"0.30"),
            ("$SYS/broker/load/sockets/15min", b"0.18"),
            ("$SYS/broker/load/connections/1min", b"0.06"),
            ("$SYS/broker/load/connections/5min", b"0.30"),
            ("$SYS/broker/load/connections/15min", b"0.18"),
        ]

        for topic_name, message in output:
            context.send_outbound(
                DataEvent(
                    data=self._connection.send_publish_packet(topic_name=topic_name, message=message, retain=True)
                )
            )
