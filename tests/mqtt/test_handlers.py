from unittest.mock import MagicMock, call

import pytest

from honeypotter.commands import CloseConnection, WriteData
from honeypotter.core import HandlerContext
from honeypotter.events import ConnectionOpened, DataReceived
from honeypotter.mqtt.connection import MqttConnection
from honeypotter.mqtt.handlers import MqttHandler
from honeypotter.mqtt.types import Subscription


class TestMqttHandler:
    @pytest.fixture
    def handler(self) -> MqttHandler:
        return MqttHandler()

    def test(self, handler: MqttHandler) -> None:
        context = MagicMock(spec=HandlerContext)

        client_connection = MqttConnection()
        client_connection.send_connect_packet()
        client_connection.send_publish_packet(topic_name="topic1", message=b"message1")
        client_connection.send_publish_packet(topic_name="topic2", message=b"message2", qos=1, message_identifier=1)
        client_connection.send_subscribe_packet(message_identifier=2, subscriptions=[Subscription(topic_filter="#")])
        client_connection.send_disconnect()

        handler.handle_inbound(context, ConnectionOpened())
        handler.handle_inbound(context, DataReceived(data=client_connection.data_to_send()))

        assert context.send_outbound.call_args_list == [
            # CONNACK
            call(WriteData(data=b" \x02\x00\x00")),
            # PUBACK
            call(WriteData(data=b"@\x02\x00\x01")),
            # SUBACK
            call(WriteData(data=b"\x90\x03\x00\x02\x00")),
            call(CloseConnection()),
        ]
