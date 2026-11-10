import asyncio
from typing import Any
from unittest.mock import Mock, call

import pytest

from honeypotter.core import Handler, HandlerContext, Pipeline
from honeypotter.events import ConnectionClosed, ConnectionOpened
from honeypotter.redis.handlers import RedisHandler
from honeypotter.redis.recorders import RedisRecorder
from honeypotter.transport import TransportProtocol


@pytest.mark.parametrize("reason", [None, ConnectionResetError("Connection reset")])
def test_transport_records_inbound_and_outbound_traffic_until_closed(reason: Exception | None) -> None:
    exporter = Mock()
    notifications: list[Any] = []

    class Observer(Handler):
        def handle_inbound(self, context: HandlerContext, event: Any) -> None:
            notifications.append(event)
            context.send_inbound(event)

    def initialize(pipeline: Pipeline) -> None:
        pipeline.add_last("redis", RedisHandler())
        pipeline.add_last("observer", Observer())
        pipeline.add_last("recorder", RedisRecorder(capture_messages_before="redis", exporter=exporter))

    transport = Mock(spec=asyncio.Transport)
    transport.get_extra_info.side_effect = {
        "sockname": ("127.0.0.1", 6379),
        "peername": ("192.0.2.1", 12345),
    }.__getitem__
    protocol = TransportProtocol(initialize)

    protocol.connection_made(transport)
    protocol.data_received(b"PING\r\n")
    protocol.data_received(b"QUIT\r\n")

    assert transport.write.call_args_list == [call(b"+PONG\r\n"), call(b"+OK\r\n")]
    transport.close.assert_called_once_with()
    exporter.assert_not_called()

    protocol.connection_lost(reason)

    assert notifications[0] == ConnectionOpened()
    assert notifications[-1] == ConnectionClosed(reason=reason)
    exporter.assert_called_once()
    record = exporter.call_args.args[0]
    assert record.honeypot.model_dump() == {"ip": "127.0.0.1", "port": 6379}
    assert record.client.model_dump() == {"ip": "192.0.2.1", "port": 12345}
    assert record.commands == [b"PING", b"QUIT"]
    assert [(message.direction, message.data) for message in record.messages] == [
        ("inbound", b"PING\r\n"),
        ("outbound", b"+PONG\r\n"),
        ("inbound", b"QUIT\r\n"),
        ("outbound", b"+OK\r\n"),
    ]
    offsets = [message.offset for message in record.messages]
    assert offsets == sorted(offsets)
    assert all(offset >= 0 for offset in offsets)
