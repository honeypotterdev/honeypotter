from unittest.mock import Mock

from honeypotter.core import Context
from honeypotter.redis.session import RedisSession
from honeypotter.transport import DataEvent


class TestRedisSession:
    def test_handle_inbound_ping(self) -> None:
        context = Mock(spec=Context)

        layer = RedisSession(context)
        layer.handle_inbound(DataEvent(data=b"*1\r\n$4\r\nPING\r\n"))

        context.send_outbound.assert_called_once_with(DataEvent(data=b"+PONG\r\n"))

    def test_handle_inbound_set(self) -> None:
        context = Mock(spec=Context)

        layer = RedisSession(context)
        layer.handle_inbound(DataEvent(data=b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"))

        context.send_outbound.assert_called_once_with(DataEvent(data=b"+OK\r\n"))

    def test_handle_inbound_unknown_command(self) -> None:
        context = Mock(spec=Context)

        layer = RedisSession(context)
        layer.handle_inbound(DataEvent(data=b"*1\r\n$4\r\nTEST\r\n"))

        context.send_outbound.assert_called_once_with(DataEvent(data=b"-ERR unknown command 'TEST'\r\n"))
