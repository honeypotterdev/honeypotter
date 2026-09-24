from unittest.mock import MagicMock, call

from honeypotter.core import Context
from honeypotter.redis.session import RedisSessionLayer
from honeypotter.transport import DataEvent, DisconnectRequestEvent


class TestRedisSession:
    def test_handle_inbound_quit_without_arguments(self) -> None:
        context = MagicMock(spec=Context)

        layer = RedisSessionLayer(context)
        layer.handle_inbound(DataEvent(data=b"*1\r\n$4\r\nQUIT\r\n"))

        assert context.send_outbound.call_args_list == [
            call(DataEvent(data=b"+OK\r\n")),
            call(DisconnectRequestEvent()),
        ]

    def test_handle_inbound_quit_with_arguments(self) -> None:
        context = MagicMock(spec=Context)

        layer = RedisSessionLayer(context)
        layer.handle_inbound(DataEvent(data=b"*2\r\n$4\r\nQUIT\r\n$3\r\nfoo\r\n"))

        assert context.send_outbound.call_args_list == [
            call(DataEvent(data=b"+OK\r\n")),
            call(DisconnectRequestEvent()),
        ]

    def test_handle_inbound_ping(self) -> None:
        context = MagicMock(spec=Context)

        layer = RedisSessionLayer(context)
        layer.handle_inbound(DataEvent(data=b"*1\r\n$4\r\nPING\r\n"))

        context.send_outbound.assert_called_once_with(DataEvent(data=b"+PONG\r\n"))

    def test_handle_inbound_set(self) -> None:
        context = MagicMock(spec=Context)

        layer = RedisSessionLayer(context)
        layer.handle_inbound(DataEvent(data=b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"))

        context.send_outbound.assert_called_once_with(DataEvent(data=b"+OK\r\n"))

    def test_handle_inbound_unknown_command(self) -> None:
        context = MagicMock(spec=Context)

        layer = RedisSessionLayer(context)
        layer.handle_inbound(DataEvent(data=b"*1\r\n$3\r\nFOO\r\n"))

        context.send_outbound.assert_called_once_with(DataEvent(data=b"-ERR unknown command 'FOO'\r\n"))

    def test_handle_inbound_unknown_commands(self) -> None:
        context = MagicMock(spec=Context)

        layer = RedisSessionLayer(context)
        layer.handle_inbound(DataEvent(data=b"*2\r\n$3\r\nFOO\r\n$3\r\nBAR\r\n"))

        context.send_outbound.assert_called_once_with(DataEvent(data=b"-ERR unknown command 'FOO'\r\n"))
