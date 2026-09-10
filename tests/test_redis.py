from unittest.mock import Mock

import pytest

from honeypotter.core import Context
from honeypotter.redis import (
    Array,
    BulkString,
    NullBulkString,
    RedisProtocol,
    RedisProtocolError,
    RedisSession,
    SimpleString,
)
from honeypotter.transport import DataEvent


class TestRedisProtocol:
    @pytest.fixture
    def protocol(self) -> RedisProtocol:
        return RedisProtocol()

    def test_receive_data_unknown_type(self, protocol: RedisProtocol) -> None:
        with pytest.raises(RedisProtocolError):
            protocol.receive_data(b"@foo\r\b")

    def test_receive_data_simple_string(self, protocol: RedisProtocol) -> None:
        assert protocol.receive_data(b"+OK\r\n") == [SimpleString(string=b"OK")]

    def test_receive_data_simple_string_empty(self, protocol: RedisProtocol) -> None:
        assert protocol.receive_data(b"+\r\n") == [SimpleString(string=b"")]

    def test_receive_data_simple_string_illegal_line_feed(self, protocol: RedisProtocol) -> None:
        with pytest.raises(RedisProtocolError):
            protocol.receive_data(b"+foo\nbar\r\n")

    def test_receive_data_bulk_string(self, protocol: RedisProtocol) -> None:
        assert protocol.receive_data(b"$5\r\nhello\r\n") == [BulkString(string=b"hello")]

    def test_receive_data_null_bulk_string(self, protocol: RedisProtocol) -> None:
        assert protocol.receive_data(b"$-1\r\n") == [NullBulkString()]

    def test_receive_data_array(self, protocol: RedisProtocol) -> None:
        assert protocol.receive_data(b"*2\r\n+hello\r\n$5\r\nworld\r\n") == [
            Array(
                array=[
                    SimpleString(string=b"hello"),
                    BulkString(string=b"world"),
                ]
            )
        ]

    def test_receive_data_array_empty(self, protocol: RedisProtocol) -> None:
        assert protocol.receive_data(b"*0\r\n") == [Array(array=[])]


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
