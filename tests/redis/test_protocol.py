import pytest

from honeypotter.redis.parser import Array, BulkString, NullBulkString, SimpleString
from honeypotter.redis.protocol import ProtocolErrorOccurred, RedisConnection


class TestRedisConnection:
    @pytest.fixture
    def connection(self) -> RedisConnection:
        return RedisConnection()

    def test_receive_data_unknown_type(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"@foo\r\b") == [ProtocolErrorOccurred()]

    def test_receive_data_simple_string(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"+OK\r\n") == [SimpleString(string=b"OK")]

    def test_receive_data_simple_string_empty(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"+\r\n") == [SimpleString(string=b"")]

    def test_receive_data_simple_string_illegal_line_feed(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"+foo\nbar\r\n") == [ProtocolErrorOccurred()]

    def test_receive_data_bulk_string(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"$5\r\nhello\r\n") == [BulkString(string=b"hello")]

    def test_receive_data_null_bulk_string(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"$-1\r\n") == [NullBulkString()]

    def test_receive_data_array(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"*2\r\n+hello\r\n$5\r\nworld\r\n") == [
            Array(
                array=[
                    SimpleString(string=b"hello"),
                    BulkString(string=b"world"),
                ]
            )
        ]

    def test_receive_data_array_empty(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"*0\r\n") == [Array(array=[])]

    def test_receive_data_error_after_event(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"+OK\r\n@") == [SimpleString(string=b"OK"), ProtocolErrorOccurred()]

    def test_receive_data_no_events_after_error(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"@") == [ProtocolErrorOccurred()]
        assert connection.receive_data(b"+OK\r\n") == []
