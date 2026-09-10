import pytest

from honeypotter.redis import Array, BulkString, RedisProtocol, RedisProtocolError, SimpleString


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

    def test_receive_data_array(self, protocol: RedisProtocol) -> None:
        assert protocol.receive_data(b"*2\r\n+hello\r\n$5\r\nworld\r\n") == [
            Array(
                array=[
                    SimpleString(string=b"hello"),
                    BulkString(string=b"world"),
                ]
            )
        ]
