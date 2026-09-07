import pytest

from honeypotter.redis import ArrayReceived, BulkStringReceived, RedisProtocol, SimpleStringReceived


class TestRedisProtocol:
    @pytest.fixture
    def protocol(self) -> RedisProtocol:
        return RedisProtocol()

    def test_receive_data_simple_string(self, protocol: RedisProtocol) -> None:
        assert protocol.receive_data(b"+OK\r\n") == [SimpleStringReceived(string=b"OK")]

    def test_receive_data_bulk_string(self, protocol: RedisProtocol) -> None:
        assert protocol.receive_data(b"$5\r\nhello\r\n") == [BulkStringReceived(string=b"hello")]

    def test_receive_data_array(self, protocol: RedisProtocol) -> None:
        assert protocol.receive_data(b"*2\r\n+hello\r\n$5\r\nworld\r\n") == [
            ArrayReceived(
                array=[
                    SimpleStringReceived(string=b"hello"),
                    BulkStringReceived(string=b"world"),
                ]
            )
        ]
