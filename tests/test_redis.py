import pytest

from honeypotter.redis import BulkStringReceived, RedisProtocol, SimpleStringReceived


class TestRedisProtocol:
    @pytest.fixture
    def protocol(self) -> RedisProtocol:
        return RedisProtocol()

    def test_receive_data_simple_string(self, protocol: RedisProtocol) -> None:
        assert protocol.receive_data(b"+OK\r\n") == [SimpleStringReceived(b"OK")]

    def test_receive_data_bulk_string(self, protocol: RedisProtocol) -> None:
        assert protocol.receive_data(b"$5\r\nhello\r\n") == [BulkStringReceived(b"hello")]
