from honeypotter.redis import RedisProtocol, SimpleStringReceived


class TestRedisProtocol:
    def test_receive_data_simple_string(self) -> None:
        protocol = RedisProtocol()

        assert protocol.receive_data(b"+OK\r\n") == [SimpleStringReceived(b"OK")]
