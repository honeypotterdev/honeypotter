import pytest

from honeypotter.redis.connection import RedisConnection
from honeypotter.redis.events import (
    ArrayReceived,
    BulkStringReceived,
    ConnectionFailed,
    NullBulkStringReceived,
    SimpleStringReceived,
)


class TestRedisConnection:
    @pytest.fixture
    def connection(self) -> RedisConnection:
        return RedisConnection()

    def test_send_simple_string(self, connection: RedisConnection) -> None:
        connection.send_simple_string(b"OK")

        assert connection.data_to_send() == b"+OK\r\n"

    def test_send_simple_error(self, connection: RedisConnection) -> None:
        connection.send_simple_error(b"ERR")

        assert connection.data_to_send() == b"-ERR\r\n"

    def test_send_bulk_string(self, connection: RedisConnection) -> None:
        connection.send_bulk_string(b"foo")

        assert connection.data_to_send() == b"$3\r\nfoo\r\n"

    def test_receive_data_simple_string(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"+OK\r\n") == [SimpleStringReceived(string=b"OK")]

    def test_receive_data_simple_string_empty(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"+\r\n") == [SimpleStringReceived(string=b"")]

    def test_receive_data_simple_string_unexpected_line_feed(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"+foo\nbar\r\n") == [ConnectionFailed()]

    def test_receive_data_bulk_string(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"$5\r\nhello\r\n") == [BulkStringReceived(string=b"hello")]

    def test_receive_data_null_bulk_string(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"$-1\r\n") == [NullBulkStringReceived()]

    def test_receive_data_array(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"*2\r\n+hello\r\n$5\r\nworld\r\n") == [
            ArrayReceived(array=[SimpleStringReceived(string=b"hello"), BulkStringReceived(string=b"world")])
        ]

    def test_receive_data_array_empty(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"*0\r\n") == [ArrayReceived(array=[])]

    def test_receive_data_inline_command_without_arguments(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"INFO\r\n") == [ArrayReceived(array=[BulkStringReceived(string=b"INFO")])]

    def test_receive_data_inline_command_with_arguments(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"SET foo bar\r\n") == [
            ArrayReceived(
                array=[
                    BulkStringReceived(string=b"SET"),
                    BulkStringReceived(string=b"foo"),
                    BulkStringReceived(string=b"bar"),
                ]
            )
        ]

    def test_receive_data_inline_command_with_quoted_argument(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"GET 'foo bar'\r\n") == [
            ArrayReceived(array=[BulkStringReceived(string=b"GET"), BulkStringReceived(string=b"foo bar")])
        ]

    def test_receive_data_inline_command_accepts_lf_and_crlf(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"INFO\n") == [ArrayReceived(array=[BulkStringReceived(string=b"INFO")])]
        assert connection.receive_data(b"INFO\r\n") == [ArrayReceived(array=[BulkStringReceived(string=b"INFO")])]

    def test_receive_data_error_after_event(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"+OK\r\n+OK\n") == [SimpleStringReceived(string=b"OK"), ConnectionFailed()]

    def test_receive_data_no_events_after_error(self, connection: RedisConnection) -> None:
        assert connection.receive_data(b"+OK\n") == [ConnectionFailed()]
        assert connection.receive_data(b"+OK\r\n") == []
