from honeypotter.redis.events import ConnectionFailed, Event
from honeypotter.redis.parsers import RespParseError, RespParser


class RedisConnection:
    def __init__(self) -> None:
        self._outgoing_buffer = bytearray()
        self._parser = RespParser()
        self._is_failed = False

    def data_to_send(self) -> bytes:
        data = bytes(self._outgoing_buffer)
        self._outgoing_buffer.clear()

        return data

    def send_simple_string(self, string: bytes) -> None:
        self._outgoing_buffer.extend(b"+" + string + b"\r\n")

    def send_simple_error(self, error: bytes) -> None:
        self._outgoing_buffer.extend(b"-" + error + b"\r\n")

    def send_bulk_string(self, string: bytes) -> None:
        self._outgoing_buffer.extend(b"$" + str(len(string)).encode() + b"\r\n" + string + b"\r\n")

    def receive_data(self, data: bytes) -> list[Event]:
        if self._is_failed:
            return []

        events: list[Event] = []

        for byte in data:
            try:
                event = self._parser.feed_byte(byte)
            except RespParseError:
                self._is_failed = True
                events.append(ConnectionFailed())
                return events

            if event is not None:
                events.append(event)

        return events
