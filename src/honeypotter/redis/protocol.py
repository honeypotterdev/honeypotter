from dataclasses import dataclass

from honeypotter.redis.parser import RespParseError, RespParser
from honeypotter.redis.values import RespValue


@dataclass(frozen=True, kw_only=True)
class ProtocolErrorOccurred:
    pass


type ConnectionEvent = RespValue | ProtocolErrorOccurred


class RedisConnection:
    def __init__(self) -> None:
        self._parser = RespParser()
        self._receive_failed = False

    def receive_data(self, data: bytes) -> list[ConnectionEvent]:
        if self._receive_failed:
            return []

        events: list[ConnectionEvent] = []

        for byte in data:
            try:
                event = self._parser.feed_byte(byte)
            except RespParseError:
                self._receive_failed = True
                events.append(ProtocolErrorOccurred())
                return events

            if event is not None:
                events.append(event)

        return events

    def send_simple_string(self, string: bytes) -> bytes:
        return b"+" + string + b"\r\n"

    def send_simple_error(self, error: bytes) -> bytes:
        return b"-" + error + b"\r\n"

    def send_bulk_string(self, string: bytes) -> bytes:
        return b"$" + str(len(string)).encode() + b"\r\n" + string + b"\r\n"
