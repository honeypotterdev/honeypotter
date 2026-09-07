from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

from honeypotter.core import Layer
from honeypotter.transport import DataEvent


class RedisProtocolState(Enum):
    WAIT_FOR_TYPE = auto()
    READ_SIMPLE_STRING = auto()
    WAIT_FOR_LF = auto()


@dataclass(frozen=True)
class SimpleStringReceived:
    string: bytes


class RedisProtocol:
    def __init__(self) -> None:
        self._state = RedisProtocolState.WAIT_FOR_TYPE
        self._buffer = bytearray()

    def receive_data(self, data: bytes) -> list[SimpleStringReceived]:
        events = []

        for input in data:
            match self._state, input:
                case RedisProtocolState.WAIT_FOR_TYPE, 43:  # "+"
                    self._state = RedisProtocolState.READ_SIMPLE_STRING

                case RedisProtocolState.READ_SIMPLE_STRING, char if char == 13:  # "\r"
                    self._state = RedisProtocolState.WAIT_FOR_LF

                case RedisProtocolState.READ_SIMPLE_STRING, char:
                    self._state = RedisProtocolState.READ_SIMPLE_STRING
                    self._buffer.append(char)

                case RedisProtocolState.WAIT_FOR_LF, char if char == 10:  # "\n"
                    self._state = RedisProtocolState.WAIT_FOR_TYPE
                    events.append(SimpleStringReceived(bytes(self._buffer)))
                    self._buffer.clear()

        return events


class RedisCodec(Layer):
    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            self.ctx.send_outbound(DataEvent(b"-ERR unknown error\r\n"))
            return

        super().handle_inbound(event)
