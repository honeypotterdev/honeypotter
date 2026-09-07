from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from typing import Any

from honeypotter.core import Layer
from honeypotter.transport import DataEvent


class State(Enum):
    WAIT_FOR_TYPE = auto()
    READ_SIMPLE_STRING = auto()
    WAIT_FOR_LF = auto()


class Token(IntEnum):
    PLUS = ord(b"+")
    CR = ord(b"\r")
    LF = ord(b"\n")


@dataclass(frozen=True)
class SimpleStringReceived:
    string: bytes


class RedisProtocol:
    def __init__(self) -> None:
        self._state = State.WAIT_FOR_TYPE
        self._buffer = bytearray()

    def receive_data(self, data: bytes) -> list[SimpleStringReceived]:
        events = []

        for byte in data:
            match self._state, byte:
                case State.WAIT_FOR_TYPE, Token.PLUS:
                    self._state = State.READ_SIMPLE_STRING

                case State.READ_SIMPLE_STRING, Token.CR:
                    self._state = State.WAIT_FOR_LF

                case State.READ_SIMPLE_STRING, byte:
                    self._state = State.READ_SIMPLE_STRING
                    self._buffer.append(byte)

                case State.WAIT_FOR_LF, Token.LF:
                    self._state = State.WAIT_FOR_TYPE
                    events.append(SimpleStringReceived(bytes(self._buffer)))
                    self._buffer.clear()

        return events


class RedisCodec(Layer):
    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            self.ctx.send_outbound(DataEvent(b"-ERR unknown error\r\n"))
            return

        super().handle_inbound(event)
