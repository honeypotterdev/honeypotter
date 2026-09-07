from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from typing import Any

from honeypotter.core import Layer
from honeypotter.transport import DataEvent


class State(Enum):
    WAIT_FOR_TYPE = auto()
    READ_SIMPLE_STRING = auto()
    WAIT_SIMPLE_STRING_LF = auto()
    READ_BULK_STRING_LENGTH = auto()
    WAIT_BULK_STRING_BEGIN_LF = auto()
    WAIT_BULK_STRING_END_LF = auto()
    READ_BULK_STRING = auto()


class Token(IntEnum):
    PLUS = ord(b"+")
    DOLLAR = ord(b"$")
    CR = ord(b"\r")
    LF = ord(b"\n")
    ZERO = ord(b"0")
    NINE = ord(b"9")


@dataclass(frozen=True)
class SimpleStringReceived:
    string: bytes


@dataclass(frozen=True)
class BulkStringReceived:
    string: bytes


class RedisProtocol:
    def __init__(self) -> None:
        self._state = State.WAIT_FOR_TYPE
        self._buffer = bytearray()
        self._bulk_string_length = 0

    def receive_data(self, data: bytes) -> list[SimpleStringReceived]:
        events = []

        for byte in data:
            match self._state, byte:
                case State.WAIT_FOR_TYPE, Token.PLUS:
                    self._state = State.READ_SIMPLE_STRING
                case State.WAIT_FOR_TYPE, Token.DOLLAR:
                    self._state = State.READ_BULK_STRING_LENGTH

                case State.READ_SIMPLE_STRING, Token.CR:
                    self._state = State.WAIT_SIMPLE_STRING_LF
                case State.READ_SIMPLE_STRING, byte:
                    self._state = State.READ_SIMPLE_STRING
                    self._buffer.append(byte)
                case State.WAIT_SIMPLE_STRING_LF, Token.LF:
                    self._state = State.WAIT_FOR_TYPE
                    events.append(SimpleStringReceived(bytes(self._buffer)))
                    self._buffer.clear()

                case State.READ_BULK_STRING_LENGTH, byte if Token.ZERO <= byte <= Token.NINE:
                    self._state = State.READ_BULK_STRING_LENGTH
                    self._buffer.append(byte)
                case State.READ_BULK_STRING_LENGTH, Token.CR:
                    self._state = State.WAIT_BULK_STRING_BEGIN_LF
                    self._bulk_string_length = int(self._buffer)
                    self._buffer.clear()

                case State.WAIT_BULK_STRING_BEGIN_LF, Token.LF:
                    self._state = State.READ_BULK_STRING

                case State.READ_BULK_STRING, byte if self._bulk_string_length > 0:
                    self._state = State.READ_BULK_STRING
                    self._buffer.append(byte)
                    self._bulk_string_length -= 1
                case State.READ_BULK_STRING, Token.CR:
                    self._state = State.WAIT_BULK_STRING_END_LF

                case State.WAIT_BULK_STRING_END_LF, Token.LF:
                    self._state = State.WAIT_FOR_TYPE
                    events.append(BulkStringReceived(bytes(self._buffer)))
                    self._buffer.clear()

                case state, byte:
                    raise ValueError(f"Unknown byte {byte.to_bytes()} in state {state!r}, buffer {self._buffer!r}")

        return events


class RedisCodec(Layer):
    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            self.ctx.send_outbound(DataEvent(b"-ERR unknown error\r\n"))
            return

        super().handle_inbound(event)
