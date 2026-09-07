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
    READ_ARRAY_LENGTH = auto()
    WAIT_ARRAY_HEADER_LF = auto()


class Token(IntEnum):
    PLUS = ord(b"+")
    DOLLAR = ord(b"$")
    ASTERISK = ord(b"*")
    CR = ord(b"\r")
    LF = ord(b"\n")
    ZERO = ord(b"0")
    NINE = ord(b"9")


@dataclass(frozen=True, kw_only=True)
class SimpleStringReceived:
    string: bytes


@dataclass(frozen=True, kw_only=True)
class BulkStringReceived:
    string: bytes


@dataclass(frozen=True, kw_only=True)
class ArrayReceived:
    array: list[SimpleStringReceived | BulkStringReceived]


class RedisProtocol:
    def __init__(self) -> None:
        self._state = State.WAIT_FOR_TYPE
        self._buffer = bytearray()
        self._bulk_string_length = 0
        self._array_length = 0
        self._array_events = []

    def receive_data(self, data: bytes) -> list[SimpleStringReceived]:
        events = []

        for byte in data:
            match self._state, byte:
                case State.WAIT_FOR_TYPE, Token.PLUS:
                    self._state = State.READ_SIMPLE_STRING
                case State.WAIT_FOR_TYPE, Token.DOLLAR:
                    self._state = State.READ_BULK_STRING_LENGTH
                case State.WAIT_FOR_TYPE, Token.ASTERISK:
                    self._state = State.READ_ARRAY_LENGTH

                case State.READ_SIMPLE_STRING, Token.CR:
                    self._state = State.WAIT_SIMPLE_STRING_LF
                case State.READ_SIMPLE_STRING, byte:
                    self._state = State.READ_SIMPLE_STRING
                    self._buffer.append(byte)
                case State.WAIT_SIMPLE_STRING_LF, Token.LF if self._array_length == 0:
                    self._state = State.WAIT_FOR_TYPE
                    events.append(SimpleStringReceived(string=bytes(self._buffer)))
                    self._buffer.clear()
                case State.WAIT_SIMPLE_STRING_LF, Token.LF:
                    self._state = State.WAIT_FOR_TYPE
                    self._array_events.append(SimpleStringReceived(string=bytes(self._buffer)))
                    self._buffer.clear()
                    self._array_length -= 1

                    if self._array_length == 0:
                        events.append(ArrayReceived(array=self._array_events))
                        self._array_events = []

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

                case State.WAIT_BULK_STRING_END_LF, Token.LF if self._array_length == 0:
                    self._state = State.WAIT_FOR_TYPE
                    events.append(BulkStringReceived(string=bytes(self._buffer)))
                    self._buffer.clear()
                case State.WAIT_BULK_STRING_END_LF, Token.LF:
                    self._state = State.WAIT_FOR_TYPE
                    self._array_events.append(BulkStringReceived(string=bytes(self._buffer)))
                    self._buffer.clear()
                    self._array_length -= 1

                    if self._array_length == 0:
                        events.append(ArrayReceived(array=self._array_events))
                        self._array_events = []

                case State.READ_ARRAY_LENGTH, byte if Token.ZERO <= byte <= Token.NINE:
                    self._state = State.READ_ARRAY_LENGTH
                    self._buffer.append(byte)
                case State.READ_ARRAY_LENGTH, Token.CR:
                    self._state = State.WAIT_ARRAY_HEADER_LF
                    self._array_length = int(self._buffer)
                    self._buffer.clear()

                case State.WAIT_ARRAY_HEADER_LF, Token.LF:
                    self._state = State.WAIT_FOR_TYPE

                case state, byte:
                    raise ValueError(f"Unknown byte {byte.to_bytes()} in state {state!r}, buffer {self._buffer!r}")

        return events


class RedisCodec(Layer):
    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            self.ctx.send_outbound(DataEvent(b"-ERR unknown error\r\n"))
            return

        super().handle_inbound(event)
