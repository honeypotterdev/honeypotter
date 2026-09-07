import logging
from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from typing import Any

from honeypotter.core import Context, Layer
from honeypotter.transport import DataEvent

_logger = logging.getLogger(__name__)


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
class SimpleString:
    string: bytes


@dataclass(frozen=True, kw_only=True)
class BulkString:
    string: bytes


@dataclass(frozen=True, kw_only=True)
class Array:
    array: list[Event]


Event = SimpleString | BulkString | Array


class RedisProtocol:
    def __init__(self) -> None:
        self._state = State.WAIT_FOR_TYPE
        self._buffer = bytearray()
        self._bulk_string_bytes_remaining = 0
        self._array_items_remaining = 0
        self._array_buffer: list[Event] = []

    def receive_data(self, data: bytes) -> list[Event]:
        events: list[Event] = []

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
                case State.WAIT_SIMPLE_STRING_LF, Token.LF:
                    self._state = State.WAIT_FOR_TYPE
                    self._accept_event(SimpleString(string=bytes(self._buffer)), events)
                    self._buffer.clear()

                case State.READ_BULK_STRING_LENGTH, byte if Token.ZERO <= byte <= Token.NINE:
                    self._state = State.READ_BULK_STRING_LENGTH
                    self._buffer.append(byte)
                case State.READ_BULK_STRING_LENGTH, Token.CR:
                    self._state = State.WAIT_BULK_STRING_BEGIN_LF
                    self._bulk_string_bytes_remaining = int(self._buffer)
                    self._buffer.clear()

                case State.WAIT_BULK_STRING_BEGIN_LF, Token.LF:
                    self._state = State.READ_BULK_STRING

                case State.READ_BULK_STRING, byte if self._bulk_string_bytes_remaining > 0:
                    self._state = State.READ_BULK_STRING
                    self._buffer.append(byte)
                    self._bulk_string_bytes_remaining -= 1
                case State.READ_BULK_STRING, Token.CR:
                    self._state = State.WAIT_BULK_STRING_END_LF

                case State.WAIT_BULK_STRING_END_LF, Token.LF:
                    self._state = State.WAIT_FOR_TYPE
                    self._accept_event(BulkString(string=bytes(self._buffer)), events)
                    self._buffer.clear()

                case State.READ_ARRAY_LENGTH, byte if Token.ZERO <= byte <= Token.NINE:
                    self._state = State.READ_ARRAY_LENGTH
                    self._buffer.append(byte)
                case State.READ_ARRAY_LENGTH, Token.CR:
                    self._state = State.WAIT_ARRAY_HEADER_LF
                    self._array_items_remaining = int(self._buffer)
                    self._buffer.clear()

                case State.WAIT_ARRAY_HEADER_LF, Token.LF:
                    self._state = State.WAIT_FOR_TYPE

                case state, byte:
                    raise ValueError(f"Unknown byte {byte.to_bytes()!r} in state {state!r}, buffer {self._buffer!r}")

        return events

    def send_simple_string(self, string: bytes) -> bytes:
        return b"+" + string + b"\r\n"

    def send_simple_error(self, error: bytes) -> bytes:
        return b"-" + error + b"\r\n"

    def _accept_event(self, event: Event, events: list[Event]) -> None:
        if self._array_items_remaining == 0:
            events.append(event)
            return

        self._array_buffer.append(event)
        self._array_items_remaining -= 1

        if self._array_items_remaining == 0:
            events.append(Array(array=self._array_buffer))
            self._array_buffer = []


class RedisCodec(Layer):
    def __init__(self, context: Context) -> None:
        super().__init__(context)
        self._protocol = RedisProtocol()

    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            events = self._protocol.receive_data(event.data)

            _logger.debug(f"Received events: {events!r}")

            for protocol_event in events:
                self._handle_event(protocol_event)

            return

        super().handle_inbound(event)

    def _handle_event(self, event: Event) -> None:
        match event:
            case Array(array=[BulkString(string=b"PING")]):
                self.ctx.send_outbound(DataEvent(data=self._protocol.send_simple_string(b"PONG")))
            case Array(array=[BulkString(string=b"ENABLE"), BulkString(string=b"HACK")]):
                self.ctx.send_outbound(DataEvent(data=self._protocol.send_simple_error(b"Nope!")))
            case Array(array=[BulkString(string=b"SET"), BulkString(string=key), BulkString(string=value)]):
                self.ctx.send_outbound(
                    DataEvent(data=self._protocol.send_simple_string(key + b" to " + value + b"? Fine, I guess."))
                )
            case Array(array=[BulkString(string=command)]):
                self.ctx.send_outbound(
                    DataEvent(data=self._protocol.send_simple_error(b"ERR unknown command '" + command + b"'"))
                )
            case _:
                self.ctx.send_outbound(DataEvent(data=self._protocol.send_simple_error(b"ERR unknown error")))
