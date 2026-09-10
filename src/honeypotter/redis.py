import logging
from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from typing import Any

from honeypotter.core import Context, Layer
from honeypotter.sm import Rule, StateMachine
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


class RedisProtocolParser(StateMachine):
    def __init__(self) -> None:
        super().__init__()

        self._buffer = bytearray()
        self._bulk_string_bytes_remaining = 0
        self._array_items_remaining = 0
        self._array_buffer: list[Event] = []

    def get_initial_state(self) -> State:
        return State.WAIT_FOR_TYPE

    def get_rules(self) -> list[Rule]:
        return [
            Rule(source=State.WAIT_FOR_TYPE, event="byte", target=State.READ_SIMPLE_STRING, condition="is_plus"),
            Rule(source=State.WAIT_FOR_TYPE, event="byte", target=State.READ_BULK_STRING_LENGTH, condition="is_dollar"),
            Rule(source=State.WAIT_FOR_TYPE, event="byte", target=State.READ_ARRAY_LENGTH, condition="is_asterisk"),
            Rule(
                source=State.READ_SIMPLE_STRING,
                event="byte",
                target=State.WAIT_SIMPLE_STRING_LF,
                condition="is_carriage_return",
            ),
            Rule(source=State.READ_SIMPLE_STRING, event="byte", target=State.READ_SIMPLE_STRING, action="buffer"),
            Rule(
                source=State.WAIT_SIMPLE_STRING_LF,
                event="byte",
                target=State.WAIT_FOR_TYPE,
                condition="is_line_feed",
                action="accept_simple_string",
            ),
            Rule(
                source=State.READ_BULK_STRING_LENGTH,
                event="byte",
                target=State.READ_BULK_STRING_LENGTH,
                condition="is_digit",
                action="buffer",
            ),
            Rule(
                source=State.READ_BULK_STRING_LENGTH,
                event="byte",
                target=State.WAIT_BULK_STRING_BEGIN_LF,
                condition="is_carriage_return",
                action="remember_bulk_string_length",
            ),
            Rule(
                source=State.WAIT_BULK_STRING_BEGIN_LF,
                event="byte",
                target=State.READ_BULK_STRING,
                condition="is_line_feed",
            ),
            Rule(
                source=State.READ_BULK_STRING,
                event="byte",
                target=State.READ_BULK_STRING,
                condition="is_bulk_string_bytes_remaining",
                action="buffer_bulk_string",
            ),
            Rule(
                source=State.READ_BULK_STRING,
                event="byte",
                target=State.WAIT_BULK_STRING_END_LF,
                condition="is_carriage_return",
            ),
            Rule(
                source=State.WAIT_BULK_STRING_END_LF,
                event="byte",
                target=State.WAIT_FOR_TYPE,
                condition="is_line_feed",
                action="accept_bulk_string",
            ),
            Rule(
                source=State.READ_ARRAY_LENGTH,
                event="byte",
                target=State.READ_ARRAY_LENGTH,
                condition="is_digit",
                action="buffer",
            ),
            Rule(
                source=State.READ_ARRAY_LENGTH,
                event="byte",
                target=State.WAIT_ARRAY_HEADER_LF,
                condition="is_carriage_return",
                action="remember_array_length",
            ),
            Rule(source=State.WAIT_ARRAY_HEADER_LF, event="byte", target=State.WAIT_FOR_TYPE, condition="is_line_feed"),
        ]

    def is_plus(self, byte: int) -> bool:
        return byte == Token.PLUS

    def is_dollar(self, byte: int) -> bool:
        return byte == Token.DOLLAR

    def is_asterisk(self, byte: int) -> bool:
        return byte == Token.ASTERISK

    def is_carriage_return(self, byte: int) -> bool:
        return byte == Token.CR

    def is_line_feed(self, byte: int) -> bool:
        return byte == Token.LF

    def is_digit(self, byte: int) -> bool:
        return Token.ZERO <= byte <= Token.NINE

    def is_bulk_string_bytes_remaining(self, byte: int) -> bool:
        return self._bulk_string_bytes_remaining > 0

    def buffer(self, byte: int) -> None:
        self._buffer.append(byte)

    def accept_simple_string(self, byte: int) -> SimpleString | Array | None:
        simple_string = SimpleString(string=bytes(self._buffer))
        self._buffer.clear()

        if self._array_items_remaining == 0:
            return simple_string

        self._array_buffer.append(simple_string)
        self._array_items_remaining -= 1

        if self._array_items_remaining != 0:
            return None

        array = Array(array=self._array_buffer)
        self._array_buffer = []

        return array

    def remember_bulk_string_length(self, byte: int) -> None:
        self._bulk_string_bytes_remaining = int(self._buffer)
        self._buffer.clear()

    def buffer_bulk_string(self, byte: int) -> None:
        self._buffer.append(byte)
        self._bulk_string_bytes_remaining -= 1

    def accept_bulk_string(self, byte: int) -> BulkString | Array | None:
        bulk_string = BulkString(string=bytes(self._buffer))
        self._buffer.clear()

        if self._array_items_remaining == 0:
            return bulk_string

        self._array_buffer.append(bulk_string)
        self._array_items_remaining -= 1

        if self._array_items_remaining != 0:
            return None

        array = Array(array=self._array_buffer)
        self._array_buffer = []

        return array

    def remember_array_length(self, byte) -> None:
        self._array_items_remaining = int(self._buffer)
        self._buffer.clear()


class RedisProtocol:
    def __init__(self) -> None:
        self._state = State.WAIT_FOR_TYPE
        self._buffer = bytearray()
        self._bulk_string_bytes_remaining = 0
        self._array_items_remaining = 0
        self._array_buffer: list[Event] = []

        self._parser = RedisProtocolParser()

    def receive_data(self, data: bytes) -> list[Event]:
        events = []

        for byte in data:
            event = self._parser.send("byte", byte)

            if event is not None:
                events.append(event)

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
