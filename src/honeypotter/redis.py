import logging
from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from typing import Any, Literal

from honeypotter.core import Context, Layer
from honeypotter.statemachine import Rule, StateMachine, UnknownTransitionError
from honeypotter.transport import DataEvent

_logger = logging.getLogger(__name__)


class State(Enum):
    WAIT_FOR_TYPE = auto()
    READ_SIMPLE_STRING = auto()
    WAIT_SIMPLE_STRING_LF = auto()
    READ_BULK_STRING_LENGTH = auto()
    WAIT_BULK_STRING_TERMINATOR_LF = auto()
    WAIT_BULK_STRING_FINAL_LF = auto()
    READ_BULK_STRING = auto()
    WAIT_NULL_BULK_STRING_ONE = auto()
    WAIT_NULL_BULK_STRING_CR = auto()
    WAIT_NULL_BULK_STRING_LF = auto()
    READ_ARRAY_LENGTH = auto()
    WAIT_ARRAY_HEADER_LF = auto()
    ERROR = auto()


class Token(IntEnum):
    PLUS = ord(b"+")
    DOLLAR = ord(b"$")
    ASTERISK = ord(b"*")
    CR = ord(b"\r")
    LF = ord(b"\n")
    ZERO = ord(b"0")
    ONE = ord(b"1")
    NINE = ord(b"9")
    MINUS = ord(b"-")


@dataclass(frozen=True, kw_only=True)
class SimpleString:
    string: bytes


@dataclass(frozen=True, kw_only=True)
class BulkString:
    string: bytes


@dataclass(frozen=True, kw_only=True)
class NullBulkString:
    pass


@dataclass(frozen=True, kw_only=True)
class Array:
    array: list[Event]


Event = SimpleString | BulkString | NullBulkString | Array


class RedisProtocolParser(StateMachine):
    def __init__(self) -> None:
        super().__init__()

        self._buffer = bytearray()
        self._bulk_string_bytes_remaining = 0
        self._array_items_remaining = 0
        self._array_buffer: list[Event] = []

    def get_strategy(self) -> Literal["ignore", "error"]:
        return "error"

    def get_initial_state(self) -> State:
        return State.WAIT_FOR_TYPE

    def get_final_state(self) -> Any:
        return State.ERROR

    def get_rules(self) -> list[Rule]:
        return [
            Rule(
                source=State.WAIT_FOR_TYPE,
                event="byte",
                target=State.READ_SIMPLE_STRING,
                condition="is_simple_string_prefix",
            ),
            Rule(
                source=State.WAIT_FOR_TYPE,
                event="byte",
                target=State.READ_BULK_STRING_LENGTH,
                condition="is_bulk_string_prefix",
            ),
            Rule(source=State.WAIT_FOR_TYPE, event="byte", target=State.READ_ARRAY_LENGTH, condition="is_array_prefix"),
            Rule(
                source=State.READ_SIMPLE_STRING,
                event="byte",
                target=State.ERROR,
                condition="is_line_feed",
                action="error",
            ),
            Rule(
                source=State.READ_SIMPLE_STRING,
                event="byte",
                target=State.WAIT_SIMPLE_STRING_LF,
                condition="is_carriage_return",
            ),
            Rule(source=State.READ_SIMPLE_STRING, event="byte", target=State.READ_SIMPLE_STRING, action="append_byte"),
            Rule(
                source=State.WAIT_SIMPLE_STRING_LF,
                event="byte",
                target=State.WAIT_FOR_TYPE,
                condition="is_line_feed",
                action="finish_simple_string",
            ),
            Rule(
                source=State.READ_BULK_STRING_LENGTH,
                event="byte",
                target=State.READ_BULK_STRING_LENGTH,
                condition="is_digit",
                action="append_byte",
            ),
            Rule(
                source=State.READ_BULK_STRING_LENGTH,
                event="byte",
                target=State.WAIT_BULK_STRING_TERMINATOR_LF,
                condition="is_carriage_return",
                action="parse_bulk_string_length",
            ),
            Rule(
                source=State.READ_BULK_STRING_LENGTH,
                event="byte",
                target=State.WAIT_NULL_BULK_STRING_ONE,
                condition="is_minus",
            ),
            Rule(
                source=State.WAIT_BULK_STRING_TERMINATOR_LF,
                event="byte",
                target=State.READ_BULK_STRING,
                condition="is_line_feed",
            ),
            Rule(
                source=State.READ_BULK_STRING,
                event="byte",
                target=State.READ_BULK_STRING,
                condition="has_bulk_string_bytes_remaining",
                action="consume_bulk_string_byte",
            ),
            Rule(
                source=State.READ_BULK_STRING,
                event="byte",
                target=State.WAIT_BULK_STRING_FINAL_LF,
                condition="is_carriage_return",
            ),
            Rule(
                source=State.WAIT_BULK_STRING_FINAL_LF,
                event="byte",
                target=State.WAIT_FOR_TYPE,
                condition="is_line_feed",
                action="finish_bulk_string",
            ),
            Rule(
                source=State.WAIT_NULL_BULK_STRING_ONE,
                event="byte",
                target=State.WAIT_NULL_BULK_STRING_CR,
                condition="is_one",
            ),
            Rule(
                source=State.WAIT_NULL_BULK_STRING_CR,
                event="byte",
                target=State.WAIT_NULL_BULK_STRING_LF,
                condition="is_carriage_return",
            ),
            Rule(
                source=State.WAIT_NULL_BULK_STRING_LF,
                event="byte",
                target=State.WAIT_FOR_TYPE,
                condition="is_line_feed",
                action="finish_null_bulk_string",
            ),
            Rule(
                source=State.READ_ARRAY_LENGTH,
                event="byte",
                target=State.READ_ARRAY_LENGTH,
                condition="is_digit",
                action="append_byte",
            ),
            Rule(
                source=State.READ_ARRAY_LENGTH,
                event="byte",
                target=State.WAIT_ARRAY_HEADER_LF,
                condition="is_carriage_return",
                action="parse_array_length",
            ),
            Rule(source=State.WAIT_ARRAY_HEADER_LF, event="byte", target=State.WAIT_FOR_TYPE, condition="is_line_feed"),
        ]

    def is_simple_string_prefix(self, byte: int) -> bool:
        return byte == Token.PLUS

    def is_bulk_string_prefix(self, byte: int) -> bool:
        return byte == Token.DOLLAR

    def is_array_prefix(self, byte: int) -> bool:
        return byte == Token.ASTERISK

    def is_carriage_return(self, byte: int) -> bool:
        return byte == Token.CR

    def is_line_feed(self, byte: int) -> bool:
        return byte == Token.LF

    def is_digit(self, byte: int) -> bool:
        return Token.ZERO <= byte <= Token.NINE

    def is_minus(self, byte: int) -> bool:
        return byte == Token.MINUS

    def is_one(self, byte: int) -> bool:
        return byte == Token.ONE

    def has_bulk_string_bytes_remaining(self, byte: int) -> bool:
        return self._bulk_string_bytes_remaining > 0

    def append_byte(self, byte: int) -> None:
        self._buffer.append(byte)

    def finish_simple_string(self, byte: int) -> Event | None:
        simple_string = SimpleString(string=bytes(self._buffer))
        self._buffer.clear()

        return self._accept_event(simple_string)

    def parse_bulk_string_length(self, byte: int) -> None:
        self._bulk_string_bytes_remaining = int(self._buffer)
        self._buffer.clear()

    def consume_bulk_string_byte(self, byte: int) -> None:
        self._buffer.append(byte)
        self._bulk_string_bytes_remaining -= 1

    def finish_bulk_string(self, byte: int) -> Event | None:
        bulk_string = BulkString(string=bytes(self._buffer))
        self._buffer.clear()

        return self._accept_event(bulk_string)

    def parse_array_length(self, byte) -> None:
        self._array_items_remaining = int(self._buffer)
        self._buffer.clear()

    def finish_null_bulk_string(self, byte: int) -> Event | None:
        null_bull_string = NullBulkString()

        return self._accept_event(null_bull_string)

    def _accept_event(self, event: Event) -> Event | None:
        if self._array_items_remaining == 0:
            return event

        self._array_buffer.append(event)
        self._array_items_remaining -= 1

        if self._array_items_remaining != 0:
            return None

        array = Array(array=self._array_buffer)
        self._array_buffer = []

        return array

    def error(self, byte: int) -> None:
        raise RedisProtocolError(f"Illegal sequence: {byte!r}")


class RedisProtocolError(Exception):
    pass


class RedisProtocol:
    def __init__(self) -> None:
        self._parser = RedisProtocolParser()

    def receive_data(self, data: bytes) -> list[Event]:
        events = []

        for byte in data:
            try:
                event = self._parser.send("byte", byte)
            except UnknownTransitionError as e:
                raise RedisProtocolError(f"Illegal sequence: {byte.to_bytes()}") from e

            if event is not None:
                events.append(event)

        return events

    def send_simple_string(self, string: bytes) -> bytes:
        return b"+" + string + b"\r\n"

    def send_simple_error(self, error: bytes) -> bytes:
        return b"-" + error + b"\r\n"


class RedisSession(Layer):
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
