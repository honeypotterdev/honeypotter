import shlex
from enum import Enum, IntEnum, auto

from honeypotter.redis.values import Array, BulkString, NullBulkString, RespValue, SimpleString
from honeypotter.statemachine import Machine, MachineError, Transition


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
    READ_INLINE_COMMAND = auto()
    FAILED = auto()


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


class RespParseError(Exception):
    def __init__(self, message: str, *, state: State, byte: int) -> None:
        super().__init__(message)
        self.state = state
        self.byte = byte


class RespParser:
    def __init__(self) -> None:
        self._buffer = bytearray()
        self._bulk_string_bytes_remaining = 0
        self._array_items_remaining = 0
        self._array_buffer: list[RespValue] = []

        self._machine = Machine(
            model=self,
            initial=State.WAIT_FOR_TYPE,
            final=State.FAILED,
            transitions=[
                Transition("byte", State.WAIT_FOR_TYPE, State.READ_SIMPLE_STRING, condition="is_simple_string_prefix"),
                Transition(
                    "byte", State.WAIT_FOR_TYPE, State.READ_BULK_STRING_LENGTH, condition="is_bulk_string_prefix"
                ),
                Transition("byte", State.WAIT_FOR_TYPE, State.READ_ARRAY_LENGTH, condition="is_array_prefix"),
                Transition(
                    "byte",
                    State.READ_SIMPLE_STRING,
                    State.FAILED,
                    condition="is_line_feed",
                    action="reject_unexpected_lf",
                ),
                Transition("byte", State.WAIT_FOR_TYPE, State.READ_INLINE_COMMAND, action="append_byte"),
                Transition(
                    "byte", State.READ_SIMPLE_STRING, State.WAIT_SIMPLE_STRING_LF, condition="is_carriage_return"
                ),
                Transition("byte", State.READ_SIMPLE_STRING, State.READ_SIMPLE_STRING, action="append_byte"),
                Transition(
                    "byte",
                    State.WAIT_SIMPLE_STRING_LF,
                    State.WAIT_FOR_TYPE,
                    condition="is_line_feed",
                    action="finish_simple_string",
                ),
                Transition(
                    "byte",
                    State.READ_BULK_STRING_LENGTH,
                    State.READ_BULK_STRING_LENGTH,
                    condition="is_digit",
                    action="append_byte",
                ),
                Transition(
                    "byte",
                    State.READ_BULK_STRING_LENGTH,
                    State.WAIT_BULK_STRING_TERMINATOR_LF,
                    condition="is_carriage_return",
                    action="parse_bulk_string_length",
                ),
                Transition(
                    "byte", State.READ_BULK_STRING_LENGTH, State.WAIT_NULL_BULK_STRING_ONE, condition="is_minus"
                ),
                Transition(
                    "byte", State.WAIT_BULK_STRING_TERMINATOR_LF, State.READ_BULK_STRING, condition="is_line_feed"
                ),
                Transition(
                    "byte",
                    State.READ_BULK_STRING,
                    State.READ_BULK_STRING,
                    condition="has_bulk_string_bytes_remaining",
                    action="consume_bulk_string_byte",
                ),
                Transition(
                    "byte", State.READ_BULK_STRING, State.WAIT_BULK_STRING_FINAL_LF, condition="is_carriage_return"
                ),
                Transition(
                    "byte",
                    State.WAIT_BULK_STRING_FINAL_LF,
                    State.WAIT_FOR_TYPE,
                    condition="is_line_feed",
                    action="finish_bulk_string",
                ),
                Transition("byte", State.WAIT_NULL_BULK_STRING_ONE, State.WAIT_NULL_BULK_STRING_CR, condition="is_one"),
                Transition(
                    "byte",
                    State.WAIT_NULL_BULK_STRING_CR,
                    State.WAIT_NULL_BULK_STRING_LF,
                    condition="is_carriage_return",
                ),
                Transition(
                    "byte",
                    State.WAIT_NULL_BULK_STRING_LF,
                    State.WAIT_FOR_TYPE,
                    condition="is_line_feed",
                    action="finish_null_bulk_string",
                ),
                Transition(
                    "byte", State.READ_ARRAY_LENGTH, State.READ_ARRAY_LENGTH, condition="is_digit", action="append_byte"
                ),
                Transition(
                    "byte",
                    State.READ_ARRAY_LENGTH,
                    State.WAIT_ARRAY_HEADER_LF,
                    condition="is_carriage_return",
                    action="parse_array_length",
                ),
                Transition("byte", State.WAIT_ARRAY_HEADER_LF, State.WAIT_FOR_TYPE, condition="is_line_feed"),
                Transition(
                    "byte",
                    State.READ_INLINE_COMMAND,
                    State.WAIT_FOR_TYPE,
                    condition="is_line_feed",
                    action="finish_inline_command",
                ),
                Transition("byte", State.READ_INLINE_COMMAND, State.READ_INLINE_COMMAND, action="append_byte"),
            ],
        )

    def feed_byte(self, byte: int) -> RespValue | None:
        try:
            return self._machine.trigger("byte", byte)
        except MachineError as e:
            error = RespParseError("Machine error occurred", state=self._machine.state, byte=byte)
            self._machine.transition_to(State.FAILED)
            raise error from e

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

    def finish_simple_string(self, byte: int) -> RespValue | None:
        simple_string = SimpleString(string=bytes(self._buffer))
        self._buffer.clear()

        return self._accept_value(simple_string)

    def parse_bulk_string_length(self, byte: int) -> None:
        self._bulk_string_bytes_remaining = int(self._buffer)
        self._buffer.clear()

    def consume_bulk_string_byte(self, byte: int) -> None:
        self._buffer.append(byte)
        self._bulk_string_bytes_remaining -= 1

    def finish_bulk_string(self, byte: int) -> RespValue | None:
        bulk_string = BulkString(string=bytes(self._buffer))
        self._buffer.clear()

        return self._accept_value(bulk_string)

    def parse_array_length(self, byte: int) -> RespValue | None:
        self._array_items_remaining = int(self._buffer)
        self._buffer.clear()

        # Zero length array case
        if self._array_items_remaining == 0:
            return Array(array=[])

        return None

    def finish_null_bulk_string(self, byte: int) -> RespValue | None:
        null_bull_string = NullBulkString()

        return self._accept_value(null_bull_string)

    def reject_unexpected_lf(self, byte: int) -> None:
        raise RespParseError("Unexpected LF", state=self._machine.state, byte=byte)

    def finish_inline_command(self, byte: int) -> RespValue:
        commands = bytes(self._buffer)
        self._buffer.clear()

        if commands.endswith(b"\r"):
            commands = commands[:-1]

        strings = [BulkString(string=command.encode()) for command in shlex.split(commands.decode())]

        return Array(array=strings)

    def _accept_value(self, event: RespValue) -> RespValue | None:
        if self._array_items_remaining == 0:
            return event

        self._array_buffer.append(event)
        self._array_items_remaining -= 1

        if self._array_items_remaining != 0:
            return None

        array = Array(array=self._array_buffer)
        self._array_buffer = []

        return array
