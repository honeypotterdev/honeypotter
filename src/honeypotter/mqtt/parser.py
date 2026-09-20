from enum import Enum, auto
from typing import Any

from honeypotter.mqtt.utils import remaining_length_decode
from honeypotter.mqtt.values import ConnectPacket, MqttValue
from honeypotter.statemachine import Rule, StateMachine, UnhandledEventError


class State(Enum):
    WAIT_FOR_TYPE = auto()
    CONNECT_READ_REMAINING_LENGTH = auto()
    CONNECT_READ_PACKET = auto()
    FAILED = auto()


class ControlPacketType(Enum):
    CONNECT = auto()


class MqttParseError(Exception):
    def __init__(self, message: str, *, state: State, byte: int) -> None:
        super().__init__(message)
        self.state = state
        self.byte = byte


class MqttParser(StateMachine):
    def __init__(self) -> None:
        super().__init__()

        self._buffer = bytearray()
        self._packet_length = 0

    def get_initial_state(self) -> Any:
        return State.WAIT_FOR_TYPE

    def get_rules(self) -> list[Rule]:
        return [
            Rule(
                source=State.WAIT_FOR_TYPE,
                event="byte",
                target=State.CONNECT_READ_REMAINING_LENGTH,
                condition="is_connect_type",
            ),
            Rule(
                source=State.CONNECT_READ_REMAINING_LENGTH,
                event="byte",
                target=State.CONNECT_READ_REMAINING_LENGTH,
                condition="has_more_bytes",
                action="append_byte",
            ),
            Rule(
                source=State.CONNECT_READ_REMAINING_LENGTH,
                event="byte",
                target=State.CONNECT_READ_PACKET,
                action="finish_remaining_length",
            ),
            Rule(
                source=State.CONNECT_READ_PACKET,
                event="byte",
                target=State.CONNECT_READ_PACKET,
                condition="has_remaining_length",
                action="append_byte",
            ),
            Rule(
                source=State.CONNECT_READ_PACKET,
                event="byte",
                target=State.WAIT_FOR_TYPE,
                action="finish_connect_packet",
            ),
        ]

    def get_final_state(self) -> Any:
        return State.FAILED

    def feed_byte(self, byte: int) -> MqttValue | None:
        try:
            return self.send("byte", byte)
        except UnhandledEventError as e:
            error = MqttParseError("Unhandled event occurred", state=self._current_state, byte=byte)
            self._transition_to(State.FAILED)
            raise error from e

    def is_connect_type(self, byte: int) -> bool:
        return bool(byte & 16)

    def has_more_bytes(self, byte: int) -> bool:
        return bool(byte & 128)

    def append_byte(self, byte: int) -> None:
        self._buffer.append(byte)

    def finish_remaining_length(self, byte: int) -> None:
        self._buffer.append(byte)
        self._packet_length = remaining_length_decode(self._buffer)
        self._buffer.clear()

    def has_remaining_length(self, byte: int) -> bool:
        self._packet_length -= 1

        return self._packet_length != 0

    def finish_connect_packet(self, byte: int) -> MqttValue:
        self._buffer.append(byte)

        # TODO: Parse variable header and payload
        return ConnectPacket(client_id="john")
