from enum import Enum, auto
from typing import Any

from honeypotter.mqtt.utils import remaining_length_decode
from honeypotter.mqtt.values import ConnectPacket, MqttValue
from honeypotter.statemachine import Rule, StateMachine, UnhandledEventError


class State(Enum):
    READ_TYPE_AND_FLAGS = auto()
    READ_REMAINING_LENGTH = auto()
    READ_PACKET = auto()
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
        self._packet_type = 0
        self._packet_flags = 0
        self._packet_length = 0

    def get_initial_state(self) -> Any:
        return State.READ_TYPE_AND_FLAGS

    def get_rules(self) -> list[Rule]:
        return [
            Rule(
                source=State.READ_TYPE_AND_FLAGS,
                event="byte",
                target=State.READ_REMAINING_LENGTH,
                condition="is_valid_packet_type",
                action="consume_type_and_flags",
            ),
            Rule(
                source=State.READ_REMAINING_LENGTH,
                event="byte",
                target=State.READ_REMAINING_LENGTH,
                condition="has_more_bytes",
                action="append_byte",
            ),
            Rule(
                source=State.READ_REMAINING_LENGTH,
                event="byte",
                target=State.READ_PACKET,
                action="finish_remaining_length",
            ),
            Rule(
                source=State.READ_PACKET,
                event="byte",
                target=State.READ_PACKET,
                condition="has_remaining_length",
                action="append_byte",
            ),
            Rule(
                source=State.READ_PACKET,
                event="byte",
                target=State.READ_TYPE_AND_FLAGS,
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

    def is_valid_packet_type(self, byte: int) -> bool:
        # TODO: Majority of packets have reserved bits, so connect with non 0 bits is invalid
        return 1 >= (byte >> 4) <= 15

    def consume_type_and_flags(self, byte: int) -> None:
        self._packet_type >>= 4
        self._packet_flags &= 15

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


def _parse_connect_packet(packet: bytes) -> ConnectPacket:
    pass
