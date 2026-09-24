from enum import Enum, auto
from typing import Any

from honeypotter.mqtt.utils import remaining_length_decode
from honeypotter.mqtt.values import (
    ConnectPacket,
    DisconnectPacket,
    Packet,
    PublishPacket,
    SubscribePacket,
    Subscription,
)
from honeypotter.statemachine import MachineTerminatedError, Rule, StateMachine, UnhandledEventError


class State(Enum):
    READ_TYPE_AND_FLAGS = auto()
    READ_REMAINING_LENGTH = auto()
    READ_PACKET = auto()
    FAILED = auto()


class ControlPacketType(Enum):
    CONNECT = auto()


class MqttParseError(Exception):
    def __init__(self, message: str, *, state: State | None = None, byte: int | None = None) -> None:
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
                target=State.READ_TYPE_AND_FLAGS,
                condition="zero_length",
                action="finish_packet",
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
                action="finish_packet",
            ),
        ]

    def get_final_state(self) -> Any:
        return State.FAILED

    def feed_byte(self, byte: int) -> Packet | None:
        try:
            return self.send("byte", byte)
        except (UnhandledEventError, MachineTerminatedError) as e:
            error = MqttParseError("Unhandled event occurred", state=self._current_state, byte=byte)
            self._transition_to(State.FAILED)
            raise error from e

    def is_valid_packet_type(self, byte: int) -> bool:
        return 1 <= (byte >> 4) <= 15

    def consume_type_and_flags(self, byte: int) -> None:
        self._packet_type = byte >> 4
        self._packet_flags = byte & 15

    def zero_length(self, byte: int) -> bool:
        return byte == 0

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

    def finish_packet(self, byte: int) -> Packet:
        self._buffer.append(byte)
        buffer = bytes(self._buffer)
        self._buffer.clear()

        packet: Packet

        match self._packet_type:
            case 1:
                packet = _parse_connect_packet(buffer, flags=self._packet_flags)
            case 3:
                packet = _parse_publish_packet(buffer, flags=self._packet_flags)
            case 8:
                packet = _parse_subscribe_packet(buffer, flags=self._packet_flags)
            case 14:
                packet = _parse_disconnect_packet(buffer, flags=self._packet_flags)
            case _:
                raise MqttParseError(f"Unknown packet type {self._packet_type}", state=self._current_state, byte=byte)

        return packet


class _MqttReader:
    def __init__(self, packet: bytes | bytearray) -> None:
        self._view = memoryview(packet)
        self._position = 0

    @property
    def remaining(self) -> int:
        return len(self._view) - self._position

    def read_bytes(self, length: int) -> bytes:
        end = self._position + length
        if end > len(self._view):
            raise MqttParseError(f"Truncated packet at offset {self._position}: expected {length} bytes")

        value = self._view[self._position : end]
        self._position = end

        return bytes(value)

    def read_uint8(self) -> int:
        return self.read_bytes(1)[0]

    def read_uint16(self) -> int:
        return int.from_bytes(self.read_bytes(2))

    def read_length_prefixed_bytes(self) -> bytes:
        """Read bytes prefixed by their unsigned 16-bit big-endian length."""
        return self.read_bytes(self.read_uint16())

    def read_utf8_string(self) -> str:
        """Read a length-prefixed string and validate MQTT UTF-8 requirements."""
        value = self.read_length_prefixed_bytes().decode("utf-8")

        if "\x00" in value:
            raise ValueError("MQTT strings must not contain U+0000")

        return value

    def read_remaining_bytes(self) -> bytes:
        return self.read_bytes(self.remaining)


def _parse_connect_packet(packet: bytes | bytearray, *, flags: int = 0) -> ConnectPacket:
    if flags != 0:
        raise ValueError("CONNECT fixed-header flags must be zero")

    reader = _MqttReader(packet)
    protocol_name = reader.read_utf8_string()
    protocol_level = reader.read_uint8()
    connect_flags = reader.read_uint8()

    if connect_flags & 1:
        raise ValueError("CONNECT reserved flag must be zero")

    clean_session = bool(connect_flags & 2)
    will_flag = bool(connect_flags & 4)
    will_qos = (connect_flags >> 3) & 3
    will_retain = bool(connect_flags & 32)
    password_flag = bool(connect_flags & 64)
    username_flag = bool(connect_flags & 128)

    keep_alive = reader.read_uint16()
    client_id = reader.read_utf8_string()
    if not client_id and not clean_session:
        raise ValueError("An empty client ID requires Clean Session")

    will_topic = None
    will_message = None

    if will_flag:
        will_topic = reader.read_utf8_string()
        will_message = reader.read_length_prefixed_bytes()

    username = reader.read_utf8_string() if username_flag else None
    password = reader.read_length_prefixed_bytes() if password_flag else None

    if reader.remaining:
        raise ValueError("Unexpected trailing bytes in CONNECT packet")

    return ConnectPacket(
        protocol_name=protocol_name,
        protocol_level=protocol_level,
        clean_session=clean_session,
        keep_alive=keep_alive,
        client_id=client_id or None,
        will_topic=will_topic,
        will_message=will_message,
        will_qos=will_qos,
        will_retain=will_retain,
        username=username,
        password=password,
    )


def _parse_publish_packet(packet: bytes | bytearray, *, flags: int = 0) -> PublishPacket:
    dup = bool(flags & 8)
    qos = (flags >> 1) & 3
    retain = bool(flags & 1)

    reader = _MqttReader(packet)
    topic_name = reader.read_utf8_string()

    if qos:
        message_identifier = reader.read_uint16()
    else:
        message_identifier = None

    message = reader.read_remaining_bytes()

    return PublishPacket(
        dup=dup, qos=qos, retain=retain, topic_name=topic_name, message_identifier=message_identifier, message=message
    )


def _parse_subscribe_packet(packet: bytes | bytearray, *, flags: int = 0) -> SubscribePacket:
    reader = _MqttReader(packet)
    message_identifier = reader.read_uint16()
    subscriptions = []

    while reader.remaining:
        topic_filter = reader.read_utf8_string()
        qos = reader.read_uint8()
        subscriptions.append(Subscription(topic_filter=topic_filter, qos=qos))

    return SubscribePacket(message_identifier=message_identifier, subscriptions=subscriptions)


def _parse_disconnect_packet(packet: bytes | bytearray, *, flags: int = 0) -> DisconnectPacket:
    reader = _MqttReader(packet)
    remaining = reader.read_remaining_bytes()

    if remaining != b"\x00":
        raise ValueError("MQTT disconnect packet must not contain \x00")

    if reader.remaining:
        raise ValueError("Unexpected trailing bytes in DISCONNECT packet")

    return DisconnectPacket()
