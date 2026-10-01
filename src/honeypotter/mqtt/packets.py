from dataclasses import dataclass
from enum import IntEnum

from honeypotter.mqtt.utils import encode_remaining_length


# TODO: Delete
@dataclass(kw_only=True)
class ConnectPacket:
    protocol_name: str = "MQTT"
    protocol_level: int = 4
    clean_session: bool = True
    keep_alive: int = 60
    client_id: str = ""
    will_topic: str | None = None
    will_message: bytes | None = None
    will_qos: int = 0
    will_retain: bool = False
    username: str | None = None
    password: bytes | None = None


class ConnectReturnCode(IntEnum):
    ACCEPTED = 0
    REFUSED_UNACCEPTABLE_PROTOCOL_VERSION = 1
    REFUSED_IDENTIFIER_REJECTED = 2
    REFUSED_SERVER_UNAVAILABLE = 3
    REFUSED_BAD_USER_NAME_OR_PASSWORD = 4
    REFUSED_NOT_AUTHORIZED = 5


# TODO: Delete
@dataclass(frozen=True, kw_only=True)
class ConnAckPacket:
    session_present: bool = False
    return_code: ConnectReturnCode = ConnectReturnCode.ACCEPTED


@dataclass(frozen=True, kw_only=True)
class PublishPacket:
    dup: bool = False
    qos: int = 0
    retain: bool = False
    topic_name: str
    message_identifier: int | None = None
    message: bytes = b""

    def to_bytes(self) -> bytes:
        header = 48

        if self.dup:
            header |= 8
        if self.qos:
            header |= self.qos << 1
        if self.retain:
            header |= 1

        header_bytes = header.to_bytes()

        topic_name_bytes = self.topic_name.encode("utf-8")
        topic_name_length_bytes = len(topic_name_bytes).to_bytes(length=2)
        variable_header = topic_name_length_bytes + topic_name_bytes

        if self.message_identifier is not None:
            variable_header += self.message_identifier.to_bytes(length=2)

        remaining_length = encode_remaining_length(len(variable_header + self.message))

        return header_bytes + remaining_length + variable_header + self.message


@dataclass(frozen=True, kw_only=True)
class PubAckPacket:
    message_identifier: int

    def to_bytes(self) -> bytes:
        variable_header = self.message_identifier.to_bytes(length=2)
        remaining_length = encode_remaining_length(len(variable_header))

        return b"\x40" + remaining_length + variable_header


@dataclass(frozen=True, kw_only=True)
class Subscription:
    topic_filter: str
    qos: int = 0


@dataclass(frozen=True, kw_only=True)
class SubscribePacket:
    message_identifier: int
    subscriptions: list[Subscription]

    def to_bytes(self) -> bytes:
        variable_header = self.message_identifier.to_bytes(length=2)
        payload = b""

        for subscription in self.subscriptions:
            subscription_topic_bytes = subscription.topic_filter.encode("utf-8")
            payload += (
                len(subscription_topic_bytes).to_bytes(length=2)
                + subscription_topic_bytes
                + subscription.qos.to_bytes()
            )

        remaining_length = encode_remaining_length(len(variable_header + payload))

        return b"\x82" + remaining_length + variable_header + payload


@dataclass(frozen=True, kw_only=True)
class SubAckPacket:
    message_identifier: int
    return_codes: list[int]

    def to_bytes(self) -> bytes:
        variable_header = self.message_identifier.to_bytes(length=2)
        payload = b"".join(code.to_bytes() for code in self.return_codes)
        remaining_length = encode_remaining_length(len(variable_header + payload))

        return b"\x90" + remaining_length + variable_header + payload


@dataclass(frozen=True)
class DisconnectPacket:
    def to_bytes(self) -> bytes:
        return b"\xe0\x00"


type Packet = (
    ConnectPacket | ConnAckPacket | PublishPacket | PubAckPacket | SubscribePacket | SubAckPacket | DisconnectPacket
)
