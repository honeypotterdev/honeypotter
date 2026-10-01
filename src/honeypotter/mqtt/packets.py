from dataclasses import dataclass
from enum import IntEnum


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
@dataclass(kw_only=True)
class ConnAckPacket:
    session_present: bool = False
    return_code: ConnectReturnCode = ConnectReturnCode.ACCEPTED


# TODO: Delete
@dataclass(kw_only=True)
class PublishPacket:
    dup: bool = False
    qos: int = 0
    retain: bool = False
    topic_name: str
    message_identifier: int | None = None
    message: bytes = b""


# TODO: Delete
@dataclass(kw_only=True)
class PubAckPacket:
    message_identifier: int


@dataclass(kw_only=True)
class Subscription:
    topic_filter: str
    qos: int = 0


# TODO: Delete
@dataclass(kw_only=True)
class SubscribePacket:
    message_identifier: int
    subscriptions: list[Subscription]


# TODO: Delete
@dataclass(kw_only=True)
class SubAckPacket:
    message_identifier: int
    return_codes: list[int]


# TODO: Delete
@dataclass(kw_only=True)
class DisconnectPacket:
    pass


type Packet = (
    ConnectPacket | ConnAckPacket | PublishPacket | PubAckPacket | SubscribePacket | SubAckPacket | DisconnectPacket
)
