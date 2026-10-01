from dataclasses import dataclass

from honeypotter.mqtt.types import Subscription


class Event:
    pass


@dataclass(kw_only=True)
class ConnectReceived(Event):
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


@dataclass(kw_only=True)
class PublishReceived(Event):
    dup: bool = False
    qos: int = 0
    retain: bool = False
    topic_name: str
    message_identifier: int | None = None
    message: bytes = b""


@dataclass(kw_only=True)
class SubscribeReceived(Event):
    message_identifier: int
    subscriptions: list[Subscription]


@dataclass(kw_only=True)
class DisconnectReceived(Event):
    pass


@dataclass(kw_only=True)
class ConnectionFailed(Event):
    pass
