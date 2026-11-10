from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from honeypotter.recorders import Message, Peer


class ConnectRecord(BaseModel):
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
    event_type: Literal["connect"] = "connect"


class PublishRecord(BaseModel):
    dup: bool = False
    qos: int = 0
    retain: bool = False
    topic_name: str
    message_identifier: int | None = None
    message: bytes = b""
    event_type: Literal["publish"] = "publish"


class SubscriptionRecord(BaseModel):
    topic_filter: str
    qos: int = 0


class SubscribeRecord(BaseModel):
    message_identifier: int
    subscriptions: list[SubscriptionRecord]
    event_type: Literal["subscribe"] = "subscribe"


class DisconnectRecord(BaseModel):
    event_type: Literal["disconnect"] = "disconnect"


type EventRecord = ConnectRecord | PublishRecord | SubscribeRecord | DisconnectRecord


class MqttSessionRecord(BaseModel):
    honeypot: Peer
    client: Peer
    events: list[EventRecord] = Field(default_factory=list)
    messages: list[Message] = Field(default_factory=list)
    created_at: datetime
