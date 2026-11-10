from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from honeypotter.recorders import Message, Peer


class ConnectRecord(BaseModel):
    protocol_name: str
    protocol_level: int
    clean_session: bool
    keep_alive: int
    client_id: str
    will_topic: str | None
    will_message: bytes | None
    will_qos: int
    will_retain: bool
    username: str | None
    password: bytes | None
    event_type: Literal["connect"] = "connect"


class PublishRecord(BaseModel):
    dup: bool
    qos: int
    retain: bool
    topic_name: str
    message_identifier: int | None
    message: bytes
    event_type: Literal["publish"] = "publish"


class SubscriptionRecord(BaseModel):
    topic_filter: str
    qos: int


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
