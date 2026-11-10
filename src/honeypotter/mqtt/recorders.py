import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from honeypotter.core import Handler, HandlerContext
from honeypotter.events import ConnectionClosed
from honeypotter.mqtt.events import ConnectReceived, DisconnectReceived, PublishReceived, SubscribeReceived
from honeypotter.recorders import Message, MessagesTap, Peer

_logger = logging.getLogger(__name__)


class ConnectReceivedDto(ConnectReceived):
    event_type: Literal["connect"] = "connect"


class PublishReceivedDto(PublishReceived):
    event_type: Literal["publish"] = "publish"


class SubscribeReceivedDto(SubscribeReceived):
    event_type: Literal["subscribe"] = "subscribe"


class DisconnectReceivedDto(DisconnectReceived):
    event_type: Literal["disconnect"] = "disconnect"


type EventDto = ConnectReceivedDto | PublishReceivedDto | SubscribeReceivedDto | DisconnectReceivedDto


class Record(BaseModel):
    honeypot: Peer
    client: Peer
    events: list[EventDto] = Field(default_factory=list)
    messages: list[Message] = Field(default_factory=list)
    created_at: datetime


class EventTap(Handler):
    def __init__(self, record: Record) -> None:
        self._record = record

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, ConnectReceived):
            self._record.events.append(ConnectReceivedDto(**event.model_dump()))
        elif isinstance(event, PublishReceived):
            self._record.events.append(PublishReceivedDto(**event.model_dump()))
        elif isinstance(event, SubscribeReceived):
            self._record.events.append(SubscribeReceivedDto(**event.model_dump()))
        elif isinstance(event, DisconnectReceived):
            self._record.events.append(DisconnectReceivedDto(**event.model_dump()))

        context.send_inbound(event)


class MqttRecorder(Handler):
    _record: Record

    def __init__(self, *, capture_messages_before: str, exporter: Callable[[BaseModel], None]) -> None:
        self._capture_messages_before = capture_messages_before
        self._exporter = exporter
        self._initial_time = time.monotonic()

    def handler_added(self, context: HandlerContext) -> None:
        self._record = Record(
            honeypot=Peer(ip=context.pipeline.metadata["sockname"][0], port=context.pipeline.metadata["sockname"][1]),
            client=Peer(ip=context.pipeline.metadata["peername"][0], port=context.pipeline.metadata["peername"][1]),
            created_at=datetime.now(tz=UTC),
        )

        context.pipeline.add_before(
            self._capture_messages_before,
            f"{context.name}:message_tap",
            MessagesTap(self._initial_time, self._record.messages),
        )
        context.pipeline.add_after(context.name, f"{context.name}:event_tap", EventTap(self._record))

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, ConnectionClosed):
            self._exporter(self._record)

        context.send_inbound(event)
