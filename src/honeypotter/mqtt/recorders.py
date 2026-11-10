import logging
import time
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from honeypotter.core import Handler, HandlerContext
from honeypotter.events import ConnectionClosed
from honeypotter.mqtt.events import ConnectReceived, DisconnectReceived, PublishReceived, SubscribeReceived
from honeypotter.mqtt.records import ConnectRecord, DisconnectRecord, MqttSessionRecord, PublishRecord, SubscribeRecord
from honeypotter.recorders import MessagesTap, Peer

_logger = logging.getLogger(__name__)


class EventTap(Handler):
    def __init__(self, record: MqttSessionRecord) -> None:
        self._record = record

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, ConnectReceived):
            self._record.events.append(ConnectRecord(**asdict(event)))
        elif isinstance(event, PublishReceived):
            self._record.events.append(PublishRecord(**asdict(event)))
        elif isinstance(event, SubscribeReceived):
            self._record.events.append(SubscribeRecord(**asdict(event)))
        elif isinstance(event, DisconnectReceived):
            self._record.events.append(DisconnectRecord(**asdict(event)))

        context.send_inbound(event)


class MqttRecorder(Handler):
    _record: MqttSessionRecord

    def __init__(self, *, capture_messages_before: str, exporter: Callable[[BaseModel], None]) -> None:
        self._capture_messages_before = capture_messages_before
        self._exporter = exporter
        self._initial_time = time.monotonic()

    def handler_added(self, context: HandlerContext) -> None:
        self._record = MqttSessionRecord(
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
