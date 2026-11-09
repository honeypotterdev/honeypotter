import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from honeypotter.core import Handler, HandlerContext
from honeypotter.shell.events import InputReceived, PasswordReceived, UsernameReceived
from honeypotter.transport import ConnectionLostEvent, DataEvent

_logger = logging.getLogger(__name__)


class Message(BaseModel):
    direction: Literal["inbound", "outbound"]
    offset: float
    data: bytes


class Record(BaseModel):
    honeypot_ip: str
    honeypot_port: int
    client_ip: str
    client_port: int
    username: bytes | None = None
    password: bytes | None = None
    shell_inputs: list[bytes] = Field(default_factory=list)
    messages: list[Message] = Field(default_factory=list)
    created_at: datetime


class MessagesTap(Handler):
    def __init__(self, initial_time: float, record: Record) -> None:
        self._initial_time = initial_time
        self._record = record

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._record.messages.append(
                Message(direction="inbound", offset=time.monotonic() - self._initial_time, data=event.data)
            )

        context.send_inbound(event)

    def handle_outbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._record.messages.append(
                Message(direction="outbound", offset=time.monotonic() - self._initial_time, data=event.data)
            )

        context.send_outbound(event)


class EventTap(Handler):
    def __init__(self, record: Record) -> None:
        self._record = record

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, UsernameReceived):
            self._record.username = event.username

        if isinstance(event, PasswordReceived):
            self._record.password = event.password

        if isinstance(event, InputReceived):
            self._record.shell_inputs.append(event.input)

        context.send_inbound(event)


class ShellRecorder(Handler):
    _record: Record

    def __init__(self, *, capture_messages_before: str, exporter: Callable[[BaseModel], None]) -> None:
        self._capture_messages_before = capture_messages_before
        self._exporter = exporter
        self._initial_time = time.monotonic()

    def handler_added(self, context: HandlerContext) -> None:
        self._record = Record(
            honeypot_ip=context.pipeline.metadata["sockname"][0],
            honeypot_port=context.pipeline.metadata["sockname"][1],
            client_ip=context.pipeline.metadata["peername"][0],
            client_port=context.pipeline.metadata["peername"][1],
            created_at=datetime.now(tz=UTC),
        )

        context.pipeline.add_before(
            self._capture_messages_before,
            f"{context.name}:message_tap",
            MessagesTap(self._initial_time, self._record),
        )
        context.pipeline.add_after(context.name, f"{context.name}:event_tap", EventTap(self._record))

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, ConnectionLostEvent):
            self._exporter(self._record)

        context.send_inbound(event)
