import logging
import time
from dataclasses import dataclass
from typing import Any, Literal

from honeypotter.core import Handler, HandlerContext
from honeypotter.shell.events import InputReceived, PasswordReceived, UsernameReceived
from honeypotter.transport import ConnectionLostEvent, DataEvent

_logger = logging.getLogger(__name__)


@dataclass(kw_only=True)
class Message:
    direction: Literal["inbound", "outbound"]
    offset: float
    data: bytes


class MessagesTap(Handler):
    def __init__(self, initial_time: float, messages: list[Message]) -> None:
        self._initial_time = initial_time
        self._messages = messages

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._messages.append(
                Message(direction="inbound", offset=time.monotonic() - self._initial_time, data=event.data)
            )

        context.send_inbound(event)

    def handle_outbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._messages.append(
                Message(direction="outbound", offset=time.monotonic() - self._initial_time, data=event.data)
            )

        context.send_outbound(event)


class EventTap(Handler):
    def __init__(self, events) -> None:
        self._events = events

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, UsernameReceived):
            self._events.append(event)

        if isinstance(event, PasswordReceived):
            self._events.append(event)

        if isinstance(event, InputReceived):
            self._events.append(event)

        context.send_inbound(event)


class ShellRecorder(Handler):
    def __init__(self, *, capture_messages_before: str) -> None:
        self._capture_messages_before = capture_messages_before
        self._initial_time = time.monotonic()
        self._messages = []
        self._events = []

    def handler_added(self, context: HandlerContext) -> None:
        context.pipeline.add_before(
            self._capture_messages_before,
            f"{context.name}:message_tap",
            MessagesTap(self._initial_time, self._messages),
        )
        context.pipeline.add_after(context.name, f"{context.name}:event_tap", EventTap(self._events))

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, ConnectionLostEvent):
            _logger.info(f"Messages: {self._messages}")
            _logger.info(f"Events: {self._events}")

        context.send_inbound(event)
