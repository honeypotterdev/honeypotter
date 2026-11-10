import time
from typing import Any, Literal

from pydantic import BaseModel

from honeypotter.core import Handler, HandlerContext
from honeypotter.transport import DataEvent


class Peer(BaseModel):
    ip: str
    port: int


class Message(BaseModel):
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
