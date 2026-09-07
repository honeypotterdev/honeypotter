from enum import Enum, auto
from typing import Any

from honeypotter.core import Layer
from honeypotter.transport import DataEvent


class State(Enum):
    READ_TYPE = auto()
    READ_BULK_STRING = auto()


class Actions(Enum):
    pass


BULK_STRING_PREFIX = int.from_bytes(b"$")

transitions = {
    (State.READ_TYPE, BULK_STRING_PREFIX): (State.READ_BULK_STRING, None),
}


class RedisCodec(Layer):
    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            self.ctx.send_outbound(DataEvent(b"-ERR unknown error\r\n"))
            return

        super().handle_inbound(event)
