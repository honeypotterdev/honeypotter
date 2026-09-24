from dataclasses import dataclass
from typing import Any

from honeypotter.constants import CR, LF
from honeypotter.core import Handler, HandlerContext
from honeypotter.transport import DataEvent


@dataclass(frozen=True)
class LineEvent:
    line: bytes


class LineDecoderHandler(Handler):
    def __init__(self) -> None:
        super().__init__()

        self._buffer = bytearray()

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if not isinstance(event, DataEvent):
            super().handle_inbound(context, event)
            return

        for byte in event.data:
            if byte not in (CR, LF):
                self._buffer.append(byte)
                continue

            context.send_inbound(LineEvent(line=bytes(self._buffer)))
            self._buffer.clear()
