from dataclasses import dataclass
from typing import Any

from honeypotter.constants import CR, LF
from honeypotter.core import Context, Layer
from honeypotter.transport import DataEvent


@dataclass(frozen=True)
class LineEvent:
    line: bytes


class LineDecoder(Layer):
    def __init__(self, context: Context) -> None:
        super().__init__(context)
        self._buffer = bytearray()

    def handle_inbound(self, event: Any) -> None:
        if not isinstance(event, DataEvent):
            super().handle_inbound(event)
            return

        for byte in event.data:
            if byte not in (CR, LF):
                self._buffer.append(byte)
                continue

            self.ctx.send_inbound(LineEvent(line=bytes(self._buffer)))
            self._buffer.clear()
