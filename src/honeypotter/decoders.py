from dataclasses import dataclass
from typing import Any

from honeypotter.core import Context, Layer
from honeypotter.transport import DataEvent

LF = int.from_bytes(b"\n")


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
            if byte != LF:
                self._buffer.append(byte)
                continue

            self.ctx.send_inbound(LineEvent(line=bytes(self._buffer)))
            self._buffer.clear()
