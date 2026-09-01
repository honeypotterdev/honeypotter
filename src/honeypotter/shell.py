import codecs
import logging
import shlex
from enum import IntEnum, auto
from typing import Any

from honeypotter.core import Context, Layer
from honeypotter.decoders import LineEvent
from honeypotter.transport import ConnectionMadeEvent, DataEvent

_logger = logging.getLogger(__name__)


class ShellState(IntEnum):
    WAITING_FOR_LOGIN = auto()
    WAITING_FOR_PASSWORD = auto()
    OPEN = auto()


class ShellSession(Layer):
    def __init__(self, context: Context) -> None:
        super().__init__(context)
        self._state: ShellState = ShellState.WAITING_FOR_LOGIN

    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, ConnectionMadeEvent):
            self.ctx.send_outbound(DataEvent(data=b"login: "))
            return

        if isinstance(event, LineEvent):
            if self._state == ShellState.WAITING_FOR_LOGIN:
                self.ctx.metadata["shell"]["login"] = event.line
                self.ctx.send_outbound(DataEvent(data=b"password: "))
                self._state = ShellState.WAITING_FOR_PASSWORD
                return

            if self._state == ShellState.WAITING_FOR_PASSWORD:
                self.ctx.metadata["shell"]["password"] = event.line
                self.ctx.send_outbound(DataEvent(data=b"/ # "))
                self._state = ShellState.OPEN
                return

            if "commands" not in self.ctx.metadata["shell"]:
                self.ctx.metadata["shell"]["commands"] = []

            self.ctx.metadata["shell"]["commands"].append(event.line)
            self._handle_cli_input(event.line)
            self.ctx.send_outbound(DataEvent(data=b"/ # "))
            return

        super().handle_inbound(event)

    def _handle_cli_input(self, line: bytes) -> None:
        command = shlex.split(line.decode("utf-8", errors="ignore"))

        match command:
            case ["sh"] | ["ash"]:
                return
            case ["echo", "-e", escaped_text]:
                text, _ = codecs.escape_decode(escaped_text.encode("utf-8"))
                self.ctx.send_outbound(DataEvent(data=text + b"\n"))
            case ["echo", text]:
                self.ctx.send_outbound(DataEvent(data=text.encode("utf-8") + b"\n"))
            case ["busybox", applet] | ["/bin/busybox", applet]:
                out = f"{applet}: applet not found\n"
                self.ctx.send_outbound(DataEvent(out.encode("utf-8")))
            case [binary, *_]:
                out = f"sh: {binary}: not found\n"
                self.ctx.send_outbound(DataEvent(out.encode("utf-8")))
