import logging
from enum import IntEnum, auto
from typing import Any

from honeypotter.core import Context, Layer
from honeypotter.decoders import LineEvent
from honeypotter.transport import ConnectionMadeEvent, DataEvent, DisconnectRequestEvent

_logger = logging.getLogger(__name__)


class ShellState(IntEnum):
    WAITING_FOR_USERNAME = auto()
    WAITING_FOR_PASSWORD = auto()
    OPEN = auto()


class ShellSession(Layer):
    def __init__(self, context: Context) -> None:
        super().__init__(context)
        self._state: ShellState = ShellState.WAITING_FOR_USERNAME

    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, ConnectionMadeEvent):
            self.ctx.send_outbound(DataEvent(data=b"username: "))
            return

        if isinstance(event, LineEvent):
            if self._state == ShellState.WAITING_FOR_USERNAME:
                self.ctx.metadata["shell.username"] = event.line
                self.ctx.send_outbound(DataEvent(data=b"password: "))
                self._state = ShellState.WAITING_FOR_PASSWORD
                return

            if self._state == ShellState.WAITING_FOR_PASSWORD:
                self.ctx.metadata["shell.password"] = event.line
                self.ctx.send_outbound(DataEvent(data=b"/ # "))
                self._state = ShellState.OPEN
                return

            if "shell.commands" not in self.ctx.metadata:
                self.ctx.metadata["shell.commands"] = []

            self.ctx.metadata["shell.commands"].append(event.line)

            _logger.info(f"Context metadata: {self.ctx.metadata}")

            self.ctx.send_outbound(DisconnectRequestEvent())

            return

        super().handle_inbound(event)
