import logging
from enum import IntEnum, auto
from typing import Any

from honeypotter.core import Context, Layer
from honeypotter.decoders import LineEvent
from honeypotter.emulators import BusyBoxEmulator
from honeypotter.transport import ConnectionMadeEvent, DataEvent

_logger = logging.getLogger(__name__)


class ShellState(IntEnum):
    WAITING_FOR_USERNAME = auto()
    WAITING_FOR_PASSWORD = auto()
    OPEN = auto()


class ShellSession(Layer):
    def __init__(self, context: Context) -> None:
        super().__init__(context)
        self._state: ShellState = ShellState.WAITING_FOR_USERNAME
        self._emulator = BusyBoxEmulator()

    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, ConnectionMadeEvent):
            self.ctx.send_outbound(DataEvent(data=b"login: "))
            return

        if isinstance(event, LineEvent):
            if self._state == ShellState.WAITING_FOR_USERNAME:
                self.ctx.metadata["shell.username"] = event.line
                self.ctx.send_outbound(DataEvent(data=b"password: "))
                self._state = ShellState.WAITING_FOR_PASSWORD
                return

            if self._state == ShellState.WAITING_FOR_PASSWORD:
                self.ctx.metadata["shell.password"] = event.line
                self.ctx.send_outbound(DataEvent(data=self._emulator.execute_line()))
                self._state = ShellState.OPEN
                return

            if "shell.inputs" not in self.ctx.metadata:
                self.ctx.metadata["shell.inputs"] = []

            self.ctx.metadata["shell.inputs"].append(event.line)
            self.ctx.send_outbound(DataEvent(data=self._emulator.execute_line(event.line)))
            return

        super().handle_inbound(event)
