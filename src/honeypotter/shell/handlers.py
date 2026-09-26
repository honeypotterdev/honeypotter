import logging
from enum import Enum, auto
from typing import Any

from honeypotter.core import Handler, HandlerContext
from honeypotter.handlers import LineEvent
from honeypotter.shell.emulators import BusyboxEmulator
from honeypotter.transport import ConnectionMadeEvent, DataEvent

_logger = logging.getLogger(__name__)


class State(Enum):
    WAITING_FOR_USERNAME = auto()
    WAITING_FOR_PASSWORD = auto()
    OPEN = auto()


class BusyboxShellHandler(Handler):
    def __init__(self) -> None:
        super().__init__()

        self._state: State = State.WAITING_FOR_USERNAME
        self._emulator = BusyboxEmulator()

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, ConnectionMadeEvent):
            context.send_outbound(DataEvent(data=b"login: "))
            return

        if isinstance(event, LineEvent):
            if self._state == State.WAITING_FOR_USERNAME:
                context.pipeline.metadata["shell.username"] = event.line
                context.send_outbound(DataEvent(data=b"password: "))
                self._state = State.WAITING_FOR_PASSWORD
                return

            if self._state == State.WAITING_FOR_PASSWORD:
                context.pipeline.metadata["shell.password"] = event.line
                context.send_outbound(DataEvent(data=self._emulator.execute_line()))
                self._state = State.OPEN
                return

            if "shell.inputs" not in context.pipeline.metadata:
                context.pipeline.metadata["shell.inputs"] = []

            context.pipeline.metadata["shell.inputs"].append(event.line)
            context.send_outbound(DataEvent(data=self._emulator.execute_line(event.line)))
            return

        super().handle_inbound(context, event)
