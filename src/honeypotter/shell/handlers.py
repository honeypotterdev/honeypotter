import logging
from enum import Enum, auto
from typing import Any

from honeypotter.commands import WriteData
from honeypotter.core import Handler, HandlerContext
from honeypotter.events import ConnectionOpened, LineReceived
from honeypotter.shell.emulators import BusyboxEmulator
from honeypotter.shell.events import InputReceived, PasswordReceived, UsernameReceived

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
        match event:
            case ConnectionOpened():
                self._handle_connection_opened(context)
            case LineReceived():
                self._handle_line(context, event)
            case _:
                context.send_inbound(event)

    def _handle_connection_opened(self, context: HandlerContext) -> None:
        context.send_outbound(WriteData(data=b"login: "))

    def _handle_line(self, context: HandlerContext, event: LineReceived) -> None:
        if self._state == State.WAITING_FOR_USERNAME:
            self._state = State.WAITING_FOR_PASSWORD
            context.send_inbound(UsernameReceived(username=event.line))
            context.send_outbound(WriteData(data=b"password: "))
            return

        if self._state == State.WAITING_FOR_PASSWORD:
            self._state = State.OPEN
            context.send_inbound(PasswordReceived(password=event.line))
            context.send_outbound(WriteData(data=self._emulator.execute_line()))
            return

        context.send_inbound(InputReceived(input=event.line))
        context.send_outbound(WriteData(data=self._emulator.execute_line(event.line)))
