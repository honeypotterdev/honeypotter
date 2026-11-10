import logging
from typing import Any

from honeypotter.commands import CloseConnection, WriteData
from honeypotter.core import Handler, HandlerContext
from honeypotter.events import ConnectionOpened, DataReceived
from honeypotter.telnet.connection import TelnetConnection
from honeypotter.telnet.events import ApplicationDataReceived, ConnectionFailed, Event
from honeypotter.telnet.types import Option, Side

_logger = logging.getLogger(__name__)


class TelnetHandler(Handler):
    def __init__(self) -> None:
        self._connection = TelnetConnection(
            allowed_local_options=[Option.ECHO, Option.SGA],
            allowed_remote_options=[Option.ECHO, Option.SGA],
        )

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case ConnectionOpened() as event:
                self._send_negotiation_options(context)
                context.send_inbound(event)
            case DataReceived():
                self._handle_data_received(context, event)
            case _:
                context.send_inbound(event)

    def handle_outbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case WriteData(data=data):
                self._connection.send_application_data(data)
                self._send_pending_data(context)
            case _:
                context.send_outbound(event)

    def _send_pending_data(self, context: HandlerContext) -> None:
        if data := self._connection.data_to_send():
            context.send_outbound(WriteData(data=data))

    def _send_negotiation_options(self, context: HandlerContext) -> None:
        self._connection.request_option(Option.ECHO, side=Side.LOCAL, enable=True)
        self._connection.request_option(Option.SGA, side=Side.LOCAL, enable=True)
        self._connection.request_option(Option.SGA, side=Side.REMOTE, enable=True)
        self._send_pending_data(context)

    def _handle_data_received(self, context: HandlerContext, event: DataReceived) -> None:
        events = self._connection.receive_data(event.data)
        self._send_pending_data(context)

        _logger.debug(f"Received events: {events!r}")

        for connection_event in events:
            self._handle_connection_event(context, connection_event)

    def _handle_connection_event(self, context: HandlerContext, event: Event) -> None:
        match event:
            case ConnectionFailed():
                context.send_outbound(CloseConnection())
            case ApplicationDataReceived(data=data):
                context.send_inbound(DataReceived(data=data))
