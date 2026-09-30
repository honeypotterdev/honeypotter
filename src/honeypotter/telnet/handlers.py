import logging
from typing import Any

from honeypotter.core import Handler, HandlerContext
from honeypotter.telnet.connection import TelnetConnection
from honeypotter.telnet.events import ApplicationDataReceived, ConnectionFailed, Event
from honeypotter.telnet.types import Option, Side
from honeypotter.transport import ConnectionMadeEvent, DataEvent, DisconnectRequestEvent

_logger = logging.getLogger(__name__)


class TelnetHandler(Handler):
    def __init__(self) -> None:
        self._connection = TelnetConnection(
            allowed_local_options=[Option.ECHO, Option.SGA],
            allowed_remote_options=[Option.ECHO, Option.SGA],
        )

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case ConnectionMadeEvent() as event:
                self._send_negotiation_options(context)
                context.send_inbound(event)
            case DataEvent():
                self._handle_data_event(context, event)
            case _:
                super().handle_inbound(context, event)

    def _send_negotiation_options(self, context: HandlerContext) -> None:
        self._connection.request_option(Option.ECHO, side=Side.LOCAL, enable=True)
        self._connection.request_option(Option.SGA, side=Side.LOCAL, enable=True)
        self._connection.request_option(Option.SGA, side=Side.REMOTE, enable=True)
        context.send_outbound(DataEvent(data=self._connection.data_to_send()))

    def _handle_data_event(self, context: HandlerContext, event: DataEvent) -> None:
        events = self._connection.receive_data(event.data)

        _logger.debug(f"Received events: {events!r}")

        for connection_event in events:
            self._handle_connection_event(context, connection_event)

    def _handle_connection_event(self, context: HandlerContext, event: Event) -> None:
        match event:
            case ConnectionFailed():
                context.send_outbound(DisconnectRequestEvent())
            case ApplicationDataReceived(data=data):
                context.send_inbound(DataEvent(data=data))
