from typing import Any

from honeypotter.commands import CloseConnection
from honeypotter.core import Handler, HandlerContext
from honeypotter.events import ConnectionClosed, DataReceived
from honeypotter.tcp.events import PayloadReceived


class TcpHandler(Handler):
    def __init__(self, max_payload_size: int = 1024) -> None:
        super().__init__()

        self._max_payload_size = max_payload_size
        self._buffer = bytearray()

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case DataReceived():
                self._handle_data_received(context, event)
            case ConnectionClosed():
                self._handle_connection_closed(context, event)
            case _:
                context.send_inbound(event)

    def _handle_data_received(self, context: HandlerContext, event: DataReceived) -> None:
        self._buffer.extend(event.data[: self._max_payload_size - len(self._buffer)])
        if len(self._buffer) == self._max_payload_size:
            self._emit_payload(context)
            context.send_outbound(CloseConnection())

    def _handle_connection_closed(self, context: HandlerContext, event: ConnectionClosed) -> None:
        if self._buffer:
            self._emit_payload(context)

        context.send_inbound(event)

    def _emit_payload(self, context: HandlerContext) -> None:
        payload = bytes(self._buffer)
        self._buffer.clear()

        context.send_inbound(PayloadReceived(payload=payload))
