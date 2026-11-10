import logging
from typing import Any

from honeypotter.commands import CloseConnection, WriteData
from honeypotter.core import Handler, HandlerContext
from honeypotter.events import DataReceived
from honeypotter.redis.connection import RedisConnection
from honeypotter.redis.events import (
    ArrayReceived,
    BulkStringReceived,
    Event,
    NullBulkStringReceived,
    SimpleStringReceived,
)
from honeypotter.redis.utils import InfoProvider

_logger = logging.getLogger(__name__)
_info_provider = InfoProvider()


class RedisHandler(Handler):
    def __init__(self) -> None:
        super().__init__()

        self._connection = RedisConnection()

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case DataReceived():
                self._handle_data_received(context, event)
            case _:
                context.send_inbound(event)

    def _handle_data_received(self, context: HandlerContext, event: DataReceived) -> None:
        events = self._connection.receive_data(event.data)

        _logger.debug(f"Received events: {events!r}")

        for connection_event in events:
            self._handle_connection_event(context, connection_event)

    def _handle_connection_event(self, context: HandlerContext, event: Event) -> None:
        context.send_inbound(event)

        match event:
            case ArrayReceived(array=[BulkStringReceived(string=command), *args]):
                self._handle_command(context, command, args)
            case _:
                self._connection.send_simple_error(b"ERR unknown error")
                context.send_outbound(WriteData(data=self._connection.data_to_send()))
                context.send_outbound(CloseConnection())

    def _handle_command(
        self,
        context: HandlerContext,
        command: bytes,
        args: list[SimpleStringReceived | BulkStringReceived | NullBulkStringReceived],
    ) -> None:
        match command.upper(), args:
            case b"QUIT", *_:
                self._connection.send_simple_string(b"OK")
                context.send_outbound(WriteData(data=self._connection.data_to_send()))
                context.send_outbound(CloseConnection())
                return
            case b"PING", []:
                self._connection.send_simple_string(b"PONG")
            case b"INFO", []:
                info = _info_provider.generate_info().encode("utf-8")
                self._connection.send_bulk_string(info)
            case b"SET", [BulkStringReceived(string=_), BulkStringReceived(string=_)]:
                self._connection.send_simple_string(b"OK")
            case _:
                self._connection.send_simple_error(b"ERR unknown command '" + command + b"'")

        if data_to_send := self._connection.data_to_send():
            context.send_outbound(WriteData(data=data_to_send))
