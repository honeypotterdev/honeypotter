import logging
from typing import Any

from honeypotter.core import Handler, HandlerContext
from honeypotter.redis.connection import ConnectionEvent, RedisConnection
from honeypotter.redis.utils import InfoProvider
from honeypotter.redis.values import Array, BulkString, RespValue
from honeypotter.transport import DataEvent, DisconnectRequestEvent

_logger = logging.getLogger(__name__)
_info_provider = InfoProvider()


class RedisHandler(Handler):
    def __init__(self) -> None:
        super().__init__()

        self._connection = RedisConnection()

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case DataEvent():
                self._handle_data_event(context, event)
            case _:
                super().handle_inbound(context, event)

    def _handle_data_event(self, context: HandlerContext, event: DataEvent) -> None:
        events = self._connection.receive_data(event.data)

        _logger.debug(f"Received events: {events!r}")

        for connection_event in events:
            self._handle_connection_event(context, connection_event)

    def _handle_connection_event(self, context: HandlerContext, event: ConnectionEvent) -> None:
        match event:
            case Array(array=[BulkString(string=command), *args]):
                self._handle_command(context, command, args)
            case _:
                self._connection.send_simple_error(b"ERR unknown error")
                context.send_outbound(DataEvent(data=self._connection.data_to_send()))
                context.send_outbound(DisconnectRequestEvent())

    def _handle_command(self, context: HandlerContext, command: bytes, args: list[RespValue]) -> None:
        self._log_command(context, command, args)

        match command.upper(), args:
            case b"QUIT", *_:
                self._connection.send_simple_string(b"OK")
                context.send_outbound(DataEvent(data=self._connection.data_to_send()))
                context.send_outbound(DisconnectRequestEvent())
                return
            case b"PING", []:
                self._connection.send_simple_string(b"PONG")
            case b"INFO", []:
                info = _info_provider.generate_info().encode("utf-8")
                self._connection.send_bulk_string(info)
            case b"SET", [BulkString(string=_), BulkString(string=_)]:
                self._connection.send_simple_string(b"OK")
            case _:
                self._connection.send_simple_error(b"ERR unknown command '" + command + b"'")

        if data_to_send := self._connection.data_to_send():
            context.send_outbound(DataEvent(data=data_to_send))

    def _log_command(self, context: HandlerContext, command: bytes, args: list[RespValue]) -> None:
        if not all(isinstance(arg, BulkString) for arg in args):
            return

        if "redis.commands" not in context.pipeline.metadata:
            context.pipeline.metadata["redis.commands"] = []

        full_command = b" ".join([command] + [arg.string for arg in args])
        context.pipeline.metadata["redis.commands"].append(full_command)
