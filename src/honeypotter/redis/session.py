import logging
from typing import Any

from honeypotter.core import Context, Layer
from honeypotter.redis.protocol import ConnectionEvent, RedisConnection
from honeypotter.redis.utils import InfoProvider
from honeypotter.redis.values import Array, BulkString
from honeypotter.transport import DataEvent, DisconnectRequestEvent

_logger = logging.getLogger(__name__)
_info_provider = InfoProvider()


class RedisSession(Layer):
    def __init__(self, context: Context) -> None:
        super().__init__(context)
        self._connection = RedisConnection()

    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            events = self._connection.receive_data(event.data)

            _logger.debug(f"Received events: {events!r}")

            for connection_event in events:
                self._handle_event(connection_event)

            return

        super().handle_inbound(event)

    def _handle_event(self, event: ConnectionEvent) -> None:
        match event:
            case Array(array=[BulkString(string=b"PING")]):
                self.ctx.send_outbound(DataEvent(data=self._connection.send_simple_string(b"PONG")))
            case Array(array=[BulkString(string=b"INFO")]):
                info = _info_provider.generate_info().encode("utf-8")
                self.ctx.send_outbound(DataEvent(data=self._connection.send_bulk_string(info)))
            case Array(array=[BulkString(string=b"SET"), BulkString(string=_), BulkString(string=_)]):
                self.ctx.send_outbound(DataEvent(data=self._connection.send_simple_string(b"OK")))
            case Array(array=[BulkString(string=command), *_rest]):
                self.ctx.send_outbound(
                    DataEvent(data=self._connection.send_simple_error(b"ERR unknown command '" + command + b"'"))
                )
            case _:
                self.ctx.send_outbound(DataEvent(data=self._connection.send_simple_error(b"ERR unknown error")))
                self.ctx.send_outbound(DisconnectRequestEvent())
