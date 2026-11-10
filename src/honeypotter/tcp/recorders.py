from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from honeypotter.core import Handler, HandlerContext
from honeypotter.events import ConnectionClosed
from honeypotter.recorders import Peer
from honeypotter.tcp.events import PayloadReceived
from honeypotter.tcp.records import TcpSessionRecord


class TcpRecorder(Handler):
    _record: TcpSessionRecord

    def __init__(self, *, exporter: Callable[[BaseModel], None]) -> None:
        self._exporter = exporter

    def handler_added(self, context: HandlerContext) -> None:
        self._record = TcpSessionRecord(
            honeypot=Peer(ip=context.pipeline.metadata["sockname"][0], port=context.pipeline.metadata["sockname"][1]),
            client=Peer(ip=context.pipeline.metadata["peername"][0], port=context.pipeline.metadata["peername"][1]),
            created_at=datetime.now(tz=UTC),
        )

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case PayloadReceived():
                self._record.payload = event.payload
            case ConnectionClosed():
                self._exporter(self._record)

        context.send_inbound(event)
