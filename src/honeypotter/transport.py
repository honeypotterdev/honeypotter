import asyncio
import logging
from collections.abc import Callable
from typing import Any

from honeypotter.commands import CloseConnection, WriteData
from honeypotter.core import Pipeline
from honeypotter.events import ConnectionClosed, ConnectionOpened, DataReceived

_logger = logging.getLogger(__name__)


class TransportPipeline(Pipeline):
    def __init__(self, transport: asyncio.Transport) -> None:
        super().__init__()

        self._transport = transport

    def handle_outbound(self, event: Any) -> None:
        if isinstance(event, WriteData):
            self._transport.write(event.data)
            return

        if isinstance(event, CloseConnection):
            self._transport.close()
            return


class TransportProtocol(asyncio.Protocol):
    pipeline: TransportPipeline

    def __init__(self, pipeline_initializer: Callable[[Pipeline], None]) -> None:
        self._pipeline_initializer = pipeline_initializer

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)

        self.pipeline = TransportPipeline(transport)
        self.pipeline.metadata["sockname"] = transport.get_extra_info("sockname")
        self.pipeline.metadata["peername"] = transport.get_extra_info("peername")

        self._pipeline_initializer(self.pipeline)

        self.pipeline.send_inbound(ConnectionOpened())

    def data_received(self, data: bytes) -> None:
        self.pipeline.send_inbound(DataReceived(data=data))

    def connection_lost(self, exc: Exception | None) -> None:
        self.pipeline.send_inbound(ConnectionClosed(reason=exc))


class TransportProtocolFactory:
    def __init__(self, pipeline_initializer: Callable[[Pipeline], None]) -> None:
        self._pipeline_initializer = pipeline_initializer

    def __call__(self) -> TransportProtocol:
        return TransportProtocol(pipeline_initializer=self._pipeline_initializer)
