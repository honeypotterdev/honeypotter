import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from honeypotter.core import Handler, Pipeline

_logger = logging.getLogger(__name__)


@dataclass
class ConnectionMadeEvent:
    pass


@dataclass
class ConnectionLostEvent:
    reason: Exception | None = None


@dataclass(frozen=True)
class DataEvent:
    data: bytes


@dataclass
class DisconnectRequestEvent:
    pass


class TransportPipeline(Pipeline):
    def __init__(self, transport: asyncio.Transport) -> None:
        super().__init__()

        self._transport = transport

    def handle_outbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._transport.write(event.data)
            return

        if isinstance(event, DisconnectRequestEvent):
            self._transport.close()
            return


class TransportProtocol(asyncio.Protocol):
    pipeline: TransportPipeline

    def __init__(self, handler_factories: list[Callable[..., Handler]]) -> None:
        self._handler_factories = handler_factories

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)

        self.pipeline = TransportPipeline(transport)
        self.pipeline.metadata["sockname"] = transport.get_extra_info("sockname")
        self.pipeline.metadata["peername"] = transport.get_extra_info("peername")

        for handler_factory in self._handler_factories:
            self.pipeline.add_handler(handler_factory())

        self.pipeline.send_inbound(ConnectionMadeEvent())

    def data_received(self, data: bytes) -> None:
        self.pipeline.send_inbound(DataEvent(data=data))

    def connection_lost(self, exc: Exception | None) -> None:
        self.pipeline.send_inbound(ConnectionLostEvent(reason=exc))


class TransportProtocolFactory:
    def __init__(self, handler_factories: list[Callable[..., Handler]]) -> None:
        self._handler_factories = handler_factories

    def __call__(self) -> TransportProtocol:
        return TransportProtocol(handler_factories=self._handler_factories)
