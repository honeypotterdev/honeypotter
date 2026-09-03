import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from honeypotter.core import Channel, Context, Layer

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


class TransportProtocolAdapterLayer(Layer):
    def __init__(self, context: Context, transport: asyncio.Transport) -> None:
        super().__init__(context)
        self._transport = transport

    def handle_outbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._transport.write(event.data)
            return

        if isinstance(event, DisconnectRequestEvent):
            self._transport.close()
            return

    def connection_made(self) -> None:
        self.ctx.send_inbound(ConnectionMadeEvent())

    def data_received(self, data: bytes) -> None:
        self.ctx.send_inbound(DataEvent(data=data))

    def connection_lost(self, exc: Exception | None) -> None:
        self.ctx.send_inbound(ConnectionLostEvent(reason=exc))


class TransportProtocol(asyncio.Protocol):
    _adapter_layer: TransportProtocolAdapterLayer

    def __init__(self, layer_factories: list[Callable[[Context], Layer]]) -> None:
        self._factories = layer_factories

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)

        channel = Channel()
        channel.metadata["sockname"] = transport.get_extra_info("sockname")
        channel.metadata["peername"] = transport.get_extra_info("peername")

        self._adapter_layer = channel.add(lambda ctx: TransportProtocolAdapterLayer(ctx, transport))

        for factory in self._factories:
            channel.add(factory)

        self._adapter_layer.connection_made()

    def data_received(self, data: bytes) -> None:
        assert self._adapter_layer is not None

        self._adapter_layer.data_received(data)

    def connection_lost(self, exc: Exception | None) -> None:
        assert self._adapter_layer is not None

        self._adapter_layer.connection_lost(exc)


class TransportProtocolFactory:
    def __init__(self, layer_factories: list[Callable[[Context], Layer]]) -> None:
        self._factories = layer_factories

    def __call__(self) -> TransportProtocol:
        return TransportProtocol(layer_factories=self._factories)
