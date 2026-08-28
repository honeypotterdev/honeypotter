import asyncio
import logging
from typing import Any

from honeypotter.core import Context, Layer
from honeypotter.transport import ConnectionLostEvent, DataEvent, DisconnectRequestEvent

_logger = logging.getLogger(__name__)


class InboundIdleTimeoutLayer(Layer):
    def __init__(self, context: Context, timeout: float = 5) -> None:
        super().__init__(context)
        self._timeout = timeout
        self._loop = asyncio.get_event_loop()
        self._timeout_handle: asyncio.TimerHandle | None = None

    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, ConnectionLostEvent):
            self._cancel_timeout_callback()
            super().handle_inbound(event)
            return

        self._reset_timeout_callback()
        super().handle_inbound(event)

    def _reset_timeout_callback(self) -> None:
        self._cancel_timeout_callback()
        self._timeout_handle = self._loop.call_later(self._timeout, self._timeout_callback)

    def _cancel_timeout_callback(self) -> None:
        if self._timeout_handle is not None:
            self._timeout_handle.cancel()

    def _timeout_callback(self) -> None:
        self.ctx.send_outbound(DisconnectRequestEvent())


class TrafficLoggingLayer(Layer):
    def __init__(self, context: Context) -> None:
        super().__init__(context)
        self._traffic: list[tuple[str, bytes]] = []

    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, ConnectionLostEvent):
            _logger.debug(
                "Connection lost. Conversation: %s, metadata: %s",
                repr(self._traffic),
                repr(self.ctx.metadata),
            )
            super().handle_inbound(event)
            return

        if isinstance(event, DataEvent):
            self._traffic.append(("inbound", event.data))

        super().handle_inbound(event)

    def handle_outbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._traffic.append(("outbound", event.data))

        super().handle_outbound(event)
