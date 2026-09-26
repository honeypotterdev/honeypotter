import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from honeypotter.constants import CR, LF
from honeypotter.core import Handler, HandlerContext
from honeypotter.transport import ConnectionLostEvent, ConnectionMadeEvent, DataEvent, DisconnectRequestEvent
from honeypotter.utils import RateLimiter

_logger = logging.getLogger(__name__)


class InboundIdleTimeoutHandler(Handler):
    def __init__(self, timeout: float = 5) -> None:
        super().__init__()
        self._timeout = timeout
        self._loop = asyncio.get_event_loop()
        self._timeout_handle: asyncio.TimerHandle | None = None

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case ConnectionLostEvent():
                self._cancel_timeout_callback()
            case _:
                self._reset_timeout_callback(context)

        super().handle_inbound(context, event)

    def _reset_timeout_callback(self, context: HandlerContext) -> None:
        self._cancel_timeout_callback()
        self._timeout_handle = self._loop.call_later(self._timeout, self._timeout_callback, context)

    def _cancel_timeout_callback(self) -> None:
        if self._timeout_handle is not None:
            self._timeout_handle.cancel()

    def _timeout_callback(self, context: HandlerContext) -> None:
        context.send_outbound(DisconnectRequestEvent())


class MessageLoggingHandler(Handler):
    def __init__(self) -> None:
        super().__init__()

        self._messages: list[tuple[str, bytes]] = []

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case DataEvent():
                self._messages.append(("inbound", event.data))
            case ConnectionLostEvent():
                self._handle_connection_lost(context, event)

        super().handle_inbound(context, event)

    def handle_outbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._messages.append(("outbound", event.data))

        super().handle_outbound(context, event)

    def _handle_connection_lost(self, context: HandlerContext, event: ConnectionLostEvent) -> None:
        _logger.debug(
            "Connection lost. Metadata: %s, Messages: %s", repr(context.pipeline.metadata), repr(self._messages)
        )


class IpRateLimiter:
    def __init__(self) -> None:
        self._rate_limiter = RateLimiter[str](
            burst=10,
            rate=10 / 3600,  # 10 per hour
            max_tracked=10_000,
        )

    def handler_factory(self) -> Handler:
        return IpRateLimiterHandler(rate_limiter=self._rate_limiter)


class IpRateLimiterHandler(Handler):
    def __init__(self, rate_limiter: RateLimiter[str]) -> None:
        super().__init__()

        self._rate_limiter = rate_limiter

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case ConnectionMadeEvent():
                self._handle_connection_made(context, event)
            case _:
                super().handle_inbound(context, event)

    def _handle_connection_made(self, context: HandlerContext, event: ConnectionMadeEvent) -> None:
        client_ip = context.pipeline.metadata["peername"][0]

        if not self._rate_limiter.is_allowed(client_ip):
            _logger.debug("Rate limit reached for %s", client_ip)
            context.send_outbound(DisconnectRequestEvent())


@dataclass(frozen=True)
class LineEvent:
    line: bytes


class LineDecoderHandler(Handler):
    def __init__(self) -> None:
        super().__init__()

        self._buffer = bytearray()

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if not isinstance(event, DataEvent):
            super().handle_inbound(context, event)
            return

        for byte in event.data:
            if byte not in (CR, LF):
                self._buffer.append(byte)
                continue

            context.send_inbound(LineEvent(line=bytes(self._buffer)))
            self._buffer.clear()
