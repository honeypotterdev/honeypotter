import asyncio
import logging
from typing import Any, Literal

from honeypotter.commands import CloseConnection, WriteData
from honeypotter.constants import CR, LF
from honeypotter.core import Handler, HandlerContext
from honeypotter.events import ConnectionClosed, ConnectionOpened, DataReceived, LineReceived
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
            case ConnectionClosed():
                self._cancel_timeout_callback()
            case _:
                self._reset_timeout_callback(context)

        context.send_inbound(event)

    def _reset_timeout_callback(self, context: HandlerContext) -> None:
        self._cancel_timeout_callback()
        self._timeout_handle = self._loop.call_later(self._timeout, self._timeout_callback, context)

    def _cancel_timeout_callback(self) -> None:
        if self._timeout_handle is not None:
            self._timeout_handle.cancel()

    def _timeout_callback(self, context: HandlerContext) -> None:
        context.send_outbound(CloseConnection())


class MaxSessionDurationHandler(Handler):
    """Close a connection after a fixed duration, regardless of inbound or outbound activity."""

    def __init__(self, max_duration: float = 600) -> None:
        super().__init__()
        self._max_duration = max_duration
        self._loop = asyncio.get_event_loop()
        self._timeout_handle: asyncio.TimerHandle | None = None

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case ConnectionOpened():
                self._start_timeout_callback(context)
            case ConnectionClosed():
                self._cancel_timeout_callback()

        context.send_inbound(event)

    def _start_timeout_callback(self, context: HandlerContext) -> None:
        if self._timeout_handle is None:
            self._timeout_handle = self._loop.call_later(self._max_duration, self._timeout_callback, context)

    def _cancel_timeout_callback(self) -> None:
        if self._timeout_handle is not None:
            self._timeout_handle.cancel()
            self._timeout_handle = None

    def _timeout_callback(self, context: HandlerContext) -> None:
        context.send_outbound(CloseConnection())


class MessageLoggingHandler(Handler):
    def __init__(self) -> None:
        super().__init__()

        self._messages: list[tuple[Literal["inbound", "outbound"], bytes]] = []

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case DataReceived():
                self._messages.append(("inbound", event.data))
            case ConnectionClosed():
                self._handle_connection_closed(context)

        context.send_inbound(event)

    def handle_outbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, WriteData):
            self._messages.append(("outbound", event.data))

        context.send_outbound(event)

    def _handle_connection_closed(self, context: HandlerContext) -> None:
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
            case ConnectionOpened():
                self._handle_connection_opened(context, event)
            case _:
                context.send_inbound(event)

    def _handle_connection_opened(self, context: HandlerContext, event: ConnectionOpened) -> None:
        client_ip = context.pipeline.metadata["peername"][0]

        if self._rate_limiter.is_allowed(client_ip):
            context.send_inbound(event)
        else:
            _logger.debug("Rate limit reached for %s", client_ip)
            context.send_outbound(CloseConnection())


class LineDecoderHandler(Handler):
    def __init__(self) -> None:
        super().__init__()

        self._buffer = bytearray()

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if not isinstance(event, DataReceived):
            context.send_inbound(event)
            return

        for byte in event.data:
            if byte not in (CR, LF):
                self._buffer.append(byte)
                continue

            context.send_inbound(LineReceived(line=bytes(self._buffer)))
            self._buffer.clear()
