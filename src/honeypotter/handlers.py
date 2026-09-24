import asyncio
import logging
from typing import Any

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
        if isinstance(event, ConnectionLostEvent):
            self._cancel_timeout_callback()
            super().handle_inbound(context, event)
            return

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


class TrafficLoggingHandler(Handler):
    def __init__(self) -> None:
        super().__init__()

        self._traffic: list[tuple[str, bytes]] = []

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, ConnectionLostEvent):
            _logger.debug(
                "Connection lost. Traffic: %s, metadata: %s",
                repr(self._traffic),
                repr(context.pipeline.metadata),
            )
            super().handle_inbound(context, event)
            return

        if isinstance(event, DataEvent):
            self._traffic.append(("inbound", event.data))

        super().handle_inbound(context, event)

    def handle_outbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._traffic.append(("outbound", event.data))

        super().handle_outbound(context, event)


class NewIpRateLimiter:
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
        if isinstance(event, ConnectionMadeEvent):
            client_ip = context.pipeline.metadata["peername"][0]

            if not self._rate_limiter.is_allowed(client_ip):
                _logger.debug("Rate limit reached for %s", client_ip)
                context.send_outbound(DisconnectRequestEvent())
                return

        super().handle_inbound(context, event)
