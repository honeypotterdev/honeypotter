import logging
from collections.abc import Callable
from typing import Any

_logger = logging.getLogger(__name__)


class Context:
    layer: Layer

    def __init__(self, stack: Channel):
        self.stack = stack
        self.prev: Context | None = None
        self.next: Context | None = None

    @property
    def metadata(self) -> dict[str, Any]:
        return self.stack.metadata

    def send_inbound(self, event: Any) -> None:
        if self.next is None:
            _logger.debug(
                f"Cannot send outbound event {event!r}: "
                f"Layer {self.layer.__class__.__name__!r} is at the bottom of the stack."
            )
            return

        _logger.debug(f">>> {self.next.layer.__class__.__name__!r}: {event!r}")

        self.next.layer.handle_inbound(event)

    def send_outbound(self, event: Any) -> None:
        if self.prev is None:
            _logger.debug(
                f"Cannot send outbound event {event!r}: "
                f"Layer {self.layer.__class__.__name__!r} is at the bottom of the stack."
            )
            return

        _logger.debug(f"<<< {self.prev.layer.__class__.__name__!r}: {event!r}")

        self.prev.layer.handle_outbound(event)


class Channel:
    def __init__(self) -> None:
        self.metadata: dict[str, Any] = {}
        self.tail: Context | None = None

    def add[T: Layer](self, layer_factory: Callable[[Context], T]) -> T:
        ctx = Context(self)
        layer = layer_factory(ctx)
        ctx.layer = layer

        if self.tail is None:
            self.tail = ctx
        else:
            self.tail.next = ctx
            ctx.prev = self.tail
            self.tail = ctx

        return layer


class Layer:
    def __init__(self, context: Context):
        self.ctx = context

    def handle_inbound(self, event: Any) -> None:
        self.ctx.send_inbound(event)

    def handle_outbound(self, event: Any) -> None:
        self.ctx.send_outbound(event)
