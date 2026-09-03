import logging
from collections.abc import Callable
from typing import Any

_logger = logging.getLogger(__name__)


class Context:
    layer: Layer

    def __init__(self, channel: Channel):
        self.channel = channel
        self.prev: Context | None = None
        self.next: Context | None = None

    @property
    def metadata(self) -> dict[str, Any]:
        return self.channel.metadata

    def send_inbound(self, event: Any) -> None:
        if self.next is None:
            _logger.debug(
                "Layer %s is at the top of the channel, dropping inbound event %s",
                repr(self.layer.__class__.__name__),
                repr(event),
            )
            return

        self.next.layer.handle_inbound(event)

    def send_outbound(self, event: Any) -> None:
        if self.prev is None:
            _logger.debug(
                "Layer %s is at the bottom of the channel, outbound inbound event %s",
                repr(self.layer.__class__.__name__),
                repr(event),
            )
            return

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
