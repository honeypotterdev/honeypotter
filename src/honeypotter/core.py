from collections.abc import Callable
from typing import Any


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
            raise RuntimeError(
                f"Cannot send inbound event {event!r}: "
                f"Layer {self.layer.__class__.__name__!r} is at the top of the stack."
            )

        self.next.layer.handle_inbound(event)

    def send_outbound(self, event: Any) -> None:
        if self.prev is None:
            raise RuntimeError(
                f"Cannot send outbound event {event!r}: "
                f"Layer {self.layer.__class__.__name__!r} is at the bottom of the stack."
            )

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
