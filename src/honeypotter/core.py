import logging
from abc import ABC, abstractmethod
from typing import Any

_logger = logging.getLogger(__name__)


class HandlerContext:
    def __init__(self, pipeline: Pipeline, handler: Handler) -> None:
        self._pipeline = pipeline
        self.handler = handler
        self.next: HandlerContext | None = None
        self.prev: HandlerContext | None = None

    @property
    def pipeline(self) -> Pipeline:
        return self._pipeline

    def send_inbound(self, event: Any) -> None:
        if self.next is None:
            handler_name = self.handler.__class__.__name__
            raise RuntimeError(f"Handler {handler_name!r} is at the top of the pipeline. Event {event!r}.")

        self.next.handler.handle_inbound(self.next, event)

    def send_outbound(self, event: Any) -> None:
        if self.prev is None:
            handler_name = self.handler.__class__.__name__
            raise RuntimeError(f"Handler {handler_name!r} is at the bottom of the pipeline. Event {event!r}.")

        self.prev.handler.handle_outbound(self.prev, event)


class HeadHandlerContext(HandlerContext):
    def send_outbound(self, event: Any) -> None:
        self.pipeline.handle_outbound(event)


class TailHandlerContext(HandlerContext):
    def send_inbound(self, event: Any) -> None:
        _logger.debug("%s: dropping inbound event %s", str(self.__class__.__name__), repr(event))


class Pipeline(ABC):
    def __init__(self) -> None:
        self.metadata: dict[str, Any] = {}

        self._head = HeadHandlerContext(self, Handler())
        self._tail = TailHandlerContext(self, Handler())
        self._head.next = self._tail
        self._tail.prev = self._head

    def add_last(self, handler: Handler) -> None:
        context = HandlerContext(self, handler)

        self._tail.prev.next = context  # type: ignore[union-attr]
        context.prev = self._tail.prev
        self._tail.prev = context
        context.next = self._tail

    def send_inbound(self, event: Any) -> None:
        self._head.send_inbound(event)

    @abstractmethod
    def handle_outbound(self, event: Any) -> None: ...


class Handler:
    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        context.send_inbound(event)

    def handle_outbound(self, context: HandlerContext, event: Any) -> None:
        context.send_outbound(event)
