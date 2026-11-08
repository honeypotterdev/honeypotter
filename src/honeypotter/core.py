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

        self._contexts: dict[str, HandlerContext] = {}

        self._head = HeadHandlerContext(self, Handler())
        self._contexts["head"] = self._head
        self._tail = TailHandlerContext(self, Handler())
        self._contexts["tail"] = self._tail

        self._head.next = self._tail
        self._tail.prev = self._head

    def add_before(self, before: str, name: str, handler: Handler) -> None:
        if name in self._contexts:
            raise RuntimeError(f"Handler {name!r} already registered in pipeline")

        new_context = HandlerContext(self, handler)
        self._contexts[name] = new_context

        new_next = self._contexts[before]
        new_prev = new_next.prev

        new_next.prev = new_context
        new_context.next = new_next

        new_prev.next = new_context
        new_context.prev = new_prev

        handler.handler_added(new_context)

    def add_after(self, after: str, name: str, handler: Handler) -> None:
        if name in self._contexts:
            raise RuntimeError(f"Handler {name!r} already registered in pipeline")

        new_context = HandlerContext(self, handler)
        self._contexts[name] = new_context

        new_prev = self._contexts[after]
        new_next = new_prev.next

        new_next.prev = new_context
        new_context.next = new_next

        new_prev.next = new_context
        new_context.prev = new_prev

        handler.handler_added(new_context)

    def add_last(self, name: str, handler: Handler) -> None:
        self.add_before("tail", name, handler)

    def add_first(self, name: str, handler: Handler) -> None:
        self.add_after("head", name, handler)

    def send_inbound(self, event: Any) -> None:
        self._head.send_inbound(event)

    @abstractmethod
    def handle_outbound(self, event: Any) -> None: ...


class Handler:
    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        context.send_inbound(event)

    def handle_outbound(self, context: HandlerContext, event: Any) -> None:
        context.send_outbound(event)

    def handler_added(self, context: HandlerContext) -> None:
        pass
