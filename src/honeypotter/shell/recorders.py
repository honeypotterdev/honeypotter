from typing import Any

from honeypotter.core import Handler, HandlerContext


class DummyHandler(Handler):
    def __init__(self, name: str) -> None:
        self._name = name

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        print(f"{self._name}: beep boop, handling inbound {event}")
        context.send_inbound(event)


class ShellRecorder(Handler):
    def __init__(self, *, wrap: str) -> None:
        self._wrap = wrap

    def handler_added(self, context: HandlerContext) -> None:
        context.pipeline.add_before(self._wrap, "dummy1", DummyHandler("Dummy #1"))
        context.pipeline.add_after(self._wrap, "dummy2", DummyHandler("Dummy #2"))
