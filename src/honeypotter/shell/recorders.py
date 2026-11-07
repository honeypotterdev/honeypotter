from typing import Any

from honeypotter.core import Handler, HandlerContext


class DummyHandler(Handler):
    def __init__(self, name: str) -> None:
        self._name = name

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        print(f"{self._name}: beep boop, handling inbound {event}")
        context.send_inbound(event)


class ShellRecorder(Handler):
    def handler_added(self, context: HandlerContext) -> None:
        context.pipeline.add_last(DummyHandler("Dummy #1"))
        context.pipeline.add_last(DummyHandler("Dummy #2"))
