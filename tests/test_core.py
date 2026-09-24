from typing import Any

from honeypotter.core import Handler, HandlerContext, Pipeline


class UppercaseHandler(Handler):
    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, bytes):
            context.send_inbound(event.upper())
            return

        super().handle_inbound(context, event)


class ReverseHandler(Handler):
    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, bytes):
            context.send_outbound(bytes(reversed(event)))
            return

        super().handle_inbound(context, event)


class QueuePipeline(Pipeline):
    def __init__(self) -> None:
        super().__init__()

        self.outbound_queue = []

    def handle_outbound(self, event: Any) -> None:
        self.outbound_queue.append(event)


class TestQueuePipeline:
    def test(self) -> None:
        pipeline = QueuePipeline()
        pipeline.add_handler(UppercaseHandler())
        pipeline.add_handler(ReverseHandler())
        pipeline.send_inbound(b"foo")

        assert pipeline.outbound_queue == [b"OOF"]
