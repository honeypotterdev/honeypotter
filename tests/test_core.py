from typing import Any

from honeypotter.core import Handler, HandlerContext, handle
from honeypotter.test import StubPipeline


class TestPipeline:
    def test_handle_method_override(self) -> None:
        class UppercaseHandler(Handler):
            def handle_inbound(self, context: HandlerContext, event: Any) -> None:
                assert isinstance(event, bytes)

                context.send_inbound(event.upper())

        class WrapHandler(Handler):
            def handle_outbound(self, context: HandlerContext, event: Any) -> None:
                assert isinstance(event, bytes)

                context.send_outbound(b"(" + event + b")")

        class ReverseHandler(Handler):
            def handle_inbound(self, context: HandlerContext, event: Any) -> None:
                assert isinstance(event, bytes)

                context.send_outbound(bytes(reversed(event)))

        pipeline = StubPipeline()
        pipeline.add_handler(UppercaseHandler())
        pipeline.add_handler(WrapHandler())
        pipeline.add_handler(ReverseHandler())
        pipeline.send_inbound(b"foo")

        assert pipeline.outbound_queue == [b"(OOF)"]

    def test_handle_method_decorator(self) -> None:
        class UppercaseHandler(Handler):
            @handle("inbound", bytes)
            def handle_inbound_bytes(self, context: HandlerContext, event: bytes) -> None:
                context.send_inbound(event.upper())

        class WrapHandler(Handler):
            @handle("outbound", bytes)
            def handle_outbound_bytes(self, context: HandlerContext, event: bytes) -> None:
                context.send_outbound(b"(" + event + b")")

        class ReverseHandler(Handler):
            @handle("inbound", bytes)
            def handle_inbound_bytes(self, context: HandlerContext, event: bytes) -> None:
                context.send_outbound(bytes(reversed(event)))

        pipeline = StubPipeline()
        pipeline.add_handler(UppercaseHandler())
        pipeline.add_handler(WrapHandler())
        pipeline.add_handler(ReverseHandler())
        pipeline.send_inbound(b"foo")

        assert pipeline.outbound_queue == [b"(OOF)"]
