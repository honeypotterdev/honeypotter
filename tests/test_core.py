from honeypotter.core import Handler, HandlerContext
from honeypotter.test import StubPipeline


class UppercaseHandler(Handler):
    def handle_inbound(self, context: HandlerContext, event: bytes) -> None:
        context.send_inbound(event.upper())


class WrapHandler(Handler):
    def handle_outbound(self, context: HandlerContext, event: bytes) -> None:
        context.send_outbound(b"(" + event + b")")


class ReverseHandler(Handler):
    def handle_inbound(self, context: HandlerContext, event: bytes) -> None:
        context.send_outbound(bytes(reversed(event)))


class TestPipeline:
    def test(self) -> None:
        pipeline = StubPipeline()
        pipeline.add_last("uppercase", UppercaseHandler())
        pipeline.add_last("wrap", WrapHandler())
        pipeline.add_last("reverse", ReverseHandler())
        pipeline.send_inbound(b"foo")

        assert pipeline.outbound_queue == [b"(OOF)"]
