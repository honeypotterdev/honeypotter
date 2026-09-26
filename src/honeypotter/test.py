from typing import Any

from honeypotter.core import Pipeline


class StubPipeline(Pipeline):
    def __init__(self) -> None:
        super().__init__()

        self.outbound_queue = []

    def handle_outbound(self, event: Any) -> None:
        self.outbound_queue.append(event)
