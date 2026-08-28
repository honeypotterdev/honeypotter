import logging
from typing import Any

from honeypotter.core import Context, Layer
from honeypotter.transport import ConnectionLostEvent, DataEvent

_logger = logging.getLogger(__name__)


class LoggingLayer(Layer):
    def __init__(self, context: Context) -> None:
        super().__init__(context)
        self._conversation: list[tuple[str, bytes]] = []

    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, ConnectionLostEvent):
            _logger.debug(
                "Connection lost. Conversation: %s, metadata: %s",
                repr(self._conversation),
                repr(self.ctx.metadata),
            )
            super().handle_inbound(event)
            return

        if isinstance(event, DataEvent):
            self._conversation.append(("inbound", event.data))

        super().handle_inbound(event)

    def handle_outbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._conversation.append(("outbound", event.data))

        super().handle_outbound(event)
