import asyncio
import logging
from typing import Any

from honeypotter.core import Layer
from honeypotter.telnet import Telnet, TelnetCodec
from honeypotter.transport import TransportProtocolFactory

_logger = logging.getLogger(__name__)


class LoggingLayer(Layer):
    def handle_inbound(self, event: Any) -> None:
        _logger.debug(f"Handling inbound event: {event} from {self.ctx.metadata['peername']}")
        super().handle_inbound(event)

    def handle_outbound(self, event: Any) -> None:
        _logger.debug(f"Handling outbound event: {event} from {self.ctx.metadata['peername']}")
        super().handle_outbound(event)


async def run() -> None:
    loop = asyncio.get_running_loop()

    server = await loop.create_server(TransportProtocolFactory([LoggingLayer, TelnetCodec, Telnet]), "127.0.0.1", 2323)

    async with server:
        await server.serve_forever()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="{levelname} {asctime} {pathname}:{lineno} {message}", style="{")
    logging.getLogger("honeypotter").setLevel(logging.DEBUG)

    asyncio.run(run())
