import asyncio
import logging

from honeypotter.decoders import LineDecoder
from honeypotter.shell import ShellSession
from honeypotter.telnet import TelnetCodec, TelnetSession
from honeypotter.transport import TransportProtocolFactory

_logger = logging.getLogger(__name__)


async def run() -> None:
    loop = asyncio.get_running_loop()

    server = await loop.create_server(
        TransportProtocolFactory(
            [
                TelnetCodec,
                TelnetSession,
                LineDecoder,
                ShellSession,
            ]
        ),
        "127.0.0.1",
        2323,
    )

    async with server:
        await server.serve_forever()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="{levelname} {asctime} {name}:{lineno} {message}", style="{")
    logging.getLogger("honeypotter").setLevel(logging.DEBUG)

    asyncio.run(run())
