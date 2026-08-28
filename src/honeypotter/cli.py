import asyncio
import logging

import click

from honeypotter.decoders import LineDecoder
from honeypotter.layers import LoggingLayer, TimeoutLayer
from honeypotter.shell import ShellSession
from honeypotter.telnet import TelnetCodec, TelnetSession
from honeypotter.transport import TransportProtocolFactory

_logger = logging.getLogger(__name__)


@click.command()
@click.option("-h", "--host", type=str, default="0.0.0.0")
@click.option("-p", "--port", type=int, default=23)
@click.option("-v", "--verbose", count=True)
def cli(host: str, port: int, verbose: int) -> None:
    logging.basicConfig(level=logging.INFO, format="{levelname} {asctime} {name}:{lineno} {message}", style="{")
    logging.getLogger("honeypotter").setLevel(logging.DEBUG if verbose else logging.INFO)

    asyncio.run(_run(host, port))


async def _run(host: str, port: int) -> None:
    loop = asyncio.get_running_loop()

    _logger.info("Starting server on %s:%s", host, port)

    server = await loop.create_server(
        TransportProtocolFactory([TimeoutLayer, LoggingLayer, TelnetCodec, TelnetSession, LineDecoder, ShellSession]),
        host=host,
        port=port,
    )

    async with server:
        await server.serve_forever()
