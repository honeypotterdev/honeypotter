import asyncio
import logging
from collections.abc import Callable

import click

from honeypotter.core import Context, Layer
from honeypotter.decoders import LineDecoder
from honeypotter.exporters import TelnetConnectionExporter
from honeypotter.layers import InboundIdleTimeoutLayer, IpRateLimiter, TrafficLoggingLayer
from honeypotter.redis import RedisCodec
from honeypotter.shell import ShellSession
from honeypotter.telnet import TelnetCodec, TelnetSession
from honeypotter.transport import TransportProtocolFactory

_logger = logging.getLogger(__name__)


@click.group()
@click.option("-v", "--verbose", count=True)
def cli(verbose: int) -> None:
    logging.basicConfig(level=logging.INFO, format="{levelname} {asctime} {name}:{lineno} {message}", style="{")
    logging.getLogger("honeypotter").setLevel(logging.DEBUG if verbose else logging.INFO)


@cli.command()
@click.option("-h", "--host", type=str, default="0.0.0.0")
@click.option("-p", "--port", type=int, default=23)
@click.option("--backend-api-key", type=str, envvar="HONEYPOTTER_API_KEY")
@click.option("--backend-url", type=str, default="https://api.honeypotter.dev/telnet-connection")
def telnet(host: str, port: int, backend_api_key: str | None, backend_url: str) -> None:
    asyncio.run(_run_telnet_server(host=host, port=port, backend_api_key=backend_api_key, backend_url=backend_url))


async def _run_telnet_server(*, host: str, port: int, backend_api_key: str | None, backend_url: str) -> None:
    loop = asyncio.get_running_loop()

    _logger.info("Starting server on %s:%s", host, port)

    ip_rate_limiter = IpRateLimiter()

    layer_factories: list[Callable[[Context], Layer]] = [
        ip_rate_limiter.layer_factory,
        InboundIdleTimeoutLayer,
        TrafficLoggingLayer,
        TelnetCodec,
        TelnetSession,
        LineDecoder,
        ShellSession,
    ]

    if backend_api_key is not None:
        exporter = TelnetConnectionExporter(api_key=backend_api_key, url=backend_url)
        layer_factories.insert(1, exporter.layer_factory)

    _logger.debug("Layers: %s", layer_factories)

    server = await loop.create_server(TransportProtocolFactory(layer_factories=layer_factories), host=host, port=port)

    async with server:
        await server.serve_forever()


@cli.command()
@click.option("-h", "--host", type=str, default="0.0.0.0")
@click.option("-p", "--port", type=int, default=6379)
def redis(host: str, port: int) -> None:
    asyncio.run(_run_redis_server(host=host, port=port))


async def _run_redis_server(*, host: str, port: int) -> None:
    loop = asyncio.get_running_loop()

    _logger.info("Starting server on %s:%s", host, port)

    layer_factories: list[Callable[[Context], Layer]] = [TrafficLoggingLayer, RedisCodec]

    _logger.debug("Layers: %s", layer_factories)

    server = await loop.create_server(TransportProtocolFactory(layer_factories=layer_factories), host=host, port=port)

    async with server:
        await server.serve_forever()
