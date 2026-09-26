import asyncio
import logging
from collections.abc import Callable

import click

from honeypotter.core import Handler
from honeypotter.handlers import InboundIdleTimeoutHandler, IpRateLimiter, LineDecoderHandler, TrafficLoggingHandler
from honeypotter.mqtt.handlers import MqttHandler
from honeypotter.redis.exporters import RedisConnectionExporter
from honeypotter.redis.handlers import RedisHandler
from honeypotter.shell.handlers import BusyboxShellHandler
from honeypotter.telnet.exporters import TelnetConnectionExporter
from honeypotter.telnet.legacy import TelnetCodecHandler, TelnetSessionHandler
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
@click.option("--api-key", type=str, envvar="HONEYPOTTER_API_KEY")
@click.option("--api-url", type=str, default="https://api.honeypotter.dev/telnet-connection")
def telnet(host: str, port: int, api_key: str | None, api_url: str) -> None:
    asyncio.run(_run_telnet_server(host=host, port=port, api_key=api_key, api_url=api_url))


async def _run_telnet_server(*, host: str, port: int, api_key: str | None, api_url: str) -> None:
    loop = asyncio.get_running_loop()

    _logger.info("Starting server on %s:%s", host, port)

    ip_rate_limiter = IpRateLimiter()

    handler_factories: list[Callable[..., Handler]] = [
        ip_rate_limiter.handler_factory,
        InboundIdleTimeoutHandler,
        TrafficLoggingHandler,
        TelnetCodecHandler,
        TelnetSessionHandler,
        LineDecoderHandler,
        BusyboxShellHandler,
    ]

    if api_key is not None:
        exporter = TelnetConnectionExporter(api_key=api_key, url=api_url)
        handler_factories.insert(2, exporter.handler_factory)

    _logger.debug("Handlers: %s", handler_factories)

    server = await loop.create_server(
        TransportProtocolFactory(handler_factories=handler_factories), host=host, port=port
    )

    async with server:
        await server.serve_forever()


@cli.command()
@click.option("-h", "--host", type=str, default="0.0.0.0")
@click.option("-p", "--port", type=int, default=6379)
@click.option("--api-key", type=str, envvar="HONEYPOTTER_API_KEY")
@click.option("--api-url", type=str, default="https://api.honeypotter.dev/redis-connection")
def redis(host: str, port: int, api_key: str | None, api_url: str) -> None:
    asyncio.run(_run_redis_server(host=host, port=port, api_key=api_key, api_url=api_url))


async def _run_redis_server(*, host: str, port: int, api_key: str | None, api_url: str) -> None:
    loop = asyncio.get_running_loop()

    _logger.info("Starting server on %s:%s", host, port)

    ip_rate_limiter = IpRateLimiter()

    handler_factories: list[Callable[..., Handler]] = [
        ip_rate_limiter.handler_factory,
        InboundIdleTimeoutHandler,
        TrafficLoggingHandler,
        RedisHandler,
    ]

    if api_key is not None:
        exporter = RedisConnectionExporter(api_key=api_key, url=api_url)
        handler_factories.insert(2, exporter.handler_factory)

    _logger.debug("Handlers: %s", handler_factories)

    server = await loop.create_server(
        TransportProtocolFactory(handler_factories=handler_factories), host=host, port=port
    )

    async with server:
        await server.serve_forever()


@cli.command()
@click.option("-h", "--host", type=str, default="0.0.0.0")
@click.option("-p", "--port", type=int, default=1883)
def mqtt(host: str, port: int) -> None:
    asyncio.run(_run_mqtt_server(host=host, port=port))


async def _run_mqtt_server(*, host: str, port: int) -> None:
    loop = asyncio.get_running_loop()

    _logger.info("Starting server on %s:%s", host, port)

    ip_rate_limiter = IpRateLimiter()

    handler_factories: list[Callable[..., Handler]] = [
        ip_rate_limiter.handler_factory,
        InboundIdleTimeoutHandler,
        TrafficLoggingHandler,
        MqttHandler,
    ]

    _logger.debug("Handlers: %s", handler_factories)

    server = await loop.create_server(
        TransportProtocolFactory(handler_factories=handler_factories), host=host, port=port
    )

    async with server:
        await server.serve_forever()
