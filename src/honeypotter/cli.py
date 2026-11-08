import asyncio
import logging

import click

from honeypotter.core import Pipeline
from honeypotter.handlers import InboundIdleTimeoutHandler, IpRateLimiter, LineDecoderHandler, MessageLoggingHandler
from honeypotter.mqtt.exporters import MqttConnectionExporter
from honeypotter.mqtt.handlers import MqttHandler
from honeypotter.redis.exporters import RedisConnectionExporter
from honeypotter.redis.handlers import RedisHandler
from honeypotter.shell.handlers import BusyboxShellHandler
from honeypotter.shell.recorders import ShellRecorder
from honeypotter.telnet.handlers import TelnetHandler
from honeypotter.transport import TransportProtocolFactory

_logger = logging.getLogger(__name__)


@click.group()
@click.option("-v", "--verbose", count=True)
@click.option("--sentry-dsn", type=str, envvar="SENTRY_DSN")
def cli(verbose: int, sentry_dsn: str | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="{levelname} {asctime} {name}:{lineno} {message}", style="{")
    logging.getLogger("honeypotter").setLevel(logging.DEBUG if verbose else logging.INFO)

    if sentry_dsn is not None:
        import sentry_sdk

        sentry_sdk.init(dsn=sentry_dsn, enable_logs=True)


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

    def pipeline_initializer(pipeline: Pipeline) -> None:
        pipeline.add_last("ip_rate_limiter", ip_rate_limiter.handler_factory())
        pipeline.add_last("inbound_idle_timeout", InboundIdleTimeoutHandler())
        pipeline.add_last("message_logging", MessageLoggingHandler())
        pipeline.add_last("telnet", TelnetHandler())
        pipeline.add_last("line_decoder", LineDecoderHandler())
        pipeline.add_last("busybox_shell", BusyboxShellHandler())
        pipeline.add_last("shell_recorder", ShellRecorder(capture_messages_before="telnet"))

    server = await loop.create_server(TransportProtocolFactory(pipeline_initializer), host=host, port=port)

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

    def pipeline_initializer(pipeline: Pipeline) -> None:
        pipeline.add_last("ip_rate_limiter", ip_rate_limiter.handler_factory())
        pipeline.add_last("inbound_idle_timeout", InboundIdleTimeoutHandler())
        pipeline.add_last("message_logging", MessageLoggingHandler())

        if api_key is not None:
            exporter = RedisConnectionExporter(api_key=api_key, url=api_url)
            pipeline.add_last("redis:exporter", exporter.handler_factory())

        pipeline.add_last("redis", RedisHandler())

    server = await loop.create_server(TransportProtocolFactory(pipeline_initializer), host=host, port=port)

    async with server:
        await server.serve_forever()


@cli.command()
@click.option("-h", "--host", type=str, default="0.0.0.0")
@click.option("-p", "--port", type=int, default=1883)
@click.option("--api-key", type=str, envvar="HONEYPOTTER_API_KEY")
@click.option("--api-url", type=str, default="https://api.honeypotter.dev/mqtt-connection")
def mqtt(host: str, port: int, api_key: str | None, api_url: str) -> None:
    asyncio.run(_run_mqtt_server(host=host, port=port, api_key=api_key, api_url=api_url))


async def _run_mqtt_server(*, host: str, port: int, api_key: str | None, api_url: str) -> None:
    loop = asyncio.get_running_loop()

    _logger.info("Starting server on %s:%s", host, port)

    ip_rate_limiter = IpRateLimiter()

    def pipeline_initializer(pipeline: Pipeline) -> None:
        pipeline.add_last("ip_rate_limit", ip_rate_limiter.handler_factory())
        pipeline.add_last("inbound_idle_timeout", InboundIdleTimeoutHandler())
        pipeline.add_last("message_logging", MessageLoggingHandler())

        if api_key is not None:
            exporter = MqttConnectionExporter(api_key=api_key, url=api_url)
            pipeline.add_last("mqtt:exporter", exporter.handler_factory())

        pipeline.add_last("mqtt", MqttHandler())

    server = await loop.create_server(TransportProtocolFactory(pipeline_initializer), host=host, port=port)

    async with server:
        await server.serve_forever()
