import asyncio
import logging
from collections.abc import Callable
from contextlib import AsyncExitStack

import click

from honeypotter.core import Pipeline
from honeypotter.exporters import HttpJsonExporter
from honeypotter.handlers import InboundIdleTimeoutHandler, IpRateLimiter, LineDecoderHandler, MessageLoggingHandler
from honeypotter.mqtt.handlers import MqttHandler
from honeypotter.mqtt.recorders import MqttRecorder
from honeypotter.redis.handlers import RedisHandler
from honeypotter.redis.recorders import RedisRecorder
from honeypotter.shell.handlers import BusyboxShellHandler
from honeypotter.shell.recorders import ShellRecorder
from honeypotter.tcp.handlers import TcpHandler
from honeypotter.tcp.recorders import TcpRecorder
from honeypotter.telnet.handlers import TelnetHandler
from honeypotter.transport import TransportProtocolFactory

_logger = logging.getLogger(__name__)


def _parse_export_headers(ctx: click.Context, param: click.Parameter, values: tuple[str, ...]) -> dict[str, str]:
    headers: dict[str, str] = {}

    for raw in values:
        name, separator, value = raw.partition(":")
        if not separator:
            raise click.BadParameter("Expected 'Name: value'.", ctx=ctx, param=param)

        headers[name.lower()] = value.strip()

    return headers


async def _run_server(
    *, stack: AsyncExitStack, host: str, port: int, pipeline_initializer: Callable[[Pipeline], None]
) -> None:
    loop = asyncio.get_running_loop()

    _logger.info("Starting server on %s:%s", host, port)

    ip_rate_limiter = IpRateLimiter()

    def initialize(pipeline: Pipeline) -> None:
        pipeline_initializer(pipeline)
        pipeline.add_first("message_logging", MessageLoggingHandler())
        pipeline.add_first("inbound_idle_timeout", InboundIdleTimeoutHandler())
        pipeline.add_first("ip_rate_limiter", ip_rate_limiter.handler_factory())

    server = await loop.create_server(TransportProtocolFactory(initialize), host=host, port=port)
    await stack.enter_async_context(server)

    # The stack unwinds in reverse order: stop accepting, close clients,
    # wait for their final records, then drain and close the exporter.
    stack.callback(server.close_clients)
    stack.callback(server.close)

    # create_server() already accepts connections. Cancellation of this wait
    # lets the stack close clients before the server waits for them to finish.
    await asyncio.Event().wait()


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
@click.option("-p", "--port", type=int, required=True)
@click.option("--export-url", type=str)
@click.option(
    "--export-header", "export_headers", type=str, multiple=True, callback=_parse_export_headers, metavar="NAME:VALUE"
)
def tcp(host: str, port: int, export_url: str | None, export_headers: dict[str, str]) -> None:
    asyncio.run(_run_tcp_server(host=host, port=port, export_url=export_url, export_headers=export_headers))


async def _run_tcp_server(*, host: str, port: int, export_url: str | None, export_headers: dict[str, str]) -> None:
    async with AsyncExitStack() as stack:
        exporter = None

        if export_url is not None:
            exporter = await stack.enter_async_context(HttpJsonExporter(url=export_url, headers=export_headers))

        def pipeline_initializer(pipeline: Pipeline) -> None:
            pipeline.add_last("tcp", TcpHandler())

            if exporter is not None:
                pipeline.add_last("tcp_recorder", TcpRecorder(exporter=exporter.export))

        await _run_server(stack=stack, host=host, port=port, pipeline_initializer=pipeline_initializer)


@cli.command()
@click.option("-h", "--host", type=str, default="0.0.0.0")
@click.option("-p", "--port", type=int, default=23)
@click.option("--export-url", type=str)
@click.option(
    "--export-header", "export_headers", type=str, multiple=True, callback=_parse_export_headers, metavar="NAME:VALUE"
)
def telnet(host: str, port: int, export_url: str | None, export_headers: dict[str, str]) -> None:
    asyncio.run(_run_telnet_server(host=host, port=port, export_url=export_url, export_headers=export_headers))


async def _run_telnet_server(*, host: str, port: int, export_url: str | None, export_headers: dict[str, str]) -> None:
    async with AsyncExitStack() as stack:
        exporter = None

        if export_url is not None:
            exporter = await stack.enter_async_context(HttpJsonExporter(url=export_url, headers=export_headers))

        def pipeline_initializer(pipeline: Pipeline) -> None:
            pipeline.add_last("telnet", TelnetHandler())
            pipeline.add_last("line_decoder", LineDecoderHandler())
            pipeline.add_last("busybox_shell", BusyboxShellHandler())

            if exporter is not None:
                pipeline.add_last(
                    "shell_recorder", ShellRecorder(capture_messages_before="telnet", exporter=exporter.export)
                )

        await _run_server(stack=stack, host=host, port=port, pipeline_initializer=pipeline_initializer)


@cli.command()
@click.option("-h", "--host", type=str, default="0.0.0.0")
@click.option("-p", "--port", type=int, default=6379)
@click.option("--export-url", type=str)
@click.option(
    "--export-header", "export_headers", type=str, multiple=True, callback=_parse_export_headers, metavar="NAME:VALUE"
)
def redis(host: str, port: int, export_url: str | None, export_headers: dict[str, str]) -> None:
    asyncio.run(_run_redis_server(host=host, port=port, export_url=export_url, export_headers=export_headers))


async def _run_redis_server(*, host: str, port: int, export_url: str | None, export_headers: dict[str, str]) -> None:
    async with AsyncExitStack() as stack:
        exporter = None

        if export_url is not None:
            exporter = await stack.enter_async_context(HttpJsonExporter(url=export_url, headers=export_headers))

        def pipeline_initializer(pipeline: Pipeline) -> None:
            pipeline.add_last("redis", RedisHandler())

            if exporter is not None:
                pipeline.add_last(
                    "redis_recorder", RedisRecorder(capture_messages_before="redis", exporter=exporter.export)
                )

        await _run_server(stack=stack, host=host, port=port, pipeline_initializer=pipeline_initializer)


@cli.command()
@click.option("-h", "--host", type=str, default="0.0.0.0")
@click.option("-p", "--port", type=int, default=1883)
@click.option("--export-url", type=str)
@click.option(
    "--export-header", "export_headers", type=str, multiple=True, callback=_parse_export_headers, metavar="NAME:VALUE"
)
def mqtt(host: str, port: int, export_url: str | None, export_headers: dict[str, str]) -> None:
    asyncio.run(_run_mqtt_server(host=host, port=port, export_url=export_url, export_headers=export_headers))


async def _run_mqtt_server(*, host: str, port: int, export_url: str | None, export_headers: dict[str, str]) -> None:
    async with AsyncExitStack() as stack:
        exporter = None

        if export_url is not None:
            exporter = await stack.enter_async_context(HttpJsonExporter(url=export_url, headers=export_headers))

        def pipeline_initializer(pipeline: Pipeline) -> None:
            pipeline.add_last("mqtt", MqttHandler())

            if exporter is not None:
                pipeline.add_last(
                    "mqtt_recorder", MqttRecorder(capture_messages_before="mqtt", exporter=exporter.export)
                )

        await _run_server(stack=stack, host=host, port=port, pipeline_initializer=pipeline_initializer)
