import asyncio
import base64
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from httpx import AsyncClient

from honeypotter.core import Context, Layer
from honeypotter.transport import ConnectionLostEvent, DataEvent

_logger = logging.getLogger(__name__)


@dataclass
class TelnetMessage:
    direction: Literal["inbound", "outbound"]
    offset: float
    data: bytes


@dataclass
class TelnetConnectionDetails:
    honeypot_ip: str
    honeypot_port: int
    client_ip: str
    client_port: int
    username: bytes | None
    password: bytes | None
    shell_inputs: list[bytes] | None
    conversation: list[TelnetMessage]
    created_at: datetime


class TelnetConnectionExporter:
    def __init__(self, *, api_key: str, url: str) -> None:
        self._client = AsyncClient(headers={"Authorization": f"Bearer {api_key}"})
        self._url = url
        self._queue = asyncio.Queue()
        self._worker_task = asyncio.create_task(self._worker())

    def layer_factory(self, context: Context) -> Layer:
        return TelnetConnectionExporterLayer(context, queue=self._queue)

    async def _worker(self) -> None:
        while True:
            details = await self._queue.get()

            try:
                await self._export(details)
            except Exception as e:  # noqa: BLE001
                _logger.error("Error while exporting Telnet connection: %s", e)
            finally:
                self._queue.task_done()

    async def _export(self, details: TelnetConnectionDetails) -> None:
        username = base64.b64encode(details.username).decode() if details.username is not None else None
        password = base64.b64encode(details.password).decode() if details.password is not None else None

        if details.shell_inputs is None:
            shell_inputs = []
        else:
            shell_inputs = [
                base64.b64encode(shell_input).decode() for shell_input in details.shell_inputs if shell_input.strip()
            ]

        r = await self._client.post(
            self._url,
            json={
                "honeypot": {"ip": details.honeypot_ip, "port": details.honeypot_port},
                "client": {"ip": details.client_ip},
                "username": username,
                "password": password,
                "shell_inputs": shell_inputs,
                "conversation": [
                    {
                        "direction": message.direction,
                        "offset": message.offset,
                        "data": base64.b64encode(message.data).decode(),
                    }
                    for message in details.conversation
                ],
                "created_at": details.created_at.isoformat(),
            },
        )
        r.raise_for_status()


class TelnetConnectionExporterLayer(Layer):
    def __init__(self, context: Context, queue: asyncio.Queue[TelnetConnectionDetails]) -> None:
        super().__init__(context)
        self._conversation: list[TelnetMessage] = []
        self._initial_time = time.monotonic()
        self._created_at = datetime.now(tz=UTC)
        self._last_direction: Literal["inbound", "outbound"] | None = None
        self._queue = queue

    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, ConnectionLostEvent):
            self._queue.put_nowait(
                TelnetConnectionDetails(
                    honeypot_ip=self.ctx.metadata["sockname"][0],
                    honeypot_port=self.ctx.metadata["sockname"][1],
                    client_ip=self.ctx.metadata["peername"][0],
                    client_port=self.ctx.metadata["peername"][1],
                    username=self.ctx.metadata.get("shell.username"),
                    password=self.ctx.metadata.get("shell.password"),
                    shell_inputs=self.ctx.metadata.get("shell.inputs"),
                    conversation=self._conversation,
                    created_at=self._created_at,
                )
            )

            super().handle_inbound(event)
            return

        if isinstance(event, DataEvent):
            self._record_data(direction="inbound", data=event.data)

        super().handle_inbound(event)

    def handle_outbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._record_data(direction="outbound", data=event.data)

        super().handle_outbound(event)

    def _record_data(self, direction: Literal["inbound", "outbound"], data: bytes) -> None:
        if self._last_direction is None or direction != self._last_direction:
            self._conversation.append(
                TelnetMessage(direction=direction, offset=time.monotonic() - self._initial_time, data=data)
            )
        else:
            self._conversation[-1].data += data

        self._last_direction = direction
