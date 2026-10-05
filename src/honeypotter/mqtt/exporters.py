import asyncio
import base64
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from httpx import AsyncClient

from honeypotter.core import Handler, HandlerContext
from honeypotter.mqtt.events import Event
from honeypotter.transport import ConnectionLostEvent, DataEvent

_logger = logging.getLogger(__name__)


@dataclass
class TcpMessage:
    direction: Literal["inbound", "outbound"]
    offset: float
    data: bytes


@dataclass
class MqttConnectionDetails:
    honeypot_ip: str
    honeypot_port: int
    client_ip: str
    client_port: int
    events: list[Event]
    messages: list[TcpMessage]
    created_at: datetime


class MqttConnectionExporter:
    def __init__(self, *, api_key: str, url: str) -> None:
        self._client = AsyncClient(headers={"Authorization": f"Bearer {api_key}"})
        self._url = url
        self._queue = asyncio.Queue[MqttConnectionDetails]()
        self._worker_task = asyncio.create_task(self._worker())

    def handler_factory(self) -> Handler:
        return MqttConnectionExporterHandler(queue=self._queue)

    async def _worker(self) -> None:
        while True:
            details = await self._queue.get()

            try:
                await self._export(details)
            except Exception as e:  # noqa: BLE001
                _logger.error("Error while exporting MQTT connection: %s", e)
            finally:
                self._queue.task_done()

    async def _export(self, details: MqttConnectionDetails) -> None:
        r = await self._client.post(
            self._url,
            json={
                "honeypot": {"ip": details.honeypot_ip, "port": details.honeypot_port},
                "client": {"ip": details.client_ip},
                "events": [event.model_dump_json() for event in details.events],
                "messages": [
                    {
                        "direction": message.direction,
                        "offset": message.offset,
                        "data": base64.b64encode(message.data).decode(),
                    }
                    for message in details.messages
                ],
                "created_at": details.created_at.isoformat(),
            },
        )
        r.raise_for_status()


class MqttConnectionExporterHandler(Handler):
    def __init__(self, queue: asyncio.Queue[MqttConnectionDetails]) -> None:
        super().__init__()

        self._messages: list[TcpMessage] = []
        self._initial_time = time.monotonic()
        self._created_at = datetime.now(tz=UTC)
        self._last_direction: Literal["inbound", "outbound"] | None = None
        self._queue = queue

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case DataEvent():
                self._record_message(direction="inbound", data=event.data)
            case ConnectionLostEvent():
                self._finalize_messages(context)

        super().handle_inbound(context, event)

    def handle_outbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._record_message(direction="outbound", data=event.data)

        super().handle_outbound(context, event)

    def _finalize_messages(self, context: HandlerContext) -> None:
        if any(message.direction == "inbound" for message in self._messages):
            self._queue.put_nowait(
                MqttConnectionDetails(
                    honeypot_ip=context.pipeline.metadata["sockname"][0],
                    honeypot_port=context.pipeline.metadata["sockname"][1],
                    client_ip=context.pipeline.metadata["peername"][0],
                    client_port=context.pipeline.metadata["peername"][1],
                    events=context.pipeline.metadata["mqtt.events"],
                    messages=self._messages,
                    created_at=self._created_at,
                )
            )

    def _record_message(self, direction: Literal["inbound", "outbound"], data: bytes) -> None:
        if self._last_direction is None or direction != self._last_direction:
            self._messages.append(
                TcpMessage(direction=direction, offset=time.monotonic() - self._initial_time, data=data)
            )
        else:
            self._messages[-1].data += data

        self._last_direction = direction
