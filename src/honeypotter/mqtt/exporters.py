import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from httpx import AsyncClient
from pydantic import BaseModel, ConfigDict, Field
from pydantic.networks import IPvAnyAddress

from honeypotter.core import Handler, HandlerContext
from honeypotter.mqtt.events import ConnectReceived, DisconnectReceived, Event, PublishReceived, SubscribeReceived
from honeypotter.transport import ConnectionLostEvent, DataEvent

_logger = logging.getLogger(__name__)


class ConnectReceivedDto(ConnectReceived):
    model_config = ConfigDict(ser_json_bytes="base64")

    event_type: Literal["connect"] = "connect"


class PublishReceivedDto(PublishReceived):
    model_config = ConfigDict(ser_json_bytes="base64")

    event_type: Literal["publish"] = "publish"


class SubscribeReceivedDto(SubscribeReceived):
    event_type: Literal["subscribe"] = "subscribe"


class DisconnectReceivedDto(DisconnectReceived):
    event_type: Literal["disconnect"] = "disconnect"


type EventDto = Annotated[
    ConnectReceivedDto | PublishReceivedDto | SubscribeReceivedDto | DisconnectReceivedDto,
    Field(discriminator="event_type"),
]


class TcpMessage(BaseModel):
    model_config = ConfigDict(ser_json_bytes="base64")

    direction: Literal["inbound", "outbound"]
    offset: float
    data: bytes


class Peer(BaseModel):
    ip: IPvAnyAddress
    port: int


class MqttConnectionDetails(BaseModel):
    model_config = ConfigDict(ser_json_bytes="base64")

    honeypot: Peer
    client: Peer
    events: list[EventDto]
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
        r = await self._client.post(self._url, content=details.model_dump_json())
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
                    honeypot=Peer(
                        ip=context.pipeline.metadata["sockname"][0], port=context.pipeline.metadata["sockname"][1]
                    ),
                    client=Peer(
                        ip=context.pipeline.metadata["peername"][0], port=context.pipeline.metadata["peername"][1]
                    ),
                    events=self._get_dtos(context.pipeline.metadata["mqtt.events"]),
                    messages=self._messages,
                    created_at=self._created_at,
                )
            )

    def _get_dtos(self, events: list[Event]) -> list[EventDto]:
        mapping = {
            ConnectReceived: ConnectReceivedDto,
            PublishReceived: PublishReceivedDto,
            SubscribeReceived: SubscribeReceivedDto,
            DisconnectReceived: DisconnectReceivedDto,
        }

        dtos = []

        for event in events:
            klass = mapping[type(event)]
            dto = klass(**event.model_dump())
            dtos.append(dto)

        return dtos

    def _record_message(self, direction: Literal["inbound", "outbound"], data: bytes) -> None:
        if self._last_direction is None or direction != self._last_direction:
            self._messages.append(
                TcpMessage(direction=direction, offset=time.monotonic() - self._initial_time, data=data)
            )
        else:
            self._messages[-1].data += data

        self._last_direction = direction
