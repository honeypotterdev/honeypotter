import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Annotated, Any, ClassVar, Literal

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


class NetworkEndpoint(BaseModel):
    ip: IPvAnyAddress
    port: int


class MqttConnectionRecord(BaseModel):
    model_config = ConfigDict(ser_json_bytes="base64")

    honeypot: NetworkEndpoint
    client: NetworkEndpoint
    events: list[EventDto]
    messages: list[TcpMessage]
    created_at: datetime


class MqttConnectionExporter:
    def __init__(self, *, api_key: str, url: str) -> None:
        self._client = AsyncClient(headers={"Authorization": f"Bearer {api_key}"})
        self._url = url
        self._queue = asyncio.Queue[MqttConnectionRecord]()
        self._worker_task = asyncio.create_task(self._worker())

    def handler_factory(self) -> Handler:
        return MqttConnectionExporterHandler(queue=self._queue)

    async def _worker(self) -> None:
        while True:
            record = await self._queue.get()

            try:
                await self._export(record)
            except Exception as e:  # noqa: BLE001
                _logger.error("Error while exporting MQTT connection: %s", e)
            finally:
                self._queue.task_done()

    async def _export(self, record: MqttConnectionRecord) -> None:
        r = await self._client.post(
            self._url, headers={"Content-Type": "application/json"}, content=record.model_dump_json()
        )
        r.raise_for_status()


class MqttConnectionExporterHandler(Handler):
    mapping: ClassVar[dict[type[Event], type[EventDto]]] = {
        ConnectReceived: ConnectReceivedDto,
        PublishReceived: PublishReceivedDto,
        SubscribeReceived: SubscribeReceivedDto,
        DisconnectReceived: DisconnectReceivedDto,
    }

    def __init__(self, queue: asyncio.Queue[MqttConnectionRecord]) -> None:
        super().__init__()

        self._messages: list[TcpMessage] = []
        self._initial_time = time.monotonic()
        self._created_at = datetime.now(tz=UTC)
        self._queue = queue

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        match event:
            case DataEvent():
                self._record_message(direction="inbound", data=event.data)
            case ConnectionLostEvent():
                self._enqueue_connection_record(context)

        super().handle_inbound(context, event)

    def handle_outbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, DataEvent):
            self._record_message(direction="outbound", data=event.data)

        super().handle_outbound(context, event)

    def _enqueue_connection_record(self, context: HandlerContext) -> None:
        if any(message.direction == "inbound" for message in self._messages):
            self._queue.put_nowait(
                MqttConnectionRecord(
                    honeypot=NetworkEndpoint(
                        ip=context.pipeline.metadata["sockname"][0], port=context.pipeline.metadata["sockname"][1]
                    ),
                    client=NetworkEndpoint(
                        ip=context.pipeline.metadata["peername"][0], port=context.pipeline.metadata["peername"][1]
                    ),
                    events=self._serialize_events(context.pipeline.metadata["mqtt.events"]),
                    messages=self._messages,
                    created_at=self._created_at,
                )
            )

    def _serialize_events(self, events: list[Event]) -> list[EventDto]:
        dtos = []

        for event in events:
            try:
                record_type = self.mapping[type(event)]
            except KeyError:
                continue

            dto = record_type(**event.model_dump())
            dtos.append(dto)

        return dtos

    def _record_message(self, direction: Literal["inbound", "outbound"], data: bytes) -> None:
        self._messages.append(TcpMessage(direction=direction, offset=time.monotonic() - self._initial_time, data=data))
