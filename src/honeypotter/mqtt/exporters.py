import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Any, ClassVar, Literal

from httpx import AsyncClient
from pydantic import BaseModel, ConfigDict
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


type EventDto = ConnectReceivedDto | PublishReceivedDto | SubscribeReceivedDto | DisconnectReceivedDto


class MessageDto(BaseModel):
    model_config = ConfigDict(ser_json_bytes="base64")

    direction: Literal["inbound", "outbound"]
    offset: float
    data: bytes


class NetworkEndpoint(BaseModel):
    ip: IPvAnyAddress
    port: int


class MqttConnectionDto(BaseModel):
    model_config = ConfigDict(ser_json_bytes="base64")

    honeypot: NetworkEndpoint
    client: NetworkEndpoint
    events: list[EventDto]
    messages: list[MessageDto]
    created_at: datetime


class MqttConnectionExporter:
    def __init__(self, *, api_key: str, url: str) -> None:
        self._client = AsyncClient(headers={"Authorization": f"Bearer {api_key}"})
        self._url = url
        self._queue = asyncio.Queue[MqttConnectionDto]()
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

    async def _export(self, record: MqttConnectionDto) -> None:
        r = await self._client.post(
            self._url, headers={"Content-Type": "application/json"}, content=record.model_dump_json()
        )
        r.raise_for_status()


class MqttConnectionExporterHandler(Handler):
    _EVENT_TYPE_TO_DTO_TYPE: ClassVar[dict[type[Event], type[EventDto]]] = {
        ConnectReceived: ConnectReceivedDto,
        PublishReceived: PublishReceivedDto,
        SubscribeReceived: SubscribeReceivedDto,
        DisconnectReceived: DisconnectReceivedDto,
    }

    def __init__(self, queue: asyncio.Queue[MqttConnectionDto]) -> None:
        super().__init__()

        self._messages: list[MessageDto] = []
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
                MqttConnectionDto(
                    honeypot=NetworkEndpoint(
                        ip=context.pipeline.metadata["sockname"][0], port=context.pipeline.metadata["sockname"][1]
                    ),
                    client=NetworkEndpoint(
                        ip=context.pipeline.metadata["peername"][0], port=context.pipeline.metadata["peername"][1]
                    ),
                    events=self._to_event_dtos(context.pipeline.metadata.get("mqtt.events", [])),
                    messages=self._messages,
                    created_at=self._created_at,
                )
            )

    def _to_event_dtos(self, events: list[Event]) -> list[EventDto]:
        dtos = []

        for event in events:
            try:
                dto_type = self._EVENT_TYPE_TO_DTO_TYPE[type(event)]
            except KeyError:
                continue

            dto = dto_type(**event.model_dump())
            dtos.append(dto)

        return dtos

    def _record_message(self, direction: Literal["inbound", "outbound"], data: bytes) -> None:
        self._messages.append(MessageDto(direction=direction, offset=time.monotonic() - self._initial_time, data=data))
