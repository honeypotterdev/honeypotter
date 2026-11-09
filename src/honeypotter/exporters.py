import asyncio
import logging
from typing import Self

from httpx import AsyncClient
from pydantic import BaseModel
from pydantic_core import to_json

from honeypotter import __version__

_logger = logging.getLogger(__name__)


class JsonlExporter:
    def __init__(self, filename: str) -> None:
        self._filename = filename

    def __call__(self, model: BaseModel) -> None:
        with open(self._filename, "ab") as f:
            f.write(to_json(model.model_dump(), bytes_mode="base64") + b"\n")


class HttpJsonExporter:
    def __init__(self, *, url: str, headers: dict | None = None) -> None:
        self._url = url
        self._headers = headers or {}
        self._headers["Content-Type"] = "application/json"
        self._headers["User-Agent"] = f"honeypotter/{__version__}"

        self._client = AsyncClient(headers=headers)
        self._queue = asyncio.Queue[BaseModel | None]()
        self._worker_task = asyncio.create_task(self._worker())

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self.aclose()

    def export(self, model: BaseModel):
        self._queue.put_nowait(model)

    async def aclose(self) -> None:
        self._queue.put_nowait(None)

        _logger.debug("Closing exporter...")

        try:
            await asyncio.wait_for(self._worker_task, timeout=5.0)
        except TimeoutError:
            _logger.warning("Exporter drain timed out; abandoning remaining records")
        finally:
            await self._client.aclose()

    async def _worker(self) -> None:
        while True:
            model = await self._queue.get()

            if model is None:
                return

            try:
                await self._export(model)
            except Exception as e:  # noqa: BLE001
                _logger.error("Error while exporting: %s", e)
            finally:
                self._queue.task_done()

    async def _export(self, model: BaseModel) -> None:
        payload = to_json(model.model_dump(), bytes_mode="base64")

        r = await self._client.post(self._url, content=payload, headers=self._headers)
        r.raise_for_status()
