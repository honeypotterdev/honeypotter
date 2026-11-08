from abc import ABC, abstractmethod

from pydantic import BaseModel
from pydantic_core import to_json


class Exporter(ABC):
    @abstractmethod
    def export(self, model: BaseModel): ...


class JsonlExporter(Exporter):
    def export(self, model: BaseModel):
        line = to_json(model.model_dump(), bytes_mode="base64")
        with open("export.jsonl", "wb+") as f:
            f.write(line + b"\n")
