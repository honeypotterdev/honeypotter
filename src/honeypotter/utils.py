from collections import UserDict
from typing import Any


class MetadataContainer(UserDict[str, Any]):
    def __getitem__(self, key: str) -> Any:
        if key not in self.data:
            self.data[key] = MetadataContainer()

        return super().__getitem__(key)
