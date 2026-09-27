from dataclasses import dataclass
from enum import IntEnum


@dataclass(frozen=True, kw_only=True)
class ApplicationData:
    data: bytes

    def to_bytes(self) -> bytes:
        return self.data


class Verb(IntEnum):
    WILL = 251
    WONT = 252
    DO = 253
    DONT = 254


@dataclass(frozen=True, kw_only=True)
class Negotiation:
    verb: Verb
    option: int

    def to_bytes(self) -> bytes:
        return b"\xff" + self.verb.to_bytes() + self.option.to_bytes()
