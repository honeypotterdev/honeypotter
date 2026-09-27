from dataclasses import dataclass
from enum import IntEnum


class Verb(IntEnum):
    WILL = 251
    WONT = 252
    DO = 253
    DONT = 254


class Option(IntEnum):
    ECHO = 1

    @classmethod
    def _missing_(cls, value: object) -> int | None:
        if not isinstance(value, int) or not 0 <= value <= 255:
            return None

        pseudo_member = int.__new__(cls, value)
        pseudo_member._value_ = value
        pseudo_member._name_ = f"UNKNOWN_{value}"
        cls._value2member_map_[value] = pseudo_member

        return pseudo_member


@dataclass(frozen=True, kw_only=True)
class ApplicationData:
    data: bytes

    def to_bytes(self) -> bytes:
        return self.data


@dataclass(frozen=True, kw_only=True)
class Negotiation:
    verb: Verb
    option: Option

    def to_bytes(self) -> bytes:
        return b"\xff" + self.verb.to_bytes() + self.option.to_bytes()


@dataclass(frozen=True, kw_only=True)
class Subnegotiation:
    data: bytes

    def to_bytes(self) -> bytes:
        return b"\xff\xfa" + self.data + b"\xff\xf0"
