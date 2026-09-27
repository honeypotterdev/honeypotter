from dataclasses import dataclass
from enum import IntEnum


class DynamicIntEnum(IntEnum):
    @classmethod
    def _missing_(cls, value: object) -> int | None:
        if not isinstance(value, int) or not 0 <= value <= 255:
            return None

        pseudo_member = int.__new__(cls, value)
        pseudo_member._value_ = value
        pseudo_member._name_ = f"UNKNOWN_{value}"
        cls._value2member_map_[value] = pseudo_member

        return pseudo_member


class CommandCode(DynamicIntEnum):
    BRK = 243  # Break
    AO = 245  # Abort Output
    AYT = 246  # Are You There
    EC = 247  # Escape Character
    EL = 248  # Erase Line


class NegotiationOption(DynamicIntEnum):
    ECHO = 1
    SGA = 3
    NAWS = 31


class NegotiationVerb(IntEnum):
    WILL = 251
    WONT = 252
    DO = 253
    DONT = 254


@dataclass(frozen=True, kw_only=True)
class ApplicationData:
    data: bytes

    def to_bytes(self) -> bytes:
        encoded = bytearray()

        for byte in self.data:
            if byte == 255:
                encoded.extend(b"\xff\xff")
            else:
                encoded.append(byte)

        return bytes(encoded)


@dataclass(frozen=True, kw_only=True)
class Command:
    code: CommandCode

    def to_bytes(self) -> bytes:
        return b"\xff" + self.code.to_bytes()


@dataclass(frozen=True, kw_only=True)
class Negotiation:
    verb: NegotiationVerb
    option: NegotiationOption

    def to_bytes(self) -> bytes:
        return b"\xff" + self.verb.to_bytes() + self.option.to_bytes()


@dataclass(frozen=True, kw_only=True)
class Subnegotiation:
    option: NegotiationOption
    data: bytes

    def to_bytes(self) -> bytes:
        return b"\xff\xfa" + self.option.to_bytes() + self.data.replace(b"\xff", b"\xff\xff") + b"\xff\xf0"
