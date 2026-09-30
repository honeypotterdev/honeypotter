from enum import Enum, IntEnum, auto


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


class Option(DynamicIntEnum):
    ECHO = 1
    SGA = 3
    NAWS = 31


class NegotiationVerb(IntEnum):
    WILL = 251
    WONT = 252
    DO = 253
    DONT = 254


class Side(Enum):
    LOCAL = auto()
    REMOTE = auto()
