from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class WriteData:
    data: bytes


@dataclass(frozen=True, kw_only=True)
class CloseConnection:
    pass
