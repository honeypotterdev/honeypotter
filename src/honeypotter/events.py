from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class ConnectionOpened:
    pass


@dataclass(frozen=True, kw_only=True)
class ConnectionClosed:
    reason: Exception | None = None


@dataclass(frozen=True, kw_only=True)
class DataReceived:
    data: bytes


@dataclass(frozen=True, kw_only=True)
class LineReceived:
    line: bytes
