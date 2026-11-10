from dataclasses import dataclass

from honeypotter.redis.types import Value


class Event:
    pass


@dataclass(frozen=True, kw_only=True)
class ValueReceived(Event):
    value: Value


@dataclass(kw_only=True)
class ConnectionFailed(Event):
    pass
