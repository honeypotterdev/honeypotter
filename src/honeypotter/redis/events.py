from dataclasses import dataclass


class Event:
    pass


@dataclass(kw_only=True)
class SimpleStringReceived(Event):
    string: bytes


@dataclass(kw_only=True)
class BulkStringReceived(Event):
    string: bytes


@dataclass(kw_only=True)
class NullBulkStringReceived(Event):
    pass


@dataclass(kw_only=True)
class ArrayReceived(Event):
    array: list[SimpleStringReceived | BulkStringReceived | NullBulkStringReceived]


@dataclass(kw_only=True)
class ConnectionFailed(Event):
    pass
