from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class SimpleString:
    string: bytes


@dataclass(frozen=True, kw_only=True)
class BulkString:
    string: bytes


@dataclass(frozen=True, kw_only=True)
class NullBulkString:
    pass


@dataclass(frozen=True, kw_only=True)
class Array:
    array: list[RespValue]


type RespValue = SimpleString | BulkString | NullBulkString | Array
