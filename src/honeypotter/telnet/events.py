from dataclasses import dataclass

from honeypotter.telnet.types import CommandCode, NegotiationVerb, Option, Side


class Event:
    pass


@dataclass(kw_only=True)
class ApplicationDataReceived(Event):
    data: bytes


@dataclass(kw_only=True)
class CommandReceived(Event):
    code: CommandCode


@dataclass(kw_only=True)
class NegotiationReceived(Event):
    verb: NegotiationVerb
    option: Option


@dataclass(kw_only=True)
class SubnegotiationReceived(Event):
    option: Option
    data: bytes


@dataclass(kw_only=True)
class OptionStateChanged(Event):
    option: Option
    side: Side
    enabled: bool


@dataclass(kw_only=True)
class ConnectionFailed(Event):
    pass
