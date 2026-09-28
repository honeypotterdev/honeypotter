from dataclasses import dataclass

from honeypotter.telnet.types import CommandCode, NegotiationOption, NegotiationVerb, Side


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
    option: NegotiationOption


@dataclass(kw_only=True)
class SubnegotiationReceived(Event):
    option: NegotiationOption
    data: bytes


@dataclass(kw_only=True)
class OptionStateChanged(Event):
    option: NegotiationOption
    side: Side
    enabled: bool


class ConnectionFailed(Event):
    pass
