from dataclasses import dataclass

from honeypotter.telnet.types import CommandCode, NegotiationOption, NegotiationVerb


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


class ConnectionFailed(Event):
    pass
