from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

from honeypotter.statemachine import Machine, Transition
from honeypotter.telnet.values import (
    ApplicationData,
    Command,
    CommandCode,
    Negotiation,
    NegotiationOption,
    NegotiationVerb,
    Subnegotiation,
    Value,
)


class State(Enum):
    READ_APPLICATION_DATA = auto()
    IAC = auto()
    READ_COMMAND = auto()
    READ_NEGOTIATION_OPTION = auto()
    READ_SUBNEGOTIATION_OPTION = auto()
    READ_SUBNEGOTIATION_DATA = auto()
    READ_SUBNEGOTIATION_IAC = auto()


@dataclass(frozen=True, kw_only=True)
class ProtocolErrorOccurred:
    pass


type ConnectionEvent = Value | ProtocolErrorOccurred


class TelnetConnection:
    def __init__(self) -> None:
        self._app_buffer = bytearray()
        self._subnegotiation_buffer = bytearray()
        self._event_buffer = []
        self._negotiation_verb = 0
        self._subnegotiation_option = 0

        self._machine = Machine(
            model=self,
            initial=State.READ_APPLICATION_DATA,
            transitions=[
                Transition("byte", State.READ_APPLICATION_DATA, State.IAC, condition="_is_iac"),
                Transition(
                    "byte", State.READ_APPLICATION_DATA, State.READ_APPLICATION_DATA, action="_app_buffer_append"
                ),
                Transition(
                    "byte", State.IAC, State.READ_APPLICATION_DATA, condition="_is_iac", action="_app_buffer_append"
                ),
                Transition(
                    "byte",
                    State.IAC,
                    State.READ_NEGOTIATION_OPTION,
                    condition="_is_verb",
                    action="_store_verb",
                    before="_flush_app_buffer",
                ),
                Transition(
                    "byte", State.IAC, State.READ_SUBNEGOTIATION_OPTION, condition="_is_sb", before="_flush_app_buffer"
                ),
                Transition(
                    "byte",
                    State.IAC,
                    State.READ_APPLICATION_DATA,
                    action="_finalize_command",
                    before="_flush_app_buffer",
                ),
                Transition(
                    "byte", State.READ_NEGOTIATION_OPTION, State.READ_APPLICATION_DATA, action="_finalize_negotiation"
                ),
                Transition(
                    "byte",
                    State.READ_SUBNEGOTIATION_OPTION,
                    State.READ_SUBNEGOTIATION_DATA,
                    action="_store_subnegotiation_option",
                ),
                Transition("byte", State.READ_SUBNEGOTIATION_DATA, State.READ_SUBNEGOTIATION_IAC, condition="_is_iac"),
                Transition(
                    "byte",
                    State.READ_SUBNEGOTIATION_DATA,
                    State.READ_SUBNEGOTIATION_DATA,
                    action="_subnegotiation_buffer_append",
                ),
                Transition(
                    "byte",
                    State.READ_SUBNEGOTIATION_IAC,
                    State.READ_SUBNEGOTIATION_DATA,
                    condition="_is_iac",
                    action="_subnegotiation_buffer_append",
                ),
                Transition(
                    "byte",
                    State.READ_SUBNEGOTIATION_IAC,
                    State.READ_APPLICATION_DATA,
                    condition="_is_se",
                    action="_finalize_subnegotiation",
                ),
            ],
        )

    def send_application_data(self, data: bytes) -> bytes:
        return ApplicationData(data=data).to_bytes()

    def send_command(self, code: CommandCode) -> bytes:
        return Command(code=code).to_bytes()

    def send_negotiation(self, verb: NegotiationVerb, option: NegotiationOption) -> bytes:
        return Negotiation(verb=verb, option=option).to_bytes()

    def send_subnegotiation(self, option: int, data: bytes) -> bytes:
        return Subnegotiation(option=NegotiationOption(option), data=data).to_bytes()

    def receive_data(self, data: bytes) -> list[ConnectionEvent]:
        for byte in data:
            event = self._machine.trigger("byte", byte)

            if event is not None:
                self._event_buffer.append(event)

        self._flush_app_buffer()

        events = self._event_buffer
        self._event_buffer = []

        return events

    def _is_iac(self, byte: int) -> bool:
        return byte == 255

    def _is_sb(self, byte: int) -> bool:
        return byte == 250

    def _is_se(self, byte: int) -> bool:
        return byte == 240

    def _is_verb(self, byte: int) -> bool:
        return NegotiationVerb.WILL <= byte <= NegotiationVerb.DONT

    def _flush_app_buffer(self, *_args: Any, **_kwargs: Any) -> None:
        if self._app_buffer:
            self._event_buffer.append(ApplicationData(data=bytes(self._app_buffer)))
            self._app_buffer.clear()

    def _app_buffer_append(self, byte: int) -> None:
        self._app_buffer.append(byte)

    def _subnegotiation_buffer_append(self, byte: int) -> None:
        self._subnegotiation_buffer.append(byte)

    def _store_verb(self, byte: int) -> None:
        self._negotiation_verb = byte

    def _store_subnegotiation_option(self, byte) -> None:
        self._subnegotiation_option = byte

    def _finalize_command(self, byte: int) -> Command:
        return Command(code=CommandCode(byte))

    def _finalize_negotiation(self, byte: int) -> Negotiation:
        negotiation = Negotiation(verb=NegotiationVerb(self._negotiation_verb), option=NegotiationOption(byte))
        self._negotiation_verb = 0

        return negotiation

    def _finalize_subnegotiation(self, byte: int) -> Subnegotiation:
        subnegotiation = Subnegotiation(
            option=NegotiationOption(self._subnegotiation_option), data=bytes(self._subnegotiation_buffer)
        )
        self._subnegotiation_option = 0
        self._subnegotiation_buffer.clear()

        return subnegotiation
