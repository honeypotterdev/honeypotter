from enum import Enum, auto
from typing import Any

from honeypotter.statemachine import Machine, MachineError, Transition
from honeypotter.telnet.events import (
    ApplicationDataReceived,
    CommandReceived,
    ConnectionFailed,
    Event,
    NegotiationReceived,
    SubnegotiationReceived,
)
from honeypotter.telnet.types import (
    CommandCode,
    NegotiationOption,
    NegotiationVerb,
)


class State(Enum):
    READ_APPLICATION_DATA = auto()
    IAC = auto()
    READ_COMMAND = auto()
    READ_NEGOTIATION_OPTION = auto()
    READ_SUBNEGOTIATION_OPTION = auto()
    READ_SUBNEGOTIATION_DATA = auto()
    READ_SUBNEGOTIATION_IAC = auto()


class TelnetConnection:
    def __init__(self) -> None:
        self._data_to_send_buffer = bytearray()
        self._app_buffer = bytearray()
        self._subnegotiation_buffer = bytearray()
        self._event_buffer = []
        self._negotiation_verb = 0
        self._subnegotiation_option = 0
        self._is_failed = False

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

    def data_to_send(self) -> bytes:
        data = bytes(self._data_to_send_buffer)
        self._data_to_send_buffer.clear()

        return data

    def send_application_data(self, data: bytes) -> None:
        self._data_to_send_buffer.extend(data.replace(b"\xff", b"\xff\xff"))

    def send_command(self, code: int) -> None:
        self._data_to_send_buffer.extend(b"\xff" + code.to_bytes())

    def send_negotiation(self, verb: int, option: NegotiationOption) -> None:
        self._data_to_send_buffer.extend(b"\xff" + verb.to_bytes() + option.to_bytes())

    def send_subnegotiation(self, option: int, data: bytes) -> None:
        self._data_to_send_buffer.extend(
            b"\xff\xfa" + option.to_bytes() + data.replace(b"\xff", b"\xff\xff") + b"\xff\xf0"
        )

    def receive_data(self, data: bytes) -> list[Event]:
        if self._is_failed:
            return []

        for byte in data:
            try:
                event = self._machine.trigger("byte", byte)
            except MachineError:
                self._is_failed = True
                events = self._event_buffer + [ConnectionFailed()]
                self._event_buffer = []
                return events

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
            self._event_buffer.append(ApplicationDataReceived(data=bytes(self._app_buffer)))
            self._app_buffer.clear()

    def _app_buffer_append(self, byte: int) -> None:
        self._app_buffer.append(byte)

    def _subnegotiation_buffer_append(self, byte: int) -> None:
        self._subnegotiation_buffer.append(byte)

    def _store_verb(self, byte: int) -> None:
        self._negotiation_verb = byte

    def _store_subnegotiation_option(self, byte) -> None:
        self._subnegotiation_option = byte

    def _finalize_command(self, byte: int) -> CommandReceived:
        return CommandReceived(code=CommandCode(byte))

    def _finalize_negotiation(self, byte: int) -> NegotiationReceived:
        negotiation = NegotiationReceived(verb=NegotiationVerb(self._negotiation_verb), option=NegotiationOption(byte))
        self._negotiation_verb = 0

        return negotiation

    def _finalize_subnegotiation(self, byte: int) -> SubnegotiationReceived:
        subnegotiation = SubnegotiationReceived(
            option=NegotiationOption(self._subnegotiation_option), data=bytes(self._subnegotiation_buffer)
        )
        self._subnegotiation_option = 0
        self._subnegotiation_buffer.clear()

        return subnegotiation
