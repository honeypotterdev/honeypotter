from enum import Enum, auto
from typing import Any

from honeypotter.statemachine import Machine, Transition
from honeypotter.telnet.values import ApplicationData, Negotiation, Option, Subnegotiation, Verb


class State(Enum):
    READ_APPLICATION_DATA = auto()
    READ_COMMAND = auto()
    READ_NEGOTIATION = auto()
    READ_SUBNEGOTIATION = auto()
    READ_SUBNEGOTIATION_COMMAND = auto()


class TelnetConnection:
    def __init__(self) -> None:
        self._app_buffer = bytearray()
        self._subnegotiation_buffer = bytearray()
        self._event_buffer = []
        self._verb = 0

        self._machine = Machine(
            model=self,
            initial=State.READ_APPLICATION_DATA,
            transitions=[
                Transition("byte", State.READ_APPLICATION_DATA, State.READ_COMMAND, condition="_is_iac"),
                Transition(
                    "byte", State.READ_APPLICATION_DATA, State.READ_APPLICATION_DATA, action="_app_buffer_append"
                ),
                Transition(
                    "byte",
                    State.READ_COMMAND,
                    State.READ_APPLICATION_DATA,
                    condition="_is_iac",
                    action="_app_buffer_append",
                ),
                Transition(
                    "byte",
                    State.READ_COMMAND,
                    State.READ_NEGOTIATION,
                    condition="_is_verb",
                    action="_store_verb",
                    before="_flush_app_buffer",
                ),
                Transition("byte", State.READ_COMMAND, State.READ_SUBNEGOTIATION, condition="_is_sb"),
                Transition("byte", State.READ_NEGOTIATION, State.READ_APPLICATION_DATA, action="_finalize_negotiation"),
                Transition("byte", State.READ_SUBNEGOTIATION, State.READ_SUBNEGOTIATION_COMMAND, condition="_is_iac"),
                Transition(
                    "byte", State.READ_SUBNEGOTIATION, State.READ_SUBNEGOTIATION, action="_subnegotiation_buffer_append"
                ),
                Transition(
                    "byte",
                    State.READ_SUBNEGOTIATION_COMMAND,
                    State.READ_APPLICATION_DATA,
                    condition="_is_se",
                    action="_finalize_subnegotiation",
                ),
            ],
        )

    def send_application_data(self, data: bytes) -> bytes:
        return ApplicationData(data=data).to_bytes()

    def send_negotiation(self, verb: Verb, option: Option) -> bytes:
        return Negotiation(verb=verb, option=option).to_bytes()

    def send_subnegotiation(self, data: bytes) -> bytes:
        return Subnegotiation(data=data).to_bytes()

    def receive_data(self, data: bytes):
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
        return Verb.WILL <= byte <= Verb.DONT

    def _flush_app_buffer(self, *_args: Any, **_kwargs: Any) -> None:
        if self._app_buffer:
            self._event_buffer.append(ApplicationData(data=bytes(self._app_buffer)))
            self._app_buffer.clear()

    def _app_buffer_append(self, byte: int) -> None:
        self._app_buffer.append(byte)

    def _subnegotiation_buffer_append(self, byte: int) -> None:
        self._subnegotiation_buffer.append(byte)

    def _store_verb(self, byte: int) -> None:
        self._verb = byte

    def _finalize_negotiation(self, byte: int) -> Negotiation:
        negotiation = Negotiation(verb=Verb(self._verb), option=Option(byte))
        self._verb = 0

        return negotiation

    def _finalize_subnegotiation(self, byte: int) -> Subnegotiation:
        subnegotiation = Subnegotiation(data=bytes(self._subnegotiation_buffer))
        self._subnegotiation_buffer.clear()

        return subnegotiation
