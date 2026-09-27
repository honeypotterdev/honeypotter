from enum import Enum, auto

from honeypotter.statemachine import Machine, Transition
from honeypotter.telnet.values import ApplicationData, Negotiation, Option, Verb


class State(Enum):
    READ_APPLICATION_DATA = auto()
    READ_COMMAND = auto()
    READ_NEGOTIATION = auto()


class TelnetConnection:
    def __init__(self) -> None:
        self._buffer = bytearray()
        self._verb = 0

        self._machine = Machine(
            model=self,
            initial=State.READ_APPLICATION_DATA,
            transitions=[
                Transition("byte", State.READ_APPLICATION_DATA, State.READ_COMMAND, condition="_is_iac"),
                Transition("byte", State.READ_APPLICATION_DATA, State.READ_APPLICATION_DATA, action="_buffer_append"),
                Transition(
                    "byte",
                    State.READ_COMMAND,
                    State.READ_APPLICATION_DATA,
                    condition="_is_iac",
                    action="_buffer_append",
                ),
                Transition(
                    "byte", State.READ_COMMAND, State.READ_NEGOTIATION, condition="_is_verb", action="_store_verb"
                ),
                Transition("byte", State.READ_NEGOTIATION, State.READ_APPLICATION_DATA, action="_finalize_negotiation"),
            ],
        )

    def send_application_data(self, data: bytes) -> bytes:
        return ApplicationData(data=data).to_bytes()

    def send_negotiation(self, verb: Verb, option: Option) -> bytes:
        return Negotiation(verb=verb, option=option).to_bytes()

    def receive_data(self, data: bytes):
        events = []

        for byte in data:
            events.append(self._machine.trigger("byte", byte))

        events = [event for event in events if event is not None]

        if self._buffer:
            events.append(ApplicationData(data=bytes(self._buffer)))
            self._buffer.clear()

        return events

    def _is_iac(self, byte: int) -> bool:
        return byte == 255

    def _is_verb(self, byte: int) -> bool:
        return Verb.WILL <= byte <= Verb.DONT

    def _buffer_append(self, byte: int) -> None:
        self._buffer.append(byte)

    def _store_verb(self, byte: int) -> None:
        self._verb = byte

    def _finalize_negotiation(self, byte: int) -> Negotiation:
        negotiation = Negotiation(verb=Verb(self._verb), option=Option(byte))
        self._verb = 0

        return negotiation
