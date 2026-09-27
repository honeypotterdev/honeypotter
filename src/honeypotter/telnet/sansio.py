from enum import Enum, auto

from honeypotter.statemachine import Machine, Transition
from honeypotter.telnet.values import ApplicationData, Negotiation, Verb


class State(Enum):
    READ_APPLICATION_DATA = auto()
    READ_COMMAND = auto()


class TelnetConnection:
    def __init__(self) -> None:
        self._buffer = bytearray()

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
            ],
        )

    def send_negotiation(self, verb: Verb, option: int) -> bytes:
        return Negotiation(verb=verb, option=option).to_bytes()

    def receive_data(self, data: bytes):
        events = []

        for byte in data:
            self._machine.trigger("byte", byte)

        if self._buffer:
            events.append(ApplicationData(data=bytes(self._buffer)))
            self._buffer.clear()

        return events

    def _buffer_append(self, byte: int) -> None:
        self._buffer.append(byte)

    def _is_iac(self, byte: int) -> bool:
        return byte == 255
