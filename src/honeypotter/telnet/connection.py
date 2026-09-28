from enum import Enum, auto
from functools import partial
from typing import Any

from honeypotter.constants import CR, LF, NUL
from honeypotter.statemachine import Machine, MachineError, Transition
from honeypotter.telnet.codes import IAC, SB, SE
from honeypotter.telnet.events import (
    ApplicationDataReceived,
    CommandReceived,
    ConnectionFailed,
    Event,
    NegotiationReceived,
    SubnegotiationReceived,
)
from honeypotter.telnet.options import OptionsNegotiator
from honeypotter.telnet.types import (
    CommandCode,
    NegotiationOption,
    NegotiationVerb,
    Side,
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
    def __init__(
        self,
        allowed_local_options: set[NegotiationOption] | None = None,
        allowed_remote_options: set[NegotiationOption] | None = None,
    ) -> None:
        self._allowed_local_options = allowed_local_options or set()
        self._allowed_remote_options = allowed_remote_options or set()
        self._local_options = OptionsNegotiator()
        self._remote_options = OptionsNegotiator()

        self._data_to_send_buffer = bytearray()
        self._app_buffer = bytearray()
        self._subnegotiation_buffer = bytearray()
        self._event_buffer: list[Event] = []
        self._negotiation_verb = 0
        self._subnegotiation_option = 0
        self._pending_cr = False
        self._is_failed = False

        self._machine = self._create_machine()

    @property
    def is_failed(self) -> bool:
        return self._is_failed

    def data_to_send(self) -> bytes:
        data = bytes(self._data_to_send_buffer)
        self._data_to_send_buffer.clear()

        return data

    def send_application_data(self, data: bytes) -> None:
        self._data_to_send_buffer.extend(self._encode_application_data(data))

    def send_command(self, code: int) -> None:
        self._data_to_send_buffer.extend(IAC.to_bytes() + code.to_bytes())

    def send_negotiation(self, verb: int, option: NegotiationOption) -> None:
        self._data_to_send_buffer.extend(IAC.to_bytes() + verb.to_bytes() + option.to_bytes())

    def send_subnegotiation(self, option: int, data: bytes) -> None:
        data = data.replace(b"\xff", b"\xff\xff")

        self._data_to_send_buffer.extend(
            IAC.to_bytes() + SB.to_bytes() + option.to_bytes() + data + IAC.to_bytes() + SE.to_bytes()
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

    def request_option(self, option: NegotiationOption, *, side: Side, enabled: bool) -> None:
        options = self._local_options if side == Side.LOCAL else self._remote_options
        action = options.request(option, enabled)

        if action is None:
            return

        mapping = {
            (Side.LOCAL, True): NegotiationVerb.WILL,
            (Side.LOCAL, False): NegotiationVerb.WONT,
            (Side.REMOTE, True): NegotiationVerb.DO,
            (Side.REMOTE, False): NegotiationVerb.DONT,
        }

        verb = mapping[(side, enabled)]

        self.send_negotiation(verb=verb, option=option)

    def is_option_enabled(self, option: NegotiationOption, *, side: Side) -> bool:
        options = self._local_options if side == Side.LOCAL else self._remote_options

        return options.is_enabled(option)

    def _encode_application_data(self, data: bytes) -> bytes:
        encoded_data = bytearray()

        for byte in data:
            if byte == IAC:
                encoded_data.extend(b"\xff\xff")
            elif byte == LF:
                encoded_data.extend(b"\r\n")
            elif byte == CR:
                encoded_data.extend(b"\r\x00")
            else:
                encoded_data.append(byte)

        return bytes(encoded_data)

    def _create_machine(self) -> Machine[State, str]:
        t = partial(Transition, "byte")

        return Machine[State, str](
            model=self,
            initial=State.READ_APPLICATION_DATA,
            transitions=[
                t(State.READ_APPLICATION_DATA, State.IAC, condition="_is_iac"),
                t(State.READ_APPLICATION_DATA, State.READ_APPLICATION_DATA, action="_app_buffer_append"),
                t(State.IAC, State.READ_APPLICATION_DATA, condition="_is_iac", action="_app_buffer_append"),
                t(
                    State.IAC,
                    State.READ_NEGOTIATION_OPTION,
                    condition="_is_verb",
                    action="_store_verb",
                    before="_flush_app_buffer",
                ),
                t(State.IAC, State.READ_SUBNEGOTIATION_OPTION, condition="_is_sb", before="_flush_app_buffer"),
                t(State.IAC, State.READ_APPLICATION_DATA, action="_finalize_command", before="_flush_app_buffer"),
                t(State.READ_NEGOTIATION_OPTION, State.READ_APPLICATION_DATA, action="_finalize_negotiation"),
                t(
                    State.READ_SUBNEGOTIATION_OPTION,
                    State.READ_SUBNEGOTIATION_DATA,
                    action="_store_subnegotiation_option",
                ),
                t(State.READ_SUBNEGOTIATION_DATA, State.READ_SUBNEGOTIATION_IAC, condition="_is_iac"),
                t(
                    State.READ_SUBNEGOTIATION_DATA,
                    State.READ_SUBNEGOTIATION_DATA,
                    action="_subnegotiation_buffer_append",
                ),
                t(
                    State.READ_SUBNEGOTIATION_IAC,
                    State.READ_SUBNEGOTIATION_DATA,
                    condition="_is_iac",
                    action="_subnegotiation_buffer_append",
                ),
                t(
                    State.READ_SUBNEGOTIATION_IAC,
                    State.READ_APPLICATION_DATA,
                    condition="_is_se",
                    action="_finalize_subnegotiation",
                ),
            ],
        )

    def _is_iac(self, byte: int) -> bool:
        return byte == IAC

    def _is_sb(self, byte: int) -> bool:
        return byte == SB

    def _is_se(self, byte: int) -> bool:
        return byte == SE

    def _is_verb(self, byte: int) -> bool:
        return NegotiationVerb.WILL <= byte <= NegotiationVerb.DONT

    def _flush_app_buffer(self, *_args: Any, **_kwargs: Any) -> None:
        if self._app_buffer:
            self._event_buffer.append(ApplicationDataReceived(data=bytes(self._app_buffer)))
            self._app_buffer.clear()

    def _app_buffer_append(self, byte: int) -> None:
        if not self._pending_cr and byte == CR:
            self._pending_cr = True
            return

        if not self._pending_cr:
            self._app_buffer.append(byte)
            return

        self._pending_cr = byte == CR

        if byte == CR:
            self._app_buffer.append(CR)
            return

        if byte == LF:
            self._app_buffer.append(LF)
            return

        if byte == NUL:
            self._app_buffer.append(CR)
            return

        self._app_buffer.extend(CR.to_bytes() + byte.to_bytes())

    def _subnegotiation_buffer_append(self, byte: int) -> None:
        self._subnegotiation_buffer.append(byte)

    def _store_verb(self, byte: int) -> None:
        self._negotiation_verb = byte

    def _store_subnegotiation_option(self, byte: int) -> None:
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
