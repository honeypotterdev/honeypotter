from collections.abc import Iterable
from enum import Enum, auto
from functools import partial
from typing import Any, ClassVar

from honeypotter.constants import CR, LF, NUL
from honeypotter.statemachine import Machine, MachineError, Transition
from honeypotter.telnet.codes import IAC, SB, SE
from honeypotter.telnet.events import (
    ApplicationDataReceived,
    CommandReceived,
    ConnectionFailed,
    Event,
    NegotiationReceived,
    OptionStateChanged,
    SubnegotiationReceived,
)
from honeypotter.telnet.options import NegotiationAction, OptionNegotiator
from honeypotter.telnet.types import CommandCode, NegotiationVerb, Option, Side


class State(Enum):
    READ_APPLICATION_DATA = auto()
    IAC = auto()
    READ_NEGOTIATION_OPTION = auto()
    READ_SUBNEGOTIATION_OPTION = auto()
    READ_SUBNEGOTIATION_DATA = auto()
    READ_SUBNEGOTIATION_IAC = auto()


class TelnetConnection:
    _REQUEST_TO_VERB: ClassVar[dict[tuple[Side, bool], NegotiationVerb]] = {
        (Side.LOCAL, True): NegotiationVerb.WILL,
        (Side.LOCAL, False): NegotiationVerb.WONT,
        (Side.REMOTE, True): NegotiationVerb.DO,
        (Side.REMOTE, False): NegotiationVerb.DONT,
    }
    _VERB_TO_REQUEST: ClassVar[dict[NegotiationVerb, tuple[Side, bool]]] = {
        NegotiationVerb.DO: (Side.LOCAL, True),
        NegotiationVerb.DONT: (Side.LOCAL, False),
        NegotiationVerb.WILL: (Side.REMOTE, True),
        NegotiationVerb.WONT: (Side.REMOTE, False),
    }

    def __init__(
        self, allowed_local_options: Iterable[int] | None = None, allowed_remote_options: Iterable[int] | None = None
    ) -> None:
        self._option_negotiators = {
            Side.LOCAL: OptionNegotiator(allowed_local_options),
            Side.REMOTE: OptionNegotiator(allowed_remote_options),
        }

        self._outgoing_buffer = bytearray()
        self._application_data_buffer = bytearray()
        self._subnegotiation_buffer = bytearray()

        self._pending_events: list[Event] = []
        self._pending_negotiation_verb = 0
        self._pending_subnegotiation_option = 0
        self._pending_cr = False

        self._is_failed = False

        self._parser_machine = self._create_parser_machine()

    @property
    def is_failed(self) -> bool:
        return self._is_failed

    def data_to_send(self) -> bytes:
        data = bytes(self._outgoing_buffer)
        self._outgoing_buffer.clear()

        return data

    def send_application_data(self, data: bytes) -> None:
        self._outgoing_buffer.extend(self._encode_application_data(data))

    def send_command(self, code: int) -> None:
        self._outgoing_buffer.extend(IAC.to_bytes() + code.to_bytes())

    def receive_data(self, data: bytes) -> list[Event]:
        if self._is_failed:
            return []

        for byte in data:
            try:
                event = self._parser_machine.trigger("byte", byte)
            except MachineError:
                self._is_failed = True
                return self._drain_events() + [ConnectionFailed()]

            if event is not None:
                self._pending_events.append(event)

                if isinstance(event, NegotiationReceived):
                    self._handle_negotiation(event)

        self._emit_application_data()

        return self._drain_events()

    def request_option(self, option: Option, *, side: Side, enable: bool) -> None:
        result = self._option_negotiators[side].request(option, enable=enable)

        if result.action is None:
            return

        verb = self._REQUEST_TO_VERB[(side, enable)]
        self._send_negotiation(verb=verb, option=option)

    def is_option_enabled(self, option: Option, *, side: Side) -> bool:
        return self._option_negotiators[side].is_enabled(option)

    def _drain_events(self) -> list[Event]:
        events = self._pending_events
        self._pending_events = []

        return events

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

    def _handle_negotiation(self, event: NegotiationReceived) -> None:
        side, peer_requests_enable = self._VERB_TO_REQUEST[event.verb]
        negotiator = self._option_negotiators[side]
        result = negotiator.receive(event.option, enable=peer_requests_enable)

        # send negotiation response
        if result.action is not None:
            verb = self._REQUEST_TO_VERB[(side, result.action is NegotiationAction.SEND_ENABLE)]
            self._send_negotiation(verb, event.option)

        if result.enabled_changed:
            self._pending_events.append(
                OptionStateChanged(option=event.option, side=side, enabled=negotiator.is_enabled(event.option))
            )

    def _send_negotiation(self, verb: int, option: Option) -> None:
        self._outgoing_buffer.extend(IAC.to_bytes() + verb.to_bytes() + option.to_bytes())

    def _send_subnegotiation(self, option: int, data: bytes) -> None:
        data = data.replace(b"\xff", b"\xff\xff")

        self._outgoing_buffer.extend(
            IAC.to_bytes() + SB.to_bytes() + option.to_bytes() + data + IAC.to_bytes() + SE.to_bytes()
        )

    def _create_parser_machine(self) -> Machine[State, str]:
        on_byte = partial(Transition, "byte")

        return Machine[State, str](
            model=self,
            initial=State.READ_APPLICATION_DATA,
            transitions=[
                on_byte(State.READ_APPLICATION_DATA, State.IAC, condition="_is_iac"),
                on_byte(State.READ_APPLICATION_DATA, State.READ_APPLICATION_DATA, action="_decode_application_byte"),
                on_byte(State.IAC, State.READ_APPLICATION_DATA, condition="_is_iac", action="_decode_application_byte"),
                on_byte(
                    State.IAC,
                    State.READ_NEGOTIATION_OPTION,
                    condition="_is_negotiation_verb",
                    action="_store_negotiation_verb",
                    before="_emit_application_data",
                ),
                on_byte(
                    State.IAC, State.READ_SUBNEGOTIATION_OPTION, condition="_is_sb", before="_emit_application_data"
                ),
                on_byte(
                    State.IAC, State.READ_APPLICATION_DATA, action="_finalize_command", before="_emit_application_data"
                ),
                on_byte(State.READ_NEGOTIATION_OPTION, State.READ_APPLICATION_DATA, action="_finalize_negotiation"),
                on_byte(
                    State.READ_SUBNEGOTIATION_OPTION,
                    State.READ_SUBNEGOTIATION_DATA,
                    action="_store_subnegotiation_option",
                ),
                on_byte(State.READ_SUBNEGOTIATION_DATA, State.READ_SUBNEGOTIATION_IAC, condition="_is_iac"),
                on_byte(
                    State.READ_SUBNEGOTIATION_DATA,
                    State.READ_SUBNEGOTIATION_DATA,
                    action="_append_subnegotiation_byte",
                ),
                on_byte(
                    State.READ_SUBNEGOTIATION_IAC,
                    State.READ_SUBNEGOTIATION_DATA,
                    condition="_is_iac",
                    action="_append_subnegotiation_byte",
                ),
                on_byte(
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

    def _is_negotiation_verb(self, byte: int) -> bool:
        return NegotiationVerb.WILL <= byte <= NegotiationVerb.DONT

    def _emit_application_data(self, *_args: Any, **_kwargs: Any) -> None:
        if self._application_data_buffer:
            self._pending_events.append(ApplicationDataReceived(data=bytes(self._application_data_buffer)))
            self._application_data_buffer.clear()

    def _decode_application_byte(self, byte: int) -> None:
        if not self._pending_cr and byte == CR:
            self._pending_cr = True
            return

        if not self._pending_cr:
            self._application_data_buffer.append(byte)
            return

        self._pending_cr = byte == CR

        if byte == CR:
            self._application_data_buffer.append(CR)
            return

        if byte == LF:
            self._application_data_buffer.append(LF)
            return

        if byte == NUL:
            self._application_data_buffer.append(CR)
            return

        self._application_data_buffer.extend(CR.to_bytes() + byte.to_bytes())

    def _append_subnegotiation_byte(self, byte: int) -> None:
        self._subnegotiation_buffer.append(byte)

    def _store_negotiation_verb(self, byte: int) -> None:
        self._pending_negotiation_verb = byte

    def _store_subnegotiation_option(self, byte: int) -> None:
        self._pending_subnegotiation_option = byte

    def _finalize_command(self, byte: int) -> CommandReceived:
        return CommandReceived(code=CommandCode(byte))

    def _finalize_negotiation(self, byte: int) -> NegotiationReceived:
        negotiation = NegotiationReceived(verb=NegotiationVerb(self._pending_negotiation_verb), option=Option(byte))
        self._pending_negotiation_verb = 0

        return negotiation

    def _finalize_subnegotiation(self, byte: int) -> SubnegotiationReceived:
        subnegotiation = SubnegotiationReceived(
            option=Option(self._pending_subnegotiation_option), data=bytes(self._subnegotiation_buffer)
        )
        self._pending_subnegotiation_option = 0
        self._subnegotiation_buffer.clear()

        return subnegotiation
