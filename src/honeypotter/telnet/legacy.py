import logging
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from typing import Any

from honeypotter.constants import CR, LF, NUL
from honeypotter.core import Handler, HandlerContext
from honeypotter.statemachine import Machine, Transition
from honeypotter.transport import ConnectionMadeEvent, DataEvent

_logger = logging.getLogger(__name__)


class TelnetCode(IntEnum):
    BINARY_TRANSMISSION = 0
    ECHO = 1
    SGA = 3
    NAWS = 31
    SE = 240
    SB = 250
    WILL = 251
    WONT = 252
    DO = 253
    DONT = 254
    IAC = 255

    @classmethod
    def _missing_(cls, value: object) -> int | None:
        if not isinstance(value, int) or not 0 <= value <= 255:
            return None

        pseudo_member = int.__new__(cls, value)
        pseudo_member._value_ = value
        pseudo_member._name_ = f"UNKNOWN_{value}"
        cls._value2member_map_[value] = pseudo_member

        return pseudo_member


@dataclass(frozen=True, kw_only=True)
class CommandEvent:
    command: TelnetCode


@dataclass(frozen=True, kw_only=True)
class NegotiationEvent:
    verb: TelnetCode
    option: TelnetCode


@dataclass(frozen=True, kw_only=True)
class SubnegotiationEvent:
    data: bytes


class OptionAction(Enum):
    SEND_ENABLE = auto()
    SEND_DISABLE = auto()


class OptionState(Enum):
    NO = auto()
    YES = auto()
    WANTNO_EMPTY = auto()
    WANTNO_OPPOSITE = auto()
    WANTYES_EMPTY = auto()
    WANTYES_OPPOSITE = auto()


class OptionInput(Enum):
    REQUEST_ENABLE = auto()
    REQUEST_DISABLE = auto()
    RECEIVE_ENABLE_ACCEPT = auto()
    RECEIVE_ENABLE_REJECT = auto()
    RECEIVE_DISABLE = auto()


class TelnetOption:
    def __init__(self) -> None:
        self._machine = Machine(
            model=self,
            initial=OptionState.NO,
            raise_on_invalid_transition=False,
            transitions=[
                # NO
                Transition(
                    source=OptionState.NO,
                    event=OptionInput.REQUEST_ENABLE,
                    target=OptionState.WANTYES_EMPTY,
                    action="send_enable",
                ),
                Transition(
                    source=OptionState.NO,
                    event=OptionInput.RECEIVE_ENABLE_ACCEPT,
                    target=OptionState.YES,
                    action="send_enable",
                ),
                Transition(
                    source=OptionState.NO,
                    event=OptionInput.RECEIVE_ENABLE_REJECT,
                    target=OptionState.NO,
                    action="send_disable",
                ),
                # YES
                Transition(
                    source=OptionState.YES,
                    event=OptionInput.REQUEST_DISABLE,
                    target=OptionState.WANTNO_EMPTY,
                    action="send_disable",
                ),
                Transition(
                    source=OptionState.YES,
                    event=OptionInput.RECEIVE_DISABLE,
                    target=OptionState.NO,
                    action="send_disable",
                ),
                # WANTNO_EMPTY
                Transition(
                    source=OptionState.WANTNO_EMPTY,
                    event=OptionInput.REQUEST_ENABLE,
                    target=OptionState.WANTNO_OPPOSITE,
                ),
                Transition(
                    source=OptionState.WANTNO_EMPTY, event=OptionInput.RECEIVE_ENABLE_ACCEPT, target=OptionState.NO
                ),
                Transition(
                    source=OptionState.WANTNO_EMPTY, event=OptionInput.RECEIVE_ENABLE_REJECT, target=OptionState.NO
                ),
                Transition(source=OptionState.WANTNO_EMPTY, event=OptionInput.RECEIVE_DISABLE, target=OptionState.NO),
                # WANTNO_OPPOSITE
                Transition(
                    source=OptionState.WANTNO_OPPOSITE,
                    event=OptionInput.REQUEST_DISABLE,
                    target=OptionState.WANTNO_EMPTY,
                ),
                Transition(
                    source=OptionState.WANTNO_OPPOSITE, event=OptionInput.RECEIVE_ENABLE_ACCEPT, target=OptionState.YES
                ),
                Transition(
                    source=OptionState.WANTNO_OPPOSITE, event=OptionInput.RECEIVE_ENABLE_REJECT, target=OptionState.YES
                ),
                Transition(
                    source=OptionState.WANTNO_OPPOSITE,
                    event=OptionInput.RECEIVE_DISABLE,
                    target=OptionState.WANTYES_EMPTY,
                    action="send_enable",
                ),
                # WANTYES_EMPTY
                Transition(
                    source=OptionState.WANTYES_EMPTY,
                    event=OptionInput.REQUEST_DISABLE,
                    target=OptionState.WANTYES_OPPOSITE,
                ),
                Transition(
                    source=OptionState.WANTYES_EMPTY, event=OptionInput.RECEIVE_ENABLE_ACCEPT, target=OptionState.YES
                ),
                Transition(
                    source=OptionState.WANTYES_EMPTY, event=OptionInput.RECEIVE_ENABLE_REJECT, target=OptionState.YES
                ),
                Transition(source=OptionState.WANTYES_EMPTY, event=OptionInput.RECEIVE_DISABLE, target=OptionState.NO),
                # WANTYES_OPPOSITE
                Transition(
                    source=OptionState.WANTYES_OPPOSITE,
                    event=OptionInput.REQUEST_ENABLE,
                    target=OptionState.WANTYES_EMPTY,
                ),
                Transition(
                    source=OptionState.WANTYES_OPPOSITE,
                    event=OptionInput.RECEIVE_ENABLE_ACCEPT,
                    target=OptionState.WANTNO_EMPTY,
                    action="send_disable",
                ),
                Transition(
                    source=OptionState.WANTYES_OPPOSITE,
                    event=OptionInput.RECEIVE_ENABLE_REJECT,
                    target=OptionState.WANTNO_EMPTY,
                    action="send_disable",
                ),
                Transition(
                    source=OptionState.WANTYES_OPPOSITE, event=OptionInput.RECEIVE_DISABLE, target=OptionState.NO
                ),
            ],
        )

    @property
    def state(self) -> OptionState:
        return self._machine.state

    def handle_input(self, option_input: OptionInput) -> OptionAction | None:
        return self._machine.trigger(option_input)

    def send_enable(self) -> OptionAction:
        return OptionAction.SEND_ENABLE

    def send_disable(self) -> OptionAction:
        return OptionAction.SEND_DISABLE


class OptionNegotiator:
    def __init__(self) -> None:
        self._options: dict[int, TelnetOption] = defaultdict[int, TelnetOption](lambda: TelnetOption())

    def is_enabled(self, option: int) -> bool:
        return self._options[option].state is OptionState.YES

    def request_enable(self, option: int) -> OptionAction | None:
        return self._options[option].handle_input(OptionInput.REQUEST_ENABLE)

    def request_disable(self, option: int) -> OptionAction | None:
        return self._options[option].handle_input(OptionInput.REQUEST_DISABLE)

    def receive_enable(self, option: int, *, accept: bool) -> OptionAction | None:
        return self._options[option].handle_input(
            OptionInput.RECEIVE_ENABLE_ACCEPT if accept else OptionInput.RECEIVE_ENABLE_REJECT
        )

    def receive_disable(self, option: int) -> OptionAction | None:
        return self._options[option].handle_input(OptionInput.RECEIVE_DISABLE)


class TelnetCodecState(Enum):
    APPLICATION_DATA = auto()
    IAC = auto()
    NEGOTIATION = auto()
    SUBNEGOTIATION = auto()
    SUBNEGOTIATION_IAC = auto()


class TelnetCodecHandler(Handler):
    def __init__(self) -> None:
        super().__init__()

        self._local_options = OptionNegotiator()
        self._peer_options = OptionNegotiator()
        self._local_supported: set[int] = {TelnetCode.ECHO, TelnetCode.SGA, TelnetCode.BINARY_TRANSMISSION}
        self._peer_supported: set[int] = {TelnetCode.ECHO, TelnetCode.SGA, TelnetCode.BINARY_TRANSMISSION}
        self._state: TelnetCodecState = TelnetCodecState.APPLICATION_DATA
        self._app_data_buffer = bytearray()
        self._subnegotiation_buffer = bytearray()
        self._negotiation_verb = 0
        self._pending_cr = False

    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, DataEvent):
            for byte in event.data:
                self._handle_state(context, byte)

            self._flush_app_data(context)
            return

        super().handle_inbound(context, event)

    def handle_outbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, DataEvent):
            context.send_outbound(DataEvent(data=self._encode_application_data(event.data)))
            return

        if isinstance(event, CommandEvent):
            context.send_outbound(DataEvent(data=bytes([TelnetCode.IAC, event.command])))
            return

        if isinstance(event, NegotiationEvent):
            self._request_negotiation(context, event.verb, event.option)
            return

        if isinstance(event, SubnegotiationEvent):
            context.send_outbound(
                DataEvent(
                    data=bytes([TelnetCode.IAC, TelnetCode.SB]) + event.data + bytes([TelnetCode.IAC, TelnetCode.SE])
                )
            )
            return

        super().handle_outbound(context, event)

    def _set_state(self, state: TelnetCodecState) -> None:
        self._state = state

    def _flush_app_data(self, context: HandlerContext) -> None:
        if self._app_data_buffer:
            self._application_data_received(context, bytes(self._app_data_buffer))
            self._app_data_buffer.clear()

    def _handle_state(self, context: HandlerContext, byte: int) -> None:
        if self._state == TelnetCodecState.APPLICATION_DATA:
            self._handle_data_state(context, byte)
            return

        if self._state == TelnetCodecState.IAC:
            self._handle_iac_state(context, byte)
            return

        if self._state == TelnetCodecState.NEGOTIATION:
            self._handle_negotiation_state(byte)
            return

        if self._state == TelnetCodecState.SUBNEGOTIATION:
            self._handle_subnegotiation_state(byte)
            return

        if self._state == TelnetCodecState.SUBNEGOTIATION_IAC:
            self._handle_subnegotiation_iac_state(context, byte)
            return

        raise RuntimeError(f"Unknown state: {self._state!r}")

    def _handle_data_state(self, context: HandlerContext, byte: int) -> None:
        if byte == TelnetCode.IAC:
            self._flush_app_data(context)
            self._set_state(TelnetCodecState.IAC)
            return

        if self._pending_cr:
            self._pending_cr = False

            if byte == LF:
                self._app_data_buffer.append(LF)
                return

            if byte == NUL:
                self._app_data_buffer.append(CR)
                return

            self._app_data_buffer.append(CR)

        if byte == CR:
            self._pending_cr = True
            return

        self._app_data_buffer.append(byte)

    def _handle_iac_state(self, context: HandlerContext, byte: int) -> None:
        if byte == TelnetCode.IAC:
            self._app_data_buffer.append(255)
            self._set_state(TelnetCodecState.APPLICATION_DATA)
            return

        if byte == TelnetCode.SB:
            self._set_state(TelnetCodecState.SUBNEGOTIATION)
            return

        if TelnetCode.WILL <= byte <= TelnetCode.DONT:
            self._negotiation_verb = byte
            self._set_state(TelnetCodecState.NEGOTIATION)
            return

        self._command_received(context, byte)
        self._set_state(TelnetCodecState.APPLICATION_DATA)

    def _handle_negotiation_state(self, byte: int) -> None:
        self._negotiation_received(self._negotiation_verb, byte)
        self._set_state(TelnetCodecState.APPLICATION_DATA)

    def _handle_subnegotiation_state(self, byte: int) -> None:
        if byte == TelnetCode.IAC:
            self._set_state(TelnetCodecState.SUBNEGOTIATION_IAC)
            return

        self._subnegotiation_buffer.append(byte)

    def _handle_subnegotiation_iac_state(self, context: HandlerContext, byte: int) -> None:
        if byte == TelnetCode.IAC:
            self._subnegotiation_buffer.append(255)
            self._set_state(TelnetCodecState.SUBNEGOTIATION)
            return

        if byte == TelnetCode.SE:
            self._subnegotiation_received(context, bytes(self._subnegotiation_buffer))
            self._subnegotiation_buffer.clear()
            self._set_state(TelnetCodecState.APPLICATION_DATA)
            return

        _logger.warning(f"Malformed Telnet IAC sequence inside subnegotiation: {byte!r}")
        self._subnegotiation_buffer.clear()
        self._set_state(TelnetCodecState.APPLICATION_DATA)

    def _application_data_received(self, context: HandlerContext, data: bytes) -> None:
        context.send_inbound(DataEvent(data=data))

    def _command_received(self, context: HandlerContext, command: int) -> None:
        context.send_inbound(CommandEvent(command=TelnetCode(command)))

    def _negotiation_received(self, verb: int, option: int) -> None:
        if verb == TelnetCode.WILL:
            action = self._peer_options.receive_enable(option, accept=option in self._peer_supported)
            self._send_negotiation_action(action, option, TelnetCode.DO, TelnetCode.DONT)
            return

        if verb == TelnetCode.WONT:
            action = self._peer_options.receive_disable(option)
            self._send_negotiation_action(action, option, TelnetCode.DO, TelnetCode.DONT)
            return

        if verb == TelnetCode.DO:
            action = self._local_options.receive_enable(option, accept=option in self._local_supported)
            self._send_negotiation_action(action, option, TelnetCode.WILL, TelnetCode.WONT)
            return

        if verb == TelnetCode.DONT:
            action = self._local_options.receive_disable(option)
            self._send_negotiation_action(action, option, TelnetCode.WILL, TelnetCode.WONT)
            return

        raise RuntimeError(f"Unknown negotiation verb: {verb!r}")

    def _request_negotiation(self, context: HandlerContext, verb: TelnetCode, option: TelnetCode) -> None:
        if verb == TelnetCode.WILL:
            action = self._local_options.request_enable(option)
            self._send_negotiation_action(context, action, option, TelnetCode.WILL, TelnetCode.WONT)
            return

        if verb == TelnetCode.WONT:
            action = self._local_options.request_disable(option)
            self._send_negotiation_action(context, action, option, TelnetCode.WILL, TelnetCode.WONT)
            return

        if verb == TelnetCode.DO:
            action = self._peer_options.request_enable(option)
            self._send_negotiation_action(context, action, option, TelnetCode.DO, TelnetCode.DONT)
            return

        if verb == TelnetCode.DONT:
            action = self._peer_options.request_disable(option)
            self._send_negotiation_action(context, action, option, TelnetCode.DO, TelnetCode.DONT)
            return

        raise ValueError(f"Unknown negotiation verb: {verb!r}")

    def _send_negotiation_action(
        self,
        context: HandlerContext,
        action: OptionAction | None,
        option: int,
        enable_verb: TelnetCode,
        disable_verb: TelnetCode,
    ) -> None:
        if action is OptionAction.SEND_ENABLE:
            self._send_negotiation(context, enable_verb, option)
        elif action is OptionAction.SEND_DISABLE:
            self._send_negotiation(context, disable_verb, option)

    def _send_negotiation(self, context: HandlerContext, verb: TelnetCode, option: int) -> None:
        context.send_outbound(DataEvent(data=bytes([TelnetCode.IAC, verb, option])))

    def _subnegotiation_received(self, context: HandlerContext, data: bytes) -> None:
        context.send_inbound(SubnegotiationEvent(data=data))

    def _encode_application_data(self, data: bytes) -> bytes:
        encoded = bytearray()

        for byte in data:
            if byte == LF:
                encoded.extend(b"\r\n")
            elif byte == CR:
                encoded.extend(b"\r\x00")
            elif byte == TelnetCode.IAC:
                encoded.extend(b"\xff\xff")
            else:
                encoded.append(byte)

        return bytes(encoded)


class TelnetSessionHandler(Handler):
    def handle_inbound(self, context: HandlerContext, event: Any) -> None:
        if isinstance(event, ConnectionMadeEvent):
            context.send_outbound(NegotiationEvent(verb=TelnetCode.WILL, option=TelnetCode.ECHO))
            context.send_outbound(NegotiationEvent(verb=TelnetCode.WILL, option=TelnetCode.SGA))
            context.send_outbound(NegotiationEvent(verb=TelnetCode.DO, option=TelnetCode.SGA))
            super().handle_inbound(context, event)
            return

        super().handle_inbound(context, event)
