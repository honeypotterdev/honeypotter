import logging
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from typing import Any

from honeypotter.constants import CR, LF, NUL
from honeypotter.core import Context, Layer
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


_TRANSITIONS: dict[tuple[OptionState, OptionInput], tuple[OptionState, OptionAction | None]] = {
    # NO
    (OptionState.NO, OptionInput.REQUEST_ENABLE): (OptionState.WANTYES_EMPTY, OptionAction.SEND_ENABLE),
    (OptionState.NO, OptionInput.RECEIVE_ENABLE_ACCEPT): (OptionState.YES, OptionAction.SEND_ENABLE),
    (OptionState.NO, OptionInput.RECEIVE_ENABLE_REJECT): (OptionState.NO, OptionAction.SEND_DISABLE),
    # YES
    (OptionState.YES, OptionInput.REQUEST_DISABLE): (OptionState.WANTNO_EMPTY, OptionAction.SEND_DISABLE),
    (OptionState.YES, OptionInput.RECEIVE_DISABLE): (OptionState.NO, OptionAction.SEND_DISABLE),
    # WANTNO_EMPTY
    (OptionState.WANTNO_EMPTY, OptionInput.REQUEST_ENABLE): (OptionState.WANTNO_OPPOSITE, None),
    (OptionState.WANTNO_EMPTY, OptionInput.RECEIVE_ENABLE_ACCEPT): (OptionState.NO, None),
    (OptionState.WANTNO_EMPTY, OptionInput.RECEIVE_ENABLE_REJECT): (OptionState.NO, None),
    (OptionState.WANTNO_EMPTY, OptionInput.RECEIVE_DISABLE): (OptionState.NO, None),
    # WANTNO_OPPOSITE
    (OptionState.WANTNO_OPPOSITE, OptionInput.REQUEST_DISABLE): (OptionState.WANTNO_EMPTY, None),
    (OptionState.WANTNO_OPPOSITE, OptionInput.RECEIVE_ENABLE_ACCEPT): (OptionState.YES, None),
    (OptionState.WANTNO_OPPOSITE, OptionInput.RECEIVE_ENABLE_REJECT): (OptionState.YES, None),
    (OptionState.WANTNO_OPPOSITE, OptionInput.RECEIVE_DISABLE): (OptionState.WANTYES_EMPTY, OptionAction.SEND_ENABLE),
    # WANTYES_EMPTY
    (OptionState.WANTYES_EMPTY, OptionInput.REQUEST_DISABLE): (OptionState.WANTYES_OPPOSITE, None),
    (OptionState.WANTYES_EMPTY, OptionInput.RECEIVE_ENABLE_ACCEPT): (OptionState.YES, None),
    (OptionState.WANTYES_EMPTY, OptionInput.RECEIVE_ENABLE_REJECT): (OptionState.YES, None),
    (OptionState.WANTYES_EMPTY, OptionInput.RECEIVE_DISABLE): (OptionState.NO, None),
    # WANTYES_OPPOSITE
    (OptionState.WANTYES_OPPOSITE, OptionInput.REQUEST_ENABLE): (OptionState.WANTYES_EMPTY, None),
    (OptionState.WANTYES_OPPOSITE, OptionInput.RECEIVE_ENABLE_ACCEPT): (
        OptionState.WANTNO_EMPTY,
        OptionAction.SEND_DISABLE,
    ),
    (OptionState.WANTYES_OPPOSITE, OptionInput.RECEIVE_ENABLE_REJECT): (
        OptionState.WANTNO_EMPTY,
        OptionAction.SEND_DISABLE,
    ),
    (OptionState.WANTYES_OPPOSITE, OptionInput.RECEIVE_DISABLE): (OptionState.NO, None),
}


class OptionNegotiator:
    def __init__(self) -> None:
        self._options: dict[int, OptionState] = defaultdict[int, OptionState](lambda: OptionState.NO)

    def is_enabled(self, option: int) -> bool:
        return self._options[option] == OptionState.YES

    def request_enable(self, option: int) -> OptionAction | None:
        return self._transition(option, OptionInput.REQUEST_ENABLE)

    def request_disable(self, option: int) -> OptionAction | None:
        return self._transition(option, OptionInput.REQUEST_DISABLE)

    def receive_enable(self, option: int, *, accept: bool) -> OptionAction | None:
        return self._transition(
            option, OptionInput.RECEIVE_ENABLE_ACCEPT if accept else OptionInput.RECEIVE_ENABLE_REJECT
        )

    def receive_disable(self, option: int) -> OptionAction | None:
        return self._transition(option, OptionInput.RECEIVE_DISABLE)

    def _transition(self, option: int, event: OptionInput) -> OptionAction | None:
        current_state = self._options[option]

        next_state, action = _TRANSITIONS.get((current_state, event), (current_state, None))
        self._options[option] = next_state

        return action


class TelnetCodecState(Enum):
    APPLICATION_DATA = auto()
    IAC = auto()
    NEGOTIATION = auto()
    SUBNEGOTIATION = auto()
    SUBNEGOTIATION_IAC = auto()


class TelnetCodec(Layer):
    def __init__(self, context: Context) -> None:
        super().__init__(context)

        self._local_options = OptionNegotiator()
        self._peer_options = OptionNegotiator()
        self._local_supported: set[int] = {TelnetCode.ECHO, TelnetCode.SGA, TelnetCode.BINARY_TRANSMISSION}
        self._peer_supported: set[int] = {TelnetCode.ECHO, TelnetCode.SGA, TelnetCode.BINARY_TRANSMISSION}
        self._state: TelnetCodecState = TelnetCodecState.APPLICATION_DATA
        self._app_data_buffer = bytearray()
        self._subnegotiation_buffer = bytearray()
        self._negotiation_verb = 0
        self._pending_cr = False

    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            for byte in event.data:
                self._handle_state(byte)

            self._flush_app_data()
            return

        super().handle_inbound(event)

    def handle_outbound(self, event: Any) -> None:
        if isinstance(event, DataEvent):
            self.ctx.send_outbound(DataEvent(data=self._encode_application_data(event.data)))
            return

        if isinstance(event, CommandEvent):
            self.ctx.send_outbound(DataEvent(data=bytes([TelnetCode.IAC, event.command])))
            return

        if isinstance(event, NegotiationEvent):
            self._request_negotiation(event.verb, event.option)
            return

        if isinstance(event, SubnegotiationEvent):
            self.ctx.send_outbound(
                DataEvent(
                    data=bytes([TelnetCode.IAC, TelnetCode.SB]) + event.data + bytes([TelnetCode.IAC, TelnetCode.SE])
                )
            )
            return

        super().handle_outbound(event)

    def _set_state(self, state: TelnetCodecState) -> None:
        self._state = state

    def _flush_app_data(self) -> None:
        if self._app_data_buffer:
            self._application_data_received(bytes(self._app_data_buffer))
            self._app_data_buffer.clear()

    def _handle_state(self, byte: int) -> None:
        if self._state == TelnetCodecState.APPLICATION_DATA:
            self._handle_data_state(byte)
            return

        if self._state == TelnetCodecState.IAC:
            self._handle_iac_state(byte)
            return

        if self._state == TelnetCodecState.NEGOTIATION:
            self._handle_negotiation_state(byte)
            return

        if self._state == TelnetCodecState.SUBNEGOTIATION:
            self._handle_subnegotiation_state(byte)
            return

        if self._state == TelnetCodecState.SUBNEGOTIATION_IAC:
            self._handle_subnegotiation_iac_state(byte)
            return

        raise RuntimeError(f"Unknown state: {self._state!r}")

    def _handle_data_state(self, byte: int) -> None:
        if byte == TelnetCode.IAC:
            self._flush_app_data()
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

    def _handle_iac_state(self, byte: int) -> None:
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

        self._command_received(byte)
        self._set_state(TelnetCodecState.APPLICATION_DATA)

    def _handle_negotiation_state(self, byte: int) -> None:
        self._negotiation_received(self._negotiation_verb, byte)
        self._set_state(TelnetCodecState.APPLICATION_DATA)

    def _handle_subnegotiation_state(self, byte: int) -> None:
        if byte == TelnetCode.IAC:
            self._set_state(TelnetCodecState.SUBNEGOTIATION_IAC)
            return

        self._subnegotiation_buffer.append(byte)

    def _handle_subnegotiation_iac_state(self, byte: int) -> None:
        if byte == TelnetCode.IAC:
            self._subnegotiation_buffer.append(255)
            self._set_state(TelnetCodecState.SUBNEGOTIATION)
            return

        if byte == TelnetCode.SE:
            self._subnegotiation_received(bytes(self._subnegotiation_buffer))
            self._subnegotiation_buffer.clear()
            self._set_state(TelnetCodecState.APPLICATION_DATA)
            return

        _logger.warning(f"Malformed Telnet IAC sequence inside subnegotiation: {byte!r}")
        self._subnegotiation_buffer.clear()
        self._set_state(TelnetCodecState.APPLICATION_DATA)

    def _application_data_received(self, data: bytes) -> None:
        self.ctx.send_inbound(DataEvent(data=data))

    def _command_received(self, command: int) -> None:
        self.ctx.send_inbound(CommandEvent(command=TelnetCode(command)))

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

    def _request_negotiation(self, verb: TelnetCode, option: TelnetCode) -> None:
        if verb == TelnetCode.WILL:
            action = self._local_options.request_enable(option)
            self._send_negotiation_action(action, option, TelnetCode.WILL, TelnetCode.WONT)
            return

        if verb == TelnetCode.WONT:
            action = self._local_options.request_disable(option)
            self._send_negotiation_action(action, option, TelnetCode.WILL, TelnetCode.WONT)
            return

        if verb == TelnetCode.DO:
            action = self._peer_options.request_enable(option)
            self._send_negotiation_action(action, option, TelnetCode.DO, TelnetCode.DONT)
            return

        if verb == TelnetCode.DONT:
            action = self._peer_options.request_disable(option)
            self._send_negotiation_action(action, option, TelnetCode.DO, TelnetCode.DONT)
            return

        raise ValueError(f"Unknown negotiation verb: {verb!r}")

    def _send_negotiation_action(
        self,
        action: OptionAction | None,
        option: int,
        enable_verb: TelnetCode,
        disable_verb: TelnetCode,
    ) -> None:
        if action is OptionAction.SEND_ENABLE:
            self._send_negotiation(enable_verb, option)
        elif action is OptionAction.SEND_DISABLE:
            self._send_negotiation(disable_verb, option)

    def _send_negotiation(self, verb: TelnetCode, option: int) -> None:
        self.ctx.send_outbound(DataEvent(data=bytes([TelnetCode.IAC, verb, option])))

    def _subnegotiation_received(self, data: bytes) -> None:
        self.ctx.send_inbound(SubnegotiationEvent(data=data))

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


class TelnetSession(Layer):
    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, ConnectionMadeEvent):
            self.ctx.send_outbound(NegotiationEvent(verb=TelnetCode.WILL, option=TelnetCode.ECHO))
            self.ctx.send_outbound(NegotiationEvent(verb=TelnetCode.WILL, option=TelnetCode.SGA))
            self.ctx.send_outbound(NegotiationEvent(verb=TelnetCode.DO, option=TelnetCode.SGA))
            super().handle_inbound(event)
            return

        super().handle_inbound(event)
