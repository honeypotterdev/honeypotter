import logging
from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from typing import Any

from honeypotter.core import Context, Layer
from honeypotter.transport import BytesEvent, ConnectionMadeEvent

_logger = logging.getLogger(__name__)


@dataclass(kw_only=True)
class ApplicationDataEvent:
    data: bytes


@dataclass(kw_only=True)
class CommandEvent:
    command: int


@dataclass(kw_only=True)
class NegotiationEvent:
    verb: int
    option: int


@dataclass(kw_only=True)
class SubnegotiationEvent:
    data: bytes


class TelnetCode(IntEnum):
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


class TelnetCodecState(Enum):
    APPLICATION_DATA = auto()
    IAC = auto()
    NEGOTIATION = auto()
    SUBNEGOTIATION = auto()
    SUBNEGOTIATION_IAC = auto()


class TelnetCodec(Layer):
    def __init__(self, context: Context) -> None:
        super().__init__(context)

        self._state: TelnetCodecState = TelnetCodecState.APPLICATION_DATA
        self._app_data_buffer = bytearray()
        self._subnegotiation_buffer = bytearray()
        self._negotiation_verb = 0

    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, BytesEvent):
            for byte in event.data:
                self._handle_state(byte)

            self._flush_app_data()
            return

        super().handle_inbound(event)

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
        if byte != TelnetCode.IAC:
            self._app_data_buffer.append(byte)
            return

        self._flush_app_data()
        self._set_state(TelnetCodecState.IAC)

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
        self.ctx.send_inbound(ApplicationDataEvent(data=data))

    def _command_received(self, command: int) -> None:
        self.ctx.send_inbound(CommandEvent(command=command))

    def _negotiation_received(self, verb: int, option: int) -> None:
        self.ctx.send_inbound(NegotiationEvent(verb=verb, option=option))

    def _subnegotiation_received(self, data: bytes) -> None:
        self.ctx.send_inbound(SubnegotiationEvent(data=data))


class Telnet(Layer):
    def handle_inbound(self, event: Any) -> None:
        if isinstance(event, ConnectionMadeEvent):
            self.ctx.send_outbound(
                BytesEvent(
                    data=bytes(
                        [
                            TelnetCode.IAC,
                            TelnetCode.WONT,
                            TelnetCode.ECHO,
                            TelnetCode.IAC,
                            TelnetCode.DONT,
                            TelnetCode.ECHO,
                            TelnetCode.IAC,
                            TelnetCode.WONT,
                            TelnetCode.SGA,
                            TelnetCode.IAC,
                            TelnetCode.DO,
                            TelnetCode.NAWS,
                        ]
                    )
                )
            )
            return

        if isinstance(event, ApplicationDataEvent):
            _logger.debug(f"Application data received: {event!r}")
            self.ctx.send_outbound(BytesEvent(data=b"Go away!\r\n"))
            return

        if isinstance(event, SubnegotiationEvent):
            _logger.debug(f"Subnegotiation received: {event!r}")
