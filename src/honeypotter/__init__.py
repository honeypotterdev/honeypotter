import asyncio
import logging
from enum import Enum, auto, IntEnum

_logger = logging.getLogger(__name__)


class TelnetCmd(IntEnum):
    ECHO = 1
    SGA = 3
    SE = 240
    SB = 250
    WILL = 251
    WONT = 252
    DO = 253
    DONT = 254
    IAC = 255


class TelnetProtocolState(Enum):
    DATA = auto()
    IAC = auto()
    OPTION = auto()


class TelnetProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peername = None
        self._state: TelnetProtocolState = TelnetProtocolState.DATA
        self._data_buffer = bytearray()
        self._verb = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport
        self._peername = transport.get_extra_info("peername")

        _logger.info(f"Connection made: {self._peername}")

        self._transport.write(
            bytes(
                [
                    TelnetCmd.IAC,
                    TelnetCmd.WONT,
                    TelnetCmd.ECHO,
                    TelnetCmd.IAC,
                    TelnetCmd.DONT,
                    TelnetCmd.ECHO,
                    TelnetCmd.IAC,
                    TelnetCmd.WONT,
                    TelnetCmd.SGA,
                ]
            )
        )

    def connection_lost(self, exc: Exception | None) -> None:
        _logger.info(f"Connection lost: {self._peername}, reason: {exc!r}")

    def data_received(self, data: bytes) -> None:
        _logger.info(f"Data received: {data!r}")

        for byte in data:
            self._handle_state(byte)

        self._flush_data()

    def _set_state(self, state: TelnetProtocolState) -> None:
        _logger.debug(f"Setting state: {state!r}")

        self._state = state

    def _flush_data(self) -> None:
        if self._data_buffer:
            self.application_data_received(bytes(self._data_buffer))
            self._data_buffer.clear()

    def _handle_state(self, byte: int) -> None:
        if self._state == TelnetProtocolState.DATA:
            self._handle_data_state(byte)
            return

        if self._state == TelnetProtocolState.IAC:
            self._handle_iac_state(byte)
            return

        if self._state == TelnetProtocolState.OPTION:
            self._handle_option_state(byte)
            return

        raise RuntimeError(f"Unknown state: {self._state!r}")

    def _handle_data_state(self, byte: int) -> None:
        if byte != TelnetCmd.IAC:
            self._data_buffer.append(byte)
            return

        self._flush_data()
        self._set_state(TelnetProtocolState.IAC)

    def _handle_iac_state(self, byte: int) -> None:
        if byte == TelnetCmd.IAC:
            self._data_buffer.append(255)
            self._set_state(TelnetProtocolState.DATA)
            return

        if TelnetCmd.WILL <= byte <= TelnetCmd.DONT:
            self._verb = byte
            self._set_state(TelnetProtocolState.OPTION)
            return

        self.command_received(byte)
        self._set_state(TelnetProtocolState.DATA)

    def _handle_option_state(self, byte: int) -> None:
        self.option_received(self._verb, byte)
        self._set_state(TelnetProtocolState.DATA)

    def application_data_received(self, data: bytes) -> None:
        _logger.info(f"Application data received: {data!r}")

    def command_received(self, cmd: int) -> None:
        _logger.info(f"Command received: {cmd!r}")

    def option_received(self, verb: int, option: int) -> None:
        _logger.info(f"Option received: {verb!r}, cmd: {option!r}")


async def run():
    loop = asyncio.get_running_loop()

    server = await loop.create_server(TelnetProtocol, "127.0.0.1", 2323)

    async with server:
        await server.serve_forever()


def main() -> None:
    logging.basicConfig(level=logging.DEBUG)

    asyncio.run(run())
