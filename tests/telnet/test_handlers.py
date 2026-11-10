from unittest.mock import Mock, call

import pytest

from honeypotter.commands import WriteData
from honeypotter.core import HandlerContext
from honeypotter.events import ConnectionOpened, DataReceived
from honeypotter.telnet.handlers import TelnetHandler


class TestTelnetHandler:
    @pytest.fixture
    def handler(self) -> TelnetHandler:
        return TelnetHandler()

    def test(self, handler: TelnetHandler) -> None:
        context = Mock(spec=HandlerContext)

        handler.handle_inbound(context, ConnectionOpened())
        handler.handle_inbound(context, DataReceived(data=b"hello"))

        assert context.send_outbound.call_args_list == [call(WriteData(data=b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x03"))]
        assert context.send_inbound.call_args_list == [call(ConnectionOpened()), call(DataReceived(data=b"hello"))]
