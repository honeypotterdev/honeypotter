from unittest.mock import Mock, call

import pytest

from honeypotter.core import HandlerContext
from honeypotter.telnet.handlers import TelnetHandler
from honeypotter.transport import ConnectionMadeEvent, DataEvent


class TestTelnetHandler:
    @pytest.fixture
    def handler(self) -> TelnetHandler:
        return TelnetHandler()

    def test(self, handler: TelnetHandler) -> None:
        context = Mock(spec=HandlerContext)

        handler.handle_inbound(context, ConnectionMadeEvent())
        handler.handle_inbound(context, DataEvent(data=b"hello"))

        assert context.send_outbound.call_args_list == [call(DataEvent(data=b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x03"))]
        assert context.send_inbound.call_args_list == [call(ConnectionMadeEvent()), call(DataEvent(data=b"hello"))]
