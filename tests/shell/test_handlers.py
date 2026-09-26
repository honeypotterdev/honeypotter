from unittest.mock import MagicMock, call

from honeypotter.core import HandlerContext
from honeypotter.handlers import LineEvent
from honeypotter.shell.handlers import BusyboxShellHandler
from honeypotter.transport import ConnectionMadeEvent, DataEvent


class TestBusyboxShellHandler:
    def test(self) -> None:
        context = MagicMock(spec=HandlerContext)

        handler = BusyboxShellHandler()

        handler.handle_inbound(context, ConnectionMadeEvent())
        handler.handle_inbound(context, LineEvent(b"john"))
        handler.handle_inbound(context, LineEvent(b"secret"))
        handler.handle_inbound(context, LineEvent(b"enable"))

        assert context.send_outbound.call_args_list == [
            call(DataEvent(data=b"login: ")),
            call(DataEvent(data=b"password: ")),
            call(DataEvent(data=b"/ # ")),
            call(DataEvent(data=b"sh: enable: not found\n/ # ")),
        ]
