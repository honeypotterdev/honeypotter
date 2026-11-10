from unittest.mock import MagicMock, call

from honeypotter.commands import WriteData
from honeypotter.core import HandlerContext
from honeypotter.events import ConnectionOpened, LineReceived
from honeypotter.shell.handlers import BusyboxShellHandler


class TestBusyboxShellHandler:
    def test(self) -> None:
        context = MagicMock(spec=HandlerContext)

        handler = BusyboxShellHandler()

        handler.handle_inbound(context, ConnectionOpened())
        handler.handle_inbound(context, LineReceived(line=b"john"))
        handler.handle_inbound(context, LineReceived(line=b"secret"))
        handler.handle_inbound(context, LineReceived(line=b"enable"))

        assert context.send_outbound.call_args_list == [
            call(WriteData(data=b"login: ")),
            call(WriteData(data=b"password: ")),
            call(WriteData(data=b"/ # ")),
            call(WriteData(data=b"sh: enable: not found\n/ # ")),
        ]
