from unittest.mock import MagicMock, call

from honeypotter.core import Context
from honeypotter.decoders import LineEvent
from honeypotter.shell import ShellSession
from honeypotter.transport import ConnectionMadeEvent, DataEvent


def test_shell_session() -> None:
    context = MagicMock(spec=Context)

    layer = ShellSession(context)

    layer.handle_inbound(ConnectionMadeEvent())
    layer.handle_inbound(LineEvent(b"john"))
    layer.handle_inbound(LineEvent(b"secret"))
    layer.handle_inbound(LineEvent(b"enable"))

    assert context.send_outbound.call_args_list == [
        call(DataEvent(data=b"login: ")),
        call(DataEvent(data=b"password: ")),
        call(DataEvent(data=b"/ # ")),
        call(DataEvent(data=b"sh: enable: not found\n")),
        call(DataEvent(data=b"/ # ")),
    ]


def test_shell_session_echo() -> None:
    context = MagicMock(spec=Context)

    layer = ShellSession(context)

    layer.handle_inbound(ConnectionMadeEvent())
    layer.handle_inbound(LineEvent(b"john"))
    layer.handle_inbound(LineEvent(b"secret"))
    layer.handle_inbound(LineEvent(b"echo hello"))

    assert context.send_outbound.call_args_list == [
        call(DataEvent(data=b"login: ")),
        call(DataEvent(data=b"password: ")),
        call(DataEvent(data=b"/ # ")),
        call(DataEvent(data=b"hello\n")),
        call(DataEvent(data=b"/ # ")),
    ]


def test_shell_session_echo_e() -> None:
    context = MagicMock(spec=Context)

    layer = ShellSession(context)

    layer.handle_inbound(ConnectionMadeEvent())
    layer.handle_inbound(LineEvent(b"john"))
    layer.handle_inbound(LineEvent(b"secret"))
    layer.handle_inbound(LineEvent(b'echo -e "\\x61\\x75\\x74\\x68\\x5f\\x6f\\x6b\\x0a"'))

    assert context.send_outbound.call_args_list == [
        call(DataEvent(data=b"login: ")),
        call(DataEvent(data=b"password: ")),
        call(DataEvent(data=b"/ # ")),
        call(DataEvent(data=b"auth_ok\n\n")),
        call(DataEvent(data=b"/ # ")),
    ]
