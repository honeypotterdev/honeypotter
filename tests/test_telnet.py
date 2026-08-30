from unittest.mock import Mock, call

from honeypotter.core import Context
from honeypotter.telnet import CommandEvent, TelnetCode, TelnetCodec
from honeypotter.transport import DataEvent


def test_telnet_code_unknown() -> None:
    assert TelnetCode(99) == 99
    assert TelnetCode(99) is TelnetCode(99)
    assert repr(TelnetCode(99)) == "<TelnetCode.UNKNOWN_99: 99>"


def test_telnet_codec_data_event() -> None:
    context = Mock(spec=Context)

    layer = TelnetCodec(context)
    layer.handle_inbound(DataEvent(b"foo"))

    context.send_inbound.assert_called_once_with(DataEvent(data=b"foo"))


def test_telnet_codec_iac_escape() -> None:
    context = Mock(spec=Context)

    layer = TelnetCodec(context)
    layer.handle_inbound(DataEvent(data=bytes([255, 255])))

    context.send_inbound.assert_called_once_with(DataEvent(data=bytes([255])))


def test_telnet_codec_cr_lf() -> None:
    context = Mock(spec=Context)

    layer = TelnetCodec(context)
    layer.handle_inbound(DataEvent(data=b"foo\r\nbar"))

    context.send_inbound.assert_called_once_with(DataEvent(data=b"foo\nbar"))


def test_telnet_codec_cr_lf_split_across_events() -> None:
    context = Mock(spec=Context)

    layer = TelnetCodec(context)
    layer.handle_inbound(DataEvent(data=b"foo\r"))
    layer.handle_inbound(DataEvent(data=b"\nbar"))

    assert context.send_inbound.call_args_list == [call(DataEvent(data=b"foo")), call(DataEvent(data=b"\nbar"))]


def test_telnet_codec_cr_nul() -> None:
    context = Mock(spec=Context)

    layer = TelnetCodec(context)
    layer.handle_inbound(DataEvent(data=b"foo\r\0bar"))

    context.send_inbound.assert_called_once_with(DataEvent(data=b"foo\rbar"))


def test_telnet_codec_cr_nul_split_across_events() -> None:
    context = Mock(spec=Context)

    layer = TelnetCodec(context)
    layer.handle_inbound(DataEvent(data=b"foo\r"))
    layer.handle_inbound(DataEvent(data=b"\0bar"))

    assert context.send_inbound.call_args_list == [call(DataEvent(data=b"foo")), call(DataEvent(data=b"\rbar"))]


def test_telnet_codec_cr() -> None:
    context = Mock(spec=Context)

    layer = TelnetCodec(context)
    layer.handle_inbound(DataEvent(data=b"foo\rbar"))

    context.send_inbound.assert_called_once_with(DataEvent(data=b"foo\rbar"))


def test_telnet_codec_cr_split_across_events() -> None:
    context = Mock(spec=Context)

    layer = TelnetCodec(context)
    layer.handle_inbound(DataEvent(data=b"foo\r"))
    layer.handle_inbound(DataEvent(data=b"bar"))

    assert context.send_inbound.call_args_list == [call(DataEvent(data=b"foo")), call(DataEvent(data=b"\rbar"))]


def test_telnet_codec_command_event() -> None:
    context = Mock(spec=Context)

    layer = TelnetCodec(context)
    layer.handle_inbound(DataEvent(data=bytes([255, 246])))  # Are You There

    context.send_inbound.assert_called_once_with(CommandEvent(command=246))
