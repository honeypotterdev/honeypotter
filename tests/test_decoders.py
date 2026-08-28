from unittest.mock import Mock, call

from honeypotter.core import Context
from honeypotter.decoders import LineDecoder, LineEvent
from honeypotter.transport import DataEvent


def test_line_decoder_cr() -> None:
    context = Mock(spec=Context)

    layer = LineDecoder(context)
    layer.handle_inbound(DataEvent(data=b"foo\rbar\r"))

    assert context.send_inbound.call_args_list == [call(LineEvent(line=b"foo")), call(LineEvent(line=b"bar"))]


def test_line_decoder_lf() -> None:
    context = Mock(spec=Context)

    layer = LineDecoder(context)
    layer.handle_inbound(DataEvent(data=b"foo\nbar\n"))

    assert context.send_inbound.call_args_list == [call(LineEvent(line=b"foo")), call(LineEvent(line=b"bar"))]


def test_line_decoder_empty_new_line() -> None:
    context = Mock(spec=Context)

    layer = LineDecoder(context)
    layer.handle_inbound(DataEvent(data=b"\n"))

    context.send_inbound.assert_called_once_with(LineEvent(line=b""))


def test_line_decoder_split_across_events() -> None:
    context = Mock(spec=Context)

    layer = LineDecoder(context)
    layer.handle_inbound(DataEvent(data=b"fo"))
    layer.handle_inbound(DataEvent(data=b"o\nbar\n"))

    assert context.send_inbound.call_args_list == [call(LineEvent(line=b"foo")), call(LineEvent(line=b"bar"))]


def test_line_decoder_buffering() -> None:
    context = Mock(spec=Context)

    layer = LineDecoder(context)
    layer.handle_inbound(DataEvent(data=b"foo"))

    context.send_inbound.assert_not_called()
