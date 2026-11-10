from unittest.mock import Mock, call

from honeypotter.core import HandlerContext
from honeypotter.events import DataReceived, LineReceived
from honeypotter.handlers import LineDecoderHandler


def test_line_decoder_cr() -> None:
    context = Mock(spec=HandlerContext)

    handler = LineDecoderHandler()
    handler.handle_inbound(context, DataReceived(data=b"foo\rbar\r"))

    assert context.send_inbound.call_args_list == [call(LineReceived(line=b"foo")), call(LineReceived(line=b"bar"))]


def test_line_decoder_lf() -> None:
    context = Mock(spec=HandlerContext)

    handler = LineDecoderHandler()
    handler.handle_inbound(context, DataReceived(data=b"foo\nbar\n"))

    assert context.send_inbound.call_args_list == [call(LineReceived(line=b"foo")), call(LineReceived(line=b"bar"))]


def test_line_decoder_empty_new_line() -> None:
    context = Mock(spec=HandlerContext)

    handler = LineDecoderHandler()
    handler.handle_inbound(context, DataReceived(data=b"\n"))

    context.send_inbound.assert_called_once_with(LineReceived(line=b""))


def test_line_decoder_split_across_events() -> None:
    context = Mock(spec=HandlerContext)

    handler = LineDecoderHandler()
    handler.handle_inbound(context, DataReceived(data=b"fo"))
    handler.handle_inbound(context, DataReceived(data=b"o\nbar\n"))

    assert context.send_inbound.call_args_list == [call(LineReceived(line=b"foo")), call(LineReceived(line=b"bar"))]


def test_line_decoder_buffering() -> None:
    context = Mock(spec=HandlerContext)

    handler = LineDecoderHandler()
    handler.handle_inbound(context, DataReceived(data=b"foo"))

    context.send_inbound.assert_not_called()
