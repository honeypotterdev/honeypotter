from unittest.mock import Mock, call

from honeypotter.core import Context
from honeypotter.telnet import (
    CommandEvent,
    OptionAction,
    OptionNegotiator,
    TelnetCode,
    TelnetCodec,
)
from honeypotter.transport import DataEvent


def test_telnet_code_unknown() -> None:
    assert TelnetCode(99) == 99
    assert TelnetCode(99) is TelnetCode(99)
    assert repr(TelnetCode(99)) == "<TelnetCode.UNKNOWN_99: 99>"


class TestOptionNegotiator:
    def test_is_enabled_defaults_to_false(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.is_enabled(1) is False

    def test_is_enabled_tracks_options_independently(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.receive_enable(1, accept=True) is OptionAction.SEND_ENABLE
        assert negotiator.is_enabled(1) is True
        assert negotiator.is_enabled(2) is False

    def test_request_enable_sends_enable_once(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.request_enable(1) is OptionAction.SEND_ENABLE
        assert negotiator.request_enable(1) is None
        assert negotiator.is_enabled(1) is False

    def test_request_disable_sends_disable_once(self) -> None:
        negotiator = OptionNegotiator()
        self._enable(negotiator, 1)

        assert negotiator.request_disable(1) is OptionAction.SEND_DISABLE
        assert negotiator.request_disable(1) is None
        assert negotiator.is_enabled(1) is False

    def test_request_enable_when_enabled_is_ignored(self) -> None:
        negotiator = OptionNegotiator()
        self._enable(negotiator, 1)

        assert negotiator.request_enable(1) is None
        assert negotiator.is_enabled(1) is True

    def test_request_disable_when_disabled_is_ignored(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.request_disable(1) is None
        assert negotiator.is_enabled(1) is False

    def test_peer_accepts_pending_enable(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.request_enable(1) is OptionAction.SEND_ENABLE
        assert negotiator.receive_enable(1, accept=True) is None
        assert negotiator.is_enabled(1) is True

    def test_peer_accepts_pending_disable(self) -> None:
        negotiator = OptionNegotiator()
        self._enable(negotiator, 1)

        assert negotiator.request_disable(1) is OptionAction.SEND_DISABLE
        assert negotiator.receive_disable(1) is None
        assert negotiator.is_enabled(1) is False

    def test_peer_rejects_pending_enable(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.request_enable(1) is OptionAction.SEND_ENABLE
        assert negotiator.receive_disable(1) is None
        assert negotiator.is_enabled(1) is False

    def test_peer_rejects_pending_disable(self) -> None:
        negotiator = OptionNegotiator()
        self._enable(negotiator, 1)

        assert negotiator.request_disable(1) is OptionAction.SEND_DISABLE
        assert negotiator.receive_enable(1, accept=True) is None
        assert negotiator.is_enabled(1) is False

    def test_unsolicited_enable_accepted(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.receive_enable(1, accept=True) is OptionAction.SEND_ENABLE
        assert negotiator.is_enabled(1) is True

    def test_unsolicited_enable_rejected(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.receive_enable(1, accept=False) is OptionAction.SEND_DISABLE
        assert negotiator.is_enabled(1) is False

    def test_unsolicited_disable_acknowledged(self) -> None:
        negotiator = OptionNegotiator()
        self._enable(negotiator, 1)

        assert negotiator.receive_disable(1) is OptionAction.SEND_DISABLE
        assert negotiator.is_enabled(1) is False

    def test_unsolicited_disable_when_disabled_is_ignored(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.receive_disable(1) is None
        assert negotiator.is_enabled(1) is False

    def test_duplicate_receive_enable_is_ignored(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.receive_enable(1, accept=True) is OptionAction.SEND_ENABLE
        assert negotiator.receive_enable(1, accept=True) is None
        assert negotiator.is_enabled(1) is True

    def test_request_enable_pending_request_disable_queued(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.request_enable(1) is OptionAction.SEND_ENABLE
        assert negotiator.request_disable(1) is None
        assert negotiator.is_enabled(1) is False
        assert negotiator.receive_enable(1, accept=True) is OptionAction.SEND_DISABLE
        assert negotiator.is_enabled(1) is False
        assert negotiator.receive_disable(1) is None
        assert negotiator.is_enabled(1) is False

    def test_request_disable_pending_request_enable_queued(self) -> None:
        negotiator = OptionNegotiator()
        self._enable(negotiator, 1)

        assert negotiator.request_disable(1) is OptionAction.SEND_DISABLE
        assert negotiator.request_enable(1) is None
        assert negotiator.is_enabled(1) is False
        assert negotiator.receive_disable(1) is OptionAction.SEND_ENABLE
        assert negotiator.is_enabled(1) is False
        assert negotiator.receive_enable(1, accept=True) is None
        assert negotiator.is_enabled(1) is True

    def test_request_disable_cancelled(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.request_enable(1) is OptionAction.SEND_ENABLE
        assert negotiator.request_disable(1) is None
        assert negotiator.request_enable(1) is None
        assert negotiator.receive_enable(1, accept=True) is None
        assert negotiator.is_enabled(1) is True

    def test_request_enable_cancelled(self) -> None:
        negotiator = OptionNegotiator()
        self._enable(negotiator, 1)

        assert negotiator.request_disable(1) is OptionAction.SEND_DISABLE
        assert negotiator.request_enable(1) is None
        assert negotiator.request_disable(1) is None
        assert negotiator.receive_disable(1) is None
        assert negotiator.is_enabled(1) is False

    def test_peer_rejects_enable_while_disable_is_queued(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.request_enable(1) is OptionAction.SEND_ENABLE
        assert negotiator.request_disable(1) is None
        assert negotiator.receive_disable(1) is None
        assert negotiator.is_enabled(1) is False

    def test_peer_rejects_disable_while_enable_is_queued(self) -> None:
        negotiator = OptionNegotiator()
        self._enable(negotiator, 1)

        assert negotiator.request_disable(1) is OptionAction.SEND_DISABLE
        assert negotiator.request_enable(1) is None
        assert negotiator.receive_enable(1, accept=True) is None
        assert negotiator.is_enabled(1) is True

    def _enable(self, negotiator: OptionNegotiator, option: int) -> None:
        assert negotiator.receive_enable(option, accept=True) is OptionAction.SEND_ENABLE
        assert negotiator.is_enabled(option) is True


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
