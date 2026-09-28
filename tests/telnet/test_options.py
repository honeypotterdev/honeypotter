from honeypotter.telnet.options import NegotiationAction, OptionNegotiator


class TestOptionNegotiator:
    def test_is_enabled_defaults_to_false(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.is_enabled(1) is False

    def test_is_enabled_tracks_options_independently(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.receive_enable(1, allowed=True) is NegotiationAction.SEND_ENABLE
        assert negotiator.is_enabled(1) is True
        assert negotiator.is_enabled(2) is False

    def test_request_enable_sends_enable_once(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.request_enable(1) is NegotiationAction.SEND_ENABLE
        assert negotiator.request_enable(1) is None
        assert negotiator.is_enabled(1) is False
