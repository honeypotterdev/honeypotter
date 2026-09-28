from honeypotter.telnet.options import NegotiationAction, NegotiationResult, OptionNegotiator


class TestOptionNegotiator:
    def test(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.is_enabled(1) is False

    def test_is_enabled_tracks_options_independently(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.receive_enable(1, allowed=True) == NegotiationResult(
            action=NegotiationAction.SEND_ENABLE, option_changed=True
        )
        assert negotiator.is_enabled(1) is True
        assert negotiator.is_enabled(2) is False

    def test_request_enable_sends_enable_once(self) -> None:
        negotiator = OptionNegotiator()

        assert negotiator.request_enable(1) == NegotiationResult(
            action=NegotiationAction.SEND_ENABLE, option_changed=False
        )
        assert negotiator.request_enable(1) == NegotiationResult(action=None, option_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_request_disable_sends_disable_once(self) -> None:
        negotiator = OptionNegotiator()
        self._enable(negotiator, 1)

        assert negotiator.request_disable(1) == NegotiationResult(
            action=NegotiationAction.SEND_DISABLE, option_changed=True
        )
        assert negotiator.request_disable(1) == NegotiationResult(action=None, option_changed=False)
        assert negotiator.is_enabled(1) is False

    def _enable(self, negotiator: OptionNegotiator, option: int) -> None:
        assert negotiator.receive_enable(option, allowed=True) == NegotiationResult(
            action=NegotiationAction.SEND_ENABLE, option_changed=True
        )
        assert negotiator.is_enabled(option) is True
