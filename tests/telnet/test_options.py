import pytest

from honeypotter.telnet.options import NegotiationAction, NegotiationResult, OptionNegotiator


class TestOptionNegotiator:
    @pytest.fixture
    def negotiator(self) -> OptionNegotiator:
        return OptionNegotiator(allowed_options=[1])

    def test_is_enabled_defaults_to_false(self, negotiator: OptionNegotiator) -> None:
        assert negotiator.is_enabled(1) is False

    def test_is_enabled_tracks_options_independently(self, negotiator: OptionNegotiator) -> None:
        negotiator.receive(1, enable=True)

        assert negotiator.is_enabled(1) is True
        assert negotiator.is_enabled(2) is False

    def test_request_enable_sends_enable_once(self, negotiator: OptionNegotiator) -> None:
        assert negotiator.request(1, enable=True) == NegotiationResult(
            action=NegotiationAction.SEND_ENABLE, enabled_changed=False
        )
        assert negotiator.request(1, enable=True) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_request_disable_sends_disable_once(self, negotiator: OptionNegotiator) -> None:
        negotiator.receive(1, enable=True)

        assert negotiator.request(1, enable=False) == NegotiationResult(
            action=NegotiationAction.SEND_DISABLE, enabled_changed=True
        )
        assert negotiator.request(1, enable=False) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_request_enable_when_enabled_is_noop(self, negotiator: OptionNegotiator) -> None:
        negotiator.receive(1, enable=True)

        assert negotiator.request(1, enable=True) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is True

    def test_request_disable_when_disabled_is_noop(self, negotiator: OptionNegotiator) -> None:
        assert negotiator.request(1, enable=False) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_peer_accepts_pending_enable(self, negotiator: OptionNegotiator) -> None:
        negotiator.request(1, enable=True)

        assert negotiator.receive(1, enable=True) == NegotiationResult(action=None, enabled_changed=True)
        assert negotiator.is_enabled(1) is True

    def test_peer_accepts_pending_disable(self, negotiator: OptionNegotiator) -> None:
        negotiator.receive(1, enable=True)
        negotiator.request(1, enable=False)

        assert negotiator.receive(1, enable=False) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_peer_rejects_pending_enable(self, negotiator: OptionNegotiator) -> None:
        negotiator.request(1, enable=True)

        assert negotiator.receive(1, enable=False) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_peer_rejects_pending_disable(self, negotiator: OptionNegotiator) -> None:
        negotiator.receive(1, enable=True)
        negotiator.request(1, enable=False)

        assert negotiator.receive(1, enable=True) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_unsolicited_enable_for_allowed_option_is_accepted(self, negotiator: OptionNegotiator) -> None:
        assert negotiator.receive(1, enable=True) == NegotiationResult(
            action=NegotiationAction.SEND_ENABLE, enabled_changed=True
        )
        assert negotiator.is_enabled(1) is True

    def test_unsolicited_enable_for_disallowed_option_is_rejected(self, negotiator: OptionNegotiator) -> None:
        assert negotiator.receive(2, enable=True) == NegotiationResult(
            action=NegotiationAction.SEND_DISABLE, enabled_changed=False
        )
        assert negotiator.is_enabled(2) is False

    def test_unsolicited_disable_acknowledged(self, negotiator: OptionNegotiator) -> None:
        negotiator.receive(1, enable=True)

        assert negotiator.receive(1, enable=False) == NegotiationResult(
            action=NegotiationAction.SEND_DISABLE, enabled_changed=True
        )
        assert negotiator.is_enabled(1) is False

    def test_unsolicited_disable_when_disabled_is_noop(self, negotiator: OptionNegotiator) -> None:
        assert negotiator.receive(1, enable=False) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_duplicate_receive_enable_is_noop(self, negotiator: OptionNegotiator) -> None:
        negotiator.receive(1, enable=True)

        assert negotiator.receive(1, enable=True) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is True

    def test_disable_is_queued_while_enable_is_pending(self, negotiator: OptionNegotiator) -> None:
        negotiator.request(1, enable=True)

        assert negotiator.request(1, enable=False) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is False
        assert negotiator.receive(1, enable=True) == NegotiationResult(
            action=NegotiationAction.SEND_DISABLE, enabled_changed=False
        )
        assert negotiator.is_enabled(1) is False
        assert negotiator.receive(1, enable=False) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_enable_is_queued_while_disable_is_pending(self, negotiator: OptionNegotiator) -> None:
        negotiator.receive(1, enable=True)
        negotiator.request(1, enable=False)

        assert negotiator.request(1, enable=True) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is False
        assert negotiator.receive(1, enable=False) == NegotiationResult(
            action=NegotiationAction.SEND_ENABLE, enabled_changed=False
        )
        assert negotiator.is_enabled(1) is False
        assert negotiator.receive(1, enable=True) == NegotiationResult(action=None, enabled_changed=True)
        assert negotiator.is_enabled(1) is True

    def test_request_enable_cancels_queued_disable(self, negotiator: OptionNegotiator) -> None:
        negotiator.request(1, enable=True)
        negotiator.request(1, enable=False)

        assert negotiator.request(1, enable=True) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.receive(1, enable=True) == NegotiationResult(action=None, enabled_changed=True)
        assert negotiator.is_enabled(1) is True

    def test_request_disable_cancels_queued_enable(self, negotiator: OptionNegotiator) -> None:
        negotiator.receive(1, enable=True)
        negotiator.request(1, enable=False)
        negotiator.request(1, enable=True)

        assert negotiator.request(1, enable=False) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.receive(1, enable=False) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_peer_rejects_enable_while_disable_is_queued(self, negotiator: OptionNegotiator) -> None:
        negotiator.request(1, enable=True)
        negotiator.request(1, enable=False)

        assert negotiator.receive(1, enable=False) == NegotiationResult(action=None, enabled_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_peer_rejects_disable_while_enable_is_queued(self, negotiator: OptionNegotiator) -> None:
        negotiator.receive(1, enable=True)
        negotiator.request(1, enable=False)
        negotiator.request(1, enable=True)

        assert negotiator.receive(1, enable=True) == NegotiationResult(action=None, enabled_changed=True)
        assert negotiator.is_enabled(1) is True
