import pytest

from honeypotter.telnet.options import Action, Result, OptionNegotiator


class TestOptionNegotiator:
    @pytest.fixture
    def negotiator(self) -> OptionNegotiator:
        return OptionNegotiator()

    @pytest.fixture
    def enabled_negotiator(self, negotiator: OptionNegotiator) -> OptionNegotiator:
        negotiator.receive(1, enable=True, allowed=True)

        return negotiator

    def test_is_enabled_defaults_to_false(self, negotiator: OptionNegotiator) -> None:
        assert negotiator.is_enabled(1) is False

    def test_is_enabled_tracks_options_independently(self, negotiator: OptionNegotiator) -> None:
        negotiator.receive(1, enable=True, allowed=True)

        assert negotiator.is_enabled(1) is True
        assert negotiator.is_enabled(2) is False

    def test_request_enable_sends_enable_once(self, negotiator: OptionNegotiator) -> None:
        assert negotiator.request(1, enable=True) == Result(
            action=Action.SEND_ENABLE, option_changed=False
        )
        assert negotiator.request(1, enable=True) == Result(action=None, option_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_request_disable_sends_disable_once(self, enabled_negotiator: OptionNegotiator) -> None:
        assert enabled_negotiator.request(1, enable=False) == Result(
            action=Action.SEND_DISABLE, option_changed=True
        )
        assert enabled_negotiator.request(1, enable=False) == Result(action=None, option_changed=False)
        assert enabled_negotiator.is_enabled(1) is False

    def test_request_enable_when_enabled_is_ignored(self, enabled_negotiator: OptionNegotiator) -> None:
        assert enabled_negotiator.request(1, enable=True) == Result(action=None, option_changed=False)
        assert enabled_negotiator.is_enabled(1) is True

    def test_request_disable_when_disabled_is_ignored(self, negotiator: OptionNegotiator) -> None:
        assert negotiator.request(1, enable=False) == Result(action=None, option_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_peer_accepts_pending_enable(self, negotiator: OptionNegotiator) -> None:
        assert negotiator.request(1, enable=True) == Result(
            action=Action.SEND_ENABLE, option_changed=False
        )
        assert negotiator.receive(1, enable=True, allowed=True) == Result(action=None, option_changed=True)
        assert negotiator.is_enabled(1) is True

    def test_peer_accepts_pending_disable(self, enabled_negotiator: OptionNegotiator) -> None:
        assert enabled_negotiator.request(1, enable=False) == Result(
            action=Action.SEND_DISABLE, option_changed=True
        )
        assert enabled_negotiator.receive(1, enable=False, allowed=True) == Result(
            action=None, option_changed=False
        )
        assert enabled_negotiator.is_enabled(1) is False

    def test_peer_rejects_pending_enable(self, negotiator: OptionNegotiator) -> None:
        assert negotiator.request(1, enable=True) == Result(
            action=Action.SEND_ENABLE, option_changed=False
        )
        assert negotiator.receive(1, enable=False, allowed=True) == Result(action=None, option_changed=False)
        assert negotiator.is_enabled(1) is False

    def test_peer_rejects_pending_disable(self, enabled_negotiator: OptionNegotiator) -> None:
        assert enabled_negotiator.request(1, enable=False) == Result(
            action=Action.SEND_DISABLE, option_changed=True
        )
        assert enabled_negotiator.receive(1, enable=True, allowed=True) == Result(
            action=None, option_changed=False
        )
        assert enabled_negotiator.is_enabled(1) is False

    def test_unsolicited_enable_accepted(self, negotiator: OptionNegotiator) -> None:
        assert negotiator.receive(1, enable=True, allowed=True) == Result(
            action=Action.SEND_ENABLE, option_changed=True
        )
        assert negotiator.is_enabled(1) is True

    # TODO: Port all legacy tests
