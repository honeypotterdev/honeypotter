from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, auto

from honeypotter.statemachine import Machine, Transition


class NegotiationAction(Enum):
    SEND_ENABLE = auto()
    SEND_DISABLE = auto()


@dataclass(kw_only=True)
class NegotiationResult:
    action: NegotiationAction | None
    enabled_changed: bool


class QState(Enum):
    NO = auto()
    YES = auto()
    WANTNO_EMPTY = auto()
    WANTNO_OPPOSITE = auto()
    WANTYES_EMPTY = auto()
    WANTYES_OPPOSITE = auto()


class QInput(Enum):
    REQUEST_ENABLE = auto()
    REQUEST_DISABLE = auto()
    RECEIVE_ENABLE_ALLOWED = auto()
    RECEIVE_ENABLE_DISALLOWED = auto()
    RECEIVE_DISABLE = auto()


class QNegotiation:
    # https://www.rfc-editor.org/info/rfc1143/
    def __init__(self) -> None:
        self._machine = Machine(
            model=self,
            initial=QState.NO,
            raise_on_invalid_transition=False,
            transitions=[
                # NO
                Transition(
                    source=QState.NO,
                    event=QInput.REQUEST_ENABLE,
                    target=QState.WANTYES_EMPTY,
                    action="_send_enable_action",
                ),
                Transition(
                    source=QState.NO,
                    event=QInput.RECEIVE_ENABLE_ALLOWED,
                    target=QState.YES,
                    action="_send_enable_action",
                ),
                Transition(
                    source=QState.NO,
                    event=QInput.RECEIVE_ENABLE_DISALLOWED,
                    target=QState.NO,
                    action="_send_disable_action",
                ),
                # YES
                Transition(
                    source=QState.YES,
                    event=QInput.REQUEST_DISABLE,
                    target=QState.WANTNO_EMPTY,
                    action="_send_disable_action",
                ),
                Transition(
                    source=QState.YES, event=QInput.RECEIVE_DISABLE, target=QState.NO, action="_send_disable_action"
                ),
                # WANTNO_EMPTY
                Transition(source=QState.WANTNO_EMPTY, event=QInput.REQUEST_ENABLE, target=QState.WANTNO_OPPOSITE),
                Transition(source=QState.WANTNO_EMPTY, event=QInput.RECEIVE_ENABLE_ALLOWED, target=QState.NO),
                Transition(source=QState.WANTNO_EMPTY, event=QInput.RECEIVE_ENABLE_DISALLOWED, target=QState.NO),
                Transition(source=QState.WANTNO_EMPTY, event=QInput.RECEIVE_DISABLE, target=QState.NO),
                # WANTNO_OPPOSITE
                Transition(source=QState.WANTNO_OPPOSITE, event=QInput.REQUEST_DISABLE, target=QState.WANTNO_EMPTY),
                Transition(source=QState.WANTNO_OPPOSITE, event=QInput.RECEIVE_ENABLE_ALLOWED, target=QState.YES),
                Transition(source=QState.WANTNO_OPPOSITE, event=QInput.RECEIVE_ENABLE_DISALLOWED, target=QState.YES),
                Transition(
                    source=QState.WANTNO_OPPOSITE,
                    event=QInput.RECEIVE_DISABLE,
                    target=QState.WANTYES_EMPTY,
                    action="_send_enable_action",
                ),
                # WANTYES_EMPTY
                Transition(source=QState.WANTYES_EMPTY, event=QInput.REQUEST_DISABLE, target=QState.WANTYES_OPPOSITE),
                Transition(source=QState.WANTYES_EMPTY, event=QInput.RECEIVE_ENABLE_ALLOWED, target=QState.YES),
                Transition(source=QState.WANTYES_EMPTY, event=QInput.RECEIVE_ENABLE_DISALLOWED, target=QState.YES),
                Transition(source=QState.WANTYES_EMPTY, event=QInput.RECEIVE_DISABLE, target=QState.NO),
                # WANTYES_OPPOSITE
                Transition(source=QState.WANTYES_OPPOSITE, event=QInput.REQUEST_ENABLE, target=QState.WANTYES_EMPTY),
                Transition(
                    source=QState.WANTYES_OPPOSITE,
                    event=QInput.RECEIVE_ENABLE_ALLOWED,
                    target=QState.WANTNO_EMPTY,
                    action="_send_disable_action",
                ),
                Transition(
                    source=QState.WANTYES_OPPOSITE,
                    event=QInput.RECEIVE_ENABLE_DISALLOWED,
                    target=QState.WANTNO_EMPTY,
                    action="_send_disable_action",
                ),
                Transition(source=QState.WANTYES_OPPOSITE, event=QInput.RECEIVE_DISABLE, target=QState.NO),
            ],
        )

    @property
    def is_enabled(self) -> bool:
        return self._machine.state is QState.YES

    def send_input(self, option_input: QInput) -> NegotiationResult:
        was_enabled = self.is_enabled
        action = self._machine.trigger(option_input)
        is_enabled = self.is_enabled

        return NegotiationResult(action=action, enabled_changed=was_enabled != is_enabled)

    def _send_enable_action(self) -> NegotiationAction:
        return NegotiationAction.SEND_ENABLE

    def _send_disable_action(self) -> NegotiationAction:
        return NegotiationAction.SEND_DISABLE


class OptionNegotiator:
    def __init__(self) -> None:
        self._negotiations: dict[int, QNegotiation] = defaultdict[int, QNegotiation](lambda: QNegotiation())

    def is_enabled(self, option: int) -> bool:
        return self._negotiations[option].is_enabled

    def request(self, option: int, *, enable: bool) -> NegotiationResult:
        q_input = QInput.REQUEST_ENABLE if enable else QInput.REQUEST_DISABLE

        return self._negotiations[option].send_input(q_input)

    def receive(self, option: int, *, enable: bool, allowed: bool) -> NegotiationResult:
        if enable:
            q_input = QInput.RECEIVE_ENABLE_ALLOWED if allowed else QInput.RECEIVE_ENABLE_DISALLOWED
        else:
            q_input = QInput.RECEIVE_DISABLE

        return self._negotiations[option].send_input(q_input)
