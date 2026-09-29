from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, auto

from honeypotter.statemachine import Machine, Transition


class Action(Enum):
    SEND_ENABLE = auto()
    SEND_DISABLE = auto()


@dataclass(kw_only=True)
class Result:
    action: Action | None
    option_changed: bool


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


class QMethod:
    def __init__(self) -> None:
        self._machine = Machine(
            model=self,
            initial=QState.NO,
            raise_on_invalid_transition=False,
            transitions=[
                # NO
                Transition(
                    source=QState.NO, event=QInput.REQUEST_ENABLE, target=QState.WANTYES_EMPTY, action="_send_enable"
                ),
                Transition(
                    source=QState.NO, event=QInput.RECEIVE_ENABLE_ALLOWED, target=QState.YES, action="_send_enable"
                ),
                Transition(
                    source=QState.NO, event=QInput.RECEIVE_ENABLE_DISALLOWED, target=QState.NO, action="_send_disable"
                ),
                # YES
                Transition(
                    source=QState.YES, event=QInput.REQUEST_DISABLE, target=QState.WANTNO_EMPTY, action="_send_disable"
                ),
                Transition(source=QState.YES, event=QInput.RECEIVE_DISABLE, target=QState.NO, action="_send_disable"),
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
                    action="_send_enable",
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
                    action="_send_disable",
                ),
                Transition(
                    source=QState.WANTYES_OPPOSITE,
                    event=QInput.RECEIVE_ENABLE_DISALLOWED,
                    target=QState.WANTNO_EMPTY,
                    action="_send_disable",
                ),
                Transition(source=QState.WANTYES_OPPOSITE, event=QInput.RECEIVE_DISABLE, target=QState.NO),
            ],
        )

    @property
    def is_enabled(self) -> bool:
        return self._machine.state is QState.YES

    def handle_input(self, option_input: QInput) -> Result:
        was_enabled = self.is_enabled
        action = self._machine.trigger(option_input)
        is_enabled = self.is_enabled

        return Result(action=action, option_changed=was_enabled != is_enabled)

    def _send_enable(self) -> Action:
        return Action.SEND_ENABLE

    def _send_disable(self) -> Action:
        return Action.SEND_DISABLE


class OptionNegotiator:
    def __init__(self) -> None:
        self._options: dict[int, QMethod] = defaultdict[int, QMethod](lambda: QMethod())

    def is_enabled(self, option: int) -> bool:
        return self._options[option].is_enabled

    def request(self, option: int, *, enable: bool) -> Result:
        q_input = QInput.REQUEST_ENABLE if enable else QInput.REQUEST_DISABLE

        return self._options[option].handle_input(q_input)

    def receive(self, option: int, *, enable: bool, allowed: bool) -> Result:
        if enable:
            q_input = QInput.RECEIVE_ENABLE_ALLOWED if allowed else QInput.RECEIVE_ENABLE_DISALLOWED
        else:
            q_input = QInput.RECEIVE_DISABLE

        return self._options[option].handle_input(q_input)
