from collections import defaultdict
from enum import Enum, auto

from honeypotter.statemachine import Machine, Transition


class NegotiationAction(Enum):
    SEND_ENABLE = auto()
    SEND_DISABLE = auto()


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
                    source=QState.NO, event=QInput.REQUEST_ENABLE, target=QState.WANTYES_EMPTY, action="send_enable"
                ),
                Transition(
                    source=QState.NO, event=QInput.RECEIVE_ENABLE_ALLOWED, target=QState.YES, action="send_enable"
                ),
                Transition(
                    source=QState.NO, event=QInput.RECEIVE_ENABLE_DISALLOWED, target=QState.NO, action="send_disable"
                ),
                # YES
                Transition(
                    source=QState.YES, event=QInput.REQUEST_DISABLE, target=QState.WANTNO_EMPTY, action="send_disable"
                ),
                Transition(source=QState.YES, event=QInput.RECEIVE_DISABLE, target=QState.NO, action="send_disable"),
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
                    action="send_enable",
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
                    action="send_disable",
                ),
                Transition(
                    source=QState.WANTYES_OPPOSITE,
                    event=QInput.RECEIVE_ENABLE_DISALLOWED,
                    target=QState.WANTNO_EMPTY,
                    action="send_disable",
                ),
                Transition(source=QState.WANTYES_OPPOSITE, event=QInput.RECEIVE_DISABLE, target=QState.NO),
            ],
        )

    @property
    def state(self) -> QState:
        return self._machine.state

    def handle_input(self, option_input: QInput) -> NegotiationAction | None:
        return self._machine.trigger(option_input)

    def send_enable(self) -> NegotiationAction:
        return NegotiationAction.SEND_ENABLE

    def send_disable(self) -> NegotiationAction:
        return NegotiationAction.SEND_DISABLE


class OptionNegotiator:
    def __init__(self) -> None:
        self._options: dict[int, QMethod] = defaultdict[int, QMethod](lambda: QMethod())

    def is_enabled(self, option: int) -> bool:
        return self._options[option].state is QState.YES

    def request_enable(self, option: int) -> NegotiationAction | None:
        return self._options[option].handle_input(QInput.REQUEST_ENABLE)

    def request_disable(self, option: int) -> NegotiationAction | None:
        return self._options[option].handle_input(QInput.REQUEST_DISABLE)

    def receive_enable(self, option: int, *, allowed: bool) -> NegotiationAction | None:
        return self._options[option].handle_input(
            QInput.RECEIVE_ENABLE_ALLOWED if allowed else QInput.RECEIVE_ENABLE_DISALLOWED
        )

    def receive_disable(self, option: int) -> NegotiationAction | None:
        return self._options[option].handle_input(QInput.RECEIVE_DISABLE)
