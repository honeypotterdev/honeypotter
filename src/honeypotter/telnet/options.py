from collections import defaultdict
from enum import Enum, auto

from honeypotter.statemachine import Machine, Transition


class OptionAction(Enum):
    SEND_ENABLE = auto()
    SEND_DISABLE = auto()


class OptionState(Enum):
    NO = auto()
    YES = auto()
    WANTNO_EMPTY = auto()
    WANTNO_OPPOSITE = auto()
    WANTYES_EMPTY = auto()
    WANTYES_OPPOSITE = auto()


class OptionInput(Enum):
    REQUEST_ENABLE = auto()
    REQUEST_DISABLE = auto()
    RECEIVE_ENABLE_ACCEPT = auto()
    RECEIVE_ENABLE_REJECT = auto()
    RECEIVE_DISABLE = auto()


class TelnetOption:
    def __init__(self) -> None:
        self._machine = Machine(
            model=self,
            initial=OptionState.NO,
            raise_on_invalid_transition=False,
            transitions=[
                # NO
                Transition(
                    source=OptionState.NO,
                    event=OptionInput.REQUEST_ENABLE,
                    target=OptionState.WANTYES_EMPTY,
                    action="send_enable",
                ),
                Transition(
                    source=OptionState.NO,
                    event=OptionInput.RECEIVE_ENABLE_ACCEPT,
                    target=OptionState.YES,
                    action="send_enable",
                ),
                Transition(
                    source=OptionState.NO,
                    event=OptionInput.RECEIVE_ENABLE_REJECT,
                    target=OptionState.NO,
                    action="send_disable",
                ),
                # YES
                Transition(
                    source=OptionState.YES,
                    event=OptionInput.REQUEST_DISABLE,
                    target=OptionState.WANTNO_EMPTY,
                    action="send_disable",
                ),
                Transition(
                    source=OptionState.YES,
                    event=OptionInput.RECEIVE_DISABLE,
                    target=OptionState.NO,
                    action="send_disable",
                ),
                # WANTNO_EMPTY
                Transition(
                    source=OptionState.WANTNO_EMPTY,
                    event=OptionInput.REQUEST_ENABLE,
                    target=OptionState.WANTNO_OPPOSITE,
                ),
                Transition(
                    source=OptionState.WANTNO_EMPTY, event=OptionInput.RECEIVE_ENABLE_ACCEPT, target=OptionState.NO
                ),
                Transition(
                    source=OptionState.WANTNO_EMPTY, event=OptionInput.RECEIVE_ENABLE_REJECT, target=OptionState.NO
                ),
                Transition(source=OptionState.WANTNO_EMPTY, event=OptionInput.RECEIVE_DISABLE, target=OptionState.NO),
                # WANTNO_OPPOSITE
                Transition(
                    source=OptionState.WANTNO_OPPOSITE,
                    event=OptionInput.REQUEST_DISABLE,
                    target=OptionState.WANTNO_EMPTY,
                ),
                Transition(
                    source=OptionState.WANTNO_OPPOSITE, event=OptionInput.RECEIVE_ENABLE_ACCEPT, target=OptionState.YES
                ),
                Transition(
                    source=OptionState.WANTNO_OPPOSITE, event=OptionInput.RECEIVE_ENABLE_REJECT, target=OptionState.YES
                ),
                Transition(
                    source=OptionState.WANTNO_OPPOSITE,
                    event=OptionInput.RECEIVE_DISABLE,
                    target=OptionState.WANTYES_EMPTY,
                    action="send_enable",
                ),
                # WANTYES_EMPTY
                Transition(
                    source=OptionState.WANTYES_EMPTY,
                    event=OptionInput.REQUEST_DISABLE,
                    target=OptionState.WANTYES_OPPOSITE,
                ),
                Transition(
                    source=OptionState.WANTYES_EMPTY, event=OptionInput.RECEIVE_ENABLE_ACCEPT, target=OptionState.YES
                ),
                Transition(
                    source=OptionState.WANTYES_EMPTY, event=OptionInput.RECEIVE_ENABLE_REJECT, target=OptionState.YES
                ),
                Transition(source=OptionState.WANTYES_EMPTY, event=OptionInput.RECEIVE_DISABLE, target=OptionState.NO),
                # WANTYES_OPPOSITE
                Transition(
                    source=OptionState.WANTYES_OPPOSITE,
                    event=OptionInput.REQUEST_ENABLE,
                    target=OptionState.WANTYES_EMPTY,
                ),
                Transition(
                    source=OptionState.WANTYES_OPPOSITE,
                    event=OptionInput.RECEIVE_ENABLE_ACCEPT,
                    target=OptionState.WANTNO_EMPTY,
                    action="send_disable",
                ),
                Transition(
                    source=OptionState.WANTYES_OPPOSITE,
                    event=OptionInput.RECEIVE_ENABLE_REJECT,
                    target=OptionState.WANTNO_EMPTY,
                    action="send_disable",
                ),
                Transition(
                    source=OptionState.WANTYES_OPPOSITE, event=OptionInput.RECEIVE_DISABLE, target=OptionState.NO
                ),
            ],
        )

    @property
    def state(self) -> OptionState:
        return self._machine.state

    def handle_input(self, option_input: OptionInput) -> OptionAction | None:
        return self._machine.trigger(option_input)

    def send_enable(self) -> OptionAction:
        return OptionAction.SEND_ENABLE

    def send_disable(self) -> OptionAction:
        return OptionAction.SEND_DISABLE


class OptionsNegotiator:
    def __init__(self) -> None:
        self._options: dict[int, TelnetOption] = defaultdict[int, TelnetOption](lambda: TelnetOption())

    def is_enabled(self, option: int) -> bool:
        return self._options[option].state is OptionState.YES

    def request(self, option: int, enabled: bool) -> OptionAction | None:
        option_input = OptionInput.REQUEST_ENABLE if enabled else OptionInput.REQUEST_DISABLE

        return self._options[option].handle_input(option_input)

    def receive_enable(self, option: int, *, accept: bool) -> OptionAction | None:
        return self._options[option].handle_input(
            OptionInput.RECEIVE_ENABLE_ACCEPT if accept else OptionInput.RECEIVE_ENABLE_REJECT
        )

    def receive_disable(self, option: int) -> OptionAction | None:
        return self._options[option].handle_input(OptionInput.RECEIVE_DISABLE)
