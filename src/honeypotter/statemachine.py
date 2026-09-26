from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any


@dataclass(frozen=True, kw_only=True)
class Rule:
    source: Any
    event: Any
    target: Any
    condition: str | None = None
    action: str | None = None


class StateMachineError(Exception):
    pass


class UnhandledEventError(StateMachineError):
    pass


class MachineTerminatedError(StateMachineError):
    pass


class StateMachine(ABC):
    def __init__(self) -> None:
        self._current_state = self.get_initial_state()
        self._transitions = self._create_transitions()

    @property
    def is_terminated(self) -> bool:
        final_state = self.get_final_state()

        return final_state is not None and self._current_state == final_state

    @abstractmethod
    def get_initial_state(self) -> Any: ...

    def get_final_state(self) -> Any:
        return None

    @abstractmethod
    def get_rules(self) -> list[Rule]: ...

    def get_current_state(self) -> Any:
        return self._current_state

    def send(self, event: Any, *args: Any, **kwargs: Any) -> Any | None:
        if self.is_terminated:
            raise MachineTerminatedError

        candidates = self._transitions[(self._current_state, event)]

        for candidate in candidates:
            if candidate.condition is not None:
                condition_callback = getattr(self, candidate.condition)

                if not condition_callback(*args, **kwargs):
                    continue

            self._transition_to(candidate.target)

            if candidate.action is None:
                return None

            action_callback = getattr(self, candidate.action)
            return action_callback(*args, **kwargs)

        self.on_unhandled_event(event, *args, **kwargs)

        return None

    def on_unhandled_event(self, event: Any, *args: Any, **kwargs: Any) -> None:
        raise UnhandledEventError(
            f"Unhandled event: {event!r}, state: {self._current_state!r}, args: {args!r}, kwargs: {kwargs!r}"
        )

    def get_mermaid_diagram(self) -> str:
        title = self.__class__.__name__
        transitions = [f"[*] --> {self._get_node_name(self.get_initial_state())}"]

        for rule in self.get_rules():
            source = self._get_node_name(rule.source)
            target = self._get_node_name(rule.target)
            event = self._get_node_name(rule.event)

            comment = event

            if rule.condition is not None:
                comment = f"{comment}[{rule.condition}]"

            transitions.append(f"{source} --> {target}: {comment}")

        if self.get_final_state() is not None:
            transitions.append(f"{self._get_node_name(self.get_final_state())} --> [*]")

        return f"---\ntitle: {title}\n---\nstateDiagram-v2\n{'\n'.join(transitions)}"

    def _create_transitions(self) -> dict[tuple[Any, Any], list[Rule]]:
        transitions = defaultdict(list)

        for rule in self.get_rules():
            transitions[(rule.source, rule.event)].append(rule)

        return transitions

    def _transition_to(self, state: Any) -> None:
        self._current_state = state

    def _get_node_name(self, state: Any) -> str:
        if isinstance(state, Enum):
            return state.name

        return str(state)


class MachineError(Exception):
    pass


@dataclass(frozen=True)
class Transition[S]:
    event: str
    source: S
    target: S
    condition: str | None = None
    action: str | None = None


class Machine[S]:
    def __init__(self, *, model: Any, initial: S, final: S | None = None, transitions: list[Transition[S]]) -> None:
        self._model = model
        self._initial = initial
        self._final = final
        self._transitions = transitions

        self._state = initial
        self._transition_table = self._create_transition_table(transitions)
        self._in_final_state = False

    @property
    def state(self) -> S:
        return self._state

    def trigger(self, event: str, *args: Any, **kwargs: Any) -> Any:
        if self._in_final_state:
            raise MachineError(f"Can't trigger event {event!r} from final state {self._state!r}")

        candidates = self._transition_table[(event, self._state)]

        for candidate in candidates:
            if candidate.condition is not None:
                condition_callback = getattr(self._model, candidate.condition)

                if not condition_callback(*args, **kwargs):
                    continue

            self.transition_to(candidate.target)

            if candidate.action is None:
                return None

            action_callback = getattr(self._model, candidate.action)
            return action_callback(*args, **kwargs)

        raise MachineError(f"Can't trigger event {event!r} from state {self._state!r}")

    def transition_to(self, state: S) -> None:
        self._state = state

        if self._final is not None and state == self._final:
            self._in_final_state = True

    def _create_transition_table(self, transitions: list[Transition[S]]) -> dict[tuple[str, S], list[Transition[S]]]:
        table = defaultdict(list)

        for transition in transitions:
            table[(transition.event, transition.source)].append(transition)

        return table
