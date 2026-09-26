from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any


class MachineError(Exception):
    pass


@dataclass(frozen=True)
class Transition[S, E]:
    event: E
    source: S
    target: S
    condition: str | None = None
    action: str | None = None


class Machine[S, E]:
    def __init__(
        self,
        *,
        model: Any,
        initial: S,
        final: S | None = None,
        transitions: list[Transition[S, E]],
        raise_on_invalid_transition: bool = True,
    ) -> None:
        self._model = model
        self._initial = initial
        self._final = final
        self._transitions = transitions
        self._raise_on_invalid_transition = raise_on_invalid_transition

        self._state = initial
        self._transition_table = self._create_transition_table(transitions)
        self._in_final_state = False

    @property
    def state(self) -> S:
        return self._state

    def trigger(self, event: E, *args: Any, **kwargs: Any) -> Any:
        if self._in_final_state:
            raise MachineError(f"Can't trigger event {event} from final state {self._state}")

        candidates = self._transition_table[(self._state, event)]

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

        if self._raise_on_invalid_transition:
            raise MachineError(f"Can't trigger event {event} from state {self._state}")

        return None

    def transition_to(self, state: S) -> None:
        self._state = state

        if self._final is not None and state == self._final:
            self._in_final_state = True

    def generate_mermaid_diagram(self, title: str) -> str:
        transitions = [f"[*] --> {self._get_node_name(self._initial)}"]

        for transition in self._transitions:
            source = self._get_node_name(transition.source)
            target = self._get_node_name(transition.target)
            event = self._get_node_name(transition.event)

            comment = event

            if transition.condition is not None:
                comment = f"{comment}[{transition.condition}]"

            transitions.append(f"{source} --> {target}: {comment}")

        if self._final is not None:
            transitions.append(f"{self._get_node_name(self._final)} --> [*]")

        return f"---\ntitle: {title}\n---\nstateDiagram-v2\n{'\n'.join(transitions)}"

    def _create_transition_table(
        self, transitions: list[Transition[S, E]]
    ) -> dict[tuple[S, E], list[Transition[S, E]]]:
        table = defaultdict(list)

        for transition in transitions:
            table[(transition.source, transition.event)].append(transition)

        return table

    def _get_node_name(self, state: Any) -> str:
        if isinstance(state, Enum):
            return state.name

        return str(state)
