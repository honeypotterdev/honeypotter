from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal


@dataclass(frozen=True, kw_only=True)
class Rule:
    source: Any
    event: Any
    target: Any
    condition: str | None = None
    action: str | None = None


class UnknownTransitionError(Exception):
    pass


class StateMachine(ABC):
    def __init__(self) -> None:
        self._current_state = self.get_initial_state()
        self._transitions = self._create_transitions()

    def get_strategy(self) -> Literal["ignore", "error"]:
        return "ignore"

    @abstractmethod
    def get_initial_state(self) -> Any: ...

    def get_final_state(self) -> Any:
        return None

    @abstractmethod
    def get_rules(self) -> list[Rule]: ...

    def get_current_state(self) -> Any:
        return self._current_state

    def send(self, event: Any, *args: Any, **kwargs: Any) -> Any | None:
        candidates = self._transitions[(self._current_state, event)]

        for candidate in candidates:
            if candidate.condition is not None:
                condition_callback = getattr(self, candidate.condition)

                if not condition_callback(*args, **kwargs):
                    continue

            self._current_state = candidate.target

            if candidate.action is None:
                return None

            action_callback = getattr(self, candidate.action)
            return action_callback(*args, **kwargs)

        if self.get_strategy() == "ignore":
            return None

        raise UnknownTransitionError(
            f"Unknown transition from {self._current_state!r} on {event!r} ({args!r}, {kwargs!r})"
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

    def _get_node_name(self, state: Any) -> str:
        if isinstance(state, Enum):
            return state.name

        return str(state)
