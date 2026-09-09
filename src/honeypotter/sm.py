from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Any


class Rule:
    def __init__(
        self, source: Any, event: Any, target: Any, *, condition: str | None = None, action: str | None = None
    ) -> None:
        self.source = source
        self.event = event
        self.target = target
        self.condition = condition
        self.action = action


class StateMachine(ABC):
    def __init__(self) -> None:
        self._current_state = self.get_initial_state()
        self._transitions = self._get_transitions()

    @abstractmethod
    def get_initial_state(self) -> Any: ...

    @abstractmethod
    def get_rules(self) -> list[Rule]: ...

    def get_current_state(self) -> Any:
        return self._current_state

    def send(self, event: Any, **kwargs: Any) -> Any | None:
        candidates = self._transitions[(self._current_state, event)]

        for candidate in candidates:
            if candidate.condition is not None:
                condition_callback = getattr(self, candidate.condition)

                if not condition_callback(**kwargs):
                    continue

            self._current_state = candidate.target

            if candidate.action is not None:
                action_callback = getattr(self, candidate.action)
                return action_callback(**kwargs)

        return None

    def _get_transitions(self) -> dict[tuple[Any, Any], list[Rule]]:
        transitions = defaultdict(list)

        for rule in self.get_rules():
            transitions[(rule.source, rule.event)].append(rule)

        return transitions
