import json
from collections.abc import Iterable
from typing import Any

from honeypotter.mqtt.events import ConnectReceived, Event, PublishReceived


def serialize_event(event: Event) -> str | None:
    match event:
        case ConnectReceived():
            return _serialize_event(
                event, "CONNECT", ("protocol_name", "protocol_level", "client_id", "username", "password")
            )
        case PublishReceived():
            return _serialize_event(event, "PUBLISH", ("topic_name", "message"))
        case _:
            return None


def _serialize_event(event: Event, name: str, attrs: Iterable[str]) -> str | None:
    pairs = [(name, attr) for name in attrs if (attr := getattr(event, name))]
    attrs = " ".join(f"{name}={_encode(value)}" for name, value in pairs)

    return f"{name} {attrs}"


def _encode(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")

    return json.dumps(value)
