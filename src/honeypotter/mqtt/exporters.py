import json
from typing import Any

from honeypotter.mqtt.events import ConnectReceived, Event


def serialize_event(event: Event) -> str | None:
    match event:
        case ConnectReceived():
            return _serialize_connect(event)
        case _:
            return None


def _serialize_connect(event: ConnectReceived) -> str:
    target_attrs = ["protocol_name", "protocol_level", "client_id", "username", "password"]

    pairs = [(name, attr) for name in target_attrs if (attr := getattr(event, name))]
    attrs = " ".join(f"{name}={_encode(value)}" for name, value in pairs)

    return f"CONNECT {attrs}"


def _encode(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")

    return json.dumps(value)
