from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class ConnectPacket:
    client_id: str


type MqttValue = ConnectPacket
