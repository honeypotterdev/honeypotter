from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class ConnectPacket:
    client_id: str
    protocol_name: str = "MQTT"
    protocol_level: int = 4
    clean_session: bool = True
    keep_alive: int = 60
    will_topic: str | None = None
    will_payload: bytes | None = None
    will_qos: int = 0
    will_retain: bool = False
    username: str | None = None
    password: bytes | None = None


type MqttValue = ConnectPacket
