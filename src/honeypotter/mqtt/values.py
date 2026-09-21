from dataclasses import dataclass

from honeypotter.mqtt.utils import remaining_length_encode


@dataclass(frozen=True, kw_only=True)
class ConnectPacket:
    protocol_name: str = "MQTT"
    protocol_level: int = 4
    clean_session: bool = True
    keep_alive: int = 60
    client_id: str
    will_topic: str | None = None
    will_payload: bytes | None = None
    will_qos: int = 0
    will_retain: bool = False
    username: str | None = None
    password: bytes | None = None

    def to_bytes(self) -> bytes:
        protocol_name_bytes = self.protocol_name.encode("utf-8")
        protocol_name_length_bytes = len(protocol_name_bytes).to_bytes(length=2)
        protocol_level_bytes = self.protocol_level.to_bytes()
        connect_flags = 0

        if self.clean_session:
            connect_flags |= 2

        # TODO: Set will flag, Will QoS, Will retain, Password and Username connect flags

        connect_flags_bytes = connect_flags.to_bytes()
        keep_alive_bytes = self.keep_alive.to_bytes(length=2)

        variable_header = (
                protocol_name_length_bytes
                + protocol_name_bytes
                + protocol_level_bytes
                + connect_flags_bytes
                + keep_alive_bytes
        )

        client_id_bytes = self.client_id.encode("utf-8")
        client_id_length_bytes = len(client_id_bytes).to_bytes(length=2)

        payload = client_id_length_bytes + client_id_bytes

        # TODO: Add will topic, will message, username and password to payload

        remaining_length = remaining_length_encode(len(variable_header + payload))

        return b"\x10" + remaining_length + variable_header + payload


type MqttValue = ConnectPacket
