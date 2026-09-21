from dataclasses import dataclass
from enum import IntEnum

from honeypotter.mqtt.utils import remaining_length_encode


@dataclass(frozen=True, kw_only=True)
class ConnectPacket:
    protocol_name: str = "MQTT"
    protocol_level: int = 4
    clean_session: bool = True
    keep_alive: int = 60
    client_id: str
    will_topic: str | None = None
    will_message: bytes | None = None
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
        if self.will_topic is not None:
            connect_flags |= 4 | (self.will_qos << 3)
        if self.will_retain:
            connect_flags |= 32
        if self.password is not None:
            connect_flags |= 64
        if self.username is not None:
            connect_flags |= 128

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

        if self.will_topic is not None and self.will_message is not None:
            will_topic_bytes = self.will_topic.encode("utf-8")
            payload += len(will_topic_bytes).to_bytes(length=2) + will_topic_bytes
            payload += len(self.will_message).to_bytes(length=2) + self.will_message

        if self.username is not None:
            username_bytes = self.username.encode("utf-8")
            payload += len(username_bytes).to_bytes(length=2) + username_bytes
        if self.password is not None:
            payload += len(self.password).to_bytes(length=2) + self.password

        remaining_length = remaining_length_encode(len(variable_header + payload))

        return b"\x10" + remaining_length + variable_header + payload


class ConnectReturnCode(IntEnum):
    ACCEPTED = 0
    REFUSED_UNACCEPTABLE_PROTOCOL_VERSION = 1
    REFUSED_IDENTIFIER_REJECTED = 2
    REFUSED_SERVER_UNAVAILABLE = 3
    REFUSED_BAD_USER_NAME_OR_PASSWORD = 4
    REFUSED_NOT_AUTHORIZED = 5


@dataclass(frozen=True, kw_only=True)
class ConnAckPacket:
    session_present: bool = False
    return_code: ConnectReturnCode = ConnectReturnCode.ACCEPTED

    def to_bytes(self) -> bytes:
        ack_flags_bytes = int(self.session_present).to_bytes()
        return_code_bytes = self.return_code.to_bytes()
        variable_header = ack_flags_bytes + return_code_bytes
        remaining_length = remaining_length_encode(len(variable_header))

        return b"\x20" + remaining_length + variable_header


type MqttValue = ConnectPacket
