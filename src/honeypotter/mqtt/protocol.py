from dataclasses import dataclass

from honeypotter.mqtt.parser import MqttParseError, MqttParser
from honeypotter.mqtt.utils import remaining_length_encode
from honeypotter.mqtt.values import MqttValue


@dataclass(frozen=True, kw_only=True)
class ProtocolErrorOccurred:
    pass


type ConnectionEvent = MqttValue | ProtocolErrorOccurred


class MqttConnection:
    def __init__(self) -> None:
        self._parser = MqttParser()
        self._receive_failed = False

    def send_connect(
        self,
        *,
        protocol_name: str = "MQTT",
        protocol_level: int = 4,
        username: str | None = None,
        password: str | None = None,
        will_retain: bool = False,
        will_qos: int = 0,
        clean_session: bool = True,
        keep_alive: int = 60,
        client_id: str,
    ):
        protocol_name_bytes = protocol_name.encode("utf-8")
        protocol_name_length_bytes = len(protocol_name_bytes).to_bytes(length=2)
        protocol_level_bytes = protocol_level.to_bytes()
        connect_flags = 0

        if clean_session:
            connect_flags |= 2

        connect_flags_bytes = connect_flags.to_bytes()
        keep_alive_bytes = keep_alive.to_bytes(length=2)

        variable_header = (
            protocol_name_length_bytes
            + protocol_name_bytes
            + protocol_level_bytes
            + connect_flags_bytes
            + keep_alive_bytes
        )

        client_id_bytes = client_id.encode("utf-8")
        client_id_length_bytes = len(client_id_bytes).to_bytes(length=2)

        payload = client_id_length_bytes + client_id_bytes

        remaining_length = remaining_length_encode(len(variable_header + payload))

        return b"\x10" + remaining_length + variable_header + payload

    def receive_data(self, data: bytes) -> list:
        if self._receive_failed:
            return []

        events: list = []

        for byte in data:
            try:
                event = self._parser.feed_byte(byte)
            except MqttParseError:
                self._receive_failed = True
                events.append(ProtocolErrorOccurred())
                return events

            if event is not None:
                events.append(event)

        return events
