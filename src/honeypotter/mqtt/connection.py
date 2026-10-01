from dataclasses import dataclass

from honeypotter.mqtt.packets import (
    ConnectReturnCode,
    Packet,
    Subscription,
)
from honeypotter.mqtt.parsers import MqttParseError, MqttParser
from honeypotter.mqtt.utils import encode_remaining_length


@dataclass(frozen=True, kw_only=True)
class ProtocolErrorOccurred:
    pass


type ConnectionEvent = Packet | ProtocolErrorOccurred


class MqttConnection:
    def __init__(self) -> None:
        self._parser = MqttParser()
        self._receive_failed = False

    def send_connect_packet(
        self,
        *,
        protocol_name: str = "MQTT",
        protocol_level: int = 4,
        clean_session: bool = True,
        keep_alive: int = 60,
        client_id: str = "",
        will_topic: str | None = None,
        will_message: bytes | None = None,
        will_qos: int = 0,
        will_retain: bool = False,
        username: str | None = None,
        password: bytes | None = None,
    ) -> bytes:
        protocol_name_bytes = protocol_name.encode("utf-8")
        protocol_name_length_bytes = len(protocol_name_bytes).to_bytes(length=2)
        protocol_level_bytes = protocol_level.to_bytes()
        connect_flags = 0

        if clean_session:
            connect_flags |= 2
        if will_topic is not None:
            connect_flags |= 4 | (will_qos << 3)
        if will_retain:
            connect_flags |= 32
        if password is not None:
            connect_flags |= 64
        if username is not None:
            connect_flags |= 128

        connect_flags_bytes = connect_flags.to_bytes()
        keep_alive_bytes = keep_alive.to_bytes(length=2)

        variable_header = (
            protocol_name_length_bytes
            + protocol_name_bytes
            + protocol_level_bytes
            + connect_flags_bytes
            + keep_alive_bytes
        )

        if client_id:
            client_id_bytes = client_id.encode("utf-8")
            client_id_length_bytes = len(client_id_bytes).to_bytes(length=2)
        else:
            client_id_bytes = b""
            client_id_length_bytes = (0).to_bytes(length=2)

        payload = client_id_length_bytes + client_id_bytes

        if will_topic is not None and will_message is not None:
            will_topic_bytes = will_topic.encode("utf-8")
            payload += len(will_topic_bytes).to_bytes(length=2) + will_topic_bytes
            payload += len(will_message).to_bytes(length=2) + will_message

        if username is not None:
            username_bytes = username.encode("utf-8")
            payload += len(username_bytes).to_bytes(length=2) + username_bytes
        if password is not None:
            payload += len(password).to_bytes(length=2) + password

        remaining_length = encode_remaining_length(len(variable_header + payload))

        return b"\x10" + remaining_length + variable_header + payload

    def send_conn_ack_packet(
        self, *, session_present: bool = False, return_code: ConnectReturnCode = ConnectReturnCode.ACCEPTED
    ) -> bytes:
        ack_flags_bytes = int(session_present).to_bytes()
        return_code_bytes = return_code.to_bytes()
        variable_header = ack_flags_bytes + return_code_bytes
        remaining_length = encode_remaining_length(len(variable_header))

        return b"\x20" + remaining_length + variable_header

    def send_publish_packet(
        self,
        *,
        dup: bool = False,
        qos: int = 0,
        retain: bool = False,
        topic_name: str,
        message_identifier: int | None = None,
        message: bytes = b"",
    ) -> bytes:
        header = 48

        if dup:
            header |= 8
        if qos:
            header |= qos << 1
        if retain:
            header |= 1

        header_bytes = header.to_bytes()

        topic_name_bytes = topic_name.encode("utf-8")
        topic_name_length_bytes = len(topic_name_bytes).to_bytes(length=2)
        variable_header = topic_name_length_bytes + topic_name_bytes

        if message_identifier is not None:
            variable_header += message_identifier.to_bytes(length=2)

        remaining_length = encode_remaining_length(len(variable_header + message))

        return header_bytes + remaining_length + variable_header + message

    def send_pub_ack_packet(self, message_identifier: int) -> bytes:
        variable_header = message_identifier.to_bytes(length=2)
        remaining_length = encode_remaining_length(len(variable_header))

        return b"\x40" + remaining_length + variable_header

    def send_subscribe_packet(self, *, message_identifier: int, subscriptions: list[Subscription]) -> bytes:
        variable_header = message_identifier.to_bytes(length=2)
        payload = b""

        for subscription in subscriptions:
            subscription_topic_bytes = subscription.topic_filter.encode("utf-8")
            payload += (
                len(subscription_topic_bytes).to_bytes(length=2)
                + subscription_topic_bytes
                + subscription.qos.to_bytes()
            )

        remaining_length = encode_remaining_length(len(variable_header + payload))

        return b"\x82" + remaining_length + variable_header + payload

    def send_sub_ack_packet(self, message_identifier: int, return_codes: list[int]) -> bytes:
        variable_header = message_identifier.to_bytes(length=2)
        payload = b"".join(code.to_bytes() for code in return_codes)
        remaining_length = encode_remaining_length(len(variable_header + payload))

        return b"\x90" + remaining_length + variable_header + payload

    def send_disconnect(self) -> bytes:
        return b"\xe0\x00"

    def receive_data(self, data: bytes) -> list[ConnectionEvent]:
        if self._receive_failed:
            return []

        events: list[ConnectionEvent] = []

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
