from dataclasses import dataclass

from honeypotter.mqtt.parser import MqttParseError, MqttParser
from honeypotter.mqtt.values import (
    ConnAckPacket,
    ConnectPacket,
    ConnectReturnCode,
    Packet,
    PubAckPacket,
    PublishPacket,
    SubscribePacket,
    Subscription,
)


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
        client_id: str | None = None,
        will_topic: str | None = None,
        will_payload: bytes | None = None,
        will_qos: int = 0,
        will_retain: bool = False,
        username: str | None = None,
        password: bytes | None = None,
    ) -> bytes:
        return ConnectPacket(
            protocol_name=protocol_name,
            protocol_level=protocol_level,
            clean_session=clean_session,
            keep_alive=keep_alive,
            client_id=client_id,
            will_topic=will_topic,
            will_message=will_payload,
            will_qos=will_qos,
            will_retain=will_retain,
            username=username,
            password=password,
        ).to_bytes()

    def send_conn_ack_packet(
        self, *, session_present: bool = False, return_code: ConnectReturnCode = ConnectReturnCode.ACCEPTED
    ) -> bytes:
        return ConnAckPacket(session_present=session_present, return_code=return_code).to_bytes()

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
        return PublishPacket(
            dup=dup,
            qos=qos,
            retain=retain,
            topic_name=topic_name,
            message_identifier=message_identifier,
            message=message,
        ).to_bytes()

    def send_pub_ack(self, message_identifier: int) -> bytes:
        return PubAckPacket(message_identifier=message_identifier).to_bytes()

    def send_subscribe_packet(self, *, message_identifier: int, subscriptions: list[Subscription]) -> bytes:
        return SubscribePacket(message_identifier=message_identifier, subscriptions=subscriptions).to_bytes()

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
