import pytest

from honeypotter.mqtt.connection import MqttConnection
from honeypotter.mqtt.packets import ConnectPacket, DisconnectPacket, PublishPacket, SubscribePacket, Subscription


class TestMqttConnection:
    @pytest.fixture
    def connection(self) -> MqttConnection:
        return MqttConnection()

    def test_send_connect_packet(self, connection: MqttConnection) -> None:
        assert connection.send_connect_packet() == b"\x10\x0c\x00\x04\x4d\x51\x54\x54\x04\x02\x00\x3c\x00\x00"

    def test_send_conn_ack_packet(self, connection: MqttConnection) -> None:
        assert connection.send_conn_ack_packet() == b"\x20\x02\x00\x00"

    def test_send_publish_packet(self, connection: MqttConnection) -> None:
        assert connection.send_publish_packet(topic_name="foo") == b"\x30\x05\x00\x03\x66\x6f\x6f"

    def test_send_pub_ack_packet(self, connection: MqttConnection) -> None:
        assert connection.send_pub_ack_packet(message_identifier=1) == b"\x40\x02\x00\x01"

    def test_send_subscribe_packet(self, connection: MqttConnection) -> None:
        assert (
            connection.send_subscribe_packet(
                message_identifier=1, subscriptions=[Subscription(topic_filter="foo", qos=0)]
            )
            == b"\x82\x08\x00\x01\x00\x03\x66\x6f\x6f\x00"
        )

    def test_send_sub_ack_packet(self, connection: MqttConnection) -> None:
        assert connection.send_sub_ack_packet(message_identifier=1, return_codes=[0]) == b"\x90\x03\x00\x01\x00"

    def test_receive_data_connect_packet(self, connection: MqttConnection) -> None:
        assert connection.receive_data(b"\x10\x10\x00\x04MQTT\x04\x02\x00<\x00\x04john") == [
            ConnectPacket(client_id="john")
        ]

    def test_receive_data_publish_packet(self, connection: MqttConnection) -> None:
        packet = PublishPacket(topic_name="foo")

        assert connection.receive_data(packet.to_bytes()) == [packet]

    def test_receive_data_subscribe_packet(self, connection: MqttConnection) -> None:
        packet = SubscribePacket(message_identifier=1, subscriptions=[Subscription(topic_filter="foo", qos=0)])

        assert connection.receive_data(packet.to_bytes()) == [packet]

    def test_receive_data_disconnect_packet(self, connection: MqttConnection) -> None:
        packet = DisconnectPacket()

        assert connection.receive_data(packet.to_bytes()) == [packet]
