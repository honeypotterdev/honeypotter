import pytest

from honeypotter.mqtt.protocol import MqttConnection
from honeypotter.mqtt.values import ConnectPacket, PublishPacket, Subscription


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
        assert connection.send_pub_ack(message_identifier=1) == b"\x40\x02\x00\x01"

    def test_send_subscribe_packet(self, connection: MqttConnection) -> None:
        assert (
            connection.send_subscribe_packet(
                message_identifier=1, subscriptions=[Subscription(topic_filter="foo", qos=0)]
            )
            == b"\x82\x08\x00\x01\x00\x03\x66\x6f\x6f\x00"
        )

    def test_receive_data_connect_packet(self, connection: MqttConnection) -> None:
        packet = ConnectPacket(client_id="john")

        assert connection.receive_data(packet.to_bytes()) == [packet]

    def test_receive_data_publish_packet(self, connection: MqttConnection) -> None:
        packet = PublishPacket(topic_name="foo")

        assert connection.receive_data(packet.to_bytes()) == [packet]
