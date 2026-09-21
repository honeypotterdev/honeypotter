import pytest

from honeypotter.mqtt.protocol import MqttConnection
from honeypotter.mqtt.values import ConnectPacket


class TestMqttConnection:
    @pytest.fixture
    def connection(self) -> MqttConnection:
        return MqttConnection()

    def test_send_connect_packet(self, connection: MqttConnection) -> None:
        assert (
            connection.send_connect_packet(client_id="john")
            == b"\x10\x10\x00\x04\x4d\x51\x54\x54\x04\x02\x00\x3c\x00\x04\x6a\x6f\x68\x6e"
        )

    def test_send_conn_ack_packet(self, connection: MqttConnection) -> None:
        assert connection.send_conn_ack_packet() == b"\x20\x02\x00\x00"

    def test_receive_data(self, connection: MqttConnection) -> None:
        packet = ConnectPacket(client_id="john")

        assert connection.receive_data(packet.to_bytes()) == [packet]
