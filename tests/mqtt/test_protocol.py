from honeypotter.mqtt.protocol import MqttConnection
from honeypotter.mqtt.values import ConnectPacket


class TestMqttConnection:
    def test_send_connect(self) -> None:
        connection = MqttConnection()

        assert (
            connection.send_connect(client_id="john")
            == b"\x10\x10\x00\x04\x4d\x51\x54\x54\x04\x02\x00\x3c\x00\x04\x6a\x6f\x68\x6e"
        )

    def test_receive_data(self) -> None:
        connection = MqttConnection()

        assert connection.receive_data(connection.send_connect(client_id="john")) == [ConnectPacket(client_id="john")]
