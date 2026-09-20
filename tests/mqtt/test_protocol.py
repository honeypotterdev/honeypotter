from honeypotter.mqtt.protocol import MqttConnection


class TestMqttConnection:
    def test(self) -> None:
        connection = MqttConnection()

        assert (
            connection.send_connect(client_id="john")
            == b"\x10\x10\x00\x04\x4d\x51\x54\x54\x04\x02\x00\x3c\x00\x04\x6a\x6f\x68\x6e"
        )
