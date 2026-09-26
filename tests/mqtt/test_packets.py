from honeypotter.mqtt.packets import ConnectPacket


class TestConnectPacket:
    def test_to_bytes(self) -> None:
        packet = ConnectPacket()

        assert packet.to_bytes() == b"\x10\x0c\x00\x04\x4d\x51\x54\x54\x04\x02\x00\x3c\x00\x00"

    def test_to_bytes_non_empty_client_id(self) -> None:
        packet = ConnectPacket(client_id="john")

        assert packet.to_bytes() == b"\x10\x10\x00\x04\x4d\x51\x54\x54\x04\x02\x00\x3c\x00\x04\x6a\x6f\x68\x6e"
