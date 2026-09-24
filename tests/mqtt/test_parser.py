import pytest
from hypothesis import given
from hypothesis import strategies as st

from honeypotter.mqtt.parser import MqttParser
from honeypotter.mqtt.values import ConnectPacket


class TestMqttParser:
    @pytest.fixture
    def parser(self) -> MqttParser:
        return MqttParser()

    @given(protocol_name=st.text().filter(lambda text: "\x00" not in text))
    def test_connect_packet(self, protocol_name: str) -> None:
        parser = MqttParser()
        connect = ConnectPacket(protocol_name=protocol_name)

        packets = [packet for byte in connect.to_bytes() if (packet := parser.feed_byte(byte)) is not None]

        assert packets == [connect]
