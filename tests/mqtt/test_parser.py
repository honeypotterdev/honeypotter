from contextlib import suppress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from honeypotter.mqtt.packets import ConnectPacket
from honeypotter.mqtt.parsers import MqttParseError, MqttParser


class TestMqttParser:
    @pytest.fixture
    def parser(self) -> MqttParser:
        return MqttParser()

    @given(
        protocol_name=st.text(alphabet=st.characters(blacklist_categories=["Cc", "Cs", "Cn"])),
        protocol_level=st.integers(min_value=4, max_value=5),
        keep_alive=st.integers(min_value=0, max_value=65535),
        client_id=st.text(alphabet=st.characters(blacklist_categories=["Cc", "Cs", "Cn"])),
    )
    def test_connect_packet(self, protocol_name: str, protocol_level: int, keep_alive: int, client_id: str) -> None:
        parser = MqttParser()
        connect = ConnectPacket(
            protocol_name=protocol_name, protocol_level=protocol_level, keep_alive=keep_alive, client_id=client_id
        )

        packets = [packet for byte in connect.to_bytes() if (packet := parser.feed_byte(byte)) is not None]

        assert packets == [connect]

    @given(data=st.binary())
    def test_general_fuzz(self, data: bytes) -> None:
        parser = MqttParser()

        for byte in data:
            with suppress(MqttParseError):
                parser.feed_byte(byte)
