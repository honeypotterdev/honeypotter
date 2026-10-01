from contextlib import suppress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from honeypotter.mqtt.parsers import MqttParseError, MqttParser


class TestMqttParser:
    @pytest.fixture
    def parser(self) -> MqttParser:
        return MqttParser()

    @given(data=st.binary())
    def test_general_fuzz(self, data: bytes) -> None:
        parser = MqttParser()

        for byte in data:
            with suppress(MqttParseError):
                parser.feed_byte(byte)
