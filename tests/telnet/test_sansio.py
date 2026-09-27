import pytest
from hypothesis import given
from hypothesis import strategies as st

from honeypotter.telnet.sansio import TelnetConnection
from honeypotter.telnet.values import ApplicationData, Negotiation, Option, Subnegotiation, Verb


class TestTelnetConnection:
    @pytest.fixture
    def connection(self) -> TelnetConnection:
        return TelnetConnection()

    @given(data=st.lists(st.integers(min_value=0, max_value=254)).map(bytes))
    def test_send_application_data(self, data: bytes) -> None:
        connection = TelnetConnection()

        assert connection.send_application_data(data) == data

    def test_send_application_data_double_iac(self, connection: TelnetConnection) -> None:
        assert connection.send_application_data(b"\xff") == b"\xff\xff"

    def test_send_negotiation(self, connection: TelnetConnection) -> None:
        assert connection.send_negotiation(Verb.WILL, Option.ECHO) == b"\xff\xfb\x01"

    def test_send_subnegotiation(self, connection: TelnetConnection) -> None:
        data = b"\x1f\x00\x64\x00\x32"  # NAWS, width: 100, height: 50

        assert connection.send_subnegotiation(data) == b"\xff\xfa\x1f\x00\x64\x00\x32\xff\xf0"

    def test_receive_data_application_data(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"foo") == [ApplicationData(data=b"foo")]

    def test_receive_data_double_iac(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"\xff\xff") == [ApplicationData(data=b"\xff")]

    def test_receive_data_negotiation(self, connection: TelnetConnection) -> None:
        message = Negotiation(verb=Verb.DO, option=Option.ECHO)

        assert connection.receive_data(message.to_bytes()) == [message]

    def test_receive_data_subnegotiation(self, connection: TelnetConnection) -> None:
        message = Subnegotiation(data=b"\x1f\x00\x64\x00\x32")

        assert connection.receive_data(message.to_bytes()) == [message]

    def test_receive_data_subnegotiation_fragmented(self, connection: TelnetConnection) -> None:
        message = Subnegotiation(data=b"\x1f\x00\x64\x00\x32")
        data = message.to_bytes()

        assert connection.receive_data(data[:3]) == []
        assert connection.receive_data(data[3:]) == [message]

    def test_receive_data_correct_order(self, connection: TelnetConnection) -> None:
        app_data_1 = ApplicationData(data=b"foo")
        negotiation = Negotiation(verb=Verb.WILL, option=Option.ECHO)
        app_data_2 = ApplicationData(data=b"bar")
        data = app_data_1.to_bytes() + negotiation.to_bytes() + app_data_2.to_bytes()

        assert connection.receive_data(data) == [app_data_1, negotiation, app_data_2]
