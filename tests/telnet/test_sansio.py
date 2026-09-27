import pytest
from hypothesis import given
from hypothesis import strategies as st

from honeypotter.telnet.sansio import TelnetConnection
from honeypotter.telnet.values import (
    ApplicationData,
    Command,
    CommandCode,
    Negotiation,
    NegotiationVerb,
    Option,
    Subnegotiation,
)


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

    def test_send_command(self, connection: TelnetConnection) -> None:
        assert connection.send_command(CommandCode.AYT) == b"\xff\xf6"

    def test_send_negotiation(self, connection: TelnetConnection) -> None:
        assert connection.send_negotiation(NegotiationVerb.WILL, Option.ECHO) == b"\xff\xfb\x01"

    def test_send_subnegotiation(self, connection: TelnetConnection) -> None:
        data = b"\x1f\x00\x64\x00\x32"  # NAWS, width: 100, height: 50

        assert connection.send_subnegotiation(data) == b"\xff\xfa\x1f\x00\x64\x00\x32\xff\xf0"

    def test_receive_data_application_data(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"foo") == [ApplicationData(data=b"foo")]

    def test_receive_data_application_data_double_iac(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"\xff\xff") == [ApplicationData(data=b"\xff")]

    @pytest.mark.parametrize(
        "second",
        [
            Command(code=CommandCode.AYT),
            Negotiation(verb=NegotiationVerb.WILL, option=Option.ECHO),
            Subnegotiation(data=b"bar"),
        ],
    )
    def test_receive_data_application_data_flush(self, connection: TelnetConnection, second: Command) -> None:
        first = ApplicationData(data=b"foo")
        third = ApplicationData(data=b"bar")
        data = first.to_bytes() + second.to_bytes() + third.to_bytes()

        assert connection.receive_data(data) == [first, second, third]

    def test_receive_data_command(self, connection: TelnetConnection) -> None:
        message = Command(code=CommandCode.AYT)

        assert connection.receive_data(message.to_bytes()) == [message]

    def test_receive_data_negotiation(self, connection: TelnetConnection) -> None:
        message = Negotiation(verb=NegotiationVerb.DO, option=Option.ECHO)

        assert connection.receive_data(message.to_bytes()) == [message]

    def test_receive_data_subnegotiation(self, connection: TelnetConnection) -> None:
        message = Subnegotiation(data=b"\x1f\x00\x64\x00\x32")

        assert connection.receive_data(message.to_bytes()) == [message]

    def test_receive_data_subnegotiation_fragmented(self, connection: TelnetConnection) -> None:
        message = Subnegotiation(data=b"\x1f\x00\x64\x00\x32")
        data = message.to_bytes()

        assert connection.receive_data(data[:3]) == []
        assert connection.receive_data(data[3:]) == [message]
