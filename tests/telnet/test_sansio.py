import pytest

from honeypotter.telnet.sansio import TelnetConnection
from honeypotter.telnet.values import ApplicationData, Negotiation, Option, Subnegotiation, Verb


class TestTelnetConnection:
    @pytest.fixture
    def connection(self) -> TelnetConnection:
        return TelnetConnection()

    def test_send_application_data(self, connection: TelnetConnection) -> None:
        assert connection.send_application_data(b"foo") == b"foo"

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
