import pytest

from honeypotter.telnet.sansio import TelnetConnection
from honeypotter.telnet.values import ApplicationData, Negotiation, Option, Verb


class TestTelnetConnection:
    @pytest.fixture
    def connection(self) -> TelnetConnection:
        return TelnetConnection()

    def test_send_application_data(self, connection: TelnetConnection) -> None:
        assert connection.send_application_data(b"foo") == b"foo"

    def test_send_negotiation(self, connection: TelnetConnection) -> None:
        assert connection.send_negotiation(Verb.WILL, Option.ECHO) == b"\xff\xfb\x01"

    def test_receive_data_application_data(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"foo") == [ApplicationData(data=b"foo")]

    def test_receive_data_double_iac(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"\xff\xff") == [ApplicationData(data=b"\xff")]

    def test_receive_data_negotiation(self, connection: TelnetConnection) -> None:
        message = Negotiation(verb=Verb.DO, option=Option.ECHO)

        assert connection.receive_data(message.to_bytes()) == [message]
