import pytest

from honeypotter.telnet.sansio import TelnetConnection
from honeypotter.telnet.values import ApplicationData


class TestTelnetConnection:
    @pytest.fixture
    def connection(self) -> TelnetConnection:
        return TelnetConnection()

    def test_send_negotiation(self, connection: TelnetConnection) -> None:
        assert connection.send_negotiation(251, 1) == b"\xff\xfb\x01"

    def test_receive_data_application_data(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"foo") == [ApplicationData(data=b"foo")]

    def test_receive_data_double_iac(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"\xff\xff") == [ApplicationData(data=b"\xff")]
