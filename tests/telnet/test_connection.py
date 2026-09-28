import pytest
from hypothesis import given
from hypothesis import strategies as st

from honeypotter.telnet.connection import TelnetConnection
from honeypotter.telnet.events import (
    ApplicationDataReceived,
    CommandReceived,
    NegotiationReceived,
    SubnegotiationReceived,
)
from honeypotter.telnet.values import CommandCode, NegotiationOption, NegotiationVerb


class TestTelnetConnection:
    @pytest.fixture
    def connection(self) -> TelnetConnection:
        return TelnetConnection()

    def test_data_to_send_drains_buffer(self, connection: TelnetConnection) -> None:
        connection.send_application_data(b"foo")

        assert connection.data_to_send() == b"foo"
        assert connection.data_to_send() == b""

    @given(data=st.lists(st.integers(min_value=0, max_value=254)).map(bytes))
    def test_send_application_data(self, data: bytes) -> None:
        connection = TelnetConnection()
        connection.send_application_data(data)

        assert connection.data_to_send() == data

    def test_send_application_data_double_iac(self, connection: TelnetConnection) -> None:
        connection.send_application_data(b"\xff")

        assert connection.data_to_send() == b"\xff\xff"

    def test_send_command(self, connection: TelnetConnection) -> None:
        connection.send_command(CommandCode.AYT)

        assert connection.data_to_send() == b"\xff\xf6"

    def test_send_negotiation(self, connection: TelnetConnection) -> None:
        connection.send_negotiation(NegotiationVerb.WILL, NegotiationOption.ECHO)

        assert connection.data_to_send() == b"\xff\xfb\x01"

    def test_send_subnegotiation(self, connection: TelnetConnection) -> None:
        connection.send_subnegotiation(option=NegotiationOption.NAWS, data=b"\x00\x64\x00\x32")

        assert connection.data_to_send() == b"\xff\xfa\x1f\x00\x64\x00\x32\xff\xf0"

    def test_send_subnegotiation_double_iac(self, connection: TelnetConnection) -> None:
        connection.send_subnegotiation(option=1, data=b"\xff")

        assert connection.data_to_send() == b"\xff\xfa\x01\xff\xff\xff\xf0"

    def test_receive_data_application_data(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"foo") == [ApplicationDataReceived(data=b"foo")]

    def test_receive_data_application_data_double_iac(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"\xff\xff") == [ApplicationDataReceived(data=b"\xff")]

    # TODO: Test app data flush on all intermediate events
    def test_receive_data_application_data_flush(self, connection: TelnetConnection) -> None:
        peer_connection = TelnetConnection()
        peer_connection.send_application_data(b"foo")
        peer_connection.send_command(CommandCode.AYT)
        peer_connection.send_application_data(b"bar")

        assert connection.receive_data(peer_connection.data_to_send()) == [
            ApplicationDataReceived(data=b"foo"),
            CommandReceived(code=CommandCode.AYT),
            ApplicationDataReceived(data=b"bar"),
        ]

    def test_receive_data_command(self, connection: TelnetConnection) -> None:
        peer_connection = TelnetConnection()
        peer_connection.send_command(CommandCode.AYT)

        assert connection.receive_data(peer_connection.data_to_send()) == [CommandReceived(code=CommandCode.AYT)]

    def test_receive_data_negotiation(self, connection: TelnetConnection) -> None:
        peer_connection = TelnetConnection()
        peer_connection.send_negotiation(NegotiationVerb.DO, NegotiationOption.ECHO)

        assert connection.receive_data(peer_connection.data_to_send()) == [
            NegotiationReceived(verb=NegotiationVerb.DO, option=NegotiationOption.ECHO)
        ]

    def test_receive_data_subnegotiation(self, connection: TelnetConnection) -> None:
        peer_connection = TelnetConnection()
        peer_connection.send_subnegotiation(NegotiationOption.NAWS, b"\x00\x64\x00\x32")

        assert connection.receive_data(peer_connection.data_to_send()) == [
            SubnegotiationReceived(option=NegotiationOption.NAWS, data=b"\x00\x64\x00\x32")
        ]

    def test_receive_data_subnegotiation_empty_data(self, connection: TelnetConnection) -> None:
        peer_connection = TelnetConnection()
        peer_connection.send_subnegotiation(NegotiationOption.NAWS, b"")

        assert connection.receive_data(peer_connection.data_to_send()) == [
            SubnegotiationReceived(option=NegotiationOption.NAWS, data=b"")
        ]

    @pytest.mark.parametrize("chunk", list(range(2)))
    def test_receive_data_subnegotiation_fragmented(self, connection: TelnetConnection, chunk: int) -> None:
        peer_connection = TelnetConnection()
        peer_connection.send_subnegotiation(NegotiationOption.NAWS, b"\x00\x64\x00\x32")
        data = peer_connection.data_to_send()

        assert connection.receive_data(data[:chunk]) == []
        assert connection.receive_data(data[chunk:]) == [
            SubnegotiationReceived(option=NegotiationOption.NAWS, data=b"\x00\x64\x00\x32")
        ]
