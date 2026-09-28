import pytest
from hypothesis import given
from hypothesis import strategies as st

from honeypotter.constants import CR, LF
from honeypotter.telnet.connection import TelnetConnection
from honeypotter.telnet.events import (
    ApplicationDataReceived,
    CommandReceived,
    NegotiationReceived,
    SubnegotiationReceived,
)
from honeypotter.telnet.types import CommandCode, NegotiationOption, NegotiationVerb, Side


class TestTelnetConnection:
    @pytest.fixture
    def connection(self) -> TelnetConnection:
        return TelnetConnection()

    def test_data_to_send_drains_buffer(self, connection: TelnetConnection) -> None:
        connection.send_application_data(b"foo")

        assert connection.data_to_send() == b"foo"
        assert connection.data_to_send() == b""

    @given(data=st.lists(st.integers(min_value=0, max_value=254).filter(lambda i: i not in {LF, CR})).map(bytes))
    def test_send_application_data(self, data: bytes) -> None:
        connection = TelnetConnection()
        connection.send_application_data(data)

        assert connection.data_to_send() == data

    def test_send_application_data_iac_escaped(self, connection: TelnetConnection) -> None:
        connection.send_application_data(b"\xff")

        assert connection.data_to_send() == b"\xff\xff"

    @pytest.mark.parametrize(
        "application_data,data_to_send",
        [
            (b"hello", b"hello"),
            (b"hello\n", b"hello\r\n"),
            (b"\n\n", b"\r\n\r\n"),
            (b"hello\nworld", b"hello\r\nworld"),
            (b"hello\r", b"hello\r\x00"),
            (b"\r\r", b"\r\x00\r\x00"),
            (b"hello\rworld", b"hello\r\x00world"),
            (b"\r\n", b"\r\x00\r\n"),
        ],
    )
    def test_send_application_data_nvt_encode(
        self, connection: TelnetConnection, application_data: bytes, data_to_send: bytes
    ) -> None:
        connection.send_application_data(application_data)

        assert connection.data_to_send() == data_to_send

    def test_send_command(self, connection: TelnetConnection) -> None:
        connection.send_command(CommandCode.AYT)

        assert connection.data_to_send() == b"\xff\xf6"

    def test_send_negotiation(self, connection: TelnetConnection) -> None:
        connection.send_negotiation(NegotiationVerb.WILL, NegotiationOption.ECHO)

        assert connection.data_to_send() == b"\xff\xfb\x01"

    def test_send_subnegotiation(self, connection: TelnetConnection) -> None:
        connection.send_subnegotiation(option=NegotiationOption.NAWS, data=b"\x00\x64\x00\x32")

        assert connection.data_to_send() == b"\xff\xfa\x1f\x00\x64\x00\x32\xff\xf0"

    def test_send_subnegotiation_iac_escape(self, connection: TelnetConnection) -> None:
        connection.send_subnegotiation(option=1, data=b"\xff")

        assert connection.data_to_send() == b"\xff\xfa\x01\xff\xff\xff\xf0"

    # TODO: Generate bytes with hypothesis
    def test_receive_data_application_data(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"foo") == [ApplicationDataReceived(data=b"foo")]

    def test_receive_data_application_data_iac_escaped(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"\xff\xff") == [ApplicationDataReceived(data=b"\xff")]

    def test_receive_data_application_data_iac_buffered(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"hello\xff") == [ApplicationDataReceived(data=b"hello")]
        assert connection.receive_data(b"\xf6") == [CommandReceived(code=CommandCode.AYT)]

    def test_receive_data_application_data_iac_fragmented(self, connection: TelnetConnection) -> None:
        assert connection.receive_data(b"hello\xff") == [ApplicationDataReceived(data=b"hello")]
        assert connection.receive_data(b"\xff") == [ApplicationDataReceived(data=b"\xff")]

    @pytest.mark.parametrize(
        "receive_data, application_data",
        [
            (b"hello", b"hello"),
            (b"hello\r\n", b"hello\n"),
            (b"\r\n\r\n", b"\n\n"),
            (b"hello\r\nworld", b"hello\nworld"),
            (b"hello\r\x00", b"hello\r"),
            (b"\r\x00\r\x00", b"\r\r"),
            (b"hello\r\x00world", b"hello\rworld"),
            (b"\r\x00\r\n", b"\r\n"),
            (b"\r\r\n", b"\r\n"),
            (b"\r\r\r\n", b"\r\r\n"),
        ],
    )
    def test_receive_data_application_data_nvt_decode(
        self, connection: TelnetConnection, receive_data: bytes, application_data: bytes
    ) -> None:
        assert connection.receive_data(receive_data) == [ApplicationDataReceived(data=application_data)]

    @pytest.mark.parametrize(
        "receive_data, application_data",
        [
            ((b"a\r", b"\nb"), (b"a", b"\nb")),
            ((b"a\r", b"\x00b"), (b"a", b"\rb")),
            ((b"a\r", b"b"), (b"a", b"\rb")),
        ],
    )
    def test_receive_data_application_data_nvt_fragmented(
        self, connection: TelnetConnection, receive_data: tuple[bytes, bytes], application_data: tuple[bytes, bytes]
    ) -> None:
        assert connection.receive_data(receive_data[0]) == [ApplicationDataReceived(data=application_data[0])]
        assert connection.receive_data(receive_data[1]) == [ApplicationDataReceived(data=application_data[1])]

    def test_receive_data_application_data_before_command(self, connection: TelnetConnection) -> None:
        peer_connection = TelnetConnection()
        peer_connection.send_application_data(b"foo")
        peer_connection.send_command(CommandCode.AYT)
        peer_connection.send_application_data(b"bar")

        assert connection.receive_data(peer_connection.data_to_send()) == [
            ApplicationDataReceived(data=b"foo"),
            CommandReceived(code=CommandCode.AYT),
            ApplicationDataReceived(data=b"bar"),
        ]

    def test_receive_data_application_data_before_negotiation(self, connection: TelnetConnection) -> None:
        peer_connection = TelnetConnection()
        peer_connection.send_application_data(b"foo")
        peer_connection.send_negotiation(NegotiationVerb.DO, NegotiationOption.ECHO)
        peer_connection.send_application_data(b"bar")

        assert connection.receive_data(peer_connection.data_to_send()) == [
            ApplicationDataReceived(data=b"foo"),
            NegotiationReceived(verb=NegotiationVerb.DO, option=NegotiationOption.ECHO),
            ApplicationDataReceived(data=b"bar"),
        ]

    def test_receive_data_application_data_before_subnegotiation(self, connection: TelnetConnection) -> None:
        peer_connection = TelnetConnection()
        peer_connection.send_application_data(b"foo")
        peer_connection.send_subnegotiation(NegotiationOption.NAWS, b"\x00\x64\x00\x32")
        peer_connection.send_application_data(b"bar")

        assert connection.receive_data(peer_connection.data_to_send()) == [
            ApplicationDataReceived(data=b"foo"),
            SubnegotiationReceived(option=NegotiationOption.NAWS, data=b"\x00\x64\x00\x32"),
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

    @pytest.mark.parametrize("split", list(range(1, 9)))
    def test_receive_data_subnegotiation_fragmented(self, connection: TelnetConnection, split: int) -> None:
        peer_connection = TelnetConnection()
        peer_connection.send_subnegotiation(NegotiationOption.NAWS, b"\x00\x64\x00\x32")
        data = peer_connection.data_to_send()

        assert connection.receive_data(data[:split]) == []
        assert connection.receive_data(data[split:]) == [
            SubnegotiationReceived(option=NegotiationOption.NAWS, data=b"\x00\x64\x00\x32")
        ]

    def test_request_option(self, connection: TelnetConnection) -> None:
        connection.request_option(NegotiationOption.ECHO, side=Side.LOCAL, enabled=True)
        connection.request_option(NegotiationOption.SGA, side=Side.LOCAL, enabled=True)
        connection.request_option(NegotiationOption.SGA, side=Side.REMOTE, enabled=True)

        assert connection.data_to_send() == b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x03"
        assert connection.is_option_enabled(NegotiationOption.ECHO, side=Side.LOCAL) is False
        assert connection.is_option_enabled(NegotiationOption.SGA, side=Side.LOCAL) is False
        assert connection.is_option_enabled(NegotiationOption.SGA, side=Side.REMOTE) is False
