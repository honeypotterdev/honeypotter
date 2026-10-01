from honeypotter.mqtt.events import ConnectReceived
from honeypotter.mqtt.exporters import serialize_event


def test_serialize_event_connect_simple() -> None:
    event = ConnectReceived()

    assert serialize_event(event) == 'CONNECT protocol_name="MQTT" protocol_level=4'


def test_serialize_event_connect_complex() -> None:
    event = ConnectReceived(client_id="foo", username="john", password=b"secret")

    assert (
        serialize_event(event)
        == 'CONNECT protocol_name="MQTT" protocol_level=4 client_id="foo" username="john" password="secret"'
    )
