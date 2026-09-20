from honeypotter.mqtt.utils import remaining_length_encode


def test_remaining_length_encode() -> None:
    assert remaining_length_encode(0) == b"\x00"
    assert remaining_length_encode(1) == b"\x01"
    assert remaining_length_encode(127) == b"\x7f"
    assert remaining_length_encode(128) == b"\x80\x01"
    assert remaining_length_encode(16_383) == b"\xff\x7f"
    assert remaining_length_encode(16_384) == b"\x80\x80\x01"
    assert remaining_length_encode(2_097_151) == b"\xff\xff\x7f"
    assert remaining_length_encode(2_097_152) == b"\x80\x80\x80\x01"
    assert remaining_length_encode(268_435_455) == b"\xff\xff\xff\x7f"
