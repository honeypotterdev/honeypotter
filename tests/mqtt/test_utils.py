import pytest

from honeypotter.mqtt.utils import remaining_length_decode, remaining_length_encode


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


def test_remaining_length_decode() -> None:
    assert remaining_length_decode(b"\x00") == 0
    assert remaining_length_decode(b"\x01") == 1
    assert remaining_length_decode(b"\x7f") == 127
    assert remaining_length_decode(b"\x80\x01") == 128
    assert remaining_length_decode(b"\xff\x7f") == 16_383
    assert remaining_length_decode(b"\x80\x80\x01") == 16_384
    assert remaining_length_decode(b"\xff\xff\x7f") == 2_097_151
    assert remaining_length_decode(b"\x80\x80\x80\x01") == 2_097_152
    assert remaining_length_decode(b"\xff\xff\xff\x7f") == 268_435_455


def test_remaining_length_decode_max_4_bytes() -> None:
    with pytest.raises(ValueError):
        remaining_length_decode(b"\x01\x01\x01\x01\x01")
