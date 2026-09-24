import pytest

from honeypotter.mqtt.utils import decode_remaining_length, encode_remaining_length


def test_encode_remaining_length() -> None:
    assert encode_remaining_length(0) == b"\x00"
    assert encode_remaining_length(1) == b"\x01"
    assert encode_remaining_length(127) == b"\x7f"
    assert encode_remaining_length(128) == b"\x80\x01"
    assert encode_remaining_length(16_383) == b"\xff\x7f"
    assert encode_remaining_length(16_384) == b"\x80\x80\x01"
    assert encode_remaining_length(2_097_151) == b"\xff\xff\x7f"
    assert encode_remaining_length(2_097_152) == b"\x80\x80\x80\x01"
    assert encode_remaining_length(268_435_455) == b"\xff\xff\xff\x7f"


def test_decode_remaining_length() -> None:
    assert decode_remaining_length(b"\x00") == 0
    assert decode_remaining_length(b"\x01") == 1
    assert decode_remaining_length(b"\x7f") == 127
    assert decode_remaining_length(b"\x80\x01") == 128
    assert decode_remaining_length(b"\xff\x7f") == 16_383
    assert decode_remaining_length(b"\x80\x80\x01") == 16_384
    assert decode_remaining_length(b"\xff\xff\x7f") == 2_097_151
    assert decode_remaining_length(b"\x80\x80\x80\x01") == 2_097_152
    assert decode_remaining_length(b"\xff\xff\xff\x7f") == 268_435_455


def test_decode_remaining_length_max_4_bytes() -> None:
    with pytest.raises(ValueError):
        decode_remaining_length(b"\x01\x01\x01\x01\x01")
