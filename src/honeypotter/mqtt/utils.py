import re


def encode_remaining_length(length: int) -> bytes:
    encoded_bytes = bytearray()

    while True:
        encoded_byte = length & 127
        length = length >> 7

        if length > 0:
            encoded_byte = encoded_byte | 128

        encoded_bytes.append(encoded_byte)

        if length == 0:
            break

    return bytes(encoded_bytes)


def decode_remaining_length(length: bytes | bytearray) -> int:
    if len(length) > 4:
        raise ValueError("Remaining length must be <= 4 bytes")

    value = 0
    multiplier = 1

    for byte in length:
        value += (byte & 127) * multiplier
        multiplier *= 128

        if byte & 128 == 0:
            break

    return value


def decode_utf8_string(data: bytes) -> str:
    """
    Decodes raw bytes into a string while enforcing MQTT strict UTF-8 rules.

    https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_UTF-8_encoded_strings_
    """

    try:
        # This handles standard UTF-8 validation and rejects surrogate pairs (U+D800..U+DFFF)
        value = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("Invalid UTF-8 sequence") from e

    # Check for null character (MUST NOT)
    if "\x00" in value:
        raise ValueError("MQTT strings MUST NOT contain U+0000")

    # Check for control and non-characters (SHOULD NOT)
    if _BAD_CHARS_RE.search(value):
        raise ValueError("MQTT strings SHOULD NOT contain control or non-characters")

    return value


_BAD_CHARS_RE = re.compile(
    r"[\u0001-\u001F]"  # Control characters
    r"|[\u007F-\u009F]"  # Control characters
    r"|[\uFDD0-\uFDEF]"  # Unicode non-characters (contiguous block)
    r"|[\uFFFE-\uFFFF]"  # Plane 0 (BMP) ends
    r"|[\U0001FFFE-\U0001FFFF]"  # Plane 1 ends
    r"|[\U0002FFFE-\U0002FFFF]"  # Plane 2 ends
    r"|[\U0003FFFE-\U0003FFFF]"  # Plane 3 ends
    r"|[\U0004FFFE-\U0004FFFF]"  # Plane 4 ends
    r"|[\U0005FFFE-\U0005FFFF]"  # Plane 5 ends
    r"|[\U0006FFFE-\U0006FFFF]"  # Plane 6 ends
    r"|[\U0007FFFE-\U0007FFFF]"  # Plane 7 ends
    r"|[\U0008FFFE-\U0008FFFF]"  # Plane 8 ends
    r"|[\U0009FFFE-\U0009FFFF]"  # Plane 9 ends
    r"|[\U000AFFFE-\U000AFFFF]"  # Plane 10 ends
    r"|[\U000BFFFE-\U000BFFFF]"  # Plane 11 ends
    r"|[\U000CFFFE-\U000CFFFF]"  # Plane 12 ends
    r"|[\U000DFFFE-\U000DFFFF]"  # Plane 13 ends
    r"|[\U000EFFFE-\U000EFFFF]"  # Plane 14 ends
    r"|[\U000FFFFE-\U000FFFFF]"  # Plane 15 ends
    r"|[\U0010FFFE-\U0010FFFF]"  # Plane 16 (End of Unicode) ends
)
