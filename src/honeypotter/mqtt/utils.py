def remaining_length_encode(length: int) -> bytes:
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


def remaining_length_decode(length: bytes) -> int:
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
