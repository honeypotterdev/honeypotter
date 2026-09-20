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
