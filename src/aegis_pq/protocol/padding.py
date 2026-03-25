def iso_7816_4_pad(data: bytes, block_size: int = 4096) -> bytes:
    if block_size <= 1:
        raise ValueError("block_size must be > 1")
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([0x80]) + bytes(pad_len - 1)


def iso_7816_4_unpad(data: bytes) -> bytes:
    idx = data.rfind(b"\x80")
    if idx == -1:
        raise ValueError("invalid ISO/IEC 7816-4 padding")
    if any(b != 0x00 for b in data[idx + 1 :]):
        raise ValueError("invalid ISO/IEC 7816-4 padding bytes")
    return data[:idx]
