from aegis_pq.protocol.padding import iso_7816_4_pad, iso_7816_4_unpad


def test_iso_7816_roundtrip():
    data = b"hello-world"
    padded = iso_7816_4_pad(data, block_size=32)
    assert len(padded) % 32 == 0
    assert iso_7816_4_unpad(padded) == data
