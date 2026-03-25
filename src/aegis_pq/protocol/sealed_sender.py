from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from typing import Any

from aegis_pq.proto import aegis_pb2 as _aegis_pb2
from aegis_pq.crypto.symmetric import aes_gcm_decrypt, aes_gcm_encrypt, hkdf_sha3_256
from aegis_pq.protocol.types import SealedEnvelope

pb: Any = _aegis_pb2


def _x25519_public_from_bytes(pub_bytes: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(pub_bytes)


def _x25519_private_from_bytes(priv_bytes: bytes) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(priv_bytes)


def seal_for_server(server_public_key: bytes, sender_id: str, recipient_id: str, payload: bytes) -> SealedEnvelope:
    eph = x25519.X25519PrivateKey.generate()
    shared = eph.exchange(_x25519_public_from_bytes(server_public_key))
    key = hkdf_sha3_256(shared, info=b"sealed-sender")
    inner = pb.RelayInnerPayload(sender_id=sender_id, recipient_id=recipient_id, payload=payload).SerializeToString()
    nonce, ciphertext = aes_gcm_encrypt(key[:32], inner)
    eph_pub = eph.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return SealedEnvelope(nonce=nonce, ciphertext=ciphertext, ephemeral_pub=eph_pub)


def unseal_at_server(server_private_key: bytes, envelope: SealedEnvelope) -> dict:
    server_sk = _x25519_private_from_bytes(server_private_key)
    eph_pub = _x25519_public_from_bytes(envelope.ephemeral_pub)
    shared = server_sk.exchange(eph_pub)
    key = hkdf_sha3_256(shared, info=b"sealed-sender")
    plaintext = aes_gcm_decrypt(key[:32], envelope.nonce, envelope.ciphertext)
    parsed = pb.RelayInnerPayload()
    parsed.ParseFromString(plaintext)
    return {
        "sender_id": parsed.sender_id,
        "recipient_id": parsed.recipient_id,
        "payload": parsed.payload,
    }


def envelope_to_bytes(envelope: SealedEnvelope) -> bytes:
    return pb.SealedEnvelope(
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        ephemeral_pub=envelope.ephemeral_pub,
    ).SerializeToString()


def envelope_from_bytes(data: bytes) -> SealedEnvelope:
    blob = pb.SealedEnvelope()
    blob.ParseFromString(data)
    return SealedEnvelope(
        nonce=blob.nonce,
        ciphertext=blob.ciphertext,
        ephemeral_pub=blob.ephemeral_pub,
    )
