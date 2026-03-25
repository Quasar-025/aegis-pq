import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519


@dataclass
class X25519KeyPair:
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def generate_x25519_keypair() -> X25519KeyPair:
    private_key = x25519.X25519PrivateKey.generate()
    return X25519KeyPair(private_key=private_key, public_key=private_key.public_key())


def x25519_ecdh(private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    return private_key.exchange(peer_public)


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return pk_bytes, sk_bytes


def random_bytes(length: int) -> bytes:
    return os.urandom(length)
