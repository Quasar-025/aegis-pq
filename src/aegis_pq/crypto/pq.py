from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from aegis_pq.crypto.symmetric import hkdf_sha3_256


try:
    import oqs  # type: ignore

    HAS_OQS = True
except Exception:
    oqs = None
    HAS_OQS = False

OQS: Any = oqs


@dataclass
class SignatureKeyPair:
    public_key: bytes
    private_key: bytes


@dataclass
class KemKeyPair:
    public_key: bytes
    private_key: bytes


class PQCryptoProvider:
    def __init__(self, kem_name: str = "Kyber1024", sig_name: str = "Dilithium5", use_oqs: bool = True):
        self.kem_name = kem_name
        self.sig_name = sig_name
        self.oqs_module_name = ""
        self.oqs_module_file = ""
        self.oqs_reason = ""

        if HAS_OQS and OQS is not None:
            self.oqs_module_name = getattr(OQS, "__name__", "")
            self.oqs_module_file = getattr(OQS, "__file__", "")

        has_signature = HAS_OQS and hasattr(OQS, "Signature")
        has_kem = HAS_OQS and hasattr(OQS, "KeyEncapsulation")
        oqs_ready = HAS_OQS and has_signature and has_kem

        if not use_oqs:
            self.oqs_reason = "oqs-disabled-by-config"
        elif not HAS_OQS:
            self.oqs_reason = "oqs-import-failed"
        elif not has_signature or not has_kem:
            self.oqs_reason = "wrong-oqs-package-or-incomplete-api"
        else:
            self.oqs_reason = "ok"

        self.use_oqs = use_oqs and oqs_ready

    def diagnostics(self) -> dict[str, str | bool]:
        return {
            "pq_enabled": self.use_oqs,
            "oqs_reason": self.oqs_reason,
            "oqs_module_name": self.oqs_module_name,
            "oqs_module_file": self.oqs_module_file,
            "has_signature_api": bool(HAS_OQS and hasattr(OQS, "Signature")),
            "has_kem_api": bool(HAS_OQS and hasattr(OQS, "KeyEncapsulation")),
            "kem": self.kem_name,
            "signature": self.sig_name,
        }

    def generate_signature_keypair(self) -> SignatureKeyPair:
        if self.use_oqs:
            with OQS.Signature(self.sig_name) as sig:
                public_key = sig.generate_keypair()
                private_key = sig.export_secret_key()
            return SignatureKeyPair(public_key=public_key, private_key=private_key)

        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        return SignatureKeyPair(
            public_key=pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            private_key=sk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        if self.use_oqs:
            with OQS.Signature(self.sig_name, secret_key=private_key) as sig:
                return sig.sign(message)
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        return sk.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if self.use_oqs:
            with OQS.Signature(self.sig_name) as sig:
                return sig.verify(message, signature, public_key)
        try:
            pk = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            pk.verify(signature, message)
            return True
        except Exception:
            return False

    def generate_kem_keypair(self) -> KemKeyPair:
        if self.use_oqs:
            with OQS.KeyEncapsulation(self.kem_name) as kem:
                public_key = kem.generate_keypair()
                private_key = kem.export_secret_key()
            return KemKeyPair(public_key=public_key, private_key=private_key)

        sk = x25519.X25519PrivateKey.generate()
        pk = sk.public_key()
        return KemKeyPair(
            public_key=pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            private_key=sk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

    def kem_encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        if self.use_oqs:
            with OQS.KeyEncapsulation(self.kem_name) as kem:
                ciphertext, shared_secret = kem.encap_secret(peer_public_key)
            return ciphertext, shared_secret

        eph_sk = x25519.X25519PrivateKey.generate()
        peer_pk = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        shared = eph_sk.exchange(peer_pk)
        ciphertext = eph_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return ciphertext, hkdf_sha3_256(shared, info=b"fallback-kem")

    def kem_decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        if self.use_oqs:
            with OQS.KeyEncapsulation(self.kem_name, secret_key=private_key) as kem:
                return kem.decap_secret(ciphertext)

        sk = x25519.X25519PrivateKey.from_private_bytes(private_key)
        eph_pk = x25519.X25519PublicKey.from_public_bytes(ciphertext)
        shared = sk.exchange(eph_pk)
        return hkdf_sha3_256(shared, info=b"fallback-kem")
