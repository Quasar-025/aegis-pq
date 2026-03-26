from dataclasses import dataclass

from aegis_pq.crypto.classical import x25519_ecdh
from aegis_pq.crypto.pq import PQCryptoProvider
from aegis_pq.crypto.symmetric import hkdf_sha3_256
from aegis_pq.errors import SignatureVerificationError
from aegis_pq.protocol.types import HandshakeInit, PreKeyBundle


@dataclass
class HandshakeSecrets:
    master_secret: bytes
    kem_shared_secret: bytes
    classical_shared_secret: bytes


class PQX3DH:
    def __init__(self, crypto: PQCryptoProvider):
        self.crypto = crypto

    def verify_bundle(self, bundle: PreKeyBundle) -> None:
        signed = bundle.user_id.encode() + bundle.kem_public_key + bundle.dh_public_key
        if not self.crypto.verify(bundle.sig_public_key, signed, bundle.bundle_signature):
            raise SignatureVerificationError(
                "invalid pre-key bundle signature (likely stale peer bundle or PQ/classical identity mismatch)"
            )
        if bundle.one_time_prekey:
            otpk = bundle.one_time_prekey
            otpk_signed = bundle.user_id.encode() + otpk.key_id.to_bytes(4, "big") + otpk.kem_public_key + otpk.dh_public_key
            if not self.crypto.verify(bundle.sig_public_key, otpk_signed, otpk.signature):
                raise SignatureVerificationError("invalid one-time pre-key signature")

    def initiator_handshake(
        self,
        sender_id: str,
        sender_sig_public_key: bytes,
        sender_sig_private_key: bytes,
        sender_ephemeral_dh_private: bytes,
        sender_ephemeral_dh_public: bytes,
        receiver_bundle: PreKeyBundle,
    ) -> tuple[HandshakeInit, HandshakeSecrets]:
        self.verify_bundle(receiver_bundle)

        kem_ciphertext, kem_ss = self.crypto.kem_encapsulate(receiver_bundle.kem_public_key)
        dh_ss = x25519_ecdh(sender_ephemeral_dh_private, receiver_bundle.dh_public_key)
        otpk_dh_ss = b""
        otpk_id = 0
        if receiver_bundle.one_time_prekey:
            otpk_dh_ss = x25519_ecdh(sender_ephemeral_dh_private, receiver_bundle.one_time_prekey.dh_public_key)
            otpk_id = receiver_bundle.one_time_prekey.key_id
        master_secret = hkdf_sha3_256(kem_ss + dh_ss + otpk_dh_ss, info=b"pq-x3dh-master")

        payload = (
            sender_id.encode()
            + sender_sig_public_key
            + sender_ephemeral_dh_public
            + kem_ciphertext
            + otpk_id.to_bytes(4, "big")
        )
        init_sig = self.crypto.sign(sender_sig_private_key, payload)
        init = HandshakeInit(
            sender_id=sender_id,
            sender_sig_public_key=sender_sig_public_key,
            sender_ephemeral_dh_public_key=sender_ephemeral_dh_public,
            kem_ciphertext=kem_ciphertext,
            sender_signature=init_sig,
            one_time_prekey_id=otpk_id,
        )
        return init, HandshakeSecrets(master_secret=master_secret, kem_shared_secret=kem_ss, classical_shared_secret=dh_ss)

    def responder_handshake(
        self,
        receiver_kem_private_key: bytes,
        receiver_dh_private_key: bytes,
        init: HandshakeInit,
        receiver_one_time_dh_private_key: bytes | None = None,
    ) -> HandshakeSecrets:
        signed_payload = (
            init.sender_id.encode()
            + init.sender_sig_public_key
            + init.sender_ephemeral_dh_public_key
            + init.kem_ciphertext
            + init.one_time_prekey_id.to_bytes(4, "big")
        )
        if not self.crypto.verify(init.sender_sig_public_key, signed_payload, init.sender_signature):
            raise SignatureVerificationError("invalid initiator handshake signature")

        kem_ss = self.crypto.kem_decapsulate(receiver_kem_private_key, init.kem_ciphertext)
        dh_ss = x25519_ecdh(receiver_dh_private_key, init.sender_ephemeral_dh_public_key)
        otpk_dh_ss = b""
        if init.one_time_prekey_id and receiver_one_time_dh_private_key:
            otpk_dh_ss = x25519_ecdh(receiver_one_time_dh_private_key, init.sender_ephemeral_dh_public_key)
        master_secret = hkdf_sha3_256(kem_ss + dh_ss + otpk_dh_ss, info=b"pq-x3dh-master")
        return HandshakeSecrets(master_secret=master_secret, kem_shared_secret=kem_ss, classical_shared_secret=dh_ss)
