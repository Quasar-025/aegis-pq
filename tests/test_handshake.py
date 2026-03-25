from aegis_pq.crypto.classical import generate_x25519_keypair
from aegis_pq.crypto.pq import PQCryptoProvider
from aegis_pq.protocol.types import PreKeyBundle
from aegis_pq.protocol.x3dh import PQX3DH


def test_pq_x3dh_master_secret_match():
    crypto = PQCryptoProvider(use_oqs=False)
    x3dh = PQX3DH(crypto)

    alice_sig = crypto.generate_signature_keypair()
    alice_eph = generate_x25519_keypair()

    bob_sig = crypto.generate_signature_keypair()
    bob_kem = crypto.generate_kem_keypair()
    bob_dh = generate_x25519_keypair()

    signed_bundle = b"bob" + bob_kem.public_key + bob_dh.public_bytes()
    bundle_sig = crypto.sign(bob_sig.private_key, signed_bundle)
    bundle = PreKeyBundle(
        user_id="bob",
        sig_public_key=bob_sig.public_key,
        kem_public_key=bob_kem.public_key,
        dh_public_key=bob_dh.public_bytes(),
        bundle_signature=bundle_sig,
    )

    init, alice_secrets = x3dh.initiator_handshake(
        sender_id="alice",
        sender_sig_public_key=alice_sig.public_key,
        sender_sig_private_key=alice_sig.private_key,
        sender_ephemeral_dh_private=alice_eph.private_bytes(),
        sender_ephemeral_dh_public=alice_eph.public_bytes(),
        receiver_bundle=bundle,
    )
    bob_secrets = x3dh.responder_handshake(
        receiver_kem_private_key=bob_kem.private_key,
        receiver_dh_private_key=bob_dh.private_bytes(),
        init=init,
    )

    assert alice_secrets.master_secret == bob_secrets.master_secret
