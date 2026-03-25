import asyncio

from aegis_pq.config import DEFAULT_CONFIG
from aegis_pq.engine import AegisClient
from aegis_pq.network.relay_client import RelayClient
from aegis_pq.network.relay_server import RelayServer
from aegis_pq.storage.blob_store import BlobStore


async def run_demo():
    relay = RelayServer(db_path="demo-relay.sqlite3", blob_root="demo-relay-blobs", auth_token=DEFAULT_CONFIG.relay.auth_token)
    tcp_server = await asyncio.start_server(relay.handle_tcp, "127.0.0.1", 8989)
    await relay.start_quic("127.0.0.1", 8990, cert_dir=".demo-quic")

    alice_blob = BlobStore("demo-blobs")
    bob_blob = BlobStore("demo-blobs")
    relay_client_alice = RelayClient(port=8989, quic_port=8990, transport="quic", auth_token=DEFAULT_CONFIG.relay.auth_token)
    relay_client_bob = RelayClient(port=8989, quic_port=8990, transport="quic", auth_token=DEFAULT_CONFIG.relay.auth_token)

    alice = AegisClient("alice", relay_client_alice, alice_blob, DEFAULT_CONFIG)
    bob = AegisClient("bob", relay_client_bob, bob_blob, DEFAULT_CONFIG)

    await alice.bootstrap()
    await bob.bootstrap()
    await alice.publish_prekey_bundle()
    await bob.publish_prekey_bundle()

    await alice.initiate_session("bob")
    print("alice -> initiated handshake")

    events = await bob.poll()
    print("bob poll:", events)

    await alice.send_text("bob", "Hello from Aegis-PQ")
    events = await bob.poll()
    print("bob poll:", events)

    await bob.send_text("alice", "Handshake complete and ratchet active")
    events = await alice.poll()
    print("alice poll:", events)

    await alice.send_file("bob", "notes.txt", b"Top secret file bytes")
    events = await bob.poll()
    print("bob file poll:", [{k: (v if k != 'content' else v.decode()) for k, v in e.items()} for e in events])

    tcp_server.close()
    await tcp_server.wait_closed()
    await relay.stop_quic()


if __name__ == "__main__":
    asyncio.run(run_demo())
