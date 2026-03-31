import asyncio

from aegis_pq.config import DEFAULT_CONFIG
from aegis_pq.engine import AegisClient
from aegis_pq.network.relay_client import RelayClient
from aegis_pq.network.relay_server import RelayServer
from aegis_pq.storage.blob_store import BlobStore
from aegis_pq.storage.keystore import LocalKeyStore


async def _scenario():
    relay = RelayServer(db_path="test-relay.sqlite3", blob_root="test-relay-blobs", auth_token="test-token")
    server = await asyncio.start_server(relay.handle_tcp, "127.0.0.1", 9797)

    alice = AegisClient(
        "alice",
        RelayClient(port=9797, transport="tcp", auth_token="test-token"),
        BlobStore("test-blobs"),
        DEFAULT_CONFIG,
        keystore=LocalKeyStore("test-keystore/alice"),
    )
    bob = AegisClient(
        "bob",
        RelayClient(port=9797, transport="tcp", auth_token="test-token"),
        BlobStore("test-blobs"),
        DEFAULT_CONFIG,
        keystore=LocalKeyStore("test-keystore/bob"),
    )

    await alice.bootstrap()
    await bob.bootstrap()
    await alice.publish_prekey_bundle()
    await bob.publish_prekey_bundle()

    await alice.initiate_session("bob")
    await bob.poll()

    await alice.send_text("bob", "hello")
    events = await bob.poll()

    server.close()
    await server.wait_closed()
    return events


async def _simultaneous_initiation_scenario():
    relay = RelayServer(db_path="test-relay.sqlite3", blob_root="test-relay-blobs", auth_token="test-token")
    server = await asyncio.start_server(relay.handle_tcp, "127.0.0.1", 9797)

    alice = AegisClient(
        "alice",
        RelayClient(port=9797, transport="tcp", auth_token="test-token"),
        BlobStore("test-blobs"),
        DEFAULT_CONFIG,
        keystore=LocalKeyStore("test-keystore/alice"),
    )
    bob = AegisClient(
        "bob",
        RelayClient(port=9797, transport="tcp", auth_token="test-token"),
        BlobStore("test-blobs"),
        DEFAULT_CONFIG,
        keystore=LocalKeyStore("test-keystore/bob"),
    )

    await alice.bootstrap()
    await bob.bootstrap()
    await alice.publish_prekey_bundle()
    await bob.publish_prekey_bundle()

    # Reproduce race: both peers initiate before polling mailbox.
    await asyncio.gather(alice.initiate_session("bob"), bob.initiate_session("alice"))

    # Consume both handshake messages and apply deterministic tie-break.
    await alice.poll()
    await bob.poll()

    await alice.send_text("bob", "a2b")
    await bob.send_text("alice", "b2a")

    bob_events = await bob.poll()
    alice_events = await alice.poll()

    server.close()
    await server.wait_closed()
    return alice_events, bob_events


def test_text_roundtrip():
    events = asyncio.run(_scenario())
    texts = [e["text"] for e in events if e.get("type") == "text"]
    assert "hello" in texts


def test_text_roundtrip_after_simultaneous_initiation():
    alice_events, bob_events = asyncio.run(_simultaneous_initiation_scenario())
    alice_texts = [e["text"] for e in alice_events if e.get("type") == "text"]
    bob_texts = [e["text"] for e in bob_events if e.get("type") == "text"]
    assert "b2a" in alice_texts
    assert "a2b" in bob_texts
