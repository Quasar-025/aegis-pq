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


def test_text_roundtrip():
    events = asyncio.run(_scenario())
    texts = [e["text"] for e in events if e.get("type") == "text"]
    assert "hello" in texts
