import argparse
import asyncio
import json
import os
import platform
import statistics
import tempfile
import time
from pathlib import Path

from aegis_pq.config import DEFAULT_CONFIG
from aegis_pq.crypto.classical import generate_x25519_keypair
from aegis_pq.crypto.pq import PQCryptoProvider
from aegis_pq.engine import AegisClient
from aegis_pq.network.relay_client import RelayClient
from aegis_pq.network.relay_server import RelayServer
from aegis_pq.protocol.ratchet import PQDoubleRatchet
from aegis_pq.protocol.types import PreKeyBundle
from aegis_pq.protocol.x3dh import PQX3DH
from aegis_pq.storage.blob_store import BlobStore
from aegis_pq.storage.keystore import LocalKeyStore


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(round((len(ordered) - 1) * p))
    return ordered[idx]


def _summary_ms(values: list[float]) -> dict:
    if not values:
        return {"count": 0, "mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "stdev_ms": 0.0}
    return {
        "count": len(values),
        "mean_ms": round(statistics.mean(values), 3),
        "p50_ms": round(_percentile(values, 0.50), 3),
        "p95_ms": round(_percentile(values, 0.95), 3),
        "min_ms": round(min(values), 3),
        "max_ms": round(max(values), 3),
        "stdev_ms": round(statistics.pstdev(values), 3),
    }


def benchmark_handshake(crypto: PQCryptoProvider, iterations: int) -> dict:
    x3dh = PQX3DH(crypto)

    alice_sig = crypto.generate_signature_keypair()
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

    durations = []
    for _ in range(iterations):
        alice_eph = generate_x25519_keypair()
        t0 = time.perf_counter()
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
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if alice_secrets.master_secret != bob_secrets.master_secret:
            raise RuntimeError("handshake benchmark mismatch")
        durations.append(elapsed_ms)

    return _summary_ms(durations)


def benchmark_ratchet(crypto: PQCryptoProvider, iterations: int, message_size: int) -> dict:
    ratchet = PQDoubleRatchet(crypto, block_size=DEFAULT_CONFIG.crypto.block_size)
    master = os.urandom(32)
    sender = ratchet.init_state("alice:bob", master, is_initiator=True)
    receiver = ratchet.init_state("alice:bob", master, is_initiator=False)

    sig = crypto.generate_signature_keypair()

    enc_ms = []
    dec_ms = []
    plaintext = b"x" * message_size

    for _ in range(iterations):
        t0 = time.perf_counter()
        packet = ratchet.encrypt(sender, "alice", sig.private_key, plaintext)
        enc_ms.append((time.perf_counter() - t0) * 1000.0)

        t1 = time.perf_counter()
        out = ratchet.decrypt(receiver, sig.public_key, packet)
        dec_ms.append((time.perf_counter() - t1) * 1000.0)

        if out != plaintext:
            raise RuntimeError("ratchet benchmark mismatch")

    return {
        "message_size_bytes": message_size,
        "encrypt": _summary_ms(enc_ms),
        "decrypt": _summary_ms(dec_ms),
    }


async def benchmark_e2e(iterations: int, message_size: int, file_size: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="aegis-perf-") as tmp:
        root = Path(tmp)
        relay = RelayServer(
            db_path=str(root / "relay.sqlite3"),
            blob_root=str(root / "relay-blobs"),
            auth_token="perf-token",
        )
        server = await asyncio.start_server(relay.handle_tcp, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        alice = AegisClient(
            "alice",
            RelayClient(host="127.0.0.1", port=port, transport="tcp", auth_token="perf-token"),
            BlobStore(str(root / "alice-blobs")),
            DEFAULT_CONFIG,
            keystore=LocalKeyStore(str(root / "alice-keystore")),
        )
        bob = AegisClient(
            "bob",
            RelayClient(host="127.0.0.1", port=port, transport="tcp", auth_token="perf-token"),
            BlobStore(str(root / "bob-blobs")),
            DEFAULT_CONFIG,
            keystore=LocalKeyStore(str(root / "bob-keystore")),
        )

        await alice.bootstrap()
        await bob.bootstrap()
        await alice.publish_prekey_bundle()
        await bob.publish_prekey_bundle()

        await asyncio.gather(alice.initiate_session("bob"), bob.initiate_session("alice"))
        await alice.poll()
        await bob.poll()

        text_latencies_ms = []
        payload = "m" * message_size
        for i in range(iterations):
            t0 = time.perf_counter()
            await alice.send_text("bob", payload + str(i))
            received = False
            for _ in range(20):
                events = await bob.poll()
                if any(ev.get("type") == "text" for ev in events):
                    received = True
                    break
            if not received:
                raise RuntimeError("text message not received in benchmark")
            text_latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        burst_n = max(10, iterations)
        burst_payload = "b" * min(32, message_size)
        t0 = time.perf_counter()
        for i in range(burst_n):
            await bob.send_text("alice", burst_payload + str(i))
        received_count = 0
        for _ in range(50):
            events = await alice.poll()
            received_count += sum(1 for ev in events if ev.get("type") == "text")
            if received_count >= burst_n:
                break
        burst_s = time.perf_counter() - t0
        if received_count < burst_n:
            raise RuntimeError("throughput burst not fully received")

        file_bytes = os.urandom(file_size)
        t1 = time.perf_counter()
        await alice.send_file("bob", "perf.bin", file_bytes)
        file_received = None
        for _ in range(30):
            events = await bob.poll()
            for ev in events:
                if ev.get("type") == "file":
                    file_received = ev
                    break
            if file_received:
                break
        if not file_received:
            raise RuntimeError("file not received in benchmark")
        file_latency_ms = (time.perf_counter() - t1) * 1000.0
        if file_received["content"] != file_bytes:
            raise RuntimeError("file content mismatch in benchmark")

        key = os.urandom(32)
        _, _, _, file_ciphertext = alice.blob_store.encrypt_detached(key, file_bytes)

        server.close()
        await server.wait_closed()

        return {
            "transport": "tcp",
            "text_roundtrip": _summary_ms(text_latencies_ms),
            "text_throughput": {
                "messages": burst_n,
                "seconds": round(burst_s, 3),
                "messages_per_second": round(burst_n / burst_s, 2) if burst_s > 0 else 0.0,
            },
            "file_transfer": {
                "file_size_bytes": file_size,
                "roundtrip_ms": round(file_latency_ms, 3),
                "ciphertext_size_bytes": len(file_ciphertext),
                "ciphertext_overhead_bytes": len(file_ciphertext) - file_size,
            },
            "crypto_profile": alice.crypto_profile(),
        }


async def run_all(handshake_iters: int, ratchet_iters: int, e2e_iters: int, message_size: int, file_size: int) -> dict:
    crypto = PQCryptoProvider(
        kem_name=DEFAULT_CONFIG.crypto.kem_name,
        sig_name=DEFAULT_CONFIG.crypto.sig_name,
        use_oqs=DEFAULT_CONFIG.crypto.use_oqs,
    )

    result = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "pid": os.getpid(),
        },
        "config": {
            "handshake_iterations": handshake_iters,
            "ratchet_iterations": ratchet_iters,
            "e2e_iterations": e2e_iters,
            "message_size_bytes": message_size,
            "file_size_bytes": file_size,
            "padding_block_size": DEFAULT_CONFIG.crypto.block_size,
        },
        "handshake": benchmark_handshake(crypto, handshake_iters),
        "ratchet": [
            benchmark_ratchet(crypto, ratchet_iters, 64),
            benchmark_ratchet(crypto, ratchet_iters, message_size),
            benchmark_ratchet(crypto, ratchet_iters, 4096),
        ],
        "e2e": await benchmark_e2e(e2e_iters, message_size, file_size),
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Aegis-PQ performance metrics")
    parser.add_argument("--handshake-iters", type=int, default=40)
    parser.add_argument("--ratchet-iters", type=int, default=200)
    parser.add_argument("--e2e-iters", type=int, default=30)
    parser.add_argument("--message-size", type=int, default=1024)
    parser.add_argument("--file-size", type=int, default=262144)
    parser.add_argument("--out", default="artifacts/performance_metrics.json")
    args = parser.parse_args()

    metrics = asyncio.run(
        run_all(
            handshake_iters=args.handshake_iters,
            ratchet_iters=args.ratchet_iters,
            e2e_iters=args.e2e_iters,
            message_size=args.message_size,
            file_size=args.file_size,
        )
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    print(f"\nSaved metrics to {out_path}")


if __name__ == "__main__":
    main()
