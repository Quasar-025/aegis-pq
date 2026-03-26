# Aegis-PQ: Hybrid Post-Quantum Secure Communication Suite

Aegis-PQ is a store-and-forward secure messaging system focused on:
- Post-quantum confidentiality (Kyber / ML-KEM)
- Post-quantum authenticity (Dilithium / ML-DSA)
- Forward secrecy and break-in recovery (double ratchet)
- Metadata minimization (sealed sender)

This README describes the real project architecture, where each part lives, and how the system works end-to-end.

## Project Layout

Top-level:
- `proto/aegis.proto`: canonical wire schema for relay RPC and app payloads
- `src/aegis_pq`: all runtime code
- `tests`: protocol and end-to-end tests
- `requirements.txt`: base runtime dependencies
- `requirements-pq.txt`: optional PQ-native dependency path (liboqs-python)

Core package map:
- `src/aegis_pq/crypto`
	- `pq.py`: PQ provider wrapper (OQS detection, sign/verify, KEM encap/decap, alias handling)
	- `classical.py`: fallback classical primitives (Ed25519/X25519)
	- `symmetric.py`: HKDF, HMAC ratchet KDF, AES-GCM helpers
- `src/aegis_pq/protocol`
	- `x3dh.py`: authenticated hybrid handshake logic
	- `ratchet.py`: root/sending/receiving chain logic
	- `sealed_sender.py`: relay-visible routing only, inner payload secrecy
	- `packet_codec.py`: protobuf packet encode/decode
	- `padding.py`: ISO/IEC 7816-4 padding helpers
	- `types.py`: protocol dataclasses
- `src/aegis_pq/network`
	- `relay_server.py`: relay control plane, mailbox API, pre-key and blob endpoints
	- `relay_client.py`: transport-neutral relay client with QUIC and TCP
	- `quic_transport.py`: aioquic stream request/response transport and cert bootstrap
- `src/aegis_pq/storage`
	- `relay_db.py`: SQLite for bundles, one-time prekeys, mailbox
	- `relay_blob_store.py`: relay blob persistence
	- `blob_store.py`: client blob encryption/decryption helpers
	- `keystore.py`: local key protection (DPAPI on Windows, encrypted fallback)
- `src/aegis_pq/ui`
	- `client_app.py`: real multi-device client UI
	- `app.py`: local two-user demo UI (single machine)
- `src/aegis_pq/engine.py`: client protocol orchestration (bootstrap, publish, handshake, send/poll)
- `src/aegis_pq/demo.py`: scripted smoke demo

## End-to-End Architecture

Logical planes:
1. Control Plane (Relay RPC): protobuf requests over QUIC or TCP.
2. Signal Plane (Messages): ratcheted encrypted packets delivered via mailbox.
3. Data Plane (Files): encrypted blob upload/download through relay blob channel.

Actors:
1. Client A (alice)
2. Client B (bob)
3. Relay (store-and-forward, zero-content visibility)

Flow summary:
1. Each client boots identity and one-time prekeys, then publishes pre-key bundle.
2. Initiator fetches peer bundle, verifies signature, runs hybrid handshake.
3. Initiator sends sealed handshake message through relay.
4. Responder processes handshake, derives same master secret, starts ratchet state.
5. Text/file key metadata is sent as ratcheted packets.
6. Files are encrypted client-side and uploaded as blobs; file key + hash travels in ratchet message.

## Cryptographic Functionality

### 1) Hybrid Handshake (PQ-X3DH style)

Implemented in `src/aegis_pq/protocol/x3dh.py`.

Inputs:
- Long-term identity signature key
- Long-term KEM and DH prekeys
- Optional one-time prekey

Derived master secret:
- `HKDF( KEM_ss || DH_ss || optional_OTPK_DH_ss )`

Security properties:
- Peer bundle authenticity (signature checked)
- Resistance against pre-key tampering
- Asynchronous session establishment for offline recipients

### 2) Double Ratchet

Implemented in `src/aegis_pq/protocol/ratchet.py`.

Properties:
- Per-message symmetric key evolution
- Authenticated encryption with AES-GCM
- Forward secrecy and post-compromise recovery behavior (state advancing per message)

### 3) Sealed Sender

Implemented in `src/aegis_pq/protocol/sealed_sender.py`.

Behavior:
- Outer envelope encrypted to relay key
- Relay can read route target only after unseal
- Sender identity and app payload remain protected from passive relay visibility

### 4) File Channel

Implemented across `src/aegis_pq/storage/blob_store.py`, `src/aegis_pq/storage/relay_blob_store.py`, and `src/aegis_pq/engine.py`.

Behavior:
- Client generates random file key
- Encrypts file locally
- Uploads ciphertext blob
- Sends `FilePointer` metadata (blob id/hash/key/nonce) via ratchet message

## Key Lifecycle and Persistence

Implemented in `src/aegis_pq/engine.py` and `src/aegis_pq/storage/keystore.py`.

Behavior:
- One-time prekeys are generated, signed, and published
- Relay consumes one-time prekeys atomically on fetch
- Client replenishes low prekey stock
- Local identity is persisted securely
- Compatibility checks rotate identity when stored key mode conflicts with current PQ mode

## Transport and Protocol Encoding

Encoding:
- All control and app messages use protobuf from `proto/aegis.proto`.

Transport:
- Primary: QUIC (`src/aegis_pq/network/quic_transport.py`)
- Fallback: TCP framed protobuf (`src/aegis_pq/network/relay_client.py` and `relay_server.py`)

Relay auth:
- Every relay request includes `auth_token`.

## Setup (Corrected and Reliable)

### A) Base setup (always)

Windows PowerShell:
```powershell
cd aegis-pq
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

macOS/Linux:
```bash
cd aegis-pq
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

### B) Optional PQ-native setup (required for true PQ demo)

Important:
- Do not install the unrelated `oqs` package from PyPI (Open Quick Script).
- Use OQS bindings path from `requirements-pq.txt`.

Commands:
```powershell
python -m pip uninstall -y oqs
pip install -r requirements-pq.txt
python -c "import oqs; print(hasattr(oqs, 'KeyEncapsulation'), hasattr(oqs, 'Signature'))"
```

Expected verification output:
```text
True True
```

If not `True True`, native liboqs setup did not complete on that machine.

## Running Modes

### 1) Smoke demo (single machine script)
```powershell
python -m aegis_pq.demo
```

### 2) Relay server
```powershell
python -m aegis_pq.network.relay_server --host 0.0.0.0 --port 8888 --quic-port 8889 --auth-token your-demo-token
```

### 3) Real client UI (recommended for multi-device demo)
Windows:
```powershell
python -m aegis_pq.ui.client_app
```

macOS/Linux:
```bash
python3 -m aegis_pq.ui.client_app
```

## UI Field Guide (What to Put Where)

In `client_app` top row:
1. `user_id`: current laptop identity (`alice` or `bob`)
2. `peer_id`: opposite user (`bob` if alice, `alice` if bob)
3. `relay_host`: relay machine IP
4. `quic`: relay QUIC port (default `8889`)
5. `tcp`: relay TCP port (default `8888`)
6. `auth_token`: exactly the same token relay started with
7. `transport`: `quic` preferred; app can fall back to TCP path

## Real Two-Laptop Demo Procedure

1. Start relay on host laptop.
2. Start bob client, connect and wait for `[system] connected`.
3. Start alice client, connect and wait for session initiation.
4. Exchange text messages.
5. Send a file from one side and poll receive event on the other side.

If session does not establish:
1. Stop all processes.
2. Delete relay state: `relay.sqlite3`, `relay-blobs/`.
3. Delete client keystores: `client-data/alice/keystore`, `client-data/bob/keystore`.
4. Reconnect in order: bob first, alice second.

## Runtime Indicators and Diagnostics

Client logs include:
1. `KEM runtime=...`
2. `SIG runtime=...`
3. `pq_enabled=True/False`
4. `oqs_reason=...`
5. `oqs_module_file=...`

Programmatic diagnostics:
- `AegisClient.crypto_profile()`
- `AegisClient.handshake_audit`

## Testing

```powershell
pytest -q
```

## Known Constraints

1. Relay certificate bootstrap is self-signed for development and demos.
2. PQ runtime depends on local liboqs availability.
3. Cross-device demos require both clients to run compatible OQS mechanisms and clean session state.
