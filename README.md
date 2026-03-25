# Aegis-PQ: Hybrid Post-Quantum Secure Communication Suite

Aegis-PQ is an applied cryptography project that implements:
- Hybrid PQ-X3DH key establishment (Kyber-1024 + X25519)
- Quantum-safe authentication (Dilithium-5 signatures)
- Post-quantum double ratchet for forward secrecy and break-in recovery
- Asynchronous store-and-forward relay with sealed sender metadata protection
- Secure text and file transfer channels with traffic padding
- Protobuf binary wire protocol for relay and client message exchange
- Full QUIC transport path for authenticated multiplexed request/response channels
- One-time pre-key lifecycle with depletion detection and automatic replenishment
- Secure local key persistence (Windows DPAPI with fallback encrypted keystore)

## Features

- End-to-end encrypted packet format: `[Header | Ciphertext | Signature]`
- ISO/IEC 7816-4 padding to fixed 4KB blocks
- Sealed sender envelope where routing metadata is encrypted for relay-only access
- File plane with detached encrypted blob channel + ratchet-delivered key material
- SQLite-backed relay mailbox, long-term pre-key bundle, and one-time pre-key store
- Relay auth token requirement across TCP and QUIC operations
- Binary protobuf envelopes replacing JSON wrappers across relay and app payloads
- CustomTkinter desktop UI for two-party live demonstration (text + files + polling)

## Security Notes

- Preferred cryptography path uses `liboqs-python` for Kyber-1024 and Dilithium-5.
- If OQS is unavailable in the local runtime, the code falls back to classical primitives for development-only operation.
- Do not use fallback mode in production security deployments.
- The included relay certificate bootstrap is self-signed for local demos. Replace with managed certificates for deployment.

## Kyber Usage Indication

Runtime indication is now explicit in the client UI and engine profile.

- Client UI prints a security line on connect:
	- `KEM runtime=Kyber1024` when liboqs Kyber is active
	- `KEM runtime=fallback-classical-kem` when Kyber is not available
- Programmatic check is available through `AegisClient.crypto_profile()`.
- Handshake audit metadata is stored per peer in `AegisClient.handshake_audit`.

## Quick Start

```powershell
cd aegis-pq
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
python -m aegis_pq.demo
```

## Demonstration Flow

```powershell
# 1) Start standalone relay (TCP + QUIC)
python -m aegis_pq.network.relay_server

# 2) In another terminal, launch UI demo
python -m aegis_pq.ui.app
```

Recommended presenter flow in UI:
1. Send Alice to Bob text.
2. Send Bob to Alice reply.
3. Send demo file and poll both sides.
4. Explain one-time pre-key consumption and replenishment after handshake activity.

## Real Two-Laptop Product Demo

Use one relay host and two independent client apps.

Laptop A (Relay Host):

```powershell
python -m aegis_pq.network.relay_server --host 0.0.0.0 --port 8888 --quic-port 8889 --auth-token your-demo-token
```

Laptop B (User alice):

```powershell
python -m aegis_pq.ui.client_app
```

Laptop C (User bob):

```powershell
python -m aegis_pq.ui.client_app
```

In each client app set:
1. `relay_host` to Laptop A IP address.
2. `auth_token` to the same token used on relay.
3. user IDs as `alice` and `bob` respectively.
4. transport to `quic`.

This is the recommended real demo path for separate devices.

## UI

```powershell
python -m aegis_pq.ui.app
```

Single-user real client mode:

```powershell
python -m aegis_pq.ui.client_app
```

## Relay Server

```powershell
python -m aegis_pq.network.relay_server
```

## Tests

```powershell
pytest -q
```
