## Lazarus Services

Asynchronous Python runtime services for the Lazarus Protocol: autonomous keeper node daemon and threshold attestation signer.

---

### Core Services

#### 1. Keeper Node Daemon (`keeper/`)
* **Deterministic Cohort Sharding:** `sha256(pk : key_hash : epoch) % 5 == 0` eliminates multi-keeper collision waste across 100-ledger epochs.
* **Emergency Threshold Bypass:** Automatically overrides cohorts when entries drop below `2,000 ledgers` (~2.7 hours to eviction).
* **Multi-Key Footprint Packing:** Packs up to 100 expiring storage keys into a single `ExtendFootprintTTLOp` envelope to reduce network fees.
* **Sequence Protection (`txBAD_SEQ`):** Manages asynchronous nonce increments safely via `SorobanServerAsync`.
* **Batched Settlement:** Buffers up to 10 signed `BumpVoucher` attestations for redemption via `record_bump_batch`.

#### 2. Attestation Signer Service (`attestation/`)
* **Enclave Signer:** Isolated Ed25519 signer enforcing monotonic keeper nonces and hourly outflow safety rules.
* **2-of-3 FROST Coordinator:** Threshold Schnorr multi-party signature coordinator producing 64-byte Ed25519 signatures verifiable on-chain by `lazarus_vault`.
* **Microservice:** Exposes lightweight HTTP endpoints (`:8085`) for keeper voucher signing.

---

### Run & Test

```bash
# Pull pre-built Docker packages from GitHub Container Registry
docker pull ghcr.io/lazarusprotocol/keeper-daemon:latest
docker pull ghcr.io/lazarusprotocol/attestation-enclave:latest

# Start Keeper Daemon and Attestation Enclave via Docker Compose
docker compose up -d

# Or build locally from source
docker compose up -d --build

# Run a single keeper pass in dev-stub mode
python3 -m keeper.cli --once --dev-stub

# Run services test suite
python3 -m unittest discover -s tests -v
```
