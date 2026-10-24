from __future__ import annotations

import time
from typing import Any, Dict, Optional

from common.voucher_xdr import (
    BumpVoucherPayload,
    hash_voucher_payload,
    sign_digest_ed25519,
)

PROTOCOL_FEE_BPS = 500
BPS_DENOMINATOR = 10_000


class HourlyCircuitBreakerError(RuntimeError):
    """Raised when the enclave hourly outflow circuit breaker is tripped."""


class EnclaveAttestationSigner:
    """
    v1 AWS Nitro Enclave isolated Ed25519 attestation signer (`mvp.md` Section 3).
    Enforces:
      - Strict positive bounty validation
      - Monotonic per-keeper sequence nonces
      - Off-chain hourly outflow circuit breaker mirroring `lazarus_vault`'s `MaxHourlyOutflow`
      - Canonical `LAZARUS_VOUCHER_V1` domain-separated Ed25519 signing
    """

    def __init__(
        self,
        secret_seed_32: bytes = b"\x2a" * 32,
        max_hourly_outflow: int = 50_000_000_000,
    ) -> None:
        if len(secret_seed_32) != 32:
            raise ValueError("secret_seed_32 must be exactly 32 bytes")
        self._secret_seed = secret_seed_32
        _, self.public_key_bytes = sign_digest_ed25519(b"\x00" * 32, self._secret_seed)
        self.max_hourly_outflow = max_hourly_outflow
        self.tracked_hour: int = 0
        self.hourly_outflow_accumulator: int = 0
        self.keeper_nonces: Dict[str, int] = {}

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    def sign_voucher(
        self,
        vault_address: str,
        voucher: BumpVoucherPayload,
        timestamp: Optional[int] = None,
    ) -> Dict[str, Any]:
        if voucher.bounty_amount <= 0:
            raise ValueError("BountyOutOfBounds: bounty_amount must be > 0")

        expected_nonce = self.keeper_nonces.get(voucher.keeper, 0) + 1
        if voucher.nonce != expected_nonce:
            raise ValueError(
                f"InvalidNonce: expected {expected_nonce}, got {voucher.nonce}"
            )

        protocol_fee = (voucher.bounty_amount * PROTOCOL_FEE_BPS) // BPS_DENOMINATOR
        total_deduction = voucher.bounty_amount + protocol_fee

        now_ts = int(timestamp if timestamp is not None else time.time())
        current_hour = now_ts // 3600
        is_new_hour = current_hour > self.tracked_hour
        prospective = (
            total_deduction
            if is_new_hour
            else self.hourly_outflow_accumulator + total_deduction
        )
        if prospective > self.max_hourly_outflow:
            raise HourlyCircuitBreakerError(
                f"HourlyOutflowExceeded: {prospective} > {self.max_hourly_outflow}"
            )

        digest_32 = hash_voucher_payload(vault_address, voucher)
        signature_64, _ = sign_digest_ed25519(digest_32, self._secret_seed)

        # Commit enclave state after all checks succeed
        if is_new_hour:
            self.tracked_hour = current_hour
        self.hourly_outflow_accumulator = prospective
        self.keeper_nonces[voucher.keeper] = voucher.nonce

        return {
            "vault_address": vault_address,
            "voucher": voucher.to_dict(),
            "digest_hex": digest_32.hex(),
            "signature": signature_64.hex(),
            "oracle_pubkey": self.public_key_hex,
        }
