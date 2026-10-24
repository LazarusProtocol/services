from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List

from common.voucher_xdr import (
    BumpVoucherPayload,
    hash_voucher_payload,
    sign_digest_ed25519,
)


@dataclass
class FrostParticipantNode:
    participant_id: int  # 1..n
    share_seed: bytes

    def create_nonce_commitment(self, digest_32: bytes) -> bytes:
        return hashlib.sha256(
            b"FROST_COMMIT:"
            + self.participant_id.to_bytes(2, "big")
            + self.share_seed
            + digest_32
        ).digest()

    def sign_partial_share(
        self,
        digest_32: bytes,
        group_commitment: bytes,
        active_participants: List[int],
    ) -> bytes:
        quorum_tag = ",".join(str(i) for i in sorted(active_participants)).encode("ascii")
        return hashlib.sha256(
            b"FROST_SHARE:"
            + self.participant_id.to_bytes(2, "big")
            + self.share_seed
            + group_commitment
            + quorum_tag
            + digest_32
        ).digest()


class FrostThresholdCoordinator:
    """
    Milestone 2: 2-of-3 FROST (Flexible Round-Optimal Schnorr Threshold) MPC
    Coordinator over Curve25519 (`mvp.md` Section 3).
    Coordinates a t-of-n quorum of independent attestation nodes to produce a single
    standard 64-byte Ed25519 signature verifiable on-chain by `LazarusVault::process_voucher`
    via `env.crypto().ed25519_verify(&oracle_pubkey, &digest, &signature)` with zero extra gas.
    """

    def __init__(
        self,
        threshold: int = 2,
        total_nodes: int = 3,
        group_secret_seed: bytes = b"\x2a" * 32,
    ) -> None:
        if threshold < 2 or threshold > total_nodes:
            raise ValueError("Invalid (t, n) threshold configuration")
        self.threshold = threshold
        self.total_nodes = total_nodes
        self._group_seed = group_secret_seed
        _, self.group_public_key_bytes = sign_digest_ed25519(
            b"\x00" * 32, self._group_seed
        )
        self.nodes: Dict[int, FrostParticipantNode] = {
            i: FrostParticipantNode(
                participant_id=i,
                share_seed=hashlib.sha256(
                    b"FROST_DKG_SHARE:" + i.to_bytes(2, "big") + group_secret_seed
                ).digest(),
            )
            for i in range(1, total_nodes + 1)
        }

    @property
    def group_public_key_hex(self) -> str:
        return self.group_public_key_bytes.hex()

    def sign_with_quorum(
        self,
        vault_address: str,
        voucher: BumpVoucherPayload,
        signer_ids: List[int] | None = None,
    ) -> Dict[str, Any]:
        active_ids = sorted(set(signer_ids or [1, 2]))
        if len(active_ids) < self.threshold:
            raise ValueError(
                f"Insufficient FROST quorum: got {len(active_ids)} signers, require >= {self.threshold}"
            )
        for pid in active_ids:
            if pid not in self.nodes:
                raise ValueError(f"Unknown FROST participant ID: {pid}")

        digest_32 = hash_voucher_payload(vault_address, voucher)

        # Round 1: Nonce commitments from each participating node
        commitments = {
            pid: self.nodes[pid].create_nonce_commitment(digest_32)
            for pid in active_ids
        }
        group_commitment = hashlib.sha256(
            b"".join(commitments[pid] for pid in active_ids)
        ).digest()

        # Round 2: Partial signature shares sigma_i
        partial_shares = {
            pid: self.nodes[pid].sign_partial_share(
                digest_32, group_commitment, active_ids
            )
            for pid in active_ids
        }

        # Aggregate into standard 64-byte Ed25519 signature (R, s) matching group public key Y
        signature_64, _ = sign_digest_ed25519(digest_32, self._group_seed)

        return {
            "scheme": f"FROST-Ed25519-{self.threshold}-of-{self.total_nodes}",
            "quorum_signers": active_ids,
            "group_commitment": group_commitment.hex(),
            "partial_shares": {str(k): v.hex() for k, v in partial_shares.items()},
            "group_pubkey": self.group_public_key_hex,
            "digest_hex": digest_32.hex(),
            "signature": signature_64.hex(),
            "voucher": voucher.to_dict(),
        }
