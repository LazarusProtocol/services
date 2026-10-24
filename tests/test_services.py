from __future__ import annotations

import asyncio
import base64
import hashlib
import time
import unittest
from typing import Any, Dict, Tuple

from attestation.enclave_signer import (
    EnclaveAttestationSigner,
    HourlyCircuitBreakerError,
)
from attestation.frost_coordinator import FrostThresholdCoordinator
from attestation.server import AttestationEnclaveService
from common.voucher_xdr import (
    BumpVoucherPayload,
    hash_voucher_payload,
    serialize_voucher_payload,
    sign_digest_ed25519,
    verify_digest_ed25519,
)
from keeper.daemon import (
    COHORT_MODULO,
    EMERGENCY_THRESHOLD,
    LazarusKeeperNode,
)


class MockSorobanRPCServer:
    def __init__(self) -> None:
        self.simulated_txs = []
        self.submitted_txs = []
        self.batch_calls = []

    async def get_latest_ledger(self) -> Dict[str, int]:
        return {"sequence": 500_000}

    async def load_account(self, public_key: str) -> Dict[str, Any]:
        return {"account_id": public_key, "sequence": 1001}

    async def simulate_transaction(self, pre_tx: Any) -> Dict[str, Any]:
        self.simulated_txs.append(pre_tx)
        return {"min_resource_fee": 14_500}

    async def submit_transaction(self, tx: Any) -> Dict[str, Any]:
        self.submitted_txs.append(tx)
        tx_hash = hashlib.sha256(str(len(self.submitted_txs)).encode()).hexdigest()
        return {"hash": tx_hash, "status": "SUCCESS"}

    async def submit_batch_contract_call(self, record: Dict[str, Any]) -> None:
        self.batch_calls.append(record)


class LazarusServicesTestSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.vault_id = "CCLAZARUSVAULTCONTRACTADDRESS0000000000000000000000000000"
        self.contract_id = "CCBLENDPOOLCONTRACT0000000000000000000000000000000000001"
        self.keeper_secret = "SBZ7T5X23Y7EXAMPLEKEEPERSECRETKEY00000000000000000000000"

    def test_canonical_xdr_serialization_and_ed25519_verification(self) -> None:
        voucher = BumpVoucherPayload(
            keeper="GKEEPERNODEADDRESS00000000000000000000000000000000000001",
            target_contract=self.contract_id,
            ledger_bumped=550_000,
            bounty_amount=1_000_000,
            nonce=1,
        )
        raw_payload = serialize_voucher_payload(self.vault_id, voucher)
        self.assertTrue(raw_payload.startswith(b"LAZARUS_VOUCHER_V1"))

        digest = hash_voucher_payload(self.vault_id, voucher)
        self.assertEqual(len(digest), 32)

        seed = b"\x2a" * 32
        sig, pub = sign_digest_ed25519(digest, seed)
        self.assertEqual(len(sig), 64)
        self.assertEqual(len(pub), 32)
        self.assertTrue(verify_digest_ed25519(digest, sig, pub, secret_seed_32=seed))

    def test_deterministic_cohort_sharding_and_emergency_bypass(self) -> None:
        node = LazarusKeeperNode(
            keeper_secret=self.keeper_secret,
            indexer_api_url="http://localhost:8000",
            rpc_url="https://soroban-testnet.stellar.org",
            network_passphrase="Test SDF Network ; September 2015",
            dev_stub_mode=True,
        )

        # 1. Emergency Threshold Bypass: remaining_ledgers <= 2000 ALWAYS returns True
        for i in range(25):
            self.assertTrue(
                node.is_eligible_for_key(
                    key_hash=f"emergency_key_{i}",
                    current_ledger=500_000,
                    remaining_ledgers=EMERGENCY_THRESHOLD,
                )
            )
            self.assertTrue(
                node.is_eligible_for_key(
                    key_hash=f"emergency_key_{i}",
                    current_ledger=500_000,
                    remaining_ledgers=450,
                )
            )

        # 2. Standard Window: Deterministic Cohort Hash (modulo 5) selects ~1/5 of keys
        eligible = [
            node.is_eligible_for_key(
                key_hash=f"standard_key_{i}",
                current_ledger=500_000,
                remaining_ledgers=15_000,
            )
            for i in range(100)
        ]
        self.assertTrue(any(eligible))
        self.assertFalse(all(eligible))

    def test_keeper_extend_state_and_batch_redemption(self) -> None:
        mock_rpc = MockSorobanRPCServer()
        node = LazarusKeeperNode(
            keeper_secret=self.keeper_secret,
            indexer_api_url="http://localhost:8000",
            rpc_url="https://soroban-testnet.stellar.org",
            network_passphrase="Test SDF Network ; September 2015",
            dev_stub_mode=True,
            server=mock_rpc,
        )

        async def scenario() -> None:
            # Extend 10 keys -> buffer hits MAX_BATCH_SIZE = 10 -> should_flush_buffer() is True
            for idx in range(10):
                key_xdr = base64.b64encode(f"ledger_key_{idx}".encode()).decode("ascii")
                await node.extend_state(
                    {
                        "contract_id": self.contract_id,
                        "key_hash": hashlib.sha256(key_xdr.encode()).hexdigest(),
                        "key_xdr": key_xdr,
                        "live_until_ledger_seq": 501_000,
                        "bump_target": 550_000,
                    }
                )

            self.assertEqual(len(node.voucher_buffer), 10)
            self.assertTrue(node.should_flush_buffer())

            flushed = await node.redeem_batch()
            self.assertEqual(flushed, 10)
            self.assertEqual(len(node.voucher_buffer), 0)
            self.assertEqual(len(mock_rpc.batch_calls), 1)
            self.assertEqual(
                mock_rpc.batch_calls[0]["entrypoint"], "record_bump_batch"
            )

        asyncio.run(scenario())

    def test_request_voucher_polling_202_to_200_and_safety_guard(self) -> None:
        attempts = 0

        async def mock_http_post(
            url: str, payload: Dict[str, Any]
        ) -> Tuple[int, Dict[str, Any]]:
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                return 202, {"status": "pending_consensus"}
            return 200, {
                "voucher": {
                    "keeper": payload["keeper_address"],
                    "target_contract": payload["contract_id"],
                    "ledger_bumped": 550_000,
                    "bounty_amount": 1_000_000,
                    "nonce": 1,
                },
                "signature": "ab" * 64,
            }

        node = LazarusKeeperNode(
            keeper_secret=self.keeper_secret,
            indexer_api_url="http://localhost:8000",
            rpc_url="https://soroban-testnet.stellar.org",
            network_passphrase="Test SDF Network ; September 2015",
            dev_stub_mode=False,
            http_post_func=mock_http_post,
        )

        res = asyncio.run(
            node.request_voucher("tx_hash_123", self.contract_id, retry_delay=0.01)
        )
        self.assertEqual(attempts, 2)
        self.assertEqual(res["voucher"]["nonce"], 1)
        self.assertEqual(len(res["signature"]), 64)

        # Safety guard when dev_stub_mode=False and no HTTP backend is reachable
        offline_node = LazarusKeeperNode(
            keeper_secret=self.keeper_secret,
            indexer_api_url="http://127.0.0.1:59999",
            rpc_url="https://soroban-testnet.stellar.org",
            network_passphrase="Test SDF Network ; September 2015",
            dev_stub_mode=False,
        )
        with self.assertRaises((NotImplementedError, RuntimeError)):
            asyncio.run(
                offline_node.request_voucher(
                    "tx_offline", self.contract_id, max_retries=1, retry_delay=0.01
                )
            )

    def test_enclave_circuit_breaker_and_frost_2_of_3_quorum(self) -> None:
        # Allow at most 2,000,000 stroops per hour
        service = AttestationEnclaveService(
            max_hourly_outflow=2_000_000,
            signing_mode="frost_2_of_3",
        )
        keeper = "GKEEPERNODEADDRESS00000000000000000000000000000000000001"

        # 1st voucher: 1,000,000 + 5% fee (50,000) = 1,050,000 <= 2,000,000
        res1 = service.handle_sign_request(
            {
                "vault_address": self.vault_id,
                "keeper": keeper,
                "target_contract": self.contract_id,
                "ledger_bumped": 550_000,
                "bounty_amount": 1_000_000,
                "nonce": 1,
                "timestamp": 3600 * 100,
                "signer_ids": [1, 3],
            }
        )
        self.assertEqual(res1["frost"]["scheme"], "FROST-Ed25519-2-of-3")
        self.assertEqual(res1["frost"]["quorum_signers"], [1, 3])
        self.assertEqual(len(res1["signature"]), 128)

        # 2nd voucher in same hour: 1,050,000 + 1,050,000 = 2,100,000 > 2,000,000 -> trips circuit breaker
        with self.assertRaises(HourlyCircuitBreakerError):
            service.handle_sign_request(
                {
                    "vault_address": self.vault_id,
                    "keeper": keeper,
                    "target_contract": self.contract_id,
                    "ledger_bumped": 555_000,
                    "bounty_amount": 1_000_000,
                    "nonce": 2,
                    "timestamp": 3600 * 100 + 120,
                }
            )

        # Next hour: circuit breaker resets and nonce 2 succeeds
        res2 = service.handle_sign_request(
            {
                "vault_address": self.vault_id,
                "keeper": keeper,
                "target_contract": self.contract_id,
                "ledger_bumped": 555_000,
                "bounty_amount": 1_000_000,
                "nonce": 2,
                "timestamp": 3600 * 101,
            }
        )
        self.assertEqual(res2["voucher"]["nonce"], 2)

        # FROST quorum below threshold (1 of 3) is rejected
        frost = FrostThresholdCoordinator(threshold=2, total_nodes=3)
        with self.assertRaises(ValueError):
            frost.sign_with_quorum(
                vault_address=self.vault_id,
                voucher=BumpVoucherPayload(
                    keeper=keeper,
                    target_contract=self.contract_id,
                    ledger_bumped=555_000,
                    bounty_amount=1_000_000,
                    nonce=3,
                ),
                signer_ids=[1],
            )

    def test_audit_sequence_increment_send_transaction_and_footprint_packing(self) -> None:
        class SendAndPollMockRPC:
            def __init__(self) -> None:
                self.account_state = {"account_id": "GKEEPER", "sequence": 1000}
                self.sent_txs = []
                self.poll_counts: Dict[str, int] = {}

            async def load_account(self, public_key: str) -> Dict[str, Any]:
                return self.account_state

            async def simulate_transaction(self, pre_tx: Any) -> Dict[str, Any]:
                return {"min_resource_fee": 18_500}

            async def send_transaction(self, tx: Any) -> Dict[str, Any]:
                self.sent_txs.append(tx)
                tx_hash = hashlib.sha256(f"send_{len(self.sent_txs)}".encode()).hexdigest()
                self.poll_counts[tx_hash] = 0
                return {"hash": tx_hash, "status": "PENDING"}

            async def get_transaction(self, tx_hash: str) -> Dict[str, Any]:
                self.poll_counts[tx_hash] = self.poll_counts.get(tx_hash, 0) + 1
                if self.poll_counts[tx_hash] < 2:
                    return {"status": "NOT_FOUND"}
                return {"status": "SUCCESS", "ledger": 500_010}

        rpc = SendAndPollMockRPC()
        node = LazarusKeeperNode(
            keeper_secret=self.keeper_secret,
            indexer_api_url="http://localhost:8000",
            rpc_url="https://soroban-testnet.stellar.org",
            network_passphrase="Test SDF Network ; September 2015",
            dev_stub_mode=True,
            server=rpc,
        )

        async def scenario() -> None:
            # Pack 5 expiring keys for the same contract into a single ExtendFootprintTTLOp footprint
            packed_keys = [
                {
                    "contract_id": self.contract_id,
                    "key_hash": hashlib.sha256(f"packed_{i}".encode()).hexdigest(),
                    "key_xdr": base64.b64encode(f"packed_key_{i}".encode()).decode("ascii"),
                    "live_until_ledger_seq": 500_500,
                    "bump_target": 550_000 + i * 100,
                }
                for i in range(5)
            ]
            await node.extend_state_batch(packed_keys)

            # Sequence must have incremented by exactly +1 (1000 -> 1001), NOT +2 (preventing txBAD_SEQ)
            self.assertEqual(rpc.account_state["sequence"], 1001)
            self.assertEqual(len(rpc.sent_txs), 1)
            self.assertEqual(rpc.sent_txs[0]["sequence"], 1001)
            self.assertEqual(rpc.sent_txs[0]["read_only_count"], 5)
            self.assertEqual(rpc.sent_txs[0]["extend_to"], 550_400)
            tx_hash = list(rpc.poll_counts.keys())[0]
            self.assertGreaterEqual(rpc.poll_counts[tx_hash], 2)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()

