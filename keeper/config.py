from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class KeeperConfig:
    keeper_secret: str
    indexer_api_url: str
    rpc_url: str
    network_passphrase: str
    vault_contract_id: str
    buffer_flush_interval: int = 600
    dev_stub_mode: bool = False

    @classmethod
    def from_env(cls) -> "KeeperConfig":
        return cls(
            keeper_secret=os.environ.get(
                "LAZARUS_KEEPER_SECRET",
                "SBZ7T5X23Y7EXAMPLEKEEPERSECRETKEY00000000000000000000000",
            ),
            indexer_api_url=os.environ.get(
                "LAZARUS_INDEXER_API_URL",
                "http://localhost:8000",
            ),
            rpc_url=os.environ.get(
                "LAZARUS_RPC_URL",
                "https://soroban-testnet.stellar.org",
            ),
            network_passphrase=os.environ.get(
                "LAZARUS_NETWORK_PASSPHRASE",
                "Test SDF Network ; September 2015",
            ),
            vault_contract_id=os.environ.get(
                "LAZARUS_VAULT_CONTRACT_ID",
                "CCWAH7BVPGYOEBPRFWPZIONBYUCCQH7OARGZLOD6ZV66SOAFBVA2DHD5",
            ),
            buffer_flush_interval=int(
                os.environ.get("LAZARUS_BUFFER_FLUSH_INTERVAL", "600")
            ),
            dev_stub_mode=os.environ.get("LAZARUS_DEV_STUB_MODE", "false").lower()
            in ("1", "true", "yes"),
        )
