from __future__ import annotations

import argparse
import asyncio
import logging
from .config import KeeperConfig
from .daemon import LazarusKeeperNode

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("lazarus.keeper.cli")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lazarus Protocol Autonomous Keeper Node Daemon"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Execute a single polling/warming/redemption cycle and exit",
    )
    parser.add_argument(
        "--dev-stub",
        action="store_true",
        help="Enable offline development stub mode",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cfg = KeeperConfig.from_env()
    if args.dev_stub:
        cfg.dev_stub_mode = True

    node = LazarusKeeperNode(
        keeper_secret=cfg.keeper_secret,
        indexer_api_url=cfg.indexer_api_url,
        rpc_url=cfg.rpc_url,
        network_passphrase=cfg.network_passphrase,
        vault_contract_id=cfg.vault_contract_id,
        buffer_flush_interval=cfg.buffer_flush_interval,
        dev_stub_mode=cfg.dev_stub_mode,
    )
    logger.info(
        "Starting LazarusKeeperNode keeper=%s indexer=%s dev_stub_mode=%s",
        node.keypair.public_key,
        cfg.indexer_api_url,
        cfg.dev_stub_mode,
    )
    if args.once:
        report = asyncio.run(node.run_once())
        logger.info("Keeper cycle complete: %s", report)
    else:
        asyncio.run(node.run())


if __name__ == "__main__":
    main()
