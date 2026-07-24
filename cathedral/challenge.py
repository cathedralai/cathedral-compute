"""Publicly derivable TDX challenge nonces anchored to finalized chain state.

A random issuer nonce is not a public freshness proof: nothing ties it to
the scoring epoch, so an issuer could reuse it and a bounded replay cache
eventually forgets. Instead the 32-byte challenge nonce is DERIVED, under a
domain separator, from independently verifiable inputs:

    nonce = sha256( DOMAIN || canonical{block_hash, network, netuid,
                                        source_epoch, miner_hotkey} )

The finalized block hash is observable by anyone from the chain; the epoch,
audience, and hotkey pin the nonce to exactly one (epoch, miner) slot. A
full validator recomputes the expected nonce from the manifest's anchored
snapshot and the historical chain, so cross-epoch evidence reuse fails
cryptographically — no forgetful cache involved. Miners can compute the
nonce only once the anchor block is finalized, which is exactly the epoch
freshness window.
"""

from __future__ import annotations

import hashlib
import json
import re

CHALLENGE_DOMAIN = b"cathedral-tdx-challenge-v1\x00"
_BLOCK_HASH_RE = re.compile(r"^(0x)?[0-9a-f]{64}$")


class ChallengeError(ValueError):
    """The challenge anchor inputs are malformed."""


def normalize_block_hash(block_hash: str) -> str:
    if not isinstance(block_hash, str):
        raise ChallengeError("block hash must be a string")
    text = block_hash.strip().lower()
    if _BLOCK_HASH_RE.fullmatch(text) is None:
        raise ChallengeError("block hash must be a 32-byte hex value")
    return text.removeprefix("0x")


def derive_challenge_nonce(
    *,
    block_hash: str,
    network: str,
    netuid: int,
    source_epoch: int,
    miner_hotkey: str,
) -> bytes:
    if not isinstance(network, str) or not network:
        raise ChallengeError("network is invalid")
    if isinstance(netuid, bool) or not isinstance(netuid, int) or netuid < 0:
        raise ChallengeError("netuid is invalid")
    if isinstance(source_epoch, bool) or not isinstance(source_epoch, int) or source_epoch < 0:
        raise ChallengeError("source epoch is invalid")
    if not isinstance(miner_hotkey, str) or not miner_hotkey:
        raise ChallengeError("miner hotkey is invalid")
    material = json.dumps(
        {
            "block_hash": normalize_block_hash(block_hash),
            "miner_hotkey": miner_hotkey,
            "netuid": int(netuid),
            "network": network,
            "source_epoch": int(source_epoch),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(CHALLENGE_DOMAIN + material).digest()


def expected_challenge_digest(
    *,
    block_hash: str,
    network: str,
    netuid: int,
    source_epoch: int,
    miner_hotkey: str,
) -> str:
    """The committed sha256 of the derived nonce, as recorded per attestation."""
    nonce = derive_challenge_nonce(
        block_hash=block_hash,
        network=network,
        netuid=netuid,
        source_epoch=source_epoch,
        miner_hotkey=miner_hotkey,
    )
    return "sha256:" + hashlib.sha256(nonce).hexdigest()
