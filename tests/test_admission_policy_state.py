"""Durable config_version high-water mark.

The in-process guard resets on restart, so a superseded but validly signed
policy could be replayed to re-open a mode or restore a revoked coldkey. The
obvious alternative, pinning the artifact digest, cannot be the production
answer on its own: the staleness ceiling forces a re-sign, a re-sign changes
issued_at and therefore the digest, so a required pin makes the service
refuse every enrollment one ceiling later until someone restarts it.

Covers:
  1. The high-water mark survives a new provider instance (a restart).
  2. A damaged or unreadable state file fails closed, not open.
  3. A state write that cannot be completed refuses the advance.
  4. Without a state path the guard stays in-process, as before.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.admission_policy import (
    ADMISSION_POLICY_SCHEMA,
    SignedAdmissionPolicyProvider,
    sign_admission_policy,
)
from cathedral.policy_registry import canonical_json

SEED = bytes(range(224, 256))
KEY_ID = "cathedral-admission-state-test-1"
PUBLIC = (
    Ed25519PrivateKey.from_private_bytes(SEED)
    .public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
)
TRUSTED = {KEY_ID: PUBLIC}
NETWORK = "finney"
NETUID = 39
COLDKEY = "5FghSHp7DXzhoiCaBQ9qmz6QRb6C94KehEKDHZ8vq6QyE29C"


def policy_bytes(config_version: int, *, coldkeys: list[str] | None = None) -> bytes:
    now = datetime.now(UTC).replace(microsecond=0)
    return canonical_json(
        sign_admission_policy(
            {
                "schema": ADMISSION_POLICY_SCHEMA,
                "mode": "selected",
                "coldkeys": [COLDKEY] if coldkeys is None else coldkeys,
                "network": NETWORK,
                "netuid": NETUID,
                "required_profile_ids": ["cpu-tdx-sn39-v2"],
                "max_enrolled_endpoints_per_coldkey": 2,
                "max_admitted_workers_total": 16,
                "config_version": config_version,
                "issued_at": (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": (now + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "signing_key_id": KEY_ID,
            },
            SEED,
        )
    )


def provider(path: Path, state: Path | None) -> SignedAdmissionPolicyProvider:
    return SignedAdmissionPolicyProvider(
        str(path),
        TRUSTED,
        network=NETWORK,
        netuid=NETUID,
        state_path=str(state) if state is not None else None,
    )


def test_the_high_water_mark_survives_a_restart(tmp_path: Path):
    artifact = tmp_path / "policy.json"
    state = tmp_path / "policy.state"

    artifact.write_bytes(policy_bytes(7))
    assert provider(artifact, state).load().config_version == 7
    assert state.read_text().strip() == "7"

    # A fresh provider is a restarted process. The superseded release must
    # still be refused, even though it verifies and is inside its window.
    artifact.write_bytes(policy_bytes(6, coldkeys=[COLDKEY, "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"]))
    assert provider(artifact, state).load() is None

    artifact.write_bytes(policy_bytes(8))
    assert provider(artifact, state).load().config_version == 8
    assert state.read_text().strip() == "8"


def test_re_signing_at_the_same_version_still_loads(tmp_path: Path):
    """Rotation must not be mistaken for rollback.

    The staleness ceiling forces periodic re-signing; a re-signed policy at
    the same config_version is the normal case and must keep working.
    """
    artifact = tmp_path / "policy.json"
    state = tmp_path / "policy.state"
    artifact.write_bytes(policy_bytes(3))
    assert provider(artifact, state).load().config_version == 3

    artifact.write_bytes(policy_bytes(3))  # fresh issued_at, new digest
    assert provider(artifact, state).load().config_version == 3


@pytest.mark.parametrize("damaged", ["", "   ", "not-a-number", "-4", "9" * 80])
def test_a_damaged_state_file_fails_closed(tmp_path: Path, damaged: str):
    artifact = tmp_path / "policy.json"
    state = tmp_path / "policy.state"
    artifact.write_bytes(policy_bytes(5))
    state.write_text(damaged)

    # Treating damage as zero would silently restore the exact rollback
    # window the file exists to close.
    assert provider(artifact, state).load() is None


def test_an_unreadable_state_file_fails_closed(tmp_path: Path):
    artifact = tmp_path / "policy.json"
    state = tmp_path / "policy.state"
    artifact.write_bytes(policy_bytes(5))
    state.mkdir()  # a directory where a file was expected

    assert provider(artifact, state).load() is None


def test_a_state_write_that_cannot_complete_refuses_the_advance(tmp_path: Path):
    artifact = tmp_path / "policy.json"
    artifact.write_bytes(policy_bytes(5))
    unwritable = tmp_path / "nonexistent-directory" / "policy.state"

    # The advance cannot be recorded, so it must not be honoured either;
    # otherwise the process would accept a version it could not remember.
    assert provider(artifact, unwritable).load() is None


def test_without_a_state_path_the_guard_stays_in_process(tmp_path: Path):
    artifact = tmp_path / "policy.json"
    artifact.write_bytes(policy_bytes(7))

    live = provider(artifact, None)
    assert live.load().config_version == 7
    artifact.write_bytes(policy_bytes(6))
    assert live.load() is None  # same process still refuses the rollback

    # A new instance is a restart with no durable record, so it accepts it.
    assert provider(artifact, None).load().config_version == 6


def test_the_state_file_is_created_private(tmp_path: Path):
    artifact = tmp_path / "policy.json"
    state = tmp_path / "policy.state"
    artifact.write_bytes(policy_bytes(2))
    provider(artifact, state).load()
    assert state.stat().st_mode & 0o077 == 0
