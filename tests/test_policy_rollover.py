"""Bounded policy-window and receipt-key rollover tests."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.policy_registry import (
    PolicyRegistryError,
    PolicyRegistryState,
    verify_registry,
)
from tests.test_registry_reissue import (
    REGISTRY_BYTES,
    REGISTRY_SEED,
    TRUSTED,
)

_SPEC = importlib.util.spec_from_file_location(
    "cathedral_measurement_approval_rollover",
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "cathedral_measurement_approval.py",
)
approval_tool = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(approval_tool)


def _future_text(days: int = 30) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    registry_path = tmp_path / "registry.json"
    registry_path.write_bytes(REGISTRY_BYTES)
    # chmod, not the write mode: write_bytes/open honour the process umask, so
    # under Ubuntu's default 002 this lands 0664 and the tool's
    # "must not be group/world writable" guard fires before the assertion below.
    registry_path.chmod(0o644)
    signing_key = tmp_path / "policy-signing.key"
    signing_key.write_text(base64.b64encode(REGISTRY_SEED).decode("ascii"))
    signing_key.chmod(0o600)
    state_path = tmp_path / "policy-state.sqlite"
    PolicyRegistryState(state_path, minimum_release=1).accept(
        verify_registry(REGISTRY_BYTES, TRUSTED)
    )
    return registry_path, signing_key, state_path


def _argv(
    tmp_path: Path,
    registry_path: Path,
    signing_key: Path,
    state_path: Path,
    *,
    valid_until: str | None = None,
) -> list[str]:
    return [
        "rollover",
        "--registry",
        str(registry_path),
        "--signing-key-file",
        str(signing_key),
        "--state",
        str(state_path),
        "--source-profile-id",
        "cpu-tdx-sample-v1",
        "--new-profile-id",
        "cpu-tdx-sample-v2",
        "--new-receipt-key-id",
        "receipt-test-2",
        "--valid-until",
        valid_until or _future_text(),
        "--operator",
        "test operator",
        "--reason",
        "bounded launch-window rollover",
        "--approval-log",
        str(tmp_path / "rollovers.jsonl"),
        "--out",
        str(tmp_path / "registry.next.json"),
        "--receipt-signing-key-out",
        str(tmp_path / "receipt.next.key"),
    ]


def test_rollover_preserves_history_adds_exact_clone_and_new_key(tmp_path: Path):
    registry_path, signing_key, state_path = _write_inputs(tmp_path)
    old_state_bytes = state_path.read_bytes()
    assert approval_tool.main(
        _argv(tmp_path, registry_path, signing_key, state_path)
    ) == 0

    registry_out = tmp_path / "registry.next.json"
    receipt_key_out = tmp_path / "receipt.next.key"
    log_path = tmp_path / "rollovers.jsonl"
    assert os.stat(registry_out).st_mode & 0o777 == 0o600
    assert os.stat(receipt_key_out).st_mode & 0o777 == 0o600
    assert os.stat(log_path).st_mode & 0o777 == 0o600

    current = json.loads(REGISTRY_BYTES)
    successor_bytes = registry_out.read_bytes()
    successor = json.loads(successor_bytes)
    snapshot = verify_registry(successor_bytes, TRUSTED)
    assert successor["release"] == current["release"] + 1
    assert successor["valid_from"] == current["valid_from"]
    assert successor["valid_until"] != current["valid_until"]
    assert successor["profiles"][0] == current["profiles"][0]
    assert successor["receipt_signing_keys"][0] == current["receipt_signing_keys"][0]

    original_profile = successor["profiles"][0]
    new_profile = successor["profiles"][1]
    assert new_profile["id"] == "cpu-tdx-sample-v2"
    for field in (
        "kind",
        "measurements",
        "runtime_measurements",
        "allowed_firmware",
        "min_tcb",
        "tdx_allowed_tcb_statuses",
        "tdx_allowed_advisories",
    ):
        assert new_profile[field] == original_profile[field]
    old_expiry = datetime.strptime(
        original_profile["valid_until"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=UTC)
    future_policy = snapshot.to_policy(at=old_expiry + timedelta(seconds=1))
    assert future_policy.registry_profile_ids == ("cpu-tdx-sample-v2",)

    seed = base64.b64decode(receipt_key_out.read_bytes().strip(), validate=True)
    assert len(seed) == 32
    expected_public = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    assert base64.b64decode(
        successor["receipt_signing_keys"][1]["public_key_base64"], validate=True
    ) == expected_public

    # The proof uses a copy: the live state is unchanged until deliberate install.
    assert state_path.read_bytes() == old_state_bytes
    live_state = PolicyRegistryState(state_path, minimum_release=1)
    live_state.accept(snapshot)
    assert live_state.current()["release"] == successor["release"]

    audit_text = log_path.read_text()
    audit = json.loads(audit_text)
    assert audit["new_profile_id"] == "cpu-tdx-sample-v2"
    assert audit["new_receipt_key_id"] == "receipt-test-2"
    assert base64.b64encode(seed).decode("ascii") not in audit_text


@pytest.mark.parametrize("days", [1, 181])
def test_rollover_rejects_out_of_bounds_window(tmp_path: Path, days: int):
    registry_path, signing_key, state_path = _write_inputs(tmp_path)
    with pytest.raises(SystemExit, match="between 7 and 180 days"):
        approval_tool.main(
            _argv(
                tmp_path,
                registry_path,
                signing_key,
                state_path,
                valid_until=_future_text(days),
            )
        )
    assert not (tmp_path / "registry.next.json").exists()
    assert not (tmp_path / "receipt.next.key").exists()


def test_rollover_rejects_duplicate_profile_and_key_ids(tmp_path: Path):
    registry_path, signing_key, state_path = _write_inputs(tmp_path)
    argv = _argv(tmp_path, registry_path, signing_key, state_path)
    argv[argv.index("--new-profile-id") + 1] = "cpu-tdx-sample-v1"
    with pytest.raises(SystemExit, match="profile id already exists"):
        approval_tool.main(argv)

    argv = _argv(tmp_path, registry_path, signing_key, state_path)
    argv[argv.index("--new-receipt-key-id") + 1] = "receipt-test-1"
    with pytest.raises(SystemExit, match="receipt key id already exists"):
        approval_tool.main(argv)


def test_rollover_rolls_back_new_key_when_registry_output_exists(tmp_path: Path):
    registry_path, signing_key, state_path = _write_inputs(tmp_path)
    existing = tmp_path / "registry.next.json"
    existing.write_text("operator-owned")
    with pytest.raises(FileExistsError):
        approval_tool.main(_argv(tmp_path, registry_path, signing_key, state_path))
    assert existing.read_text() == "operator-owned"
    assert not (tmp_path / "receipt.next.key").exists()
    assert not (tmp_path / "rollovers.jsonl").exists()


def test_rollover_rolls_back_both_outputs_when_audit_log_is_unsafe(tmp_path: Path):
    registry_path, signing_key, state_path = _write_inputs(tmp_path)
    target = tmp_path / "audit-target"
    target.write_text("")
    target.chmod(0o600)
    (tmp_path / "rollovers.jsonl").symlink_to(target)
    with pytest.raises(SystemExit, match="regular non-symlink"):
        approval_tool.main(_argv(tmp_path, registry_path, signing_key, state_path))
    assert not (tmp_path / "registry.next.json").exists()
    assert not (tmp_path / "receipt.next.key").exists()
    assert target.read_text() == ""


def test_rollover_proof_rejects_state_ahead_of_registry(tmp_path: Path):
    registry_path, signing_key, state_path = _write_inputs(tmp_path)
    with sqlite3.connect(state_path) as connection:
        connection.execute(
            "UPDATE policy_registry_state SET release = release + 10"
        )
    with pytest.raises(PolicyRegistryError, match="rollback"):
        approval_tool.main(_argv(tmp_path, registry_path, signing_key, state_path))
    assert not (tmp_path / "registry.next.json").exists()
    assert not (tmp_path / "receipt.next.key").exists()


def test_rollover_rejects_control_characters_in_identifiers(tmp_path: Path):
    registry_path, signing_key, state_path = _write_inputs(tmp_path)
    argv = _argv(tmp_path, registry_path, signing_key, state_path)
    argv[argv.index("--new-profile-id") + 1] = "cpu\nprofile"
    with pytest.raises(SystemExit, match="identifier"):
        approval_tool.main(argv)
