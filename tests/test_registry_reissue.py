"""Same-policy registry reissue: fresh publication time, unchanged material.

The 24-hour freshness ceiling (max_age_seconds=86400) is a fail-closed
security contract and is never widened. A higher signed release may republish
the SAME policy with a later ``generated_at``. Verification must still reject
future publication, staleness, expiry, replay, rollback, equivocation, wrong
signers, and any tampering with the preserved material.
"""

from __future__ import annotations

import base64
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.policy_registry import (
    PolicyRegistryError,
    PolicyRegistryState,
    canonical_json,
    sign_registry,
    verify_registry,
)

REGISTRY_SEED = bytes(range(32))
RECEIPT_SEED = bytes(range(32, 64))
NOW = datetime.now(UTC).replace(microsecond=0)
WINDOW_FROM = NOW - timedelta(hours=1)
WINDOW_UNTIL = NOW + timedelta(hours=47)


def _registry_text(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _public_raw(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _public_b64(seed: bytes) -> str:
    return base64.b64encode(_public_raw(seed)).decode("ascii")


def _fresh_registry_document() -> dict[str, object]:
    return sign_registry(
        {
            "schema": "cathedral_policy_registry_v1",
            "release": 1,
            "generated_at": _registry_text(WINDOW_FROM),
            "valid_from": _registry_text(WINDOW_FROM),
            "valid_until": _registry_text(WINDOW_UNTIL),
            "signing_key_id": "cathedral-policy-test-1",
            "receipt_signing_keys": [
                {
                    "id": "receipt-test-1",
                    "algorithm": "ed25519",
                    "public_key_base64": _public_b64(RECEIPT_SEED),
                    "purpose": "assurance_receipt",
                    "status": "active",
                    "status_changed_at": _registry_text(WINDOW_FROM),
                    "valid_from": _registry_text(WINDOW_FROM),
                    "valid_until": _registry_text(WINDOW_UNTIL),
                    "revoked_at": None,
                    "replacement_key_id": None,
                    "metadata": {"environment": "test-only"},
                }
            ],
            "profiles": [
                {
                    "id": "cpu-tdx-sample-v1",
                    "kind": "cpu_tdx",
                    "status": "active",
                    "status_changed_at": _registry_text(WINDOW_FROM),
                    "valid_from": _registry_text(WINDOW_FROM),
                    "valid_until": _registry_text(WINDOW_UNTIL),
                    "retire_at": None,
                    "measurements": ["tdx-measurement-sha256:sample-v1"],
                    "runtime_measurements": ["runtime-sha256:sample-v1"],
                    "allowed_firmware": [],
                    "min_tcb": 0,
                    "tdx_allowed_tcb_statuses": ["UpToDate"],
                    "tdx_allowed_advisories": [],
                    "metadata": {"description": "registry reissue tests"},
                }
            ],
            "metadata": {"purpose": "registry reissue tests"},
        },
        REGISTRY_SEED,
    )


REGISTRY_DOCUMENT = _fresh_registry_document()
REGISTRY_BYTES = canonical_json(REGISTRY_DOCUMENT)
TRUSTED = {"cathedral-policy-test-1": _public_raw(REGISTRY_SEED)}

_SPEC = importlib.util.spec_from_file_location(
    "cathedral_measurement_approval",
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "cathedral_measurement_approval.py",
)
approval_tool = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(approval_tool)


def _resigned(mutate) -> bytes:
    document = json.loads(REGISTRY_BYTES)
    document.pop("signature", None)
    mutate(document)
    return canonical_json(sign_registry(document, REGISTRY_SEED))


# ---------------------------------------------------------------------------
# verify_registry publication-time semantics
# ---------------------------------------------------------------------------

def test_prepublication_still_verifies():
    # The fixture registry has generated_at == valid_from (one hour ago).
    snapshot = verify_registry(REGISTRY_BYTES, TRUSTED)
    assert snapshot.release == REGISTRY_DOCUMENT["release"]


def test_reissue_publication_after_activation_verifies():
    now_text = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def republish(document):
        document["release"] += 1
        document["generated_at"] = now_text  # later than valid_from

    snapshot = verify_registry(_resigned(republish), TRUSTED, max_age_seconds=86400)
    assert snapshot.release == REGISTRY_DOCUMENT["release"] + 1


def test_publication_at_or_after_expiry_is_rejected():
    def at_expiry(document):
        document["release"] += 1
        document["generated_at"] = document["valid_until"]

    with pytest.raises(PolicyRegistryError, match="precede expiry"):
        verify_registry(_resigned(at_expiry), TRUSTED)


def test_future_publication_is_rejected():
    future = (datetime.now(UTC) + timedelta(minutes=10)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    def futurize(document):
        document["release"] += 1
        document["generated_at"] = future

    with pytest.raises(PolicyRegistryError, match="future"):
        verify_registry(_resigned(futurize), TRUSTED)


def test_stale_publication_is_rejected_at_the_24h_ceiling():
    stale = (datetime.now(UTC) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def stale_publish(document):
        document["release"] += 1
        document["generated_at"] = stale
        document["valid_from"] = stale  # keep window sane for this case

    with pytest.raises(PolicyRegistryError, match="too stale"):
        verify_registry(_resigned(stale_publish), TRUSTED, max_age_seconds=86400)


def test_empty_validity_window_is_rejected():
    def collapse(document):
        document["valid_until"] = document["valid_from"]

    with pytest.raises(PolicyRegistryError, match="validity window"):
        verify_registry(_resigned(collapse), TRUSTED)


# ---------------------------------------------------------------------------
# The renew (reissue) tool
# ---------------------------------------------------------------------------

def _write_inputs(tmp_path: Path, registry_bytes: bytes = REGISTRY_BYTES):
    registry_path = tmp_path / "registry.json"
    registry_path.write_bytes(registry_bytes)
    signing_key = tmp_path / "policy-signing.key"
    signing_key.write_text(base64.b64encode(REGISTRY_SEED).decode())
    signing_key.chmod(0o600)
    return registry_path, signing_key


def _renew_argv(
    tmp_path: Path,
    registry_path: Path,
    signing_key: Path,
    out_name: str = "registry.reissued.json",
    state: Path | None = None,
) -> list[str]:
    argv = [
        "renew",
        "--registry",
        str(registry_path),
        "--signing-key-file",
        str(signing_key),
        "--operator",
        "test-operator",
        "--reason",
        "restore publication freshness",
        "--approval-log",
        str(tmp_path / "approvals.jsonl"),
        "--out",
        str(tmp_path / out_name),
    ]
    if state is not None:
        argv += ["--state", str(state)]
    return argv


@pytest.fixture()
def reissued(tmp_path: Path):
    registry_path, signing_key = _write_inputs(tmp_path)
    code = approval_tool.main(_renew_argv(tmp_path, registry_path, signing_key))
    assert code == 0
    return tmp_path / "registry.reissued.json", tmp_path / "approvals.jsonl"


def test_reissue_preserves_every_security_field_and_restores_freshness(reissued):
    out_path, log_path = reissued
    encoded = out_path.read_bytes()
    # Fresh under the strict 24-hour ceiling with the trusted key.
    snapshot = verify_registry(encoded, TRUSTED, max_age_seconds=86400)
    original = json.loads(REGISTRY_BYTES)
    document = json.loads(encoded)

    assert document["release"] == original["release"] + 1
    assert document["generated_at"] != original["generated_at"]
    assert document["generated_at"] > document["valid_from"]

    # Deep-compare: nothing but release/generated_at/signature/audit changed.
    assert approval_tool._reissue_stripped(document) == approval_tool._reissue_stripped(
        original
    )
    # Explicitly: window, profiles, measurements, keys, transitions unchanged.
    assert document["valid_from"] == original["valid_from"]
    assert document["valid_until"] == original["valid_until"]
    assert document["profiles"] == original["profiles"]
    assert document["receipt_signing_keys"] == original["receipt_signing_keys"]

    # Bounded audit record in metadata plus an approval-log line.
    record = document["metadata"]["reissues"][-1]
    assert set(record) == {"reissued_at", "operator", "reason"}
    assert record["operator"] == "test-operator"
    assert record["reissued_at"] == document["generated_at"]
    logged = json.loads(log_path.read_text().strip().splitlines()[-1])
    assert logged["previous_release"] == original["release"]
    assert logged["action"] == "registry_reissue_prepared"
    assert logged["new_release"] == snapshot.release
    # Secure output file semantics.
    assert (out_path.stat().st_mode & 0o777) == 0o600
    assert (log_path.stat().st_mode & 0o777) == 0o600


def test_reissue_audit_list_is_bounded(tmp_path: Path):
    document = json.loads(REGISTRY_BYTES)
    document.pop("signature")
    document["metadata"] = dict(document["metadata"])
    document["metadata"]["reissues"] = [
        {"reissued_at": f"t{i}", "operator": "o", "reason": "r"}
        for i in range(approval_tool.MAX_REISSUE_AUDIT_ENTRIES + 5)
    ]
    registry_path, signing_key = _write_inputs(
        tmp_path, canonical_json(sign_registry(document, REGISTRY_SEED))
    )
    assert approval_tool.main(_renew_argv(tmp_path, registry_path, signing_key)) == 0
    reissues = json.loads((tmp_path / "registry.reissued.json").read_bytes())[
        "metadata"
    ]["reissues"]
    assert len(reissues) == approval_tool.MAX_REISSUE_AUDIT_ENTRIES


def test_reissue_refuses_to_overwrite_existing_output(tmp_path: Path):
    registry_path, signing_key = _write_inputs(tmp_path)
    # First run succeeds and creates the output.
    assert approval_tool.main(_renew_argv(tmp_path, registry_path, signing_key)) == 0
    out_path = tmp_path / "registry.reissued.json"
    created = out_path.read_bytes()
    log_lines = (tmp_path / "approvals.jsonl").read_text().splitlines()
    # Second run reaches the existing-output gate: inputs still exist and are
    # valid, only the output collides.
    with pytest.raises(FileExistsError):
        approval_tool.main(_renew_argv(tmp_path, registry_path, signing_key))
    assert out_path.read_bytes() == created  # first artifact untouched
    assert (tmp_path / "approvals.jsonl").read_text().splitlines() == log_lines


def test_state_store_accepts_reissue_and_rejects_replay_and_equivocation(
    reissued, tmp_path: Path
):
    out_path, _log = reissued
    current = verify_registry(REGISTRY_BYTES, TRUSTED)
    successor = verify_registry(out_path.read_bytes(), TRUSTED, max_age_seconds=86400)

    state = PolicyRegistryState(tmp_path / "state.sqlite", minimum_release=1)
    state.accept(current)
    state.accept(successor)  # monotonic successor, no re-anchor
    state.accept(successor)  # identical replay is idempotent

    # Rollback to the prior release is rejected.
    with pytest.raises(PolicyRegistryError, match="rollback"):
        state.accept(current)

    # A different document at the SAME release is equivocation.
    now_text = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def equivocate(document):
        document["release"] = successor.release
        document["generated_at"] = now_text
        document["metadata"] = dict(document["metadata"])
        document["metadata"]["note"] = "different bytes, same release"

    rival = verify_registry(_resigned(equivocate), TRUSTED, max_age_seconds=86400)
    with pytest.raises(PolicyRegistryError, match="equivocated"):
        state.accept(rival)


def test_reissue_signed_by_an_untrusted_key_is_rejected(reissued):
    out_path, _log = reissued
    rogue_trusted = {"cathedral-policy-test-1": bytes(32)}
    with pytest.raises(PolicyRegistryError, match="signature verification failed"):
        verify_registry(out_path.read_bytes(), rogue_trusted, max_age_seconds=86400)


def test_deep_compare_catches_any_policy_material_change():
    original = json.loads(REGISTRY_BYTES)
    tampered = json.loads(REGISTRY_BYTES)
    tampered["release"] += 1
    tampered["generated_at"] = "2026-01-01T00:00:00Z"
    tampered["metadata"] = dict(tampered["metadata"])
    tampered["metadata"]["reissues"] = [{"any": "audit"}]
    # Allowed deltas only -> equal under the stripped comparison.
    assert approval_tool._reissue_stripped(tampered) == approval_tool._reissue_stripped(
        original
    )
    # One measurement added -> caught.
    tampered["profiles"] = json.loads(json.dumps(tampered["profiles"]))
    tampered["profiles"][0]["measurements"].append("tdx-measurement-sha256:evil")
    assert approval_tool._reissue_stripped(tampered) != approval_tool._reissue_stripped(
        original
    )


# ---------------------------------------------------------------------------
# State store: publication-time monotonicity + migration
# ---------------------------------------------------------------------------

def _snapshot_with(release: int, generated_text: str):
    def shape(document):
        document["release"] = release
        document["generated_at"] = generated_text

    return verify_registry(_resigned(shape), TRUSTED, max_age_seconds=86400)


def test_state_store_persists_and_enforces_publication_monotonicity(tmp_path: Path):
    now = datetime.now(UTC)
    text = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    base = json.loads(REGISTRY_BYTES)
    first = _snapshot_with(base["release"], base["generated_at"])
    later = _snapshot_with(base["release"] + 1, text(now - timedelta(minutes=30)))
    backwards = _snapshot_with(base["release"] + 2, text(now - timedelta(minutes=59)))

    state = PolicyRegistryState(tmp_path / "state.sqlite", minimum_release=1)
    state.accept(first)
    assert state.current()["generated_at"] == base["generated_at"]
    state.accept(later)  # monotonic advance
    assert state.current()["generated_at"] == text(now - timedelta(minutes=30))
    state.accept(later)  # idempotent replay
    with pytest.raises(PolicyRegistryError, match="publication time moved backwards"):
        state.accept(backwards)
    # Equal publication time at a higher release is allowed.
    equal = _snapshot_with(base["release"] + 2, text(now - timedelta(minutes=30)))
    state.accept(equal)


def test_state_store_migrates_legacy_schema_and_applies_guard_after(tmp_path: Path):
    import sqlite3 as sqlite_module

    path = tmp_path / "legacy-state.sqlite"
    with sqlite_module.connect(path) as connection:
        connection.execute(
            "CREATE TABLE policy_registry_state ("
            "singleton INTEGER PRIMARY KEY, release INTEGER NOT NULL, "
            "digest TEXT NOT NULL, profile_states_json TEXT NOT NULL, "
            "receipt_key_states_json TEXT NOT NULL DEFAULT '{}', "
            "accepted_at TEXT NOT NULL)"
        )
    state = PolicyRegistryState(path, minimum_release=1)
    with sqlite_module.connect(path) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(policy_registry_state)")
        }
    assert "generated_at" in columns
    assert state.current() is None

    # Seed a legacy-style row WITHOUT a recorded publication time: the guard
    # must not reject the next accept (no basis), then start enforcing. The
    # legacy row sits at a lower release so the accept is a normal successor.
    base = json.loads(REGISTRY_BYTES)
    first = _snapshot_with(base["release"] + 1, base["generated_at"])
    with sqlite_module.connect(path) as connection:
        connection.execute(
            "INSERT INTO policy_registry_state(singleton, release, digest, "
            "profile_states_json, receipt_key_states_json, accepted_at) "
            "VALUES (1, ?, ?, ?, ?, ?)",
            (
                base["release"],
                "sha256:" + "0" * 64,
                "{}",
                "{}",
                "2026-07-01T00:00:00Z",
            ),
        )
    migrated = PolicyRegistryState(path, minimum_release=1)
    assert migrated.current()["generated_at"] == ""
    migrated.accept(first)  # legacy row: no publication-time basis, accepted
    assert migrated.current()["generated_at"] == base["generated_at"]
    now = datetime.now(UTC)
    stale_text = (now - timedelta(minutes=61)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if stale_text < base["generated_at"]:
        with pytest.raises(PolicyRegistryError, match="moved backwards"):
            migrated.accept(_snapshot_with(first.release + 1, stale_text))


def test_renew_state_proof_uses_a_temporary_copy(tmp_path: Path):
    registry_path, signing_key = _write_inputs(tmp_path)
    current = verify_registry(REGISTRY_BYTES, TRUSTED)
    state_path = tmp_path / "production-state.sqlite"
    state = PolicyRegistryState(state_path, minimum_release=1)
    state.accept(current)
    before = state_path.read_bytes()

    code = approval_tool.main(
        _renew_argv(tmp_path, registry_path, signing_key, state=state_path)
    )
    assert code == 0
    # The production state file was only copied, never written.
    assert PolicyRegistryState(state_path, minimum_release=1).current()[
        "release"
    ] == current.release
    assert state_path.read_bytes() == before


def test_renew_aborts_when_production_state_is_ahead(tmp_path: Path):
    registry_path, signing_key = _write_inputs(tmp_path)
    ahead = _snapshot_with(
        json.loads(REGISTRY_BYTES)["release"] + 5,
        datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    state_path = tmp_path / "production-state.sqlite"
    PolicyRegistryState(state_path, minimum_release=1).accept(ahead)

    with pytest.raises(PolicyRegistryError, match="rollback"):
        approval_tool.main(
            _renew_argv(tmp_path, registry_path, signing_key, state=state_path)
        )
    assert not (tmp_path / "registry.reissued.json").exists()


# ---------------------------------------------------------------------------
# Signing-seed and audit-log file hygiene
# ---------------------------------------------------------------------------

def test_signing_seed_loader_rejects_bad_files(tmp_path: Path):
    good = tmp_path / "seed.key"
    good.write_text(base64.b64encode(REGISTRY_SEED).decode())
    good.chmod(0o600)
    assert approval_tool._load_signing_seed(str(good)) == REGISTRY_SEED

    lax = tmp_path / "lax.key"
    lax.write_text(base64.b64encode(REGISTRY_SEED).decode())
    lax.chmod(0o644)
    with pytest.raises(SystemExit, match="group/world"):
        approval_tool._load_signing_seed(str(lax))

    link = tmp_path / "link.key"
    link.symlink_to(good)
    with pytest.raises(SystemExit, match="regular non-symlink"):
        approval_tool._load_signing_seed(str(link))

    short = tmp_path / "short.key"
    short.write_text(base64.b64encode(b"tooshort").decode())
    short.chmod(0o600)
    with pytest.raises(SystemExit, match="32-byte"):
        approval_tool._load_signing_seed(str(short))

    garbage = tmp_path / "garbage.key"
    garbage.write_text("!!!not-base64!!!")
    garbage.chmod(0o600)
    with pytest.raises(SystemExit, match="canonical base64"):
        approval_tool._load_signing_seed(str(garbage))

    huge = tmp_path / "huge.key"
    huge.write_bytes(b"A" * 200)
    huge.chmod(0o600)
    with pytest.raises(SystemExit, match="too large"):
        approval_tool._load_signing_seed(str(huge))


def test_bounded_operator_and_reason_fields(tmp_path: Path):
    with pytest.raises(SystemExit, match="control characters"):
        approval_tool._bounded_field("evil\x1b[31moperator", "operator")
    with pytest.raises(SystemExit, match="1..200"):
        approval_tool._bounded_field("x" * 201, "reason")
    with pytest.raises(SystemExit, match="1..200"):
        approval_tool._bounded_field("", "operator")


def test_symlink_approval_log_is_rejected_and_output_rolled_back(tmp_path: Path):
    registry_path, signing_key = _write_inputs(tmp_path)
    target = tmp_path / "real-log.jsonl"
    target.write_text("")
    target.chmod(0o600)
    log_symlink = tmp_path / "approvals.jsonl"
    log_symlink.symlink_to(target)

    with pytest.raises(SystemExit, match="regular non-symlink"):
        approval_tool.main(_renew_argv(tmp_path, registry_path, signing_key))
    # No unlogged artifact: the freshly created output was rolled back.
    assert not (tmp_path / "registry.reissued.json").exists()
    assert target.read_text() == ""


def test_lax_mode_approval_log_is_rejected(tmp_path: Path):
    registry_path, signing_key = _write_inputs(tmp_path)
    log_path = tmp_path / "approvals.jsonl"
    log_path.write_text("")
    log_path.chmod(0o644)
    with pytest.raises(SystemExit, match="group/world"):
        approval_tool.main(_renew_argv(tmp_path, registry_path, signing_key))
    assert not (tmp_path / "registry.reissued.json").exists()


# ---------------------------------------------------------------------------
# Historical verification still rejects future publication
# ---------------------------------------------------------------------------

def test_historical_verification_rejects_future_publication():
    future_text = (datetime.now(UTC) + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    def futurize(document):
        document["release"] += 1
        document["generated_at"] = future_text

    encoded = _resigned(futurize)
    historical_moment = datetime.now(UTC) - timedelta(minutes=30)
    with pytest.raises(PolicyRegistryError, match="future"):
        verify_registry(encoded, TRUSTED, historical_at=historical_moment)


def test_exact_idempotent_accept_backfills_legacy_generated_at(tmp_path: Path):
    """The migration-bypass counterexample: a legacy row at the SAME release
    and SAME digest with generated_at='' must be backfilled by the exact
    idempotent accept, so the next higher release can never move publication
    time backwards unnoticed."""
    import sqlite3 as sqlite_module

    base = json.loads(REGISTRY_BYTES)
    current = verify_registry(REGISTRY_BYTES, TRUSTED)
    path = tmp_path / "state.sqlite"
    state = PolicyRegistryState(path, minimum_release=1)
    state.accept(current)
    # Simulate the migrated legacy row: same release, same digest, no
    # recorded publication time.
    with sqlite_module.connect(path) as connection:
        connection.execute("UPDATE policy_registry_state SET generated_at = ''")
    migrated = PolicyRegistryState(path, minimum_release=1)
    assert migrated.current()["generated_at"] == ""

    # Exact idempotent accept takes the same-release/same-digest early
    # return; it must atomically backfill the publication time.
    migrated.accept(current)
    assert migrated.current()["generated_at"] == base["generated_at"]

    # The bypass is closed: a higher release publishing EARLIER than the
    # backfilled time is rejected.
    earlier = (
        datetime.strptime(base["generated_at"], "%Y-%m-%dT%H:%M:%SZ")
        - timedelta(minutes=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(PolicyRegistryError, match="publication time moved backwards"):
        migrated.accept(_snapshot_with(base["release"] + 1, earlier))
    # And a later publication still advances normally.
    later = (
        datetime.strptime(base["generated_at"], "%Y-%m-%dT%H:%M:%SZ")
        + timedelta(minutes=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    migrated.accept(_snapshot_with(base["release"] + 1, later))
    assert migrated.current()["generated_at"] == later
