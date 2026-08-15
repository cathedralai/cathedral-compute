"""Approved-coldkey allowlist gate at enrollment (issue #56).

Covers:
  1. Allowlisted coldkey enrolls; non-allowlisted rejected 403 with logged
     hotkey, coldkey, and reason.
  2. Unresolvable coldkey fails closed (hotkeys-only snapshot, absent
     mapping, or no resolver at all).
  3. Stale, malformed, or badly signed allowlist artifacts fail closed in
     production mode; so do release rollbacks and pinned-digest mismatches.
  4. Production mode with no allowlist configured rejects all enrollment;
     non-production mode without an allowlist keeps the open behavior.
  5. Gate ordering: a rejected request records no durable row and burns no
     per-hotkey attempt budget.
  6. Reconciliation lists and, with --remove, retires only non-allowlisted
     rows.
  7. Snapshot backward compatibility: hotkeys-only formats still gate
     registration while coldkey resolution fails closed.
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import sqlite3
from unittest import mock
import time
from base64 import b64encode
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from substrateinterface import Keypair, KeypairType

from cathedral.cli import cmd_enroll_reconcile
from cathedral.coldkey_allowlist import (
    ColdkeyAllowlistError,
    SignedColdkeyAllowlistProvider,
    load_allowlist_keys,
    sign_allowlist,
    verify_allowlist,
)
from cathedral.enroll import (
    JsonHotkeyRegistrationProvider,
    RegistryApp,
    RegistryStore,
    canonical_enroll_payload,
    now_iso,
)
from cathedral.lifecycle import WorkerLifecycleState

# ---------------------------------------------------------------------------
# Shared helpers (same WSGI-call style as test_enrollment_hardening.py)
# ---------------------------------------------------------------------------

KEYPAIR = Keypair.create_from_uri("//Alice", crypto_type=KeypairType.SR25519)
HOTKEY = KEYPAIR.ss58_address
COLDKEY = Keypair.create_from_uri("//AliceCold", crypto_type=KeypairType.SR25519).ss58_address
OTHER_COLDKEY = Keypair.create_from_uri("//Mallory", crypto_type=KeypairType.SR25519).ss58_address

PRIVATE_SEED = bytes(range(64, 96))
PUBLIC_KEY = (
    Ed25519PrivateKey.from_private_bytes(PRIVATE_SEED)
    .public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
)
SIGNING_KEY_ID = "cathedral-enroll-allowlist-test-1"
TRUSTED = {SIGNING_KEY_ID: PUBLIC_KEY}

# Production mode requires a public IP literal endpoint.
ENDPOINT = "https://8.8.8.8:8090"


def _signed_payload(
    endpoint_url: str = ENDPOINT,
    *,
    keypair: Keypair = KEYPAIR,
    hotkey: str = HOTKEY,
    nonce: str = "aa" * 16,
    timestamp: str | None = None,
) -> dict[str, str]:
    ts = timestamp if timestamp is not None else now_iso()
    message = canonical_enroll_payload(hotkey, endpoint_url, nonce, ts)
    sig = b64encode(keypair.sign(message)).decode("ascii")
    return {
        "hotkey": hotkey,
        "endpoint_url": endpoint_url,
        "nonce": nonce,
        "timestamp": ts,
        "signature_b64": sig,
    }


def _call(
    app: RegistryApp,
    payload: dict,
    *,
    remote_addr: str = "1.2.3.4",
) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/v1/enroll",
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
        "REMOTE_ADDR": remote_addr,
    }
    seen: dict = {}

    def start_response(status: str, headers: list) -> None:
        seen["status"] = status

    raw = b"".join(app(environ, start_response))
    return int(seen["status"].split()[0]), json.loads(raw.decode("utf-8"))


def _allowlist_document(
    coldkeys: list[str],
    *,
    release: int = 1,
    generated_at: str | None = None,
    valid_from: str | None = None,
    valid_until: str | None = None,
    seed: bytes = PRIVATE_SEED,
) -> dict:
    now = datetime.now(UTC)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    unsigned = {
        "schema": "cathedral_coldkey_allowlist_v1",
        "release": release,
        "generated_at": generated_at or now.strftime(fmt),
        "valid_from": valid_from or (now - timedelta(hours=1)).strftime(fmt),
        "valid_until": valid_until or (now + timedelta(days=30)).strftime(fmt),
        "signing_key_id": SIGNING_KEY_ID,
        "coldkeys": coldkeys,
    }
    return sign_allowlist(unsigned, seed)


def _write_allowlist(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")))


def _snapshot_file(tmp_path: Path, mapping: dict[str, str] | list[str]) -> Path:
    hk_file = tmp_path / "registered-hotkeys.json"
    hk_file.write_text(json.dumps({"hotkeys": mapping}))
    return hk_file


def _provider(tmp_path: Path, mapping: dict[str, str] | list[str]) -> JsonHotkeyRegistrationProvider:
    return JsonHotkeyRegistrationProvider(
        str(_snapshot_file(tmp_path, mapping)), max_age_seconds=3600
    )


def _allowlist_provider(
    tmp_path: Path,
    coldkeys: list[str],
    **document_kwargs,
) -> SignedColdkeyAllowlistProvider:
    path = tmp_path / "allowlist.json"
    _write_allowlist(path, _allowlist_document(coldkeys, **document_kwargs))
    return SignedColdkeyAllowlistProvider(str(path), TRUSTED)


def _app(
    tmp_path: Path,
    *,
    db: str = "registry.sqlite",
    coldkey_allowlist: object | None = None,
    registration_provider: object | None = None,
    production_mode: bool = True,
    hotkey_enroll_limit: int = 20,
) -> RegistryApp:
    return RegistryApp(
        RegistryStore(str(tmp_path / db)),
        registration_provider=registration_provider,
        coldkey_allowlist=coldkey_allowlist,
        production_mode=production_mode,
        hotkey_enroll_limit=hotkey_enroll_limit,
    )


# ---------------------------------------------------------------------------
# 1. Allowlisted enrolls; non-allowlisted rejected 403 with logged reason
# ---------------------------------------------------------------------------

def test_allowlisted_coldkey_enrolls(tmp_path: Path) -> None:
    app = _app(
        tmp_path,
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=_allowlist_provider(tmp_path, [COLDKEY]),
    )
    status, body = _call(app, _signed_payload(nonce="10" * 16))
    assert status == 200
    assert body["status"] == "enrolled"
    # The token is minted at enrollment and handed back here (#60 interim).
    assert body["worker_token"]
    assert [e.hotkey for e in app.store.enrollments()] == [HOTKEY]


def test_non_allowlisted_coldkey_rejected_with_logged_reason(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(
        tmp_path,
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=_allowlist_provider(tmp_path, [OTHER_COLDKEY]),
    )
    with caplog.at_level(logging.WARNING, logger="cathedral.enroll"):
        status, body = _call(app, _signed_payload(nonce="11" * 16))
    assert status == 403
    assert "not approved" in body["error"]
    assert app.store.enrollments() == []
    assert "reason=coldkey_not_allowlisted" in caplog.text
    assert f"hotkey={HOTKEY}" in caplog.text
    assert f"coldkey={COLDKEY}" in caplog.text


# ---------------------------------------------------------------------------
# 2. Unresolvable coldkey fails closed
# ---------------------------------------------------------------------------

def test_hotkeys_only_snapshot_makes_coldkey_unresolvable(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Legacy list format: registration passes, resolution fails closed.
    app = _app(
        tmp_path,
        registration_provider=_provider(tmp_path, [HOTKEY]),
        coldkey_allowlist=_allowlist_provider(tmp_path, [COLDKEY]),
    )
    with caplog.at_level(logging.WARNING, logger="cathedral.enroll"):
        status, body = _call(app, _signed_payload(nonce="20" * 16))
    assert status == 403
    assert "could not be resolved" in body["error"]
    assert "coldkey=unresolvable" in caplog.text
    assert app.store.enrollments() == []


def test_hotkey_absent_from_extended_mapping_fails_closed(tmp_path: Path) -> None:
    other_hotkey = "5" + "R" * 47
    provider = _provider(tmp_path, {other_hotkey: COLDKEY, HOTKEY: COLDKEY})
    # Registration passes for HOTKEY, but simulate a mapping that lost it by
    # asserting the provider contract directly for the absent key.
    assert provider.resolve_coldkey("5" + "S" * 47) is None
    assert provider.resolve_coldkey(HOTKEY) == COLDKEY


def test_provider_without_resolver_fails_closed(tmp_path: Path) -> None:
    class _RegisteredNoResolver:
        def is_registered(self, hotkey: str) -> bool | None:
            return True

    app = _app(
        tmp_path,
        registration_provider=_RegisteredNoResolver(),
        coldkey_allowlist=_allowlist_provider(tmp_path, [COLDKEY]),
    )
    status, body = _call(app, _signed_payload(nonce="21" * 16))
    assert status == 403
    assert "could not be resolved" in body["error"]


# ---------------------------------------------------------------------------
# 3. Stale / malformed / bad-signature allowlist fails closed in production
# ---------------------------------------------------------------------------

def _production_app_with_allowlist_file(tmp_path: Path, path: Path) -> RegistryApp:
    return _app(
        tmp_path,
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=SignedColdkeyAllowlistProvider(str(path), TRUSTED),
    )


def test_stale_allowlist_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    old = (datetime.now(UTC) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_allowlist(path, _allowlist_document([COLDKEY], generated_at=old))
    app = _production_app_with_allowlist_file(tmp_path, path)
    status, body = _call(app, _signed_payload(nonce="30" * 16))
    assert status == 403
    assert "unavailable" in body["error"]


def test_malformed_allowlist_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    path.write_text("{not json")
    app = _production_app_with_allowlist_file(tmp_path, path)
    status, _ = _call(app, _signed_payload(nonce="31" * 16))
    assert status == 403


def test_missing_allowlist_file_fails_closed(tmp_path: Path) -> None:
    app = _production_app_with_allowlist_file(tmp_path, tmp_path / "missing.json")
    status, _ = _call(app, _signed_payload(nonce="32" * 16))
    assert status == 403


def test_bad_signature_allowlist_fails_closed(tmp_path: Path) -> None:
    document = _allowlist_document([COLDKEY])
    # Tamper after signing: membership changes, signature does not.
    document["coldkeys"] = [COLDKEY, OTHER_COLDKEY]
    path = tmp_path / "allowlist.json"
    _write_allowlist(path, document)
    app = _production_app_with_allowlist_file(tmp_path, path)
    status, _ = _call(app, _signed_payload(nonce="33" * 16))
    assert status == 403


def test_untrusted_signing_seed_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    _write_allowlist(path, _allowlist_document([COLDKEY], seed=bytes(range(32))))
    app = _production_app_with_allowlist_file(tmp_path, path)
    status, _ = _call(app, _signed_payload(nonce="34" * 16))
    assert status == 403


def test_release_rollback_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    _write_allowlist(path, _allowlist_document([COLDKEY], release=5))
    provider = SignedColdkeyAllowlistProvider(str(path), TRUSTED)
    assert provider.is_allowed(COLDKEY) is True
    _write_allowlist(path, _allowlist_document([COLDKEY], release=4))
    assert provider.is_allowed(COLDKEY) is None


def test_pinned_artifact_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    document = _allowlist_document([COLDKEY])
    _write_allowlist(path, document)
    good = verify_allowlist(path.read_bytes(), TRUSTED)
    pinned = SignedColdkeyAllowlistProvider(str(path), TRUSTED, pinned_digest=good.digest)
    assert pinned.is_allowed(COLDKEY) is True
    mismatched = SignedColdkeyAllowlistProvider(
        str(path), TRUSTED, pinned_digest="sha256:" + "0" * 64
    )
    assert mismatched.is_allowed(COLDKEY) is None


def test_empty_allowlist_rejects_without_failing_open(tmp_path: Path) -> None:
    provider = _allowlist_provider(tmp_path, [])
    assert provider.is_allowed(COLDKEY) is False


def test_load_allowlist_keys_digest_pinning(tmp_path: Path) -> None:
    keys_file = tmp_path / "keys.json"
    keys_file.write_text(
        json.dumps({SIGNING_KEY_ID: b64encode(PUBLIC_KEY).decode("ascii")})
    )
    import hashlib

    digest = "sha256:" + hashlib.sha256(keys_file.read_bytes()).hexdigest()
    assert load_allowlist_keys(str(keys_file), pinned_digest=digest) == TRUSTED
    with pytest.raises(ColdkeyAllowlistError, match="digest does not match"):
        load_allowlist_keys(str(keys_file), pinned_digest="sha256:" + "1" * 64)
    with pytest.raises(ColdkeyAllowlistError, match="pinned digest"):
        load_allowlist_keys(str(keys_file), production_mode=True)


# ---------------------------------------------------------------------------
# 4. Allowlist-unset behavior per mode
# ---------------------------------------------------------------------------

def test_production_mode_without_allowlist_rejects_all(tmp_path: Path) -> None:
    app = _app(
        tmp_path,
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=None,
    )
    status, body = _call(app, _signed_payload(nonce="40" * 16))
    assert status == 403
    assert "allowlist not configured" in body["error"]
    assert app.store.enrollments() == []


def test_non_production_without_allowlist_keeps_current_behavior(tmp_path: Path) -> None:
    app = _app(tmp_path, production_mode=False)
    status, body = _call(
        app, _signed_payload("https://miner.example.com:8090", nonce="41" * 16)
    )
    assert status == 200
    assert body["status"] == "enrolled"
    # The token is minted at enrollment and handed back here (#60 interim).
    assert body["worker_token"]


def test_non_production_with_allowlist_activates_gate(tmp_path: Path) -> None:
    app = _app(
        tmp_path,
        production_mode=False,
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=_allowlist_provider(tmp_path, [OTHER_COLDKEY]),
    )
    status, _ = _call(app, _signed_payload(nonce="42" * 16))
    assert status == 403


# ---------------------------------------------------------------------------
# 5. Gate ordering: rejections create no enrollment but do cost attempt budget
# ---------------------------------------------------------------------------

def test_rejected_enrollment_creates_no_enrollment_row(tmp_path: Path) -> None:
    db = tmp_path / "ordering.sqlite"
    allowlist_path = tmp_path / "allowlist.json"
    _write_allowlist(allowlist_path, _allowlist_document([OTHER_COLDKEY]))
    app = RegistryApp(
        RegistryStore(str(db)),
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=SignedColdkeyAllowlistProvider(str(allowlist_path), TRUSTED),
        production_mode=True,
        hotkey_enroll_limit=4,
    )
    status, _ = _call(app, _signed_payload(nonce="50" * 16))
    assert status == 403

    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0] == 0

    # Approving the coldkey lets the very next request through.
    _write_allowlist(allowlist_path, _allowlist_document([COLDKEY], release=2))
    status, _ = _call(app, _signed_payload(nonce="51" * 16))
    assert status == 200

    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0] == 1


def test_rejected_enrollment_still_consumes_attempt_budget(tmp_path: Path) -> None:
    """The durable per-hotkey limit must bound rejected requests too.

    Each gate reads and verifies an operator-controlled artifact, so a rejected
    request is not free. Without a durable record, a distributed caller could
    drive unbounded signature and allowlist verifications past the per-process
    IP limiter.
    """
    db = tmp_path / "ordering-budget.sqlite"
    allowlist_path = tmp_path / "allowlist.json"
    _write_allowlist(allowlist_path, _allowlist_document([OTHER_COLDKEY]))
    app = RegistryApp(
        RegistryStore(str(db)),
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=SignedColdkeyAllowlistProvider(str(allowlist_path), TRUSTED),
        production_mode=True,
        hotkey_enroll_limit=1,
    )
    status, _ = _call(app, _signed_payload(nonce="60" * 16))
    assert status == 403

    with sqlite3.connect(db) as conn:
        assert (
            conn.execute("SELECT COUNT(*) FROM hotkey_enroll_attempts").fetchone()[0]
            == 1
        )

    # Budget is spent, so the next request is rate limited before the gates
    # run again, even though the coldkey is now approved.
    _write_allowlist(allowlist_path, _allowlist_document([COLDKEY], release=2))
    status, _ = _call(app, _signed_payload(nonce="61" * 16))
    assert status == 429

    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0] == 0


# ---------------------------------------------------------------------------
# 6. Reconciliation command
# ---------------------------------------------------------------------------

def _reconcile_args(tmp_path: Path, *, remove: bool) -> argparse.Namespace:
    return argparse.Namespace(
        registry_db=str(tmp_path / "reconcile.sqlite"),
        allowlist=str(tmp_path / "allowlist.json"),
        allowlist_keys=str(tmp_path / "keys.json"),
        allowlist_keys_digest=None,
        allowlist_max_age_seconds=86400,
        registered_hotkeys_file=str(tmp_path / "registered-hotkeys.json"),
        registration_max_age_seconds=3600,
        remove=remove,
    )


def _reconcile_fixture(tmp_path: Path) -> tuple[RegistryStore, str, str]:
    approved = HOTKEY
    rogue = "5" + "G" * 47
    store = RegistryStore(str(tmp_path / "reconcile.sqlite"))
    store.enroll(approved, "https://8.8.8.8:8090")
    store.enroll(rogue, "https://9.9.9.9:8090")
    _write_allowlist(tmp_path / "allowlist.json", _allowlist_document([COLDKEY]))
    (tmp_path / "keys.json").write_text(
        json.dumps({SIGNING_KEY_ID: b64encode(PUBLIC_KEY).decode("ascii")})
    )
    _snapshot_file(tmp_path, {approved: COLDKEY, rogue: OTHER_COLDKEY})
    return store, approved, rogue


def test_reconcile_lists_non_allowlisted_without_changes(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    store, approved, rogue = _reconcile_fixture(tmp_path)
    assert cmd_enroll_reconcile(_reconcile_args(tmp_path, remove=False)) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["checked"] == 2
    assert [entry["hotkey"] for entry in report["flagged"]] == [rogue]
    assert report["flagged"][0]["status"] == "not_allowlisted"
    assert report["flagged"][0]["coldkey"] == OTHER_COLDKEY
    assert report["removed"] == []
    # Listing changes nothing.
    assert store.lifecycle_snapshot(rogue).state is WorkerLifecycleState.PENDING
    assert store.lifecycle_snapshot(approved).state is WorkerLifecycleState.PENDING


def test_reconcile_remove_retires_only_non_allowlisted(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    store, approved, rogue = _reconcile_fixture(tmp_path)
    assert cmd_enroll_reconcile(_reconcile_args(tmp_path, remove=True)) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["removed"] == [rogue]
    assert store.lifecycle_snapshot(rogue).state is WorkerLifecycleState.RETIRED
    assert store.lifecycle_snapshot(approved).state is WorkerLifecycleState.PENDING
    with sqlite3.connect(tmp_path / "reconcile.sqlite") as conn:
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM attestations WHERE hotkey = ?", (rogue,)
            ).fetchone()[0]
            == 0
        )


def test_reconcile_flags_unresolvable_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    store, approved, rogue = _reconcile_fixture(tmp_path)
    # Snapshot that lost the rogue hotkey: unresolvable, still flagged.
    _snapshot_file(tmp_path, {approved: COLDKEY})
    assert cmd_enroll_reconcile(_reconcile_args(tmp_path, remove=False)) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["flagged"][0]["hotkey"] == rogue
    assert report["flagged"][0]["status"] == "unresolvable"


def test_reconcile_aborts_on_hotkeys_only_snapshot(tmp_path: Path) -> None:
    _reconcile_fixture(tmp_path)
    _snapshot_file(tmp_path, [HOTKEY])
    with pytest.raises(ValueError, match="no coldkey mapping"):
        cmd_enroll_reconcile(_reconcile_args(tmp_path, remove=True))


def test_reconcile_aborts_on_stale_snapshot(tmp_path: Path) -> None:
    import os

    _reconcile_fixture(tmp_path)
    stale = time.time() - 7200
    os.utime(tmp_path / "registered-hotkeys.json", (stale, stale))
    with pytest.raises(ValueError, match="missing, stale, empty, or malformed"):
        cmd_enroll_reconcile(_reconcile_args(tmp_path, remove=True))


def test_reconcile_aborts_on_empty_snapshot(tmp_path: Path) -> None:
    """Finding: a torn or failed rotation write (zero-byte redirect, or a
    well-formed but empty extended snapshot) must abort reconcile loudly,
    the same as a stale or malformed one. It must never be read as 'nobody
    is registered' and retire the whole board."""
    import os

    store, approved, rogue = _reconcile_fixture(tmp_path)
    (tmp_path / "registered-hotkeys.json").write_text('{"hotkeys": {}}')
    fresh = time.time()
    os.utime(tmp_path / "registered-hotkeys.json", (fresh, fresh))
    with pytest.raises(ValueError, match="registration snapshot"):
        cmd_enroll_reconcile(_reconcile_args(tmp_path, remove=True))
    assert store.lifecycle_snapshot(rogue).state is WorkerLifecycleState.PENDING
    assert store.lifecycle_snapshot(approved).state is WorkerLifecycleState.PENDING


# ---------------------------------------------------------------------------
# 7. Snapshot backward compatibility
# ---------------------------------------------------------------------------

def test_legacy_snapshot_formats_still_gate_registration(tmp_path: Path) -> None:
    list_file = tmp_path / "list.json"
    list_file.write_text(json.dumps([HOTKEY]))
    object_file = tmp_path / "object.json"
    object_file.write_text(json.dumps({"hotkeys": [HOTKEY]}))
    newline_file = tmp_path / "lines.txt"
    newline_file.write_text(f"# comment\n{HOTKEY}\n")

    for path in (list_file, object_file, newline_file):
        provider = JsonHotkeyRegistrationProvider(str(path), max_age_seconds=3600)
        assert provider.is_registered(HOTKEY) is True
        assert provider.is_registered("5" + "Z" * 47) is False
        # No ownership data: coldkey resolution fails closed.
        assert provider.resolve_coldkey(HOTKEY) is None


def test_extended_snapshot_gates_registration_and_resolves(tmp_path: Path) -> None:
    provider = _provider(tmp_path, {HOTKEY: COLDKEY})
    assert provider.is_registered(HOTKEY) is True
    assert provider.is_registered("5" + "Z" * 47) is False
    assert provider.resolve_coldkey(HOTKEY) == COLDKEY
    assert provider.resolve_coldkey("5" + "Z" * 47) is None


def test_extended_snapshot_with_invalid_values_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"hotkeys": {HOTKEY: 7}}))
    provider = JsonHotkeyRegistrationProvider(str(bad), max_age_seconds=3600)
    assert provider.is_registered(HOTKEY) is None
    assert provider.resolve_coldkey(HOTKEY) is None


# ---------------------------------------------------------------------------
# Worker token minted at enrollment (#60 interim: removes the manual step)
# ---------------------------------------------------------------------------



def _iso_seconds_from_now(offset: int) -> str:
    """A canonical timestamp offset from now, for re-signing the same nonce."""
    from datetime import UTC, datetime, timedelta

    moment = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=offset)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _attempt_count(store: RegistryStore, hotkey: str) -> int:
    """Rows the durable per-hotkey enrollment limiter has recorded."""
    with sqlite3.connect(store.path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM hotkey_enroll_attempts WHERE hotkey = ?", (hotkey,)
        ).fetchone()
    return int(row[0])


def test_worker_token_is_minted_once_and_survives_re_enrollment(tmp_path: Path) -> None:
    """The token must be stable across re-enrollment.

    A miner that changes endpoint re-enrols, and the validator has already
    stored the token it was minted. Rotating it on every enrollment would
    break the validator's copy until the next epoch read, so the first token
    wins and later enrollments return the same one.
    """
    app = _app(
        tmp_path,
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=_allowlist_provider(tmp_path, [COLDKEY]),
    )
    status, body = _call(app, _signed_payload(nonce="20" * 16))
    assert status == 200
    minted = body["worker_token"]
    assert minted and app.store.worker_token(HOTKEY) == minted

    status, body = _call(
        app,
        _signed_payload(endpoint_url="https://8.8.4.4:9443", nonce="21" * 16),
    )
    assert status == 200
    assert body["worker_token"] == minted
    assert app.store.worker_token(HOTKEY) == minted


def test_worker_token_is_accepted_by_the_runtime_bearer_rules(tmp_path: Path) -> None:
    """A minted token must never be the thing that makes a miner unreachable.

    The runtime refuses any token that is empty, over-long, or carries a byte
    outside printable ASCII, and it reports that as missing_auth for the whole
    epoch. Minting has to stay inside those bounds by construction.
    """
    from cathedral.enroll import generate_worker_token
    from cathedral.runtime import MAX_BEARER_TOKEN_LENGTH, _validate_bearer_token

    for _ in range(32):
        token = generate_worker_token()
        assert 0 < len(token) <= MAX_BEARER_TOKEN_LENGTH
        assert all(0x21 <= ord(character) <= 0x7E for character in token)
        _validate_bearer_token(token, required=True)

    assert len({generate_worker_token() for _ in range(64)}) == 64


def test_unenrolled_hotkey_has_no_worker_token(tmp_path: Path) -> None:
    app = _app(
        tmp_path,
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=_allowlist_provider(tmp_path, [COLDKEY]),
    )
    assert app.store.worker_token("5" + "Z" * 47) is None


def test_a_database_without_the_column_migrates_and_reads_as_no_token(
    tmp_path: Path,
) -> None:
    """The real migration, from a schema that genuinely predates the column.

    The previous version of this test created the current schema and then set
    worker_token to NULL, which exercised neither the ALTER TABLE nor the
    "legacy row has no token" read. Build the old table by hand instead, then
    open it through RegistryStore and let the migration run.
    """
    db = tmp_path / "legacy.sqlite"
    legacy_hotkey = "5" + "L" * 47
    with sqlite3.connect(db) as conn:
        conn.execute(
            """
            CREATE TABLE enrollments (
                hotkey TEXT PRIMARY KEY,
                endpoint_url TEXT NOT NULL,
                enrolled_at_iso TEXT NOT NULL,
                updated_at_iso TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO enrollments VALUES (?, ?, ?, ?)",
            (legacy_hotkey, "https://8.8.8.8:8443", now_iso(), now_iso()),
        )

    store = RegistryStore(str(db))
    columns = set()
    with sqlite3.connect(db) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(enrollments)")}
    assert "worker_token" in columns, "opening the store must add the column"
    # The pre-existing row keeps its data and reads as having no token, which
    # is what makes the operator's token file still answer for it.
    assert store.worker_token(legacy_hotkey) is None
    assert [e.hotkey for e in store.enrollments()] == [legacy_hotkey]


def test_token_precedence_prefers_the_file_and_reports_a_conflict(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The precedence the validator actually uses, exercising the real code.

    File first is deliberate: a worker enrolled before minting is running the
    file's value, and re-enrollment happens without human involvement on an
    endpoint change (#61). Letting the minted token win there would switch the
    validator to a credential the running worker does not have.
    """
    from cathedral.cli import resolve_worker_token

    app = _app(
        tmp_path,
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=_allowlist_provider(tmp_path, [COLDKEY]),
    )
    status, body = _call(app, _signed_payload(nonce="30" * 16))
    assert status == 200
    minted = body["worker_token"]

    # No file entry: the minted token is used. This is the new-miner path, and
    # it is the whole point of the change.
    assert resolve_worker_token({}, app.store, HOTKEY) == minted

    # Matching file entry: same answer, no conflict reported.
    with caplog.at_level(logging.WARNING):
        assert resolve_worker_token({HOTKEY: minted}, app.store, HOTKEY) == minted
    assert "differs from the token" not in caplog.text

    # Conflicting file entry: the file wins and the operator is told, because
    # both values are credible and guessing silently breaks a running worker.
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        assert (
            resolve_worker_token({HOTKEY: "operator-set-value"}, app.store, HOTKEY)
            == "operator-set-value"
        )
    assert "differs from the token" in caplog.text

    # A hotkey with neither has no token at all, which the runtime reports as
    # missing_auth for that one miner rather than failing the epoch.
    assert resolve_worker_token({}, app.store, "5" + "Z" * 47) is None


def test_a_retransmission_is_refused_without_consuming_the_hotkey_budget(
    tmp_path: Path,
) -> None:
    """A lost 200 must not lock the hotkey out of enrollment.

    Replaying the same signed request is still refused, deliberately: answering
    it with the token would hand a bearer credential to anyone who captured the
    request inside its expiry window. What changes is that the replay is no
    longer CHARGED, so the fresh request that actually recovers the token is
    not itself rate limited.
    """
    app = _app(
        tmp_path,
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=_allowlist_provider(tmp_path, [COLDKEY]),
    )
    payload = _signed_payload(nonce="31" * 16)
    status, body = _call(app, payload)
    assert status == 200
    minted = body["worker_token"]

    # The replay is still refused. It must never return the credential.
    for _ in range(5):
        status, body = _call(app, payload)
        assert status == 400
        assert "nonce already used" in body["error"]
        assert "worker_token" not in body

    # But they cost the hotkey nothing. Counted directly rather than inferred
    # from a later success, so a limiter that charged them would fail here.
    assert _attempt_count(app.store, HOTKEY) == 1, (
        "only the original request may be charged; retransmissions must not be"
    )
    status, body = _call(app, _signed_payload(nonce="32" * 16))
    assert status == 200
    assert body["worker_token"] == minted, "recovery returns the same token"

    # A different endpoint under an already-used nonce is not a retransmission.
    # It is charged and refused exactly as before, so this is not a bypass.
    # Asserting the 400 alone would not pin this: nonce reuse returns 400 either
    # way, so an is_completed_enrollment that ignored the endpoint would pass.
    # The charge is the property, so count attempts across the call.
    charged_before = _attempt_count(app.store, HOTKEY)
    status, _ = _call(
        app, _signed_payload(endpoint_url="https://8.8.4.4:9443", nonce="31" * 16)
    )
    assert status == 400
    assert _attempt_count(app.store, HOTKEY) == charged_before + 1, (
        "a replay under a DIFFERENT endpoint is not a retransmission and must "
        "still be charged"
    )


def test_production_refuses_a_non_loopback_plaintext_bind(tmp_path: Path) -> None:
    """The listener speaks plaintext and its response now carries a credential."""
    from cathedral.enroll import _is_loopback_host

    assert _is_loopback_host("127.0.0.1") is True
    assert _is_loopback_host("127.0.0.5") is True
    # ::1 is loopback but the server below is AF_INET only, so accepting it
    # would pass validation and then fail at bind with enrollment offline.
    for host in ("::1", "0.0.0.0", "::", "8.8.8.8", "", None, "localhost"):
        assert _is_loopback_host(host) is False, host


def test_the_registry_database_is_owner_only(tmp_path: Path) -> None:
    """The database now holds worker bearer tokens.

    The operator's token file carries the same credential class and is refused
    unless owner-only, so this file must not be left at whatever the process
    umask produced. A world-readable database hands every worker's token to any
    local account.
    """
    import os
    import stat

    db = tmp_path / "registry.sqlite"
    previous = os.umask(0o000)  # worst case: nothing is masked off
    try:
        store = RegistryStore(str(db))
    finally:
        os.umask(previous)

    assert stat.S_IMODE(os.stat(db).st_mode) == 0o600
    for suffix in ("-wal", "-shm", "-journal"):
        sibling = Path(str(db) + suffix)
        if sibling.exists():
            assert stat.S_IMODE(os.stat(sibling).st_mode) == 0o600, suffix
    assert store.worker_token("5" + "Z" * 47) is None


def test_each_hotkey_gets_a_distinct_token(tmp_path: Path) -> None:
    """Two miners must never share a credential.

    Randomness of the generator and stability for one hotkey are both already
    pinned, and neither catches persistence that stores one fixed valid token
    for everyone. That mutation leaves every miner holding the bearer
    credential every worker accepts.
    """
    second = Keypair.create_from_uri("//Bob", crypto_type=KeypairType.SR25519)
    app = _app(
        tmp_path,
        registration_provider=_provider(
            tmp_path, {HOTKEY: COLDKEY, second.ss58_address: COLDKEY}
        ),
        coldkey_allowlist=_allowlist_provider(tmp_path, [COLDKEY]),
    )

    status, first_body = _call(app, _signed_payload(nonce="40" * 16))
    assert status == 200
    status, second_body = _call(
        app,
        _signed_payload(
            endpoint_url="https://8.8.4.4:8443",
            keypair=second,
            hotkey=second.ss58_address,
            nonce="41" * 16,
        ),
    )
    assert status == 200

    assert first_body["worker_token"] != second_body["worker_token"]
    assert app.store.worker_token(HOTKEY) == first_body["worker_token"]
    assert app.store.worker_token(second.ss58_address) == second_body["worker_token"]


def test_a_nonce_is_only_a_retransmission_of_its_own_exact_request(
    tmp_path: Path,
) -> None:
    """A retransmission is a retransmission of ONE request, byte for byte.

    Matching on hotkey, nonce and endpoint is not enough: the timestamp is
    signed too, so a miner can re-sign the same nonce and endpoint with a fresh
    timestamp. That request was never sent before, and treating it as a
    retransmission hands out an uncharged trip through the registration and
    allowlist gates, repeatable for the whole signature TTL.

    Matching on the current enrollment row is also not enough: enrol N1 at E1,
    move to E2 with N2, then sign N1 at E2 and the row reads E2.
    """
    app = _app(
        tmp_path,
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=_allowlist_provider(tmp_path, [COLDKEY]),
    )
    first = "https://8.8.8.8:8090"
    second = "https://8.8.4.4:9443"

    original = _signed_payload(endpoint_url=first, nonce="50" * 16)
    assert _call(app, original)[0] == 200

    # Byte-identical retransmission: uncharged, still refused, and it must not
    # reach the admission gates at all. Sparing only the charge still lets a
    # miner buy registration and allowlist work from as many addresses as it
    # likes for the whole signature validity window, so the property is that
    # the gates are never consulted.
    charged = _attempt_count(app.store, HOTKEY)
    gate_calls: list[str] = []
    real_is_registered = app.registration_provider.is_registered

    def counting_is_registered(hotkey: str):  # type: ignore[no-untyped-def]
        gate_calls.append(hotkey)
        return real_is_registered(hotkey)

    app.registration_provider.is_registered = counting_is_registered  # type: ignore[assignment]
    try:
        assert _call(app, original)[0] == 400
    finally:
        app.registration_provider.is_registered = real_is_registered  # type: ignore[assignment]
    assert _attempt_count(app.store, HOTKEY) == charged
    assert gate_calls == [], (
        "an exact replay must be answered before the registration gate runs"
    )

    # Same nonce and endpoint, fresh timestamp. Never sent before, so charged.
    later = _signed_payload(
        endpoint_url=first,
        nonce="50" * 16,
        timestamp=_iso_seconds_from_now(1),
    )
    assert later["timestamp"] != original["timestamp"]
    charged = _attempt_count(app.store, HOTKEY)
    assert _call(app, later)[0] == 400
    assert _attempt_count(app.store, HOTKEY) == charged + 1, (
        "a re-signed request is not a retransmission and must be charged"
    )

    # And the endpoint-advance sequence stays closed.
    assert _call(app, _signed_payload(endpoint_url=second, nonce="51" * 16))[0] == 200
    charged = _attempt_count(app.store, HOTKEY)
    assert _call(app, _signed_payload(endpoint_url=second, nonce="50" * 16))[0] == 400
    assert _attempt_count(app.store, HOTKEY) == charged + 1


def test_the_runtime_is_wired_to_the_minted_token(tmp_path: Path) -> None:
    """The composition, not just the function.

    resolve_worker_token being correct proves nothing if _build_runtime hands
    the runtime `tokens.get` instead. That mutation leaves every test here
    green while a freshly enrolled worker with no file entry gets missing_auth
    for the whole epoch, which is the exact failure this change exists to end.
    """
    import argparse

    from cathedral.cli import _build_runtime

    app = _app(
        tmp_path,
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=_allowlist_provider(tmp_path, [COLDKEY]),
    )
    registry_db = tmp_path / "registry.sqlite"
    status, body = _call(app, _signed_payload(nonce="60" * 16))
    assert status == 200
    minted = body["worker_token"]

    args = argparse.Namespace(
        registry_db=str(registry_db),
        ledger_db=str(tmp_path / "ledger.sqlite"),
        tokens_file=None,  # no operator file at all: the new-miner case
        measurements_file=None,
        policy_registry=None,
        production_mode=False,
        development=True,
    )
    runtime, _ledger, tokens = _build_runtime(args)

    assert tokens == {}, "no token file was configured"
    assert runtime.token_provider(HOTKEY) == minted, (
        "the runtime must read the token minted at enrollment"
    )
    assert runtime.token_provider("5" + "Z" * 47) is None


def test_a_fresh_database_is_never_briefly_world_readable(tmp_path: Path) -> None:
    """SQLite creates a new database 0644 regardless of umask.

    Narrowing it afterwards leaves a window where a local account can open a
    handle that keeps reading every token written later, because the mode is
    checked at open time and not on each read. The file is therefore created
    owner-only before SQLite ever opens it. Asserting only the final mode does
    not catch this: that assertion passes with the precreation removed.
    """
    import os
    import stat

    db = tmp_path / "fresh.sqlite"
    observed: list[int] = []
    real_connect = sqlite3.connect

    def watching_connect(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if isinstance(path, str) and path == str(db) and os.path.exists(path):
            observed.append(stat.S_IMODE(os.stat(path).st_mode))
        return real_connect(path, *args, **kwargs)

    previous = os.umask(0o000)
    try:
        with mock.patch.object(sqlite3, "connect", watching_connect):
            RegistryStore(str(db))
    finally:
        os.umask(previous)

    assert observed, "expected at least one connect against an existing file"
    assert all(mode == 0o600 for mode in observed), (
        f"readable by others before SQLite opened it: {[oct(m) for m in observed]}"
    )


def test_a_database_owned_by_another_user_fails_closed(tmp_path: Path) -> None:
    """Refusing beats running with tokens in a file we cannot secure.

    Mocking chmod to raise does NOT test this: it exercises the chmod path and
    stays green with the ownership check deleted. The owner has to actually
    differ, so lstat is mocked to report a foreign uid and the test asserts
    SQLite is never opened.
    """
    import os
    import stat as stat_module

    db = tmp_path / "foreign.sqlite"
    db.write_bytes(b"")
    real_lstat = os.lstat
    foreign_uid = os.getuid() + 1

    class _ForeignStat:
        st_mode = stat_module.S_IFREG | 0o644
        st_uid = foreign_uid

    def lying_lstat(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if str(path) == str(db):
            return _ForeignStat()
        return real_lstat(path, *args, **kwargs)

    opened: list[str] = []
    real_connect = sqlite3.connect

    def watching_connect(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        opened.append(str(path))
        return real_connect(path, *args, **kwargs)

    with mock.patch.object(os, "lstat", lying_lstat):
        with mock.patch.object(sqlite3, "connect", watching_connect):
            with pytest.raises(PermissionError) as raised:
                RegistryStore(str(db))

    assert "must run as its owner" in str(raised.value)
    assert opened == [], "SQLite must never open a database owned by another user"


def test_root_does_not_get_an_ownership_exemption(tmp_path: Path) -> None:
    """A root service must not adopt a database an untrusted user pre-created.

    Initialising it leaves that user as the owner, and chmod 0600 then locks
    read and write to them rather than to root. The ancestor-chain policy is
    stubbed to trusted here so the assertion isolates the leaf ownership check
    rather than passing for the unrelated reason that tmp_path is not
    root-owned.
    """
    import os
    import stat as stat_module

    import cathedral.enroll as enroll_module
    from cathedral.privileged_paths import PathVerdict

    db = tmp_path / "planted.sqlite"
    db.write_bytes(b"")
    real_lstat = os.lstat

    class _AttackerOwned:
        st_mode = stat_module.S_IFREG | 0o600
        st_uid = os.getuid() + 1

    def lying_lstat(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if str(path) == str(db):
            return _AttackerOwned()
        return real_lstat(path, *args, **kwargs)

    def trusted_chain(target, **kwargs):  # type: ignore[no-untyped-def]
        return PathVerdict(target=str(target), violations=())

    with mock.patch.object(enroll_module, "os") as patched_os:
        patched_os.lstat = lying_lstat
        patched_os.getuid = lambda: 0
        patched_os.path = os.path
        patched_os.chmod = os.chmod
        patched_os.open = os.open
        patched_os.close = os.close
        with mock.patch(
            "cathedral.privileged_paths.inspect_creatable_file", trusted_chain
        ):
            with pytest.raises(PermissionError, match="must run as its owner"):
                RegistryStore(str(db))


def test_a_world_writable_directory_is_refused(tmp_path: Path) -> None:
    """SQLite opens by path, so the directory is what binds the check.

    If any user can write the directory, the file checked is not necessarily
    the file opened, and no amount of checking the path closes that.
    """
    import os

    exposed = tmp_path / "exposed"
    exposed.mkdir()
    os.chmod(exposed, 0o777)
    with pytest.raises(PermissionError) as raised:
        RegistryStore(str(exposed / "registry.sqlite"))
    assert "group- or world-writable" in str(raised.value), str(raised.value)


def test_a_sticky_world_writable_directory_is_also_refused(tmp_path: Path) -> None:
    """The sticky bit is not an exemption, and believing it was is the bug.

    Sticky stops another user deleting or renaming an inode they do not own,
    which is why a /tmp-shaped directory looks safe. It does not stop them
    CREATING one. An untrusted account pre-creates registry.sqlite-journal and
    keeps the descriptor; SQLite reuses that inode, so a sidecar leaks minted
    tokens even though the main database is 0600 and unswappable.
    """
    import os

    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o1777)  # sticky, world-writable: the /tmp shape
    with pytest.raises(PermissionError) as raised:
        RegistryStore(str(shared / "registry.sqlite"))
    assert "group- or world-writable" in str(raised.value), str(raised.value)


def test_a_symlinked_database_path_is_refused(tmp_path: Path) -> None:
    """A symlink at the database path redirects minted tokens to its target.

    SQLite follows it, so the credential lands wherever the link points and the
    chmod applies to the target rather than to anything we control. The path is
    operator configuration, so this is not miner-reachable, but the file now
    holds bearer tokens and a link there is never intentional.
    """
    real = tmp_path / "real.sqlite"
    real.write_bytes(b"")
    link = tmp_path / "link.sqlite"
    link.symlink_to(real)

    with pytest.raises(PermissionError) as raised:
        RegistryStore(str(link))
    # Assert a phrase that cannot appear in the path. pytest names tmp_path
    # after the test, so a bare "symlink" pattern matches this test's own
    # directory name and passes even when the check is gone.
    assert "is a symlink" in str(raised.value), str(raised.value)


def test_a_lost_creation_race_fails_closed_instead_of_recursing(tmp_path: Path) -> None:
    """The retry must terminate.

    The first version recursed on FileExistsError. An attacker who can create
    and unlink the leaf between the check and the open drives that into a
    RecursionError at startup, which is a crash rather than a refusal. The
    retry is bounded and ends in an explicit refusal.
    """
    import os

    db = tmp_path / "raced.sqlite"
    real_open = os.open
    real_lstat = os.lstat
    attempts: list[int] = []

    def always_taken(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        if str(path) == str(db) and flags & os.O_CREAT:
            attempts.append(1)
            raise FileExistsError(17, "File exists")
        return real_open(path, flags, *args, **kwargs)

    def always_vanished(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if str(path) == str(db):
            raise FileNotFoundError(2, "No such file or directory")
        return real_lstat(path, *args, **kwargs)

    with mock.patch.object(os, "open", always_taken):
        with mock.patch.object(os, "lstat", always_vanished):
            with pytest.raises(PermissionError) as raised:
                RegistryStore(str(db))

    assert "repeated races" in str(raised.value), str(raised.value)
    assert 1 < len(attempts) <= 16, f"expected a bounded number of retries, got {len(attempts)}"
