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


def test_rows_written_before_the_column_existed_fall_back_to_the_file(
    tmp_path: Path,
) -> None:
    """A legacy enrollment has a NULL token and must not shadow the operator's
    file. The lookup returns None so the file-based provider still answers."""
    app = _app(
        tmp_path,
        registration_provider=_provider(tmp_path, {HOTKEY: COLDKEY}),
        coldkey_allowlist=_allowlist_provider(tmp_path, [COLDKEY]),
    )
    status, _ = _call(app, _signed_payload(nonce="22" * 16))
    assert status == 200

    with sqlite3.connect(app.store.path) as conn:
        conn.execute("UPDATE enrollments SET worker_token = NULL WHERE hotkey = ?", (HOTKEY,))
    assert app.store.worker_token(HOTKEY) is None
