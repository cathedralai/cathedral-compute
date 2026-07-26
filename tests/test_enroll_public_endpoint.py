"""Path B: the gated public enrollment endpoint, safe from its first start.

The enrollment primitives existed but had never served a request. These are
the checks that had to hold before the endpoint could be exposed at all.

Covers, in order:
  1. sr25519 verifier discovery across both packaging shapes, and a startup
     preflight that refuses to serve rather than 403-ing every caller.
  2. Endpoint validation: canonical HTTPS public IP literal, explicit port,
     no path, query, or fragment.
  3. Domain separation: the signed preimage carries the protocol tag, the
     network, and the netuid, and MINING.md documents the same bytes.
  4. Concurrency: online backup, controlled WAL migration, explicit busy
     timeout, atomic and pruned attempt accounting, and a bounded 503 under
     real two-process lock contention.
  5. Strict registration snapshot verification, failing closed on every
     schema, audience, freshness, finality, and file-hygiene deviation.
  6. Resource bounds: a capped per-IP limiter, pruned attempt rows, a
     loopback-only listener, and X-Forwarded-For that cannot be spoofed.
  7. Response honesty: enrolled_pending_secret, never a bare success.
  8. The wallet-local submit CLI, with no secret in argv, env, or output.
  9. The runbook's deployment posture: confinement and the two P2 fixes.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sqlite3
import subprocess
import sys
import time
import types
from base64 import b64encode
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from substrateinterface import Keypair, KeypairType

import cathedral.enroll as enroll_module
from cathedral.cli import (
    cmd_enroll_backup,
    cmd_enroll_journal_mode,
    cmd_enroll_submit,
)
from cathedral.enroll import (
    DEFAULT_ENROLL_NETUID,
    DEFAULT_ENROLL_NETWORK,
    ENROLL_DOMAIN_TAG,
    REGISTRATION_SNAPSHOT_SCHEMA,
    IpRateLimiter,
    JsonHotkeyRegistrationProvider,
    RegistryApp,
    RegistryStore,
    SignatureVerifierUnavailable,
    canonical_enroll_payload,
    load_keypair_class,
    now_iso,
    preflight_signature_verifier,
    validate_endpoint_url,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

KEYPAIR = Keypair.create_from_uri("//Alice", crypto_type=KeypairType.SR25519)
HOTKEY = KEYPAIR.ss58_address
COLDKEY = Keypair.create_from_uri("//AliceCold", crypto_type=KeypairType.SR25519).ss58_address
ENDPOINT = "https://8.8.8.8:8443"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _AllowAllColdkeys:
    def is_allowed(self, coldkey: str) -> bool:
        return True


def _signed_payload(
    *,
    endpoint_url: str = ENDPOINT,
    keypair: Keypair = KEYPAIR,
    hotkey: str = HOTKEY,
    nonce: str = "aa" * 16,
    timestamp: str | None = None,
    sign_network: str = DEFAULT_ENROLL_NETWORK,
    sign_netuid: int = DEFAULT_ENROLL_NETUID,
    claim_network: str | None = None,
    claim_netuid: int | None = None,
) -> dict[str, object]:
    """Build one enrollment body.

    ``sign_*`` is what goes into the signed preimage; ``claim_*`` is what the
    request body declares. They differ only in the relabelling tests.
    """
    ts = timestamp if timestamp is not None else now_iso()
    message = canonical_enroll_payload(
        hotkey, endpoint_url, nonce, ts, network=sign_network, netuid=sign_netuid
    )
    return {
        "hotkey": hotkey,
        "endpoint_url": endpoint_url,
        "nonce": nonce,
        "timestamp": ts,
        "network": sign_network if claim_network is None else claim_network,
        "netuid": sign_netuid if claim_netuid is None else claim_netuid,
        "signature_b64": b64encode(keypair.sign(message)).decode("ascii"),
    }


def _call(
    app: RegistryApp,
    payload: dict | bytes | None,
    *,
    method: str = "POST",
    path: str = "/v1/enroll",
    remote_addr: str = "1.2.3.4",
    forwarded_for: str | None = None,
) -> tuple[int, dict, dict[str, str]]:
    if isinstance(payload, bytes):
        body = payload
    elif payload is None:
        body = b""
    else:
        body = json.dumps(payload).encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
        "REMOTE_ADDR": remote_addr,
    }
    if forwarded_for is not None:
        environ["HTTP_X_FORWARDED_FOR"] = forwarded_for
    seen: dict = {}

    def start_response(status: str, headers: list) -> None:
        seen["status"] = status
        seen["headers"] = {name: value for name, value in headers}

    raw = b"".join(app(environ, start_response))
    return int(seen["status"].split()[0]), json.loads(raw.decode("utf-8")), seen["headers"]


def _snapshot_document(
    *,
    hotkeys: dict[str, str] | None = None,
    schema: str = REGISTRATION_SNAPSHOT_SCHEMA,
    network: str = DEFAULT_ENROLL_NETWORK,
    netuid: int = DEFAULT_ENROLL_NETUID,
    block: int = 8_708_117,
    block_is_finalized: bool = True,
    generated_at: str | None = None,
) -> dict[str, object]:
    return {
        "schema": schema,
        "network": network,
        "netuid": netuid,
        "block": block,
        "block_is_finalized": block_is_finalized,
        "generated_at": generated_at or now_iso(),
        "hotkeys": {HOTKEY: COLDKEY} if hotkeys is None else hotkeys,
    }


def _write_snapshot(tmp_path: Path, document: dict[str, object]) -> Path:
    path = tmp_path / "registered-hotkeys.json"
    path.write_text(json.dumps(document, sort_keys=True))
    return path


def _strict_provider(path: Path, **kwargs) -> JsonHotkeyRegistrationProvider:
    options = {
        "max_age_seconds": 3600,
        "strict": True,
        "network": DEFAULT_ENROLL_NETWORK,
        "netuid": DEFAULT_ENROLL_NETUID,
        # Tests do not run as root; the production default (uid 0) is asserted
        # separately in test_strict_default_expects_a_root_owned_snapshot.
        "expected_uid": os.getuid(),
    }
    options.update(kwargs)
    return JsonHotkeyRegistrationProvider(str(path), **options)


def _app(tmp_path: Path, **kwargs) -> RegistryApp:
    options = {
        "production_mode": True,
        "coldkey_allowlist": _AllowAllColdkeys(),
    }
    options.update(kwargs)
    store = options.pop("store", None) or RegistryStore(str(tmp_path / "registry.sqlite"))
    return RegistryApp(store, **options)


# ---------------------------------------------------------------------------
# 1. Verifier discovery and the startup preflight
# ---------------------------------------------------------------------------


class _FakeKeypair:
    """Stand-in exposing only the contract the enrollment path uses."""

    def __init__(self, ss58_address: str) -> None:
        self.ss58_address = ss58_address

    def verify(self, message: bytes, signature: bytes) -> bool:
        return Keypair(ss58_address=self.ss58_address).verify(message, signature)


def test_verifier_falls_back_to_bittensor_wallet(monkeypatch: pytest.MonkeyPatch) -> None:
    """The deployed producer venv has bittensor_wallet and no substrateinterface."""
    fake = types.ModuleType("cathedral_fake_wallet")
    fake.Keypair = _FakeKeypair

    def _import(name: str):
        if name == "substrateinterface":
            raise ModuleNotFoundError("no substrateinterface here")
        if name == "bittensor_wallet":
            return fake
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(enroll_module.importlib, "import_module", _import)
    source, keypair_class = load_keypair_class()

    assert source == "bittensor_wallet"
    assert keypair_class is _FakeKeypair
    # The fallback is not merely importable: it passes the same known-answer
    # check the service runs at startup.
    assert preflight_signature_verifier(_FakeKeypair) == _FakeKeypair.__module__


def test_verifier_discovery_reports_nothing_when_neither_package_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _import(name: str):
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(enroll_module.importlib, "import_module", _import)
    assert load_keypair_class() == (None, None)


def test_preflight_refuses_when_no_verifier_is_importable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(enroll_module, "Keypair", None)
    with pytest.raises(SignatureVerifierUnavailable, match="no sr25519 verifier"):
        preflight_signature_verifier()


def test_preflight_rejects_a_verifier_that_accepts_everything() -> None:
    """Importable is not the same as working.

    A stub that returns True would admit any signature from any key, so the
    preflight checks the rejection direction too.
    """

    class _AlwaysTrue:
        def __init__(self, ss58_address: str) -> None:
            self.ss58_address = ss58_address

        def verify(self, message: bytes, signature: bytes) -> bool:
            return True

    with pytest.raises(SignatureVerifierUnavailable, match="known-answer"):
        preflight_signature_verifier(_AlwaysTrue)


def test_preflight_rejects_a_verifier_that_rejects_everything() -> None:
    class _AlwaysFalse:
        def __init__(self, ss58_address: str) -> None:
            self.ss58_address = ss58_address

        def verify(self, message: bytes, signature: bytes) -> bool:
            return False

    with pytest.raises(SignatureVerifierUnavailable, match="known-answer"):
        preflight_signature_verifier(_AlwaysFalse)


def test_main_refuses_to_serve_without_a_verifier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Failing loudly at start beats 403-ing every request forever."""
    monkeypatch.setattr(enroll_module, "Keypair", None)

    def _must_not_bind(*args, **kwargs):
        raise AssertionError("a listener was opened without a working verifier")

    monkeypatch.setattr(enroll_module, "make_server", _must_not_bind)
    monkeypatch.setattr(
        sys, "argv", ["cathedral.enroll", "--db", str(tmp_path / "r.sqlite")]
    )

    with pytest.raises(SystemExit) as excinfo:
        enroll_module.main()

    assert excinfo.value.code == 2
    assert "refusing to serve" in capsys.readouterr().err


def test_app_cannot_be_constructed_without_a_verifier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = RegistryStore(str(tmp_path / "r.sqlite"))
    monkeypatch.setattr(enroll_module, "Keypair", None)
    with pytest.raises(SignatureVerifierUnavailable):
        RegistryApp(store)


# ---------------------------------------------------------------------------
# 2. Endpoint validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://8.8.8.8:8443",  # not https
        "https://8.8.8.8",  # no explicit port
        "https://8.8.8.8:8443/v1/evidence",  # path
        "https://8.8.8.8:8443/",  # bare trailing slash is still a path
        "https://8.8.8.8:8443?a=1",  # query
        "https://8.8.8.8:8443#frag",  # fragment
        "https://miner.example.com:8443",  # hostname
        "https://0177.0.0.1:8443",  # non-canonical (octal) literal
        "https://2130706433:8443",  # non-canonical (integer) literal
        "https://010.010.010.010:8443",  # zero-padded literal
        "https://192.168.1.5:8443",  # private
        "https://127.0.0.1:8443",  # loopback
        "https://8.8.8.8:0",  # port 0
        "https://8.8.8.8:99999",  # port out of range
        "https://8.8.8.8:notaport",
        "https://user:pass@8.8.8.8:8443",  # credentials
        "https://8.8.8.8:8443 ",  # trailing whitespace
        "https://[::ffff:8.8.8.8]:8443",  # non-canonical IPv6 alias
        "",
    ],
)
def test_production_endpoint_rejects(endpoint: str) -> None:
    with pytest.raises(ValueError):
        validate_endpoint_url(endpoint, require_ip_literal=True)


@pytest.mark.parametrize(
    "endpoint",
    ["https://8.8.8.8:8443", "https://34.61.154.15:8443", "https://[2606:4700::1111]:8443"],
)
def test_production_endpoint_accepts_canonical_https_ip_literals(endpoint: str) -> None:
    assert validate_endpoint_url(endpoint, require_ip_literal=True) == endpoint


def test_path_and_query_are_rejected_outside_production_too() -> None:
    """The endpoint is an origin. The prober appends its own path."""
    for endpoint in ("https://miner.example.com:8443/evidence", "https://m.example.com:8443?x=1"):
        with pytest.raises(ValueError):
            validate_endpoint_url(endpoint)


def test_endpoint_with_a_path_is_rejected_end_to_end(tmp_path: Path) -> None:
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    app = _app(tmp_path, registration_provider=_strict_provider(snapshot))
    status, body, _ = _call(
        app, _signed_payload(endpoint_url="https://8.8.8.8:8443/v1/evidence", nonce="b1" * 16)
    )
    assert status == 400
    assert "path" in body["error"]


# ---------------------------------------------------------------------------
# 3. Signed domain separation
# ---------------------------------------------------------------------------


def test_preimage_carries_the_domain_tag_and_audience() -> None:
    document = json.loads(
        canonical_enroll_payload(HOTKEY, ENDPOINT, "aa" * 16, "2026-07-26T00:00:00Z")
    )
    assert document["domain"] == ENROLL_DOMAIN_TAG == "cathedral-enroll-v1"
    assert document["network"] == "finney"
    assert document["netuid"] == 39
    assert set(document) == {
        "domain",
        "endpoint_url",
        "hotkey",
        "netuid",
        "network",
        "nonce",
        "timestamp",
    }


def test_preimage_differs_across_networks_and_subnets() -> None:
    finney = canonical_enroll_payload(HOTKEY, ENDPOINT, "aa" * 16, "2026-07-26T00:00:00Z")
    testnet = canonical_enroll_payload(
        HOTKEY, ENDPOINT, "aa" * 16, "2026-07-26T00:00:00Z", network="test", netuid=292
    )
    other_subnet = canonical_enroll_payload(
        HOTKEY, ENDPOINT, "aa" * 16, "2026-07-26T00:00:00Z", netuid=40
    )
    other_protocol = canonical_enroll_payload(
        HOTKEY, ENDPOINT, "aa" * 16, "2026-07-26T00:00:00Z", domain="some-other-protocol-v1"
    )
    assert len({finney, testnet, other_subnet, other_protocol}) == 4


def test_wrong_audience_is_rejected_403(tmp_path: Path) -> None:
    """A correctly signed SN292 testnet enrollment must not land on SN39."""
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    app = _app(tmp_path, registration_provider=_strict_provider(snapshot))
    status, body, _ = _call(
        app, _signed_payload(sign_network="test", sign_netuid=292, nonce="c1" * 16)
    )
    assert status == 403
    assert body["error"] == "enrollment is for a different network or netuid"


def test_relabelling_a_foreign_signature_fails_the_signature_check(tmp_path: Path) -> None:
    """The audience is inside the signature, not only beside it.

    Signing for testnet SN292 and then claiming finney/39 in the body gets
    past the explicit audience field and dies on the preimage.
    """
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    app = _app(tmp_path, registration_provider=_strict_provider(snapshot))
    status, body, _ = _call(
        app,
        _signed_payload(
            sign_network="test",
            sign_netuid=292,
            claim_network="finney",
            claim_netuid=39,
            nonce="c2" * 16,
        ),
    )
    assert status == 403
    assert body["error"] == "enrollment signature did not verify"


def test_missing_audience_fields_are_a_malformed_request(tmp_path: Path) -> None:
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    app = _app(tmp_path, registration_provider=_strict_provider(snapshot))
    payload = _signed_payload(nonce="c3" * 16)
    del payload["network"]
    status, _body, _ = _call(app, payload)
    assert status == 400


def test_mining_doc_signing_example_matches_the_canonical_preimage() -> None:
    """MINING.md and canonical_enroll_payload must never drift apart.

    A miner following a stale example produces a signature the registry
    rejects, and the rejection reason ("signature did not verify") gives them
    no way to discover that the document changed.
    """
    text = (REPO_ROOT / "MINING.md").read_text()
    marker = "<!-- enroll-preimage-example -->"
    assert marker in text, "MINING.md must carry the machine-checked preimage example"
    block = text.split(marker, 1)[1].split("```", 2)[1]
    if block.startswith("json"):
        block = block[len("json") :]
    documented = json.loads(block)

    rebuilt = json.loads(
        canonical_enroll_payload(
            documented["hotkey"],
            documented["endpoint_url"],
            documented["nonce"],
            documented["timestamp"],
            network=documented["network"],
            netuid=documented["netuid"],
        )
    )
    assert documented == rebuilt
    assert documented["domain"] == ENROLL_DOMAIN_TAG


# ---------------------------------------------------------------------------
# 4. Concurrency
# ---------------------------------------------------------------------------


def test_busy_timeout_is_set_on_every_connection(tmp_path: Path) -> None:
    store = RegistryStore(str(tmp_path / "r.sqlite"), busy_timeout_ms=1234)
    with store._connect() as conn:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 1234


def test_default_busy_timeout_does_not_change_the_shared_evidence_path(
    tmp_path: Path,
) -> None:
    """RegistryStore is shared with the epoch/evidence path.

    cathedral/runtime.py, prober.py, and key_release.py all construct a
    RegistryStore without a busy timeout. Before this work, _connect used a
    bare sqlite3.connect(), which the driver gives timeout=5.0 and applies as
    sqlite3_busy_timeout(5000). The default must stay exactly that, or an
    enrollment change silently retunes how long the epoch loop waits for a
    lock. The enrollment service passes its own lower bound explicitly.
    """
    reference = sqlite3.connect(str(tmp_path / "reference.sqlite"))
    try:
        inherited = reference.execute("PRAGMA busy_timeout").fetchone()[0]
    finally:
        reference.close()

    store = RegistryStore(str(tmp_path / "r.sqlite"))
    with store._connect() as conn:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == inherited
    assert enroll_module.DEFAULT_SQLITE_BUSY_TIMEOUT_MS == inherited == 5000


def test_online_backup_is_transaction_safe(tmp_path: Path) -> None:
    """Back up a database another connection is mid-transaction on.

    The copy must contain committed state and pass an integrity check. This
    is what `cp` of a live file cannot promise.
    """
    store = RegistryStore(str(tmp_path / "r.sqlite"))
    store.enroll(HOTKEY, ENDPOINT)

    writer = sqlite3.connect(str(tmp_path / "r.sqlite"))
    writer.execute("BEGIN")
    writer.execute(
        "INSERT INTO hotkey_enroll_attempts(hotkey, attempted_at_iso) VALUES (?, ?)",
        ("5" + "Z" * 47, now_iso()),
    )
    try:
        destination = str(tmp_path / "backup.sqlite")
        pages = store.backup_to(destination)
    finally:
        writer.rollback()
        writer.close()

    assert pages > 0
    copy = sqlite3.connect(destination)
    try:
        assert copy.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert copy.execute("SELECT hotkey FROM enrollments").fetchall() == [(HOTKEY,)]
        # The uncommitted row must not be in the copy.
        assert copy.execute("SELECT COUNT(*) FROM hotkey_enroll_attempts").fetchone()[0] == 0
    finally:
        copy.close()


def test_backup_refuses_to_overwrite(tmp_path: Path) -> None:
    store = RegistryStore(str(tmp_path / "r.sqlite"))
    destination = tmp_path / "backup.sqlite"
    destination.write_bytes(b"existing")
    with pytest.raises(ValueError, match="already exists"):
        store.backup_to(str(destination))
    assert destination.read_bytes() == b"existing"


def test_journal_mode_migration_backs_up_first_then_switches(tmp_path: Path) -> None:
    registry = tmp_path / "r.sqlite"
    store = RegistryStore(str(registry))
    store.enroll(HOTKEY, ENDPOINT)
    assert store.journal_mode() == "delete"

    args = argparse.Namespace(
        registry_db=str(registry),
        mode="wal",
        backup_to=str(tmp_path / "pre-wal.sqlite"),
        sqlite_busy_timeout_ms=None,
    )
    assert cmd_enroll_journal_mode(args) == 0

    assert (tmp_path / "pre-wal.sqlite").is_file()
    assert RegistryStore(str(registry)).journal_mode() == "wal"
    # The migrated database is still fully usable.
    RegistryStore(str(registry)).enroll("5" + "Q" * 47, "https://9.9.9.9:8443")


def test_backup_cli_reports_the_copy(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    registry = tmp_path / "r.sqlite"
    RegistryStore(str(registry)).enroll(HOTKEY, ENDPOINT)
    args = argparse.Namespace(
        registry_db=str(registry),
        out=str(tmp_path / "copy.sqlite"),
        sqlite_busy_timeout_ms=None,
    )
    assert cmd_enroll_backup(args) == 0
    reported = json.loads(capsys.readouterr().out)
    assert reported["integrity_check"] == "ok"
    assert reported["pages"] > 0


def test_attempt_accounting_is_atomic_and_prunes_expired_rows(tmp_path: Path) -> None:
    store = RegistryStore(str(tmp_path / "r.sqlite"))
    with store._connect() as conn:
        stale = (datetime.now(UTC) - timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
        conn.executemany(
            "INSERT INTO hotkey_enroll_attempts(hotkey, attempted_at_iso) VALUES (?, ?)",
            [(HOTKEY, stale) for _ in range(50)],
        )

    assert store.check_and_record_hotkey_attempt(HOTKEY, limit=2, window_seconds=3600) is True
    with store._connect() as conn:
        # The 50 expired rows are gone; only the fresh attempt survives.
        assert conn.execute(
            "SELECT COUNT(*) FROM hotkey_enroll_attempts WHERE hotkey = ?", (HOTKEY,)
        ).fetchone()[0] == 1

    assert store.check_and_record_hotkey_attempt(HOTKEY, limit=2, window_seconds=3600) is True
    # Third attempt inside the window is over the limit and records nothing.
    assert store.check_and_record_hotkey_attempt(HOTKEY, limit=2, window_seconds=3600) is False
    with store._connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM hotkey_enroll_attempts WHERE hotkey = ?", (HOTKEY,)
        ).fetchone()[0] == 2


_LOCK_HOLDER = """
import sqlite3, sys, time
path, hold = sys.argv[1], float(sys.argv[2])
conn = sqlite3.connect(path, timeout=0.1, isolation_level=None)
conn.execute("PRAGMA busy_timeout = 100")
conn.execute("BEGIN EXCLUSIVE")
conn.execute(
    "INSERT INTO hotkey_enroll_attempts(hotkey, attempted_at_iso) VALUES ('lockholder','x')"
)
print("locked", flush=True)
time.sleep(hold)
conn.execute("ROLLBACK")
conn.close()
"""


def test_enrollment_inside_a_write_window_returns_a_bounded_503(tmp_path: Path) -> None:
    """The real contention shape: another *process* holds the write lock.

    This is what an enrollment POST landing inside an epoch write window
    looks like. It must fail fast with a retry instruction, must not hang,
    must not corrupt anything, and the service must keep serving afterwards.
    """
    registry = tmp_path / "registry.sqlite"
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    store = RegistryStore(str(registry), busy_timeout_ms=400)
    app = _app(
        tmp_path,
        store=store,
        registration_provider=_strict_provider(snapshot),
    )

    holder = subprocess.Popen(
        [sys.executable, "-c", _LOCK_HOLDER, str(registry), "3"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "locked"

        started = time.monotonic()
        status, body, headers = _call(app, _signed_payload(nonce="d1" * 16))
        elapsed = time.monotonic() - started

        assert status == 503, body
        assert headers["Retry-After"] == str(enroll_module.ENROLL_BUSY_RETRY_AFTER_SECONDS)
        assert body["error"] == "registry busy, retry shortly"
        # Bounded: a small multiple of the busy timeout, nowhere near the
        # holder's three seconds.
        assert elapsed < 2.0, elapsed
    finally:
        holder.wait(timeout=15)

    # The database survived the contention.
    check = sqlite3.connect(str(registry))
    try:
        assert check.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        check.close()

    # And the same app serves the retry successfully.
    status, body, _ = _call(app, _signed_payload(nonce="d2" * 16))
    assert status == 200
    assert body["status"] == "enrolled_pending_secret"


def test_a_failing_enrollment_leaves_no_partial_row(tmp_path: Path) -> None:
    """One miner's failure cannot damage state the epoch loop reads."""
    registry = tmp_path / "registry.sqlite"
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    store = RegistryStore(str(registry))
    app = _app(tmp_path, store=store, registration_provider=_strict_provider(snapshot))

    stranger = Keypair.create_from_uri("//Stranger", crypto_type=KeypairType.SR25519)
    status, _body, _ = _call(
        app,
        _signed_payload(keypair=stranger, hotkey=stranger.ss58_address, nonce="d3" * 16),
    )
    assert status == 403
    assert store.enrollments() == []

    status, _body, _ = _call(app, _signed_payload(nonce="d4" * 16))
    assert status == 200
    assert [e.hotkey for e in store.enrollments()] == [HOTKEY]


# ---------------------------------------------------------------------------
# 5. Strict snapshot verification
# ---------------------------------------------------------------------------


def test_strict_snapshot_accepts_a_well_formed_document(tmp_path: Path) -> None:
    provider = _strict_provider(_write_snapshot(tmp_path, _snapshot_document()))
    assert provider.is_registered(HOTKEY) is True
    assert provider.resolve_coldkey(HOTKEY) == COLDKEY


@pytest.mark.parametrize(
    "override",
    [
        {"schema": "cathedral_registration_snapshot_v1"},
        {"schema": "something_else"},
        {"network": "test"},
        {"netuid": 292},
        {"block_is_finalized": False},
        {"block_is_finalized": "yes"},
        {"block": 0},
        {"block": -1},
        {"block": "8708117"},
        {"block": True},
        {"generated_at": "not-a-timestamp"},
        {"hotkeys": [HOTKEY]},
        {"hotkeys": {HOTKEY: 7}},
        {"hotkeys": {"not a valid ss58!": COLDKEY}},
    ],
)
def test_strict_snapshot_fails_closed_on_every_deviation(
    tmp_path: Path, override: dict
) -> None:
    provider = _strict_provider(_write_snapshot(tmp_path, _snapshot_document(**override)))
    assert provider.is_registered(HOTKEY) is None
    assert provider.resolve_coldkey(HOTKEY) is None


def test_strict_snapshot_rejects_a_stale_generated_at(tmp_path: Path) -> None:
    old = (datetime.now(UTC) - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = _write_snapshot(tmp_path, _snapshot_document(generated_at=old))
    # mtime is fresh; only the document's own claim is stale, which is the
    # case a `touch` would otherwise hide.
    assert _strict_provider(path).is_registered(HOTKEY) is None


def test_strict_snapshot_rejects_a_future_generated_at(tmp_path: Path) -> None:
    ahead = (datetime.now(UTC) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = _write_snapshot(tmp_path, _snapshot_document(generated_at=ahead))
    assert _strict_provider(path).is_registered(HOTKEY) is None


def test_strict_snapshot_rejects_a_stale_mtime(tmp_path: Path) -> None:
    path = _write_snapshot(tmp_path, _snapshot_document())
    old = time.time() - 7200
    os.utime(path, (old, old))
    assert _strict_provider(path).is_registered(HOTKEY) is None


def test_strict_snapshot_rejects_a_block_rollback(tmp_path: Path) -> None:
    """Replaying an older capture would re-admit deregistered hotkeys."""
    path = _write_snapshot(tmp_path, _snapshot_document(block=8_708_200))
    provider = _strict_provider(path)
    assert provider.is_registered(HOTKEY) is True

    path.write_text(json.dumps(_snapshot_document(block=8_708_100), sort_keys=True))
    assert provider.is_registered(HOTKEY) is None

    # Moving forward again is fine.
    path.write_text(json.dumps(_snapshot_document(block=8_708_300), sort_keys=True))
    assert provider.is_registered(HOTKEY) is True


def test_strict_snapshot_rejects_a_symlink(tmp_path: Path) -> None:
    real = _write_snapshot(tmp_path, _snapshot_document())
    link = tmp_path / "linked.json"
    link.symlink_to(real)
    assert _strict_provider(link).is_registered(HOTKEY) is None


def test_strict_snapshot_rejects_foreign_ownership(tmp_path: Path) -> None:
    path = _write_snapshot(tmp_path, _snapshot_document())
    provider = _strict_provider(path, expected_uid=os.getuid() + 1)
    assert provider.is_registered(HOTKEY) is None


def test_strict_snapshot_rejects_a_group_or_world_writable_file(tmp_path: Path) -> None:
    path = _write_snapshot(tmp_path, _snapshot_document())
    os.chmod(path, 0o666)
    assert _strict_provider(path).is_registered(HOTKEY) is None


def test_strict_default_expects_a_root_owned_snapshot(tmp_path: Path) -> None:
    """Production default is uid 0, so a file this user owns fails closed."""
    path = _write_snapshot(tmp_path, _snapshot_document())
    provider = JsonHotkeyRegistrationProvider(
        str(path),
        max_age_seconds=3600,
        strict=True,
        network=DEFAULT_ENROLL_NETWORK,
        netuid=DEFAULT_ENROLL_NETUID,
    )
    assert provider.expected_uid == 0
    if os.getuid() != 0:
        assert provider.is_registered(HOTKEY) is None


def test_strict_mode_requires_an_audience() -> None:
    with pytest.raises(ValueError, match="network and netuid"):
        JsonHotkeyRegistrationProvider("/nonexistent", max_age_seconds=60, strict=True)


def test_stale_snapshot_rejects_the_enrollment_403(tmp_path: Path) -> None:
    old = (datetime.now(UTC) - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    snapshot = _write_snapshot(tmp_path, _snapshot_document(generated_at=old))
    app = _app(tmp_path, registration_provider=_strict_provider(snapshot))
    status, body, _ = _call(app, _signed_payload(nonce="e1" * 16))
    assert status == 403
    assert body["error"] == "hotkey not registered on subnet"


def test_unregistered_hotkey_rejected_403(tmp_path: Path) -> None:
    stranger = Keypair.create_from_uri("//Stranger", crypto_type=KeypairType.SR25519)
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    app = _app(tmp_path, registration_provider=_strict_provider(snapshot))
    status, body, _ = _call(
        app,
        _signed_payload(keypair=stranger, hotkey=stranger.ss58_address, nonce="e2" * 16),
    )
    assert status == 403
    assert body["error"] == "hotkey not registered on subnet"


# ---------------------------------------------------------------------------
# 6. Resource bounds and exposure
# ---------------------------------------------------------------------------


def test_ip_limiter_keys_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """The key space comes from the network, so it needs a hard ceiling."""
    limiter = IpRateLimiter(limit=5, window_seconds=3600, max_keys=64)
    for index in range(5000):
        limiter.allow(f"10.0.{index // 256}.{index % 256}")
    assert limiter.tracked_keys() <= 64


def test_ip_limiter_drops_expired_buckets_before_live_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 1000.0}
    monkeypatch.setattr(enroll_module.time, "monotonic", lambda: clock["now"])
    limiter = IpRateLimiter(limit=5, window_seconds=60, max_keys=1024)
    for index in range(100):
        limiter.allow(f"10.1.0.{index}")
    assert limiter.tracked_keys() == 100

    clock["now"] += 120  # everything expires
    limiter.allow("10.2.0.1")
    assert limiter.tracked_keys() == 1


def test_ip_limiter_still_bounds_a_single_address() -> None:
    limiter = IpRateLimiter(limit=2, window_seconds=3600, max_keys=8)
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is False


def test_spoofed_forwarded_for_is_ineffective_when_untrusted(tmp_path: Path) -> None:
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    app = _app(
        tmp_path,
        registration_provider=_strict_provider(snapshot),
        limiter=IpRateLimiter(limit=1, window_seconds=3600),
        trusted_proxy=False,
    )
    status, _body, _ = _call(app, _signed_payload(nonce="f1" * 16), remote_addr="9.9.9.9")
    assert status == 200
    # Same peer, a different claimed X-Forwarded-For: still the same bucket.
    status, body, _ = _call(
        app,
        _signed_payload(nonce="f2" * 16),
        remote_addr="9.9.9.9",
        forwarded_for="1.1.1.1",
    )
    assert status == 429
    assert body["error"] == "rate limit exceeded"


def test_trusted_proxy_discards_a_forwarded_for_list(tmp_path: Path) -> None:
    """nginx overwrites the header, so exactly one IP must be present.

    A list means the header reached us unfiltered; falling back to
    REMOTE_ADDR keeps the limiter honest instead of letting a caller prepend
    a fresh identity per request.
    """
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    app = _app(
        tmp_path,
        registration_provider=_strict_provider(snapshot),
        limiter=IpRateLimiter(limit=1, window_seconds=3600),
        trusted_proxy=True,
    )
    # A single IP literal is honoured, so this consumes the 7.7.7.7 bucket.
    status, _body, _ = _call(
        app, _signed_payload(nonce="f3" * 16), remote_addr="9.9.9.9", forwarded_for="7.7.7.7"
    )
    assert status == 200
    # No header at all: this consumes the peer's own 9.9.9.9 bucket.
    status, _body, _ = _call(app, _signed_payload(nonce="f6" * 16), remote_addr="9.9.9.9")
    assert status == 200
    # Anything that is not exactly one IP literal falls back to that same
    # consumed peer bucket rather than minting a fresh identity per request.
    for forwarded in ("8.8.4.4, 7.7.7.7", "not-an-ip", "", "1.1.1.1 2.2.2.2"):
        status, _body, _ = _call(
            app,
            _signed_payload(nonce="f4" * 16),
            remote_addr="9.9.9.9",
            forwarded_for=forwarded,
        )
        assert status == 429, forwarded


def test_malformed_bodies_are_400(tmp_path: Path) -> None:
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    app = _app(tmp_path, registration_provider=_strict_provider(snapshot))
    for body in (b"{}", b"not json", b"[]", b"null", b"a" * 40_000):
        status, _payload, _ = _call(app, body)
        assert status == 400, body[:20]


def test_non_post_and_unknown_paths_are_404(tmp_path: Path) -> None:
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    app = _app(tmp_path, registration_provider=_strict_provider(snapshot))
    status, _body, _ = _call(app, _signed_payload(), method="GET")
    assert status == 404
    status, _body, _ = _call(app, _signed_payload(), path="/v1/enroll/extra")
    assert status == 404


def test_replayed_nonce_is_rejected(tmp_path: Path) -> None:
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    app = _app(tmp_path, registration_provider=_strict_provider(snapshot))
    payload = _signed_payload(nonce="f5" * 16)
    status, _body, _ = _call(app, payload)
    assert status == 200
    status, body, _ = _call(app, payload)
    assert status == 400
    assert body["error"] == "enroll nonce already used"


def test_main_refuses_a_non_loopback_bind(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    def _must_not_bind(*args, **kwargs):
        raise AssertionError("a non-loopback listener was opened")

    monkeypatch.setattr(enroll_module, "make_server", _must_not_bind)
    monkeypatch.setattr(
        sys,
        "argv",
        ["cathedral.enroll", "--db", str(tmp_path / "r.sqlite"), "--host", "0.0.0.0"],
    )
    with pytest.raises(SystemExit) as excinfo:
        enroll_module.main()
    assert excinfo.value.code == 2
    assert "loopback" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# 7. Response honesty
# ---------------------------------------------------------------------------


def test_success_response_does_not_claim_the_miner_is_ready(tmp_path: Path) -> None:
    snapshot = _write_snapshot(tmp_path, _snapshot_document())
    app = _app(tmp_path, registration_provider=_strict_provider(snapshot))
    status, body, _ = _call(app, _signed_payload(nonce="a1" * 16))

    assert status == 200
    assert body["status"] == "enrolled_pending_secret"
    assert body["scored"] is False
    assert body["network"] == "finney"
    assert body["netuid"] == 39
    assert "operator" in body["next_step"]
    assert body["check_progress"] == "/v1/attested"
    # No wording that reads as "done".
    assert body["status"] != "enrolled"


# ---------------------------------------------------------------------------
# 8. Miner-side submit CLI
# ---------------------------------------------------------------------------


_MINER_SEED_URI = "//MinerSecretSeedMustNeverLeak"
_MINER_KEYPAIR = Keypair.create_from_uri(_MINER_SEED_URI, crypto_type=KeypairType.SR25519)


def _submit_args(**overrides) -> argparse.Namespace:
    captured: dict = {}

    def _transport(url: str, body: bytes, timeout: float) -> tuple[int, object]:
        captured["url"] = url
        captured["body"] = json.loads(body.decode("utf-8"))
        captured["timeout"] = timeout
        return 200, {"status": "enrolled_pending_secret", "scored": False}

    options = {
        "registry_url": "https://api.cathedral.computer",
        "endpoint_url": ENDPOINT,
        "wallet_name": "cathedral",
        "hotkey_name": "miner",
        "wallet_path": None,
        "network": DEFAULT_ENROLL_NETWORK,
        "netuid": DEFAULT_ENROLL_NETUID,
        "timeout_seconds": 30.0,
        "transport": _transport,
        "keypair_factory": lambda *_args: _MINER_KEYPAIR,
    }
    options.update(overrides)
    args = argparse.Namespace(**options)
    args._captured = captured
    return args


def test_submit_signs_a_verifiable_enrollment(capsys: pytest.CaptureFixture) -> None:
    args = _submit_args()
    assert cmd_enroll_submit(args) == 0

    body = args._captured["body"]
    assert args._captured["url"] == "https://api.cathedral.computer/v1/enroll"
    assert body["hotkey"] == _MINER_KEYPAIR.ss58_address
    assert body["network"] == "finney"
    assert body["netuid"] == 39
    # The signature verifies against the exact preimage the registry rebuilds.
    message = canonical_enroll_payload(
        body["hotkey"],
        body["endpoint_url"],
        body["nonce"],
        body["timestamp"],
        network=body["network"],
        netuid=body["netuid"],
    )
    import base64 as _base64

    assert Keypair(ss58_address=body["hotkey"]).verify(
        message, _base64.b64decode(body["signature_b64"])
    )
    assert json.loads(capsys.readouterr().out)["http_status"] == 200


def test_submit_never_puts_a_secret_in_the_request_or_the_output(
    capsys: pytest.CaptureFixture,
) -> None:
    """Only public material leaves the miner's machine."""
    args = _submit_args()
    cmd_enroll_submit(args)
    printed = capsys.readouterr().out

    secrets_to_check = [_MINER_SEED_URI]
    if _MINER_KEYPAIR.private_key is not None:
        secrets_to_check.append(_MINER_KEYPAIR.private_key.hex())
    seed_hex = _MINER_KEYPAIR.seed_hex
    if isinstance(seed_hex, bytes):
        seed_hex = seed_hex.hex()
    if seed_hex:
        secrets_to_check.append(str(seed_hex))
    assert len(secrets_to_check) >= 2, "the test must actually have a secret to look for"

    haystack = json.dumps(args._captured["body"]) + printed
    for secret in secrets_to_check:
        assert secret not in haystack
    # And the CLI never accepts one either.
    assert not hasattr(args, "seed")
    assert set(args._captured["body"]) == {
        "endpoint_url",
        "hotkey",
        "network",
        "netuid",
        "nonce",
        "signature_b64",
        "timestamp",
    }


def test_submit_generates_a_fresh_nonce_each_time() -> None:
    first, second = _submit_args(), _submit_args()
    cmd_enroll_submit(first)
    cmd_enroll_submit(second)
    assert first._captured["body"]["nonce"] != second._captured["body"]["nonce"]


def test_submit_rejects_a_plaintext_registry_url() -> None:
    with pytest.raises(ValueError, match="https"):
        cmd_enroll_submit(_submit_args(registry_url="http://api.cathedral.computer"))


def test_submit_rejects_an_endpoint_the_registry_would_reject() -> None:
    for endpoint in ("https://miner.example.com:8443", "https://8.8.8.8", ENDPOINT + "/x"):
        with pytest.raises(ValueError):
            cmd_enroll_submit(_submit_args(endpoint_url=endpoint))


def test_submit_sends_an_identifiable_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    """urllib's default agent is blocked by the CDN in front of production.

    Left at the default, every miner's first submit would fail with an opaque
    403 that has nothing to do with their enrollment.
    """
    from cathedral.cli import ENROLL_SUBMIT_USER_AGENT, _post_json

    seen: dict = {}

    class _Response:
        status = 200

        def read(self, _limit: int) -> bytes:
            return b'{"status":"enrolled_pending_secret"}'

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

    def _urlopen(request, timeout=None):
        seen["headers"] = dict(request.header_items())
        return _Response()

    monkeypatch.setattr("cathedral.cli.urllib.request.urlopen", _urlopen)
    _post_json("https://example.invalid/v1/enroll", b"{}", 5.0)

    agents = [value for name, value in seen["headers"].items() if name.lower() == "user-agent"]
    assert agents == [ENROLL_SUBMIT_USER_AGENT]
    assert "Python-urllib" not in str(agents)


def test_submit_reports_a_rejection_as_a_nonzero_exit(
    capsys: pytest.CaptureFixture,
) -> None:
    def _rejecting(url: str, body: bytes, timeout: float) -> tuple[int, object]:
        return 403, {"error": "coldkey is not approved for enrollment"}

    assert cmd_enroll_submit(_submit_args(transport=_rejecting)) == 1
    assert json.loads(capsys.readouterr().out)["http_status"] == 403


def test_submit_round_trips_against_the_real_app(tmp_path: Path) -> None:
    """End to end: the CLI's body is accepted by the registry it targets."""
    hotkey = _MINER_KEYPAIR.ss58_address
    snapshot = _write_snapshot(
        tmp_path, _snapshot_document(hotkeys={hotkey: COLDKEY})
    )
    app = _app(tmp_path, registration_provider=_strict_provider(snapshot))

    def _direct(url: str, body: bytes, timeout: float) -> tuple[int, object]:
        status, payload, _headers = _call(app, json.loads(body.decode("utf-8")))
        return status, payload

    args = _submit_args(transport=_direct)
    assert cmd_enroll_submit(args) == 0
    assert [e.hotkey for e in app.store.enrollments()] == [hotkey]


# ---------------------------------------------------------------------------
# 9. Deployment posture: confinement and the two PR #69 P2 fixes
# ---------------------------------------------------------------------------


def _runbook() -> str:
    return (REPO_ROOT / "docs" / "ALLOWLIST_ROLLOUT.md").read_text()


def test_runbook_never_copies_a_live_sqlite_file() -> None:
    """P2: `cp` of a live database can produce an unrecoverable copy."""
    text = _runbook()
    assert "cp -a /var/lib/cathedral-confidential-sn39/registry.sqlite" not in text
    assert "enroll backup" in text
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("cp ", "sudo cp ", "$ cp ")) and "registry.sqlite" in stripped:
            raise AssertionError(f"runbook still copies a live database: {stripped}")


def test_runbook_rotates_the_allowlist_without_a_fail_closed_window() -> None:
    """P2: never replace the pinned artifact before the coordinated restart."""
    text = _runbook()
    assert "versioned path" in text
    # The live path must not be overwritten in place during rotation.
    assert "install -m 0644 -o root -g root \\\n  /root/enroll-allowlist-sn39.release2.json /etc/cathedral/enroll-allowlist-sn39.json" not in text
    assert "enroll-allowlist-sn39.r2.json" in text


def test_runbook_documents_the_confinement_and_the_exact_nginx_route() -> None:
    text = _runbook()
    for directive in (
        "ProtectSystem=strict",
        "ReadWritePaths=/var/lib/cathedral-confidential-sn39",
        "ReadOnlyPaths=",
        "InaccessiblePaths=",
        # Empty bounding set is what makes "runs as root" mean "owns these
        # files" instead of "can open anything".
        "CapabilityBoundingSet=\n",
        "NoNewPrivileges=true",
        "SystemCallFilter=@system-service",
        "IPAddressDeny=any",
        "IPAddressAllow=localhost",
        # The service verifies allowlist signatures and must never be able to
        # read the seed that makes them.
        "InaccessiblePaths=/etc/cathedral/enroll-allowlist-signing-sn39.key",
    ):
        assert directive in text, directive
    for nginx_directive in (
        "location = /v1/enroll",
        "limit_except POST",
        "limit_req ",
        "limit_conn ",
        "client_max_body_size",
        "proxy_set_header X-Forwarded-For $remote_addr;",
        # Behind the CDN, $remote_addr is a CDN egress address unless real_ip
        # is configured, which would make both the rate-limit key and the
        # forwarded address identify the CDN rather than the miner.
        "real_ip_header CF-Connecting-IP;",
        "set_real_ip_from",
        "real_ip_recursive off;",
    ):
        assert nginx_directive in text, nginx_directive


def test_runbook_starts_the_service_on_loopback_only() -> None:
    text = _runbook()
    assert "--host 127.0.0.1" in text
    assert "--development-allow-non-loopback" not in text.split("## Rotation")[0]
