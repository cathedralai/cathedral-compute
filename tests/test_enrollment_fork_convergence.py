"""Regression coverage for the deployed enrollment-fork convergence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import sqlite3
import stat
import sys
import threading
import types
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from substrateinterface import Keypair, KeypairType

import cathedral.enroll as enroll_module
from cathedral.cli import (
    build_parser,
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
    RegistryStore,
    SignatureVerifierUnavailable,
    _QuietRequestHandler,
    canonical_allowlist_enroll_payload,
    canonical_enroll_payload,
    load_keypair_class,
    now_iso,
    preflight_signature_verifier,
    validate_endpoint_url,
)
from cathedral.policy_registry import canonical_json


KEYPAIR = Keypair.create_from_uri("//Alice", crypto_type=KeypairType.SR25519)
HOTKEY = KEYPAIR.ss58_address
COLDKEY = Keypair.create_from_uri(
    "//AliceCold", crypto_type=KeypairType.SR25519
).ss58_address
ENDPOINT = "https://8.8.8.8:8443"
REPO_ROOT = Path(__file__).resolve().parent.parent


class _FallbackKeypair:
    def __init__(self, ss58_address: str) -> None:
        self.ss58_address = ss58_address

    def verify(self, message: bytes, signature: bytes) -> bool:
        return Keypair(ss58_address=self.ss58_address).verify(message, signature)


def test_verifier_falls_back_to_bittensor_wallet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fallback = types.ModuleType("fake_bittensor_wallet")
    fallback.Keypair = _FallbackKeypair

    def import_module(name: str):
        if name == "substrateinterface":
            raise ModuleNotFoundError(name)
        if name == "bittensor_wallet":
            return fallback
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(enroll_module.importlib, "import_module", import_module)
    source, candidate = load_keypair_class()
    assert source == "bittensor_wallet"
    assert candidate is _FallbackKeypair
    assert preflight_signature_verifier(candidate) == candidate.__module__


def test_preflight_refuses_missing_or_permissive_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(enroll_module, "Keypair", None)
    with pytest.raises(SignatureVerifierUnavailable, match="no sr25519 verifier"):
        preflight_signature_verifier()

    class AlwaysTrue:
        def __init__(self, ss58_address: str) -> None:
            pass

        def verify(self, message: bytes, signature: bytes) -> bool:
            return True

    with pytest.raises(SignatureVerifierUnavailable, match="known-answer"):
        preflight_signature_verifier(AlwaysTrue)


def test_main_refuses_to_bind_without_a_verifier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    monkeypatch.setattr(enroll_module, "Keypair", None)
    monkeypatch.setattr(
        enroll_module,
        "make_server",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("listener opened")
        ),
    )
    monkeypatch.setattr(
        sys, "argv", ["cathedral.enroll", "--db", str(tmp_path / "registry.sqlite")]
    )
    with pytest.raises(SystemExit) as excinfo:
        enroll_module.main()
    assert excinfo.value.code == 2
    assert "refusing to serve" in capsys.readouterr().err


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://8.8.8.8:8443",
        "https://8.8.8.8",
        "https://8.8.8.8:8443/",
        "https://8.8.8.8:8443?a=1",
        "https://8.8.8.8:8443#fragment",
        "https://8.8.8.8.:8443",
        "https://miner.example.com:8443",
        "https://192.168.1.2:8443",
        "https://[::ffff:8.8.8.8]:8443",
        "https://8.8.8.8:0",
        "https://8.8.8.8:99999",
        "https://8.8.8.8:notaport",
        "https://user:pass@8.8.8.8:8443",
        "https://8.8.8.8:8443 ",
    ],
)
def test_production_endpoint_grammar_rejects_aliases_and_resources(
    endpoint: str,
) -> None:
    with pytest.raises(ValueError):
        validate_endpoint_url(endpoint, require_ip_literal=True)


def test_allowlist_preimage_is_domain_and_audience_bound() -> None:
    document = json.loads(
        canonical_allowlist_enroll_payload(
            HOTKEY, ENDPOINT, "aa" * 16, "2026-08-16T00:00:00Z"
        )
    )
    assert document["domain"] == ENROLL_DOMAIN_TAG
    assert document["network"] == DEFAULT_ENROLL_NETWORK
    assert document["netuid"] == DEFAULT_ENROLL_NETUID
    assert canonical_enroll_payload(
        HOTKEY, ENDPOINT, "aa" * 16, "2026-08-16T00:00:00Z"
    ) == canonical_allowlist_enroll_payload(
        HOTKEY, ENDPOINT, "aa" * 16, "2026-08-16T00:00:00Z"
    )
    assert canonical_allowlist_enroll_payload(
        HOTKEY,
        ENDPOINT,
        "aa" * 16,
        "2026-08-16T00:00:00Z",
        netuid=40,
    ) != canonical_allowlist_enroll_payload(
        HOTKEY, ENDPOINT, "aa" * 16, "2026-08-16T00:00:00Z"
    )


def test_mining_signing_example_matches_the_canonical_preimage() -> None:
    text = (REPO_ROOT / "MINING.md").read_text()
    sample = text.split("<!-- enroll-preimage-example -->", 1)[1]
    document = json.loads(sample.split("```json", 1)[1].split("```", 1)[0])
    assert canonical_enroll_payload(
        document["hotkey"],
        document["endpoint_url"],
        document["nonce"],
        document["timestamp"],
        network=document["network"],
        netuid=document["netuid"],
    ) == json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def _snapshot(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema": REGISTRATION_SNAPSHOT_SCHEMA,
        "network": DEFAULT_ENROLL_NETWORK,
        "netuid": DEFAULT_ENROLL_NETUID,
        "block": 9_000_000,
        "block_is_finalized": True,
        "generated_at": now_iso(),
        "hotkeys": {HOTKEY: COLDKEY},
    }
    document.update(overrides)
    return document


def _write_snapshot(path: Path, **overrides: object) -> None:
    path.write_text(json.dumps(_snapshot(**overrides), sort_keys=True))
    os.chmod(path, 0o600)


def _strict(
    path: Path,
    *,
    store: RegistryStore | None = None,
    advance_on_use: bool = True,
) -> JsonHotkeyRegistrationProvider:
    high_water_store = store or RegistryStore(
        str(path.parent / "snapshot-high-water.sqlite")
    )
    return JsonHotkeyRegistrationProvider(
        str(path),
        max_age_seconds=3600,
        strict=True,
        network=DEFAULT_ENROLL_NETWORK,
        netuid=DEFAULT_ENROLL_NETUID,
        expected_uid=os.getuid(),
        high_water_store=high_water_store,
        advance_high_water_on_use=advance_on_use,
    )


def test_strict_snapshot_accepts_finalized_audience_bound_mapping(
    tmp_path: Path,
) -> None:
    path = tmp_path / "registered.json"
    _write_snapshot(path)
    provider = _strict(path)
    assert provider.is_registered(HOTKEY) is True
    assert provider.resolve_coldkey(HOTKEY) == COLDKEY


@pytest.mark.parametrize(
    "override",
    [
        {"schema": "cathedral_registration_snapshot_v1"},
        {"network": "test"},
        {"netuid": 292},
        {"block_is_finalized": False},
        {"block": 0},
        {"block": True},
        {"generated_at": "not-a-timestamp"},
        {"hotkeys": [HOTKEY]},
        {"hotkeys": {HOTKEY: 7}},
    ],
)
def test_strict_snapshot_fails_closed_on_invalid_claims(
    tmp_path: Path, override: dict[str, object]
) -> None:
    path = tmp_path / "registered.json"
    _write_snapshot(path, **override)
    assert _strict(path).load_snapshot() is None


def test_strict_snapshot_rejects_rollback_symlink_and_writable_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "registered.json"
    _write_snapshot(path, block=20)
    provider = _strict(path)
    assert provider.is_registered(HOTKEY) is True
    _write_snapshot(path, block=19)
    assert provider.is_registered(HOTKEY) is None

    link = tmp_path / "linked.json"
    link.symlink_to(path)
    assert _strict(link).load_snapshot() is None

    os.chmod(path, 0o622)
    assert _strict(path).load_snapshot() is None


def test_strict_snapshot_high_water_survives_provider_restart(tmp_path: Path) -> None:
    path = tmp_path / "registered.json"
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    _write_snapshot(path, block=20)
    assert _strict(path, store=store).is_registered(HOTKEY) is True
    assert (
        store.registration_snapshot_high_water(
            DEFAULT_ENROLL_NETWORK, DEFAULT_ENROLL_NETUID
        )
        == 20
    )

    _write_snapshot(path, block=19)
    restarted = _strict(path, store=RegistryStore(str(tmp_path / "registry.sqlite")))
    assert restarted.is_registered(HOTKEY) is None


def test_snapshot_high_water_migrates_and_rejects_same_block_equivocation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "registry.sqlite"
    RegistryStore(str(database))
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE registration_snapshot_high_water")
        connection.execute(
            """
            CREATE TABLE registration_snapshot_high_water (
                network TEXT NOT NULL,
                netuid INTEGER NOT NULL,
                block INTEGER NOT NULL,
                PRIMARY KEY(network, netuid)
            )
            """
        )
        connection.execute(
            "INSERT INTO registration_snapshot_high_water VALUES (?, ?, ?)",
            (DEFAULT_ENROLL_NETWORK, DEFAULT_ENROLL_NETUID, 20),
        )

    migrated = RegistryStore(str(database))
    with sqlite3.connect(database) as connection:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(registration_snapshot_high_water)"
            )
        }
        assert "snapshot_digest" in columns
        assert connection.execute(
            "SELECT snapshot_digest FROM registration_snapshot_high_water"
        ).fetchone()[0] is None

    path = tmp_path / "registered.json"
    _write_snapshot(path, block=20)
    assert _strict(path, store=migrated).is_registered(HOTKEY) is None
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT block, snapshot_digest FROM registration_snapshot_high_water"
        ).fetchone() == (20, None)

    _write_snapshot(path, block=21)
    document = json.loads(path.read_text())
    expected_digest = "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest()
    assert _strict(path, store=migrated).is_registered(HOTKEY) is True
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT block, snapshot_digest FROM registration_snapshot_high_water"
        ).fetchone() == (21, expected_digest)
    assert _strict(path, store=RegistryStore(str(database))).is_registered(HOTKEY) is True
    document["hotkeys"] = {HOTKEY: HOTKEY}
    path.write_text(json.dumps(document, sort_keys=True))
    os.chmod(path, 0o600)
    assert _strict(path, store=RegistryStore(str(database))).is_registered(HOTKEY) is None
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT block, snapshot_digest FROM registration_snapshot_high_water"
        ).fetchone() == (21, expected_digest)


def test_snapshot_high_water_updates_block_and_digest_atomically(tmp_path: Path) -> None:
    database = tmp_path / "registry.sqlite"
    store = RegistryStore(str(database))
    path = tmp_path / "registered.json"
    _write_snapshot(path, block=20)
    assert _strict(path, store=store).is_registered(HOTKEY) is True
    with sqlite3.connect(database) as connection:
        first = connection.execute(
            "SELECT block, snapshot_digest FROM registration_snapshot_high_water"
        ).fetchone()

    _write_snapshot(path, block=21, hotkeys={HOTKEY: HOTKEY})
    document = json.loads(path.read_text())
    expected_digest = "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest()
    assert _strict(path, store=store).is_registered(HOTKEY) is True
    with sqlite3.connect(database) as connection:
        second = connection.execute(
            "SELECT block, snapshot_digest FROM registration_snapshot_high_water"
        ).fetchone()
    assert second == (21, expected_digest)
    assert second[1] != first[1]

    restarted = _strict(path, store=RegistryStore(str(database)))
    assert restarted.is_registered(HOTKEY) is True


def test_pure_strict_snapshot_parse_does_not_advance_high_water(tmp_path: Path) -> None:
    path = tmp_path / "registered.json"
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    _write_snapshot(path, block=20)
    provider = _strict(path, store=store, advance_on_use=False)
    assert provider.load_snapshot() is not None
    assert (
        store.registration_snapshot_high_water(
            DEFAULT_ENROLL_NETWORK, DEFAULT_ENROLL_NETUID
        )
        is None
    )


def test_invalid_empty_snapshot_does_not_advance_high_water(tmp_path: Path) -> None:
    path = tmp_path / "registered.json"
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    _write_snapshot(path, block=21, hotkeys={})
    provider = _strict(path, store=store)
    assert provider.is_registered(HOTKEY) is None
    assert (
        store.registration_snapshot_high_water(
            DEFAULT_ENROLL_NETWORK, DEFAULT_ENROLL_NETUID
        )
        is None
    )


def test_strict_snapshot_uses_declared_time_not_only_mtime(tmp_path: Path) -> None:
    path = tmp_path / "registered.json"
    old = (datetime.now(UTC) - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_snapshot(path, generated_at=old)
    assert _strict(path).load_snapshot() is None


def test_ip_limiter_is_bounded_and_thread_safe() -> None:
    limiter = IpRateLimiter(limit=2, window_seconds=3600, max_keys=32)
    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lambda index: limiter.allow(f"10.0.0.{index}"), range(200)))
    assert limiter.tracked_keys() <= 32
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is False


def test_attempt_limit_decision_is_atomic(tmp_path: Path) -> None:
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    barrier = threading.Barrier(8)

    def attempt(_: int) -> bool:
        barrier.wait()
        return store.check_and_record_hotkey_attempt(
            HOTKEY, limit=1, window_seconds=3600
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))
    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 7


def test_online_backup_is_integral_owner_only_and_non_overwriting(
    tmp_path: Path,
) -> None:
    source = tmp_path / "registry.sqlite"
    destination = tmp_path / "backup.sqlite"
    store = RegistryStore(str(source))
    store.enroll(HOTKEY, ENDPOINT)
    writer = sqlite3.connect(source)
    writer.execute("BEGIN")
    writer.execute(
        "INSERT INTO hotkey_enroll_attempts(hotkey, attempted_at_iso) VALUES (?, ?)",
        ("5" + "Z" * 47, now_iso()),
    )
    try:
        assert store.backup_to(str(destination)) > 0
    finally:
        writer.rollback()
        writer.close()
    assert destination.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(destination) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0] == 1
        assert (
            connection.execute("SELECT COUNT(*) FROM hotkey_enroll_attempts").fetchone()[0]
            == 0
        )
    with pytest.raises(FileExistsError):
        store.backup_to(str(destination))


class _FailingBackupSource:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        destination: Path | None = None,
        fail_integrity: bool = False,
    ) -> None:
        self.connection = connection
        self.destination = destination
        self.fail_integrity = fail_integrity

    def execute(self, statement: str):
        if self.fail_integrity and statement == "PRAGMA integrity_check":
            return _StaticRow(("corrupt",))
        return self.connection.execute(statement)

    def backup(self, target: sqlite3.Connection) -> None:
        if self.destination is not None:
            self.destination.write_text("replacement")
        raise sqlite3.OperationalError("injected backup failure")

    def close(self) -> None:
        self.connection.close()


class _StaticRow:
    def __init__(self, value: tuple[str]) -> None:
        self.value = value

    def fetchone(self) -> tuple[str]:
        return self.value


class _ReplacementRaceSource(_FailingBackupSource):
    def backup(self, target: sqlite3.Connection) -> None:
        self.connection.backup(target)
        assert self.destination is not None
        self.destination.write_text("replacement")


@pytest.mark.parametrize("fail_integrity", [False, True])
def test_failed_backup_removes_created_destination_and_retry_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_integrity: bool,
) -> None:
    source = tmp_path / "registry.sqlite"
    destination = tmp_path / "backup.sqlite"
    RegistryStore(str(source))
    open_read_only = enroll_module._open_sqlite_read_only
    monkeypatch.setattr(
        enroll_module,
        "_open_sqlite_read_only",
        lambda path, timeout: _FailingBackupSource(
            open_read_only(path, timeout), fail_integrity=fail_integrity
        ),
    )

    with pytest.raises((sqlite3.OperationalError, ValueError)):
        enroll_module.backup_sqlite_database(str(source), str(destination))
    assert not destination.exists()
    assert list(tmp_path.glob(".cathedral-backup-*")) == []

    monkeypatch.undo()
    assert enroll_module.backup_sqlite_database(str(source), str(destination)).pages > 0


def test_failed_backup_preserves_replacement_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "registry.sqlite"
    destination = tmp_path / "backup.sqlite"
    RegistryStore(str(source))
    open_read_only = enroll_module._open_sqlite_read_only
    monkeypatch.setattr(
        enroll_module,
        "_open_sqlite_read_only",
        lambda path, timeout: _ReplacementRaceSource(
            open_read_only(path, timeout), destination=destination
        ),
    )

    with pytest.raises(FileExistsError):
        enroll_module.backup_sqlite_database(str(source), str(destination))
    assert destination.read_text() == "replacement"
    assert list(tmp_path.glob(".cathedral-backup-*")) == []


def test_post_link_backup_failure_removes_published_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "registry.sqlite"
    destination = tmp_path / "backup.sqlite"
    RegistryStore(str(source))
    real_fsync = enroll_module.os.fsync
    injected = False

    def fail_first_post_link_directory_sync(descriptor: int) -> None:
        nonlocal injected
        metadata = os.fstat(descriptor)
        if not injected and stat.S_ISDIR(metadata.st_mode) and destination.exists():
            injected = True
            raise OSError("injected post-link fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(enroll_module.os, "fsync", fail_first_post_link_directory_sync)
    with pytest.raises(OSError, match="injected post-link fsync failure"):
        enroll_module.backup_sqlite_database(str(source), str(destination))
    assert injected is True
    assert not destination.exists()
    assert list(tmp_path.glob(".cathedral-backup-*")) == []


def test_post_link_failure_preserves_concurrent_destination_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "registry.sqlite"
    destination = tmp_path / "backup.sqlite"
    RegistryStore(str(source))
    real_lstat = enroll_module.os.lstat
    replaced = False

    def replace_before_publication_check(path: str | os.PathLike[str]):
        nonlocal replaced
        if os.path.abspath(path) == str(destination) and not replaced and destination.exists():
            destination.unlink()
            destination.write_text("replacement")
            replaced = True
        return real_lstat(path)

    monkeypatch.setattr(enroll_module.os, "lstat", replace_before_publication_check)
    with pytest.raises(PermissionError, match="published backup does not match"):
        enroll_module.backup_sqlite_database(str(source), str(destination))
    assert replaced is True
    assert destination.read_text() == "replacement"
    assert list(tmp_path.glob(".cathedral-backup-*")) == []


def _legacy_registry(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            PRAGMA user_version = 7;
            CREATE TABLE enrollments (
                hotkey TEXT PRIMARY KEY,
                endpoint_url TEXT NOT NULL,
                enrolled_at_iso TEXT NOT NULL,
                updated_at_iso TEXT NOT NULL
            );
            CREATE TABLE enroll_nonces (
                hotkey TEXT NOT NULL,
                nonce TEXT NOT NULL,
                used_at_iso TEXT NOT NULL,
                PRIMARY KEY(hotkey, nonce)
            );
            """
        )
        connection.execute(
            "INSERT INTO enrollments VALUES (?, ?, ?, ?)",
            (HOTKEY, ENDPOINT, now_iso(), now_iso()),
        )
    os.chmod(path, 0o600)


def _schema_signature(path: Path) -> tuple[object, ...]:
    with sqlite3.connect(path) as connection:
        objects = tuple(
            connection.execute(
                """
                SELECT type, name, tbl_name, sql
                FROM sqlite_master
                ORDER BY type, name
                """
            ).fetchall()
        )
        tables = tuple(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        )
        columns = tuple(
            (table, tuple(connection.execute(f"PRAGMA table_info({table})").fetchall()))
            for table in tables
        )
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    return objects, columns, user_version


def test_backup_cli_reports_integrity(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    source = tmp_path / "registry.sqlite"
    RegistryStore(str(source))
    destination = tmp_path / "backup.sqlite"
    args = argparse.Namespace(
        registry_db=str(source), out=str(destination), sqlite_busy_timeout_ms=1000
    )
    assert cmd_enroll_backup(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["integrity_check"] == "ok"
    assert output["destination"] == str(destination)


def test_backup_cli_copies_exact_legacy_schema_before_migration(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    source = tmp_path / "legacy.sqlite"
    destination = tmp_path / "legacy.backup.sqlite"
    _legacy_registry(source)
    legacy_schema = _schema_signature(source)
    args = argparse.Namespace(
        registry_db=str(source), out=str(destination), sqlite_busy_timeout_ms=1000
    )

    assert cmd_enroll_backup(args) == 0
    capsys.readouterr()
    assert _schema_signature(source) == legacy_schema
    assert _schema_signature(destination) == legacy_schema

    RegistryStore(str(source))
    assert _schema_signature(source) != legacy_schema
    assert _schema_signature(destination) == legacy_schema


def test_journal_mode_cli_backs_up_before_switching(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    source = tmp_path / "registry.sqlite"
    RegistryStore(str(source))
    backup = tmp_path / "pre-wal.sqlite"
    args = argparse.Namespace(
        registry_db=str(source),
        backup_to=str(backup),
        mode="wal",
        sqlite_busy_timeout_ms=1000,
    )
    assert cmd_enroll_journal_mode(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["journal_mode_after"] == "wal"
    assert backup.is_file()
    assert RegistryStore(str(source)).journal_mode() == "wal"


def test_journal_mode_cli_changes_no_legacy_schema(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    source = tmp_path / "legacy.sqlite"
    backup = tmp_path / "legacy.pre-wal.sqlite"
    _legacy_registry(source)
    legacy_schema = _schema_signature(source)
    args = argparse.Namespace(
        registry_db=str(source),
        backup_to=str(backup),
        mode="wal",
        sqlite_busy_timeout_ms=1000,
    )

    assert cmd_enroll_journal_mode(args) == 0
    capsys.readouterr()
    assert _schema_signature(source) == legacy_schema
    assert _schema_signature(backup) == legacy_schema
    with sqlite3.connect(source) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_submit_signs_domain_bound_request_without_exporting_seed(
    tmp_path: Path, capsys: pytest.CaptureFixture,
) -> None:
    captured: dict[str, object] = {}

    def transport(url: str, body: bytes, timeout: float) -> tuple[int, object]:
        captured.update(url=url, body=json.loads(body), timeout=timeout)
        return 200, {"status": "enrolled", "worker_token": "public-response-fixture"}

    args = argparse.Namespace(
        registry_url="https://api.cathedral.computer",
        endpoint_url=ENDPOINT,
        wallet_name="cathedral",
        hotkey_name="miner",
        wallet_path=None,
        network=DEFAULT_ENROLL_NETWORK,
        netuid=DEFAULT_ENROLL_NETUID,
        timeout_seconds=30.0,
        token_out=str(tmp_path / "worker-token"),
        transport=transport,
        keypair_factory=lambda *_: KEYPAIR,
    )
    assert cmd_enroll_submit(args) == 0
    body = captured["body"]
    assert isinstance(body, dict)
    message = canonical_allowlist_enroll_payload(
        body["hotkey"],
        body["endpoint_url"],
        body["nonce"],
        body["timestamp"],
        network=body["network"],
        netuid=body["netuid"],
    )
    assert Keypair(ss58_address=body["hotkey"]).verify(
        message, base64.b64decode(body["signature_b64"])
    )
    stdout = capsys.readouterr().out
    assert "//Alice" not in json.dumps(body) + stdout
    assert "public-response-fixture" not in stdout
    assert json.loads(stdout)["credential_saved"] is True


def test_submit_parser_requires_token_output_path() -> None:
    command = [
        "enroll",
        "submit",
        "--registry-url",
        "https://api.cathedral.computer",
        "--endpoint-url",
        ENDPOINT,
        "--wallet-name",
        "cathedral",
        "--hotkey-name",
        "miner",
    ]
    with pytest.raises(SystemExit):
        build_parser().parse_args(command)
    parsed = build_parser().parse_args([*command, "--token-out", "worker-token"])
    assert parsed.token_out == "worker-token"


def test_submit_rejects_missing_or_empty_token_output_before_private_key_or_transport(
) -> None:
    calls: list[str] = []

    def keypair_factory(*_args: object) -> Keypair:
        calls.append("keypair")
        return KEYPAIR

    def transport(_url: str, _body: bytes, _timeout: float) -> tuple[int, object]:
        calls.append("transport")
        return 200, {"status": "enrolled", "worker_token": "discarded-token"}

    for token_out in (None, "", "   "):
        args = _submit_args(transport, token_out=token_out)
        args.keypair_factory = keypair_factory
        with pytest.raises(ValueError, match="--token-out is required"):
            cmd_enroll_submit(args)
    args = _submit_args(transport, token_out=None)
    args.keypair_factory = keypair_factory
    del args.token_out
    with pytest.raises(ValueError, match="--token-out is required"):
        cmd_enroll_submit(args)
    assert calls == []


def _submit_args(transport, *, token_out: Path | str | None) -> argparse.Namespace:
    return argparse.Namespace(
        registry_url="https://api.cathedral.computer",
        endpoint_url=ENDPOINT,
        wallet_name="cathedral",
        hotkey_name="miner",
        wallet_path=None,
        network=DEFAULT_ENROLL_NETWORK,
        netuid=DEFAULT_ENROLL_NETUID,
        timeout_seconds=30.0,
        token_out=None if token_out is None else str(token_out),
        transport=transport,
        keypair_factory=lambda *_: KEYPAIR,
    )


def test_submit_writes_token_owner_only_without_overwrite_or_stdout_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    token = "worker-token-secret-fixture"

    def transport(_url: str, _body: bytes, _timeout: float) -> tuple[int, object]:
        return 200, {"status": "enrolled", "worker_token": token}

    target = tmp_path / "worker-token"
    args = _submit_args(transport, token_out=target)
    assert cmd_enroll_submit(args) == 0
    stdout = capsys.readouterr().out
    assert token not in stdout
    assert target.read_text() == token + "\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert json.loads(stdout)["credential_path"] == str(target)

    with pytest.raises(FileExistsError):
        cmd_enroll_submit(args)
    assert capsys.readouterr().out == ""
    assert target.read_text() == token + "\n"


def test_submit_failure_never_writes_or_prints_response_token(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    token = "failure-response-secret-fixture"

    def rejected(_url: str, _body: bytes, _timeout: float) -> tuple[int, object]:
        return 403, {"error": "denied", "worker_token": token}

    target = tmp_path / "worker-token"
    assert cmd_enroll_submit(_submit_args(rejected, token_out=target)) == 1
    stdout = capsys.readouterr().out
    assert token not in stdout
    assert not target.exists()

    def malformed(_url: str, _body: bytes, _timeout: float) -> tuple[int, object]:
        return 200, {"status": "enrolled"}

    with pytest.raises(ValueError, match="no valid worker token"):
        cmd_enroll_submit(_submit_args(malformed, token_out=target))
    assert capsys.readouterr().out == ""
    assert not target.exists()


def test_quiet_handler_bounds_connection_and_sanitizes_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    assert _QuietRequestHandler.timeout == 10
    assert _QuietRequestHandler.protocol_version == "HTTP/1.0"
    with caplog.at_level(logging.INFO, logger="cathedral.enroll"):
        _QuietRequestHandler.log_message(object(), "%s", "GET /bad\nforged")
    assert "GET /bad?forged" in caplog.text
    assert "\nforged" not in caplog.text
