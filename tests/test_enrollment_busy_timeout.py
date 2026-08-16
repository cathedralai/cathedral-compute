from __future__ import annotations

import io
import json
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

import pytest

import cathedral.enroll as enroll_module
from cathedral.enroll import RegistryApp, RegistryStore


def _call(app: RegistryApp) -> tuple[int, dict[str, Any], dict[str, str]]:
    captured: dict[str, Any] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = int(status.split()[0])
        captured["headers"] = dict(headers)

    body = b"".join(
        app(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/v1/attested",
                "CONTENT_LENGTH": "0",
                "REMOTE_ADDR": "127.0.0.1",
                "wsgi.input": io.BytesIO(b""),
            },
            start_response,
        )
    )
    return captured["status"], json.loads(body), captured["headers"]


def test_registry_store_applies_explicit_busy_timeout(tmp_path: Path) -> None:
    store = RegistryStore(str(tmp_path / "registry.sqlite"), busy_timeout_ms=1234)

    with store._connect() as conn:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 1234


def test_registry_store_keeps_sqlite_default_timeout(tmp_path: Path) -> None:
    store = RegistryStore(str(tmp_path / "registry.sqlite"))

    with store._connect() as conn:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    assert store.busy_timeout_ms == enroll_module.DEFAULT_SQLITE_BUSY_TIMEOUT_MS


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "4000"])
def test_registry_store_rejects_invalid_busy_timeout(
    tmp_path: Path, value: object
) -> None:
    with pytest.raises(ValueError, match="busy_timeout_ms must be positive"):
        RegistryStore(str(tmp_path / "registry.sqlite"), busy_timeout_ms=value)  # type: ignore[arg-type]


def test_registry_contention_returns_bounded_503(tmp_path: Path) -> None:
    database = tmp_path / "registry.sqlite"
    store = RegistryStore(str(database), busy_timeout_ms=100)
    app = RegistryApp(store)
    writer = sqlite3.connect(database, timeout=0.1, isolation_level=None)
    writer.execute("BEGIN EXCLUSIVE")
    writer.execute(
        "INSERT INTO hotkey_enroll_attempts(hotkey, attempted_at_iso) VALUES (?, ?)",
        ("lock-holder", "2026-08-15T00:00:00Z"),
    )

    try:
        started = time.monotonic()
        status, body, headers = _call(app)
        elapsed = time.monotonic() - started
    finally:
        writer.rollback()
        writer.close()

    assert status == 503
    assert body == {"error": "registry busy, retry shortly"}
    assert headers["Retry-After"] == str(
        enroll_module.ENROLL_BUSY_RETRY_AFTER_SECONDS
    )
    assert elapsed < 1.0

    status, body, _headers = _call(app)
    assert status == 200
    assert body["count"] == 0


def test_non_contention_operational_error_is_not_hidden(tmp_path: Path) -> None:
    app = RegistryApp(RegistryStore(str(tmp_path / "registry.sqlite")))

    def fail_board() -> dict[str, Any]:
        raise sqlite3.OperationalError("no such table: broken")

    app.store.board = fail_board  # type: ignore[method-assign]

    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        _call(app)


def test_main_accepts_deployed_busy_timeout_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    class StopServer(Exception):
        pass

    class Server:
        def __enter__(self) -> Server:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def serve_forever(self) -> None:
            raise StopServer

    def make_server(
        host: str, port: int, app: RegistryApp, **kwargs: object
    ) -> Server:
        captured.update(host=host, port=port, app=app, **kwargs)
        return Server()

    monkeypatch.setattr(enroll_module, "make_server", make_server)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cathedral.enroll",
            "--db",
            str(tmp_path / "registry.sqlite"),
            "--sqlite-busy-timeout-ms",
            "4000",
        ],
    )

    with pytest.raises(StopServer):
        enroll_module.main()

    assert captured["host"] == "127.0.0.1"
    assert captured["app"].store.busy_timeout_ms == 4000
    assert captured["handler_class"] is enroll_module._QuietRequestHandler


def test_main_rejects_nonpositive_busy_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def must_not_bind(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("invalid timeout reached the listener")

    monkeypatch.setattr(enroll_module, "make_server", must_not_bind)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cathedral.enroll",
            "--db",
            str(tmp_path / "registry.sqlite"),
            "--sqlite-busy-timeout-ms",
            "0",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        enroll_module.main()

    assert excinfo.value.code == 2
