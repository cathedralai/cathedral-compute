"""JSONL/TTY event stream contract: stable fields, redaction, TTY rendering."""

from __future__ import annotations

import io
import json

import pytest

from cathedral.events import FAIL, NOT_PROVEN, PASS, EventLogger


class _FakeTty(io.StringIO):
    def isatty(self) -> bool:  # pragma: no cover - trivial
        return True


def test_jsonl_record_has_stable_contract_fields():
    stream = io.StringIO()
    logger = EventLogger(mode="thin", jsonl=stream, tty=None)
    record = logger.event(
        "VECTOR_ACCEPTED",
        stage="verify",
        status=PASS,
        hotkey="5CtobExampleHotkey",
        duration_ms=12.345,
        artifact="sha256:" + "a" * 64,
        detail="signature+freshness+policy ok",
    )
    line = json.loads(stream.getvalue())
    assert line == record
    assert line["event"] == "VECTOR_ACCEPTED"
    assert line["mode"] == "thin"
    assert line["status"] == "PASS"
    assert line["stage"] == "verify"
    assert line["duration_ms"] == 12.345
    assert line["ts"].endswith("Z")


def test_credential_shaped_values_are_redacted_everywhere():
    stream = io.StringIO()
    logger = EventLogger(mode="full_provenance", jsonl=stream, tty=None)
    logger.event(
        "FETCH_FAILED",
        stage="fetch",
        status=FAIL,
        detail="request failed: Authorization: bearer=abc123 rejected",
        remediation="rotate the token=deadbeef value",
        endpoint="https://x?api_key=zzz",
    )
    text = stream.getvalue()
    assert "abc123" not in text
    assert "deadbeef" not in text
    assert "zzz" not in text
    assert "[REDACTED]" in text


def test_unstable_event_codes_and_statuses_are_refused():
    logger = EventLogger(mode="thin", jsonl=io.StringIO(), tty=None)
    with pytest.raises(ValueError, match="unstable event code"):
        logger.event("lowercase code", stage="verify")
    with pytest.raises(ValueError, match="unknown status"):
        logger.event("GOOD_CODE", stage="verify", status="MAYBE")


def test_tty_rendering_includes_remediation_and_skips_non_tty():
    tty = _FakeTty()
    logger = EventLogger(mode="thin", jsonl=io.StringIO(), tty=tty, color=False)
    logger.event(
        "VECTOR_REJECTED",
        stage="verify",
        status=NOT_PROVEN,
        hotkey="5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK",
        remediation="check the publisher URL",
    )
    rendered = tty.getvalue()
    assert "VECTOR_REJECTED" in rendered
    assert "NOT_PROVEN" in rendered
    assert "5Ctob" in rendered and "wawK" in rendered  # shortened hotkey
    assert "check the publisher URL" in rendered

    silent = io.StringIO()  # not a tty
    logger2 = EventLogger(mode="thin", jsonl=io.StringIO(), tty=silent)
    logger2.event("VECTOR_ACCEPTED", stage="verify", status=PASS)
    assert silent.getvalue() == ""


def test_jsonl_file_append(tmp_path):
    path = tmp_path / "events.jsonl"
    logger = EventLogger(mode="thin", jsonl=None, jsonl_path=str(path), tty=None)
    logger.event("STARTUP", stage="startup", status=PASS, detail="mode=thin")
    logger.event("SHUTDOWN", stage="startup", status=PASS)
    logger.close()
    lines = [json.loads(line) for line in path.read_text().strip().splitlines()]
    assert [line["event"] for line in lines] == ["STARTUP", "SHUTDOWN"]


def test_nested_secrets_and_control_chars_are_scrubbed(tmp_path):
    stream = io.StringIO()
    logger = EventLogger(mode="thin\x1b[31m", jsonl=stream, tty=None)
    logger.event(
        "AUDIT_RESULT",
        stage="verify\x00stage",
        status=PASS,
        hotkey="5C\x1b[2Jtob",
        payload={"inner": {"token=deep-secret": ["bearer=nested-cred", 3]}},
    )
    text = stream.getvalue()
    assert "deep-secret" not in text
    assert "nested-cred" not in text
    assert "\\u001b" not in text and "\x1b" not in text
    assert "\\u0000" not in text
    record = json.loads(text)
    assert record["mode"].startswith("thin")


def test_jsonl_path_rejects_symlinks_and_lax_modes(tmp_path):
    real = tmp_path / "real.jsonl"
    real.write_text("")
    real.chmod(0o600)
    link = tmp_path / "link.jsonl"
    link.symlink_to(real)
    with pytest.raises(OSError):
        EventLogger(mode="thin", jsonl_path=str(link), tty=None)
    lax = tmp_path / "lax.jsonl"
    lax.write_text("")
    lax.chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        EventLogger(mode="thin", jsonl_path=str(lax), tty=None)
    fresh = tmp_path / "fresh.jsonl"
    logger = EventLogger(mode="thin", jsonl_path=str(fresh), tty=None)
    logger.event("STARTUP", stage="startup", status=PASS)
    logger.close()
    assert (fresh.stat().st_mode & 0o777) == 0o600


def test_bearer_header_and_named_fields_never_leak(tmp_path):
    stream = io.StringIO()
    logger = EventLogger(mode="thin", jsonl=stream, tty=None)
    logger.event(
        "FETCH_FAILED",
        stage="fetch",
        status=FAIL,
        detail="server said: Authorization: Bearer sekrit-token-123 rejected",
        payload={"token": "sekrit-2", "nested": {"Api_Key": "sekrit-3"}},
        headers={"authorization": "Basic sekrit-4"},
    )
    text = stream.getvalue()
    for secret in ("sekrit-token-123", "sekrit-2", "sekrit-3", "sekrit-4"):
        assert secret not in text
    assert "[REDACTED]" in text
