"""Structured validator/verifier event streams: stable JSONL plus ergonomic TTY.

One emitter, two faithful views of the same event:

  * JSONL — one JSON object per line, stable field names, machine-parseable,
    safe for journald/tail/Zellij panes and downstream tooling. This is the
    durable stream; nothing is ever printed here that is not in the record.
  * TTY   — a concise, aligned, human line per event with meaningful color
    (status only), emitted only when the destination is an interactive
    terminal and color is not disabled. No decorative noise.

Every event carries: UTC timestamp, stable event code, stage, mode,
optional miner hotkey, a PASS/FAIL/NOT_PROVEN/INFO status, optional duration,
optional evidence/artifact reference, and remediation guidance on failures.

Secrets are never accepted: values are rendered with a redaction pass that
drops credential-shaped substrings defensively, mirroring the CLI's output
redaction.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import UTC, datetime
from typing import IO, Any

PASS = "PASS"
FAIL = "FAIL"
NOT_PROVEN = "NOT_PROVEN"
INFO = "INFO"
_STATUSES = (PASS, FAIL, NOT_PROVEN, INFO)

_EVENT_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
# Full credential grammar: key=value / key: value forms AND scheme-prefixed
# header values ("Authorization: Bearer <secret>", "Basic <secret>").
# Full credential grammar: bare and QUOTED values (single/double quotes,
# JSON-serialized and Python-repr forms, values containing spaces),
# scheme-prefixed opaque header values, and URL-safe tokens.
_SECRET_RE = re.compile(
    r"(?i)([\"']?)(bearer|basic|token|secret|hmac|api_key|authorization|"
    r"password|private_key)\1((\s*[=:]\s*)|\s+)"
    r"(?:(?:bearer|basic)\s+)?"
    r"(\"[^\"]*\"|'[^']*'|\S+)"
)
_SENSITIVE_FIELD_RE = re.compile(
    r"(?i)^(authorization|.*(token|secret|password|credential|api_key|"
    r"private_key|hmac).*)$"
)

_COLORS = {
    PASS: "\x1b[32m",       # green
    FAIL: "\x1b[31;1m",     # bold red
    NOT_PROVEN: "\x1b[33m",  # yellow
    INFO: "\x1b[2m",        # dim
}
_RESET = "\x1b[0m"


def _now_iso() -> str:
    dt = datetime.now(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _neutralize(value: str) -> str:
    """Strip ANSI/control characters, redact secrets, bound the length."""
    cleaned = _CONTROL_RE.sub(" ", value)
    cleaned = _SECRET_RE.sub(
        lambda match: (match.group(2) or "credential") + "=[REDACTED]", cleaned
    )
    return cleaned[:2048]


def _scrub(value):
    """Recursive scrub of every string in nested dict/list payloads."""
    if isinstance(value, str):
        return _neutralize(value)
    if isinstance(value, dict):
        # Sensitive FIELD NAMES redact the entire value regardless of shape.
        return {
            _neutralize(str(key)): (
                "[REDACTED]"
                if _SENSITIVE_FIELD_RE.match(str(key))
                else _scrub(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_scrub(item) for item in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _neutralize(str(value))


def _redact(value: str) -> str:
    return _neutralize(value)


class EventLogger:
    """Emit one event to a JSONL stream and, optionally, a TTY stream.

    ``mode`` names the validator mode responsible for the events
    (``thin`` / ``full_provenance`` / ``shadow`` …) and is stamped on every
    record so concurrent modes remain unmistakable in a merged stream.
    """

    def __init__(
        self,
        *,
        mode: str,
        jsonl: IO[str] | None = None,
        jsonl_path: str | None = None,
        tty: IO[str] | None = None,
        color: bool | None = None,
    ) -> None:
        self.mode = _neutralize(mode)[:32]
        self._jsonl = jsonl
        self._jsonl_file: IO[str] | None = None
        if jsonl_path:
            # Secure append: refuse symlinks/non-regular files, create 0600,
            # refuse group/world-accessible existing logs.
            flags = (
                os.O_WRONLY
                | os.O_APPEND
                | os.O_CREAT
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            descriptor = os.open(jsonl_path, flags, 0o600)
            import stat as _stat

            opened = os.fstat(descriptor)
            if not _stat.S_ISREG(opened.st_mode) or opened.st_mode & 0o077:
                os.close(descriptor)
                raise ValueError(
                    "event log must be a private (0600) regular file"
                )
            self._jsonl_file = os.fdopen(descriptor, "a", encoding="utf-8")
        self._tty = tty if tty is not None else sys.stderr
        if color is None:
            color = (
                hasattr(self._tty, "isatty")
                and self._tty.isatty()
                and not os.environ.get("NO_COLOR")
            )
        self._color = bool(color)
        self._is_tty = bool(hasattr(self._tty, "isatty") and self._tty.isatty())

    def close(self) -> None:
        if self._jsonl_file is not None:
            self._jsonl_file.close()
            self._jsonl_file = None

    # -- emission ---------------------------------------------------------

    def event(
        self,
        code: str,
        *,
        stage: str,
        status: str = INFO,
        hotkey: str | None = None,
        duration_ms: float | None = None,
        artifact: str | None = None,
        remediation: str | None = None,
        detail: str | None = None,
        **fields: Any,
    ) -> dict[str, Any]:
        if _EVENT_CODE_RE.fullmatch(code) is None:
            raise ValueError(f"unstable event code {code!r}")
        if status not in _STATUSES:
            raise ValueError(f"unknown status {status!r}")
        record: dict[str, Any] = {
            "ts": _now_iso(),
            "event": code,
            "stage": _neutralize(stage)[:32],
            "mode": self.mode,
            "status": status,
        }
        if hotkey is not None:
            record["hotkey"] = _neutralize(hotkey)
        if duration_ms is not None:
            record["duration_ms"] = round(float(duration_ms), 3)
        if artifact is not None:
            record["artifact"] = _redact(str(artifact))
        if detail is not None:
            record["detail"] = _redact(str(detail))
        if remediation is not None:
            record["remediation"] = _redact(str(remediation))
        for key, value in fields.items():
            if key not in record:
                record[key] = _scrub(value)
        self._write_jsonl(record)
        self._write_tty(record)
        return record

    # -- streams ----------------------------------------------------------

    def _write_jsonl(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=False, separators=(",", ":"))
        for target in (self._jsonl, self._jsonl_file):
            if target is not None:
                target.write(line + "\n")
                target.flush()

    def _write_tty(self, record: dict[str, Any]) -> None:
        if self._tty is None or not self._is_tty:
            return
        status = record["status"]
        badge = f"{status:<10}"
        if self._color:
            badge = _COLORS[status] + badge + _RESET
        clock = record["ts"][11:23]
        parts = [f"{clock} {badge} {record['event']:<28} [{record['mode']}]"]
        if "hotkey" in record:
            hotkey = record["hotkey"]
            parts.append(hotkey if len(hotkey) <= 12 else f"{hotkey[:6]}..{hotkey[-4:]}")
        if "duration_ms" in record:
            parts.append(f"{record['duration_ms']:.0f}ms")
        if "detail" in record:
            parts.append(str(record["detail"]))
        if "artifact" in record:
            parts.append(f"ref={record['artifact']}")
        line = "  ".join(parts)
        if record.get("remediation"):
            line += f"\n{'':>13}↳ {record['remediation']}"
        self._tty.write(line + "\n")
        self._tty.flush()
