"""Miner enrollment registry and public attestation board.

Small stdlib HTTP service:

    python -m cathedral.enroll --db cathedral-enroll.sqlite --host 127.0.0.1 --port 8080

The trust topology stays inverted: miners enroll an endpoint, then validators
fetch evidence from that miner-owned endpoint.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Protocol
from urllib.parse import urlparse
from wsgiref.simple_server import make_server

from cathedral.assurance import (
    ATTESTATION_ADMISSION_POLICY,
    AssuranceClaims,
    assurance_from_dict,
    empty_assurance_claims,
)
from cathedral.admission_policy import (
    DEFAULT_POLICY_MAX_AGE_SECONDS,
    SignedAdmissionPolicyProvider,
    load_policy_keys,
)
from cathedral.coldkey_allowlist import (
    DEFAULT_ALLOWLIST_MAX_AGE_SECONDS,
    SignedColdkeyAllowlistProvider,
    load_allowlist_keys,
)
from cathedral.common import Attested, is_globally_routable
from cathedral.lifecycle import (
    CAPACITY_CONSUMING_STATES,
    NETWORK_ELIGIBLE_STATES,
    TERMINAL_STATES,
    LifecycleError,
    LifecycleReason,
    LifecycleSnapshot,
    WorkerLifecycleState,
    canonical_utc,
    parse_utc,
    require_transition,
    require_transition_reason,
    retry_delay_seconds,
)

try:
    from substrateinterface import Keypair
except Exception:  # pragma: no cover - exercised only when dependency import fails
    Keypair = None  # type: ignore[assignment]


logger = logging.getLogger("cathedral.enroll")

HOTKEY_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,128}$")
ENROLL_NONCE_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")
NETWORK_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MAX_NETUID = 65_535
ENROLL_REQUEST_SCHEMA_V2 = "cathedral_enroll_request_v2"
MAX_BODY = 16 * 1024
DEFAULT_VERIFICATION_TTL_SECONDS = 60 * 60
DEFAULT_ENROLL_SIGNATURE_TTL_SECONDS = 10 * 60
VERIFICATION_TTL_ENV = "CATHEDRAL_VERIFICATION_TTL_SECONDS"
ENROLL_SIGNATURE_TTL_ENV = "CATHEDRAL_ENROLL_SIGNATURE_TTL_SECONDS"
REJECTED_HOSTS = {"localhost", "metadata.google.internal"}

DEFAULT_HOTKEY_ENROLL_LIMIT = 20
DEFAULT_HOTKEY_ENROLL_WINDOW_SECONDS = 3600
_DEFAULT_REGISTRATION_MAX_AGE_SECONDS = 3600

# The bearer token the validator presents to a worker. Kept well inside
# runtime.MAX_BEARER_TOKEN_LENGTH (4096) and restricted to the printable
# ASCII the runtime's own validator accepts, so a minted token can never be
# the thing that makes a miner unreachable.
WORKER_TOKEN_BYTES = 32


def generate_worker_token() -> str:
    """Mint one bearer token for a worker.

    ``secrets.token_urlsafe`` yields url-safe base64, which is a strict subset
    of the printable-ASCII range ``_validate_bearer_token`` requires.
    """
    return secrets.token_urlsafe(WORKER_TOKEN_BYTES)


def _is_loopback_host(host: object) -> bool:
    """True only for an address that cannot receive traffic off the machine.

    An empty host and ``0.0.0.0`` / ``::`` are wildcards, not loopback, and a
    hostname is refused rather than resolved: resolution is not stable and a
    name that resolves to loopback today is not a guarantee.
    """
    if not isinstance(host, str) or not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    # IPv6 loopback is refused rather than accepted: the WSGI server used below
    # is AF_INET only, so accepting ::1 would pass validation and then die at
    # bind time with an address-family error, taking enrollment offline for a
    # reason the operator was told nothing about.
    return address.is_loopback and address.version == 4


def _valid_worker_token(token: object) -> bool:
    return (
        isinstance(token, str)
        and 0 < len(token) <= 4096
        and all(0x21 <= ord(character) <= 0x7E for character in token)
    )


class RegistrationProvider(Protocol):
    """Gate enrollment to hotkeys registered on the subnet.

    Implementations query the Bittensor metagraph, a local cache, or a
    registry service. Return True (registered), False (not registered), or
    None (cannot confirm right now). None is treated as fail-closed: the
    enrollment is rejected and the miner must retry when the provider is
    available. See docs/DESIGN.md §6.
    """

    def is_registered(self, hotkey: str) -> bool | None:
        ...


# Sentinel distinguishing "content is not valid JSON" from a legitimate
# ``None``/``null`` JSON document (which is valid JSON but not a hotkey list).
_JSON_PARSE_FAILED = object()


class JsonHotkeyRegistrationProvider:
    """RegistrationProvider backed by a local hotkey snapshot file.

    Note: this snapshot-based approach is a deliberately minimal production
    policy — it substitutes a live subnet metagraph query with a rotated
    file to avoid a hard chain-connectivity dependency at launch.

    Supports four formats, tried in this order:
    - JSON array: ``["hotkey1", "hotkey2", ...]``
    - JSON object: ``{"hotkeys": ["hotkey1", "hotkey2", ...]}``
    - Extended JSON object: ``{"hotkeys": {"hotkey1": "coldkey1", ...}}``,
      rotated by the same metagraph cron; the only format that also carries
      the hotkey-to-coldkey ownership mapping for the coldkey allowlist gate.
    - Newline-delimited: one hotkey per line; blank lines and ``#`` comments ignored.

    Fail-closed rules (``is_registered`` returns ``None``):
    - File does not exist or cannot be read (``OSError``).
    - File mtime is older than *max_age_seconds* (stale snapshot).
    - File parses as JSON but is not a recognised array/object shape.
    - File parses to zero hotkeys (empty snapshot). On a live subnet the
      validator itself is always registered, so an empty parse result can
      only be a torn or failed rotation write, never a truthful metagraph
      view; it is refused the same as a stale or malformed file.

    Returns ``True`` when the hotkey is present, ``False`` when absent and
    the file is fresh and readable.  ``None`` always triggers a 403 via the
    existing ``RegistryApp`` fail-closed logic — callers must never treat
    ``None`` as "not registered" and must never treat it as "registered".

    ``resolve_coldkey`` follows the same rules and additionally returns
    ``None`` when the snapshot is one of the hotkeys-only formats: those
    remain valid for registration gating, but cannot prove ownership, so
    coldkey resolution fails closed until the rotation cron emits the
    extended format.

    Typical update cycle: rotate the file from a cron job that re-fetches the
    metagraph; the max-age bound ensures a stuck cron is caught within one
    interval instead of silently admitting stale/deregistered hotkeys.
    """

    def __init__(self, path: str, *, max_age_seconds: int) -> None:
        if max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be a positive integer")
        self.path = path
        self.max_age_seconds = max_age_seconds

    def load_snapshot(self) -> tuple[set[str], dict[str, str] | None] | None:
        """Read and parse the snapshot, applying the freshness bound.

        Returns ``(hotkeys, coldkey_by_hotkey)`` where the mapping is ``None``
        for the hotkeys-only formats, or ``None`` overall when the file is
        missing, unreadable, stale, empty, or malformed (fail closed).
        """
        try:
            stat_result = os.stat(self.path)
            age = time.time() - stat_result.st_mtime
            if age > self.max_age_seconds:
                return None  # stale snapshot; fail closed
            with open(self.path, "r", encoding="utf-8") as fh:
                content = fh.read()
        except OSError:
            return None  # missing or unreadable file; fail closed
        parsed = self._parse(content)
        if parsed is not None and not parsed[0]:
            # Zero hotkeys can only be a torn or failed rotation write on a
            # live subnet (the validator itself is always registered); fail
            # closed the same as a stale or malformed snapshot rather than
            # let an empty view read as "nobody is registered".
            return None
        return parsed

    def is_registered(self, hotkey: str) -> bool | None:
        snapshot = self.load_snapshot()
        if snapshot is None:
            return None
        hotkeys, _coldkeys = snapshot
        return hotkey in hotkeys

    def resolve_coldkey(self, hotkey: str) -> str | None:
        """Return the coldkey owning *hotkey*, or None when unprovable.

        None (fail closed) when the snapshot is missing/stale/malformed, when
        it is a hotkeys-only format that carries no ownership data, or when
        the hotkey has no entry in the mapping.
        """
        snapshot = self.load_snapshot()
        if snapshot is None:
            return None
        _hotkeys, coldkeys = snapshot
        if coldkeys is None:
            return None  # hotkeys-only snapshot cannot prove ownership
        return coldkeys.get(hotkey)

    def _parse(self, content: str) -> tuple[set[str], dict[str, str] | None] | None:
        """Parse content as JSON array, JSON object, or newline-delimited list.

        Returns ``None`` on malformed/unrecognised JSON structure. Never raises.
        A valid JSON document that isn't a recognised shape is treated as
        malformed (fail closed) rather than falling back to newline parsing,
        to avoid silently misinterpreting a broken JSON snapshot as an empty
        or partial hotkey list.
        """
        stripped = content.strip()
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = _JSON_PARSE_FAILED
        if data is not _JSON_PARSE_FAILED:
            if isinstance(data, list) and all(isinstance(h, str) for h in data):
                return set(data), None
            if isinstance(data, dict):
                raw_hotkeys = data.get("hotkeys")
                if isinstance(raw_hotkeys, list) and all(
                    isinstance(h, str) for h in raw_hotkeys
                ):
                    return set(raw_hotkeys), None
                if isinstance(raw_hotkeys, dict) and all(
                    isinstance(h, str)
                    and h
                    and isinstance(c, str)
                    and c
                    for h, c in raw_hotkeys.items()
                ):
                    return set(raw_hotkeys), dict(raw_hotkeys)
            return None  # recognisable-as-JSON but wrong shape; fail closed
        # Not JSON at all: newline-delimited. Lines starting with '#' are comments.
        return {
            line.strip()
            for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        }, None


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _positive_int_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _parse_iso_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601 UTC") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(UTC)


def validate_hotkey(hotkey: object) -> str:
    if not isinstance(hotkey, str) or not HOTKEY_RE.fullmatch(hotkey):
        raise ValueError("hotkey must be a 32-128 character ss58/base58-like string")
    return hotkey


def validate_enroll_nonce(nonce: object) -> str:
    if not isinstance(nonce, str) or not ENROLL_NONCE_RE.fullmatch(nonce):
        raise ValueError("nonce must be a 16-64 byte hex string")
    return nonce.lower()


def validate_enroll_timestamp(
    timestamp: object,
    *,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_ENROLL_SIGNATURE_TTL_SECONDS,
) -> str:
    if not isinstance(timestamp, str):
        raise ValueError("timestamp must be an ISO-8601 UTC string")
    parsed = _parse_iso_utc(timestamp)
    current = now if now is not None else datetime.now(UTC)
    age = abs((current - parsed).total_seconds())
    if age > max_age_seconds:
        raise ValueError("timestamp is outside the enrollment signature window")
    return timestamp


def validate_endpoint_url(endpoint_url: object, *, require_ip_literal: bool = False) -> str:
    """Validate an enrollment endpoint URL.

    :param require_ip_literal: when True (production mode), the host must be
        a public IP literal. This closes the DNS check/use (TOCTOU) gap for
        launch without a pinned custom connector: a hostname resolved at
        enrollment time could resolve to a different, non-global address by
        the time the prober connects (DNS rebinding). An IP literal has no
        such gap because there is nothing left to resolve. Non-production
        callers may still enroll a hostname endpoint; see ``prober.py`` for
        the matching probe-time gate.
    """
    if not isinstance(endpoint_url, str):
        raise ValueError("endpoint_url must be a string")
    parsed = urlparse(endpoint_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("endpoint_url must use http or https")
    if not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("endpoint_url must include a host and no credentials")
    if parsed.fragment:
        raise ValueError("endpoint_url must not include a fragment")
    host = parsed.hostname
    if host is None:
        raise ValueError("endpoint_url must include a host")
    normalized_host = host.rstrip(".").lower()
    if "%" in normalized_host or normalized_host in REJECTED_HOSTS:
        raise ValueError("endpoint_url host is not allowed")
    try:
        ip = ipaddress.ip_address(normalized_host)
    except ValueError:
        if require_ip_literal:
            raise ValueError(
                "endpoint_url must be a public IP literal in production mode "
                "(hostnames are rejected to close the DNS check/use gap)"
            ) from None
    else:
        if not is_globally_routable(ip):
            raise ValueError("endpoint_url host must be a public address")
    return endpoint_url


def canonical_endpoint_key(endpoint_url: str) -> str:
    """The normal form two enrollments are the same machine under.

    Must agree with ``runtime._canonical_endpoint``. The runtime dedups
    targets on that normal form and excludes **every** claimant of a
    duplicate, so any uniqueness rule here that compares raw strings is worse
    than no rule: an attacker enrolls a cosmetic variant of a victim's
    endpoint, both collide at epoch time, and both are dropped before
    attestation. Scheme and host case, a trailing dot, an IPv6 spelling, a
    default port, and a bare ``/`` path are all the same address.

    This is a comparison key only. The endpoint the miner signed is what gets
    stored and dialled; nothing here rewrites it.
    """
    parsed = urlparse(endpoint_url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    try:
        port = parsed.port
    except ValueError:
        # Unparseable port: fall back to the raw authority rather than
        # silently collapsing two different endpoints onto one key.
        return f"{scheme}://{(parsed.netloc or '').lower()}"
    default_port = 443 if scheme == "https" else 80
    authority = host if port in {None, default_port} else f"{host}:{port}"
    return f"{scheme}://{authority}"


def canonical_enroll_payload(hotkey: str, endpoint_url: str, nonce: str, timestamp: str) -> bytes:
    """Canonical bytes miners sign before calling /v1/enroll.

    Legacy v1 request. Accepted only while no admission policy is
    configured; see ``canonical_enroll_payload_v2``.
    """

    payload = {
        "endpoint_url": endpoint_url,
        "hotkey": hotkey,
        "nonce": nonce,
        "timestamp": timestamp,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def canonical_enroll_payload_v2(
    *,
    hotkey: str,
    coldkey: str,
    network: str,
    netuid: int,
    endpoint_url: str,
    requested_profile_id: str,
    nonce: str,
    timestamp: str,
    expires_at: str,
) -> bytes:
    """Canonical bytes miners sign for a v2 enrollment request.

    Every field the registry will act on is inside the signature, so a
    request cannot be replayed against a different subnet, endpoint, or
    profile than the one the hotkey agreed to. The ``schema`` member is
    domain separation: a v1 signature can never satisfy a v2 request
    because the two byte strings cannot collide.

    The submitted ``coldkey`` is signed but never trusted. The registry
    resolves ownership from the registration snapshot and rejects the
    request when the two disagree; including it in the signature is what
    makes that disagreement attributable rather than ambiguous.
    """

    payload = {
        "coldkey": coldkey,
        "endpoint_url": endpoint_url,
        "expires_at": expires_at,
        "hotkey": hotkey,
        "netuid": netuid,
        "network": network,
        "nonce": nonce,
        "requested_profile_id": requested_profile_id,
        "schema": ENROLL_REQUEST_SCHEMA_V2,
        "timestamp": timestamp,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def validate_network(network: object) -> str:
    if not isinstance(network, str) or NETWORK_RE.fullmatch(network) is None:
        raise ValueError("network must be a bounded lowercase identifier")
    return network


def validate_netuid(netuid: object) -> int:
    if isinstance(netuid, bool) or not isinstance(netuid, int) or not 0 <= netuid <= MAX_NETUID:
        raise ValueError("netuid must be an integer within the subnet range")
    return netuid


def validate_profile_id(profile_id: object) -> str:
    if not isinstance(profile_id, str) or PROFILE_ID_RE.fullmatch(profile_id) is None:
        raise ValueError("requested_profile_id must be a bounded identifier")
    return profile_id


def validate_enroll_expiry(
    expires_at: object,
    timestamp: str,
    *,
    now: datetime | None = None,
    max_ttl_seconds: int = DEFAULT_ENROLL_SIGNATURE_TTL_SECONDS,
) -> str:
    """Validate the miner-declared expiry of a v2 enrollment request.

    The expiry must be in the future, must follow the request timestamp, and
    must not extend the request beyond the server's own signature TTL: a
    miner cannot mint a request that outlives the replay window the registry
    is willing to police.
    """
    if not isinstance(expires_at, str):
        raise ValueError("expires_at must be an ISO-8601 UTC string")
    parsed = _parse_iso_utc(expires_at)
    issued = _parse_iso_utc(timestamp)
    current = now if now is not None else datetime.now(UTC)
    if parsed <= issued:
        raise ValueError("expires_at must follow the request timestamp")
    if (parsed - issued).total_seconds() > max_ttl_seconds:
        raise ValueError("expires_at exceeds the maximum enrollment request lifetime")
    if parsed <= current:
        raise ValueError("enrollment request has expired")
    return expires_at


def verify_enroll_signature(hotkey: str, message: bytes, signature_b64: object) -> None:
    if Keypair is None:
        raise ValueError("sr25519 signature verifier unavailable")
    if not isinstance(signature_b64, str):
        raise ValueError("signature_b64 is required")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("signature_b64 must be valid base64") from exc
    if len(signature) != 64:
        raise ValueError("signature_b64 must decode to a 64 byte sr25519 signature")
    try:
        ok = Keypair(ss58_address=hotkey).verify(message, signature)
    except Exception as exc:
        raise ValueError("invalid enroll signature") from exc
    if not ok:
        raise ValueError("invalid enroll signature")


class EnrollmentRejected(Exception):
    """One enrollment was refused by a policy cap or an identity conflict.

    Deliberately not a ``ValueError``: the WSGI app turns a ``ValueError``
    into a 400 with the message echoed back, while these carry a stable
    machine-readable ``reason`` and answer 403.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class Enrollment:
    hotkey: str
    endpoint_url: str


@dataclass(frozen=True)
class VerifiedAttestationRecord:
    """Verifier-owned assurance persisted for one enrolled worker."""

    hotkey: str
    chip_id: str
    tier: str
    assurance: AssuranceClaims


class RegistryStore:
    def __init__(
        self,
        path: str,
        *,
        verification_ttl_seconds: int | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = path
        if verification_ttl_seconds is None:
            verification_ttl_seconds = _positive_int_from_env(
                VERIFICATION_TTL_ENV,
                DEFAULT_VERIFICATION_TTL_SECONDS,
            )
        if (
            isinstance(verification_ttl_seconds, bool)
            or not isinstance(verification_ttl_seconds, int)
            or verification_ttl_seconds <= 0
        ):
            raise ValueError("verification_ttl_seconds must be positive")
        self.verification_ttl_seconds = verification_ttl_seconds
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lifecycle_lock = threading.RLock()
        self._precreate_database()
        self._init()
        self._restrict_database_mode()

    def _lifecycle_now(self) -> datetime:
        when = self._clock()
        if (
            not isinstance(when, datetime)
            or when.tzinfo is None
            or when.utcoffset() != timedelta(0)
        ):
            raise LifecycleError("worker lifecycle clock must return UTC")
        return when

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _precreate_database(self) -> None:
        """Create the database file owner-only before SQLite opens it.

        SQLite creates a new database 0644 regardless of umask, so narrowing it
        afterwards leaves a window on a fresh install where a local account can
        open a handle that keeps reading every token written later. Creating it
        ourselves first closes that window; on an existing database this is a
        no-op.
        """
        if self.path == ":memory:" or self.path.startswith("file::memory:"):
            return

        # Refuse a path that is not a plain file we own, BEFORE SQLite opens it.
        # SQLite follows a symlink, so a link here silently redirects worker
        # bearer tokens to its target and the chmod below lands on the target
        # too. The path is operator configuration rather than miner input, so
        # this is not a miner-reachable attack; it is refused because a link or
        # a foreign-owned file at this path is never intentional and the file
        # now holds credentials.
        try:
            existing = os.lstat(self.path)
        except FileNotFoundError:
            existing = None
        except OSError:
            # Anything else about the path surfaces from sqlite3.connect with a
            # better message than we could produce here.
            return
        if existing is not None:
            if stat.S_ISLNK(existing.st_mode):
                raise ValueError(
                    f"registry database path {self.path!r} is a symlink; the "
                    "registry holds worker bearer tokens and must be a regular "
                    "file the service owns"
                )
            if not stat.S_ISREG(existing.st_mode):
                raise ValueError(
                    f"registry database path {self.path!r} is not a regular file"
                )
            if existing.st_uid != os.getuid() and os.getuid() != 0:
                raise PermissionError(
                    f"registry database {self.path!r} is owned by another user. "
                    "It holds worker bearer tokens, so every process that opens "
                    "it must run as that owner."
                )
            return

        try:
            os.close(os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600))
        except OSError:
            return

    def _restrict_database_mode(self) -> None:
        """Make the database owner-only.

        This file now holds worker bearer tokens. The operator's token file
        carries the same credential class and is refused unless it is
        owner-only (``cli.py::_load_production_tokens``), so leaving this one
        at whatever the process umask produced would be an asymmetry with a
        real consequence: any local account that can read the file reads every
        worker's token and can impersonate the validator to those workers.

        The journal, WAL and shared-memory siblings hold the same rows and are
        created by SQLite rather than by us, so they are narrowed too. A
        sibling that does not exist is not an error.
        """
        if self.path == ":memory:" or self.path.startswith("file::memory:"):
            return
        for suffix in ("", "-journal", "-wal", "-shm"):
            try:
                os.chmod(self.path + suffix, 0o600)
            except FileNotFoundError:
                continue
            except PermissionError as exc:
                # Refusing is deliberate. The alternative is running with worker
                # bearer tokens in a file this process cannot secure, and no
                # signal that anything is wrong.
                raise PermissionError(
                    f"cannot restrict {self.path + suffix} to owner-only: it is "
                    "owned by another user. The registry holds worker bearer "
                    "tokens, so every process that opens it must run as that "
                    "owner."
                ) from exc

    def _init(self) -> None:
        with self._connect() as conn:
            # Serialize schema/backfill clock sampling across RegistryStore
            # instances before any lifecycle timestamp is consumed.
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS enrollments (
                    hotkey TEXT PRIMARY KEY,
                    endpoint_url TEXT NOT NULL,
                    enrolled_at_iso TEXT NOT NULL,
                    updated_at_iso TEXT NOT NULL
                )
                """
            )
            enrollment_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(enrollments)")
            }
            # The owning coldkey resolved from the registration snapshot at
            # enrollment time, and the profile the miner asked to be tested
            # under. Both are NULL for rows written before the admission
            # policy existed; the caps treat an unresolved coldkey as its own
            # bucket rather than pooling every legacy row together.
            if "coldkey" not in enrollment_columns:
                conn.execute("ALTER TABLE enrollments ADD COLUMN coldkey TEXT")
            if "requested_profile_id" not in enrollment_columns:
                conn.execute("ALTER TABLE enrollments ADD COLUMN requested_profile_id TEXT")
            # The normal form uniqueness and caps compare on. Derived, not
            # authoritative: endpoint_url stays exactly what the miner signed.
            if "endpoint_canonical" not in enrollment_columns:
                conn.execute("ALTER TABLE enrollments ADD COLUMN endpoint_canonical TEXT")
                conn.execute(
                    "UPDATE enrollments SET endpoint_canonical = endpoint_url"
                    " WHERE endpoint_canonical IS NULL"
                )
            # The bearer token the validator presents to this worker. Minted
            # once at enrollment and returned to the miner in that response,
            # so no operator has to transcribe a secret by hand. NULL for rows
            # written before this existed; those keep working from the
            # operator's token file, which still wins on lookup.
            if "worker_token" not in enrollment_columns:
                conn.execute("ALTER TABLE enrollments ADD COLUMN worker_token TEXT")
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS enrollments_endpoint_canonical_idx
                ON enrollments(endpoint_canonical)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS enrollments_coldkey_idx
                ON enrollments(coldkey)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attestations (
                    hotkey TEXT PRIMARY KEY,
                    chip_id TEXT,
                    tier TEXT,
                    verification_status TEXT NOT NULL,
                    last_verified_iso TEXT NOT NULL,
                    error TEXT,
                    assurance_json TEXT,
                    FOREIGN KEY(hotkey) REFERENCES enrollments(hotkey)
                )
                """
            )
            attestation_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(attestations)")
            }
            if "assurance_json" not in attestation_columns:
                conn.execute("ALTER TABLE attestations ADD COLUMN assurance_json TEXT")
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS attestations_chip_id_idx
                ON attestations(chip_id)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS enroll_nonces (
                    hotkey TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    used_at_iso TEXT NOT NULL,
                    PRIMARY KEY(hotkey, nonce)
                )
                """
            )
            nonce_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(enroll_nonces)")
            }
            # A digest of the exact signed bytes this nonce was spent on. A
            # retransmission is a retransmission of ONE request, so the match
            # has to cover every signed field. Comparing the endpoint alone let
            # a miner re-sign the same nonce and endpoint with a fresh
            # timestamp and take an uncharged trip through every gate. NULL on
            # rows written before this column, which are therefore never
            # treated as retransmissions.
            if "request_digest" not in nonce_columns:
                conn.execute("ALTER TABLE enroll_nonces ADD COLUMN request_digest TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS hotkey_enroll_attempts (
                    hotkey TEXT NOT NULL,
                    attempted_at_iso TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS hotkey_enroll_attempts_idx
                ON hotkey_enroll_attempts(hotkey, attempted_at_iso)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS worker_lifecycle_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hotkey TEXT NOT NULL REFERENCES enrollments(hotkey),
                    generation INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    from_state TEXT,
                    to_state TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    evidence_verified_at TEXT,
                    evidence_expires_at TEXT,
                    measurement TEXT,
                    evidence_digest TEXT,
                    policy_digest TEXT,
                    policy_registry_release INTEGER,
                    policy_registry_digest TEXT,
                    retry_count INTEGER NOT NULL,
                    next_retry_at TEXT,
                    operator_detail TEXT,
                    UNIQUE(hotkey, generation, revision)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS worker_lifecycle_current (
                    hotkey TEXT PRIMARY KEY REFERENCES enrollments(hotkey),
                    state TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    event_id INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    state_changed_at TEXT NOT NULL,
                    evidence_verified_at TEXT,
                    evidence_expires_at TEXT,
                    measurement TEXT,
                    evidence_digest TEXT,
                    policy_digest TEXT,
                    policy_registry_release INTEGER,
                    policy_registry_digest TEXT,
                    retry_count INTEGER NOT NULL,
                    next_retry_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS worker_lifecycle_events_no_update
                BEFORE UPDATE ON worker_lifecycle_events
                BEGIN
                    SELECT RAISE(ABORT, 'worker lifecycle events are append-only');
                END
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS worker_lifecycle_events_no_delete
                BEFORE DELETE ON worker_lifecycle_events
                BEGIN
                    SELECT RAISE(ABORT, 'worker lifecycle events are append-only');
                END
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS worker_lifecycle_due_idx
                ON worker_lifecycle_current(state, next_retry_at, evidence_expires_at)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS worker_lifecycle_clock (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    last_seen_at TEXT NOT NULL
                )
                """
            )
            self._backfill_lifecycle(conn)

    def _advance_lifecycle_clock(
        self, conn: sqlite3.Connection, when: datetime
    ) -> None:
        encoded = canonical_utc(when)
        row = conn.execute(
            "SELECT last_seen_at FROM worker_lifecycle_clock WHERE singleton = 1"
        ).fetchone()
        if row is None:
            latest = conn.execute(
                "SELECT MAX(state_changed_at) FROM worker_lifecycle_current"
            ).fetchone()[0]
            if isinstance(latest, str) and parse_utc(latest) > when:
                encoded = latest
            conn.execute(
                "INSERT INTO worker_lifecycle_clock(singleton, last_seen_at) VALUES (1, ?)",
                (encoded,),
            )
            if encoded != canonical_utc(when):
                raise LifecycleError("worker lifecycle clock moved backwards")
            return
        last_seen = parse_utc(row["last_seen_at"])
        if when < last_seen:
            raise LifecycleError("worker lifecycle clock moved backwards")
        if when > last_seen:
            conn.execute(
                "UPDATE worker_lifecycle_clock SET last_seen_at = ? WHERE singleton = 1",
                (encoded,),
            )

    def _backfill_lifecycle(self, conn: sqlite3.Connection) -> None:
        when = self._lifecycle_now()
        self._advance_lifecycle_clock(conn, when)
        rows = conn.execute(
            """
            SELECT e.hotkey, a.verification_status, a.last_verified_iso,
                   a.assurance_json
            FROM enrollments e
            LEFT JOIN attestations a ON a.hotkey = e.hotkey
            LEFT JOIN worker_lifecycle_current c ON c.hotkey = e.hotkey
            WHERE c.hotkey IS NULL
            ORDER BY e.hotkey
            """
        ).fetchall()
        for row in rows:
            state = WorkerLifecycleState.PENDING
            reason = LifecycleReason.BACKFILL_PENDING
            evidence_at = None
            expires_at = None
            evidence_digest = None
            policy_digest = None
            if row["verification_status"] == "VERIFIED":
                try:
                    evidence_at = _parse_iso_utc(row["last_verified_iso"])
                except (TypeError, ValueError):
                    state = WorkerLifecycleState.STALE
                    reason = LifecycleReason.BACKFILL_STALE
                else:
                    expires_at = evidence_at + timedelta(
                        seconds=self.verification_ttl_seconds
                    )
                    # Historical rows did not persist the exact measurement,
                    # so migration cannot prove current policy eligibility even
                    # when their old timestamp is still inside the TTL.
                    state = WorkerLifecycleState.STALE
                    reason = LifecycleReason.BACKFILL_STALE
                    assurance = self._stored_assurance(row["assurance_json"])
                    evidence_digest = assurance.hardware.evidence_digest
                    policy_digest = assurance.software.policy_digest
                    if not ATTESTATION_ADMISSION_POLICY.allows(assurance):
                        state = WorkerLifecycleState.FAILED
                        reason = LifecycleReason.VERIFICATION_FAILED
            elif row["verification_status"] is not None:
                state = WorkerLifecycleState.FAILED
                reason = LifecycleReason.VERIFICATION_FAILED
            self._insert_initial_lifecycle(
                conn,
                row["hotkey"],
                state,
                reason,
                when,
                evidence_verified_at=evidence_at,
                evidence_expires_at=expires_at,
                evidence_digest=evidence_digest,
                policy_digest=policy_digest,
            )

    def _insert_initial_lifecycle(
        self,
        conn: sqlite3.Connection,
        hotkey: str,
        state: WorkerLifecycleState,
        reason: LifecycleReason,
        when: datetime,
        *,
        evidence_verified_at: datetime | None = None,
        evidence_expires_at: datetime | None = None,
        evidence_digest: str | None = None,
        policy_digest: str | None = None,
    ) -> None:
        occurred = canonical_utc(when)
        evidence_text = (
            canonical_utc(evidence_verified_at)
            if evidence_verified_at is not None
            else None
        )
        expires_text = (
            canonical_utc(evidence_expires_at)
            if evidence_expires_at is not None
            else None
        )
        cursor = conn.execute(
            """
            INSERT INTO worker_lifecycle_events(
                hotkey, generation, revision, from_state, to_state, reason,
                occurred_at, evidence_verified_at, evidence_expires_at,
                measurement, evidence_digest, policy_digest,
                policy_registry_release, policy_registry_digest, retry_count,
                next_retry_at, operator_detail
            ) VALUES (?, 1, 1, NULL, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, NULL, 0, NULL, NULL)
            """,
            (
                hotkey,
                state.value,
                reason.value,
                occurred,
                evidence_text,
                expires_text,
                evidence_digest,
                policy_digest,
            ),
        )
        event_id = int(cursor.lastrowid)
        conn.execute(
            """
            INSERT INTO worker_lifecycle_current(
                hotkey, state, generation, revision, event_id, reason,
                state_changed_at, evidence_verified_at, evidence_expires_at,
                measurement, evidence_digest, policy_digest,
                policy_registry_release, policy_registry_digest, retry_count,
                next_retry_at
            ) VALUES (?, ?, 1, 1, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, NULL, 0, NULL)
            """,
            (
                hotkey,
                state.value,
                event_id,
                reason.value,
                occurred,
                evidence_text,
                expires_text,
                evidence_digest,
                policy_digest,
            ),
        )

    @staticmethod
    def _lifecycle_snapshot_from_row(row: sqlite3.Row) -> LifecycleSnapshot:
        try:
            return LifecycleSnapshot(
                hotkey=row["hotkey"],
                state=WorkerLifecycleState(row["state"]),
                generation=int(row["generation"]),
                revision=int(row["revision"]),
                event_id=int(row["event_id"]),
                reason=LifecycleReason(row["reason"]),
                state_changed_at=parse_utc(row["state_changed_at"]),
                evidence_verified_at=(
                    parse_utc(row["evidence_verified_at"])
                    if row["evidence_verified_at"] is not None
                    else None
                ),
                evidence_expires_at=(
                    parse_utc(row["evidence_expires_at"])
                    if row["evidence_expires_at"] is not None
                    else None
                ),
                measurement=row["measurement"],
                evidence_digest=row["evidence_digest"],
                policy_digest=row["policy_digest"],
                policy_registry_release=row["policy_registry_release"],
                policy_registry_digest=row["policy_registry_digest"],
                retry_count=int(row["retry_count"]),
                next_retry_at=(
                    parse_utc(row["next_retry_at"])
                    if row["next_retry_at"] is not None
                    else None
                ),
            )
        except (KeyError, TypeError, ValueError, LifecycleError) as exc:
            raise LifecycleError("persisted worker lifecycle state is invalid") from exc

    def _lifecycle_row(
        self, conn: sqlite3.Connection, hotkey: str
    ) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM worker_lifecycle_current WHERE hotkey = ?", (hotkey,)
        ).fetchone()
        if row is None:
            raise LifecycleError(f"worker {hotkey!r} has no lifecycle state")
        return row

    def _transition_lifecycle_in_connection(
        self,
        conn: sqlite3.Connection,
        hotkey: str,
        target: WorkerLifecycleState,
        reason: LifecycleReason,
        when: datetime,
        *,
        evidence_verified_at: datetime | None = None,
        evidence_expires_at: datetime | None = None,
        measurement: str | None = None,
        evidence_digest: str | None = None,
        policy_digest: str | None = None,
        policy_registry_release: int | None = None,
        policy_registry_digest: str | None = None,
        retry_count: int | None = None,
        next_retry_at: datetime | None = None,
        operator_detail: str | None = None,
        expected_generation: int | None = None,
        expected_revision: int | None = None,
        inherit_policy_registry: bool = True,
    ) -> LifecycleSnapshot:
        if not isinstance(target, WorkerLifecycleState) or not isinstance(
            reason, LifecycleReason
        ):
            raise LifecycleError("worker lifecycle transition metadata is invalid")
        for value in (expected_generation, expected_revision):
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
            ):
                raise LifecycleError("worker lifecycle expectation is invalid")
        if (policy_registry_release is None) != (policy_registry_digest is None):
            raise LifecycleError(
                "worker lifecycle policy registry reference is invalid"
            )
        self._advance_lifecycle_clock(conn, when)
        current = self._lifecycle_snapshot_from_row(
            self._lifecycle_row(conn, hotkey)
        )
        if expected_generation is not None and current.generation != expected_generation:
            raise LifecycleError("worker lifecycle generation changed")
        if expected_revision is not None and current.revision != expected_revision:
            raise LifecycleError("worker lifecycle revision changed")
        if when < current.state_changed_at:
            raise LifecycleError("worker lifecycle transition time moved backwards")
        require_transition(current.state, target)
        require_transition_reason(target, reason)
        verified_at = (
            evidence_verified_at
            if evidence_verified_at is not None
            else current.evidence_verified_at
        )
        expires_at = (
            evidence_expires_at
            if evidence_expires_at is not None
            else current.evidence_expires_at
        )
        chosen_measurement = measurement if measurement is not None else current.measurement
        chosen_evidence = (
            evidence_digest if evidence_digest is not None else current.evidence_digest
        )
        chosen_policy = policy_digest if policy_digest is not None else current.policy_digest
        if inherit_policy_registry and policy_registry_release is None:
            chosen_release = current.policy_registry_release
            chosen_registry_digest = current.policy_registry_digest
        else:
            chosen_release = policy_registry_release
            chosen_registry_digest = policy_registry_digest
        retries = current.retry_count if retry_count is None else retry_count
        if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:
            raise LifecycleError("worker lifecycle retry count is invalid")
        if target is WorkerLifecycleState.ATTESTED:
            if (
                verified_at is None
                or expires_at is None
                or verified_at > when
                or expires_at <= when
                or not isinstance(chosen_measurement, str)
                or not chosen_measurement
                or not isinstance(chosen_evidence, str)
                or not isinstance(chosen_policy, str)
            ):
                raise LifecycleError("attested lifecycle state requires fresh evidence")
            if reason is LifecycleReason.ATTESTATION_VERIFIED:
                retries = 0
                next_retry_at = None
        if target in TERMINAL_STATES or target is WorkerLifecycleState.FAILED:
            next_retry_at = None
        if next_retry_at is not None and next_retry_at < when:
            raise LifecycleError("worker lifecycle retry cannot be scheduled in the past")
        detail = operator_detail.strip()[:300] if isinstance(operator_detail, str) else None
        revision = current.revision + 1
        occurred = canonical_utc(when)
        values = {
            "hotkey": hotkey,
            "generation": current.generation,
            "revision": revision,
            "from_state": current.state.value,
            "to_state": target.value,
            "reason": reason.value,
            "occurred_at": occurred,
            "evidence_verified_at": canonical_utc(verified_at) if verified_at else None,
            "evidence_expires_at": canonical_utc(expires_at) if expires_at else None,
            "measurement": chosen_measurement,
            "evidence_digest": chosen_evidence,
            "policy_digest": chosen_policy,
            "policy_registry_release": chosen_release,
            "policy_registry_digest": chosen_registry_digest,
            "retry_count": retries,
            "next_retry_at": canonical_utc(next_retry_at) if next_retry_at else None,
            "operator_detail": detail,
        }
        cursor = conn.execute(
            """
            INSERT INTO worker_lifecycle_events(
                hotkey, generation, revision, from_state, to_state, reason,
                occurred_at, evidence_verified_at, evidence_expires_at,
                measurement, evidence_digest, policy_digest,
                policy_registry_release, policy_registry_digest, retry_count,
                next_retry_at, operator_detail
            ) VALUES (
                :hotkey, :generation, :revision, :from_state, :to_state, :reason,
                :occurred_at, :evidence_verified_at, :evidence_expires_at,
                :measurement, :evidence_digest, :policy_digest,
                :policy_registry_release, :policy_registry_digest, :retry_count,
                :next_retry_at, :operator_detail
            )
            """,
            values,
        )
        event_id = int(cursor.lastrowid)
        updated = conn.execute(
            """
            UPDATE worker_lifecycle_current SET
                state=:to_state, revision=:revision, event_id=:event_id,
                reason=:reason, state_changed_at=:occurred_at,
                evidence_verified_at=:evidence_verified_at,
                evidence_expires_at=:evidence_expires_at,
                measurement=:measurement, evidence_digest=:evidence_digest,
                policy_digest=:policy_digest,
                policy_registry_release=:policy_registry_release,
                policy_registry_digest=:policy_registry_digest,
                retry_count=:retry_count, next_retry_at=:next_retry_at
            WHERE hotkey=:hotkey AND generation=:generation
              AND revision=:prior_revision
            """,
            {**values, "event_id": event_id, "prior_revision": current.revision},
        )
        if updated.rowcount != 1:
            raise LifecycleError("concurrent worker lifecycle transition rejected")
        return self._lifecycle_snapshot_from_row(
            self._lifecycle_row(conn, hotkey)
        )

    def transition_lifecycle(
        self,
        hotkey: str,
        target: WorkerLifecycleState,
        reason: LifecycleReason,
        *,
        at: datetime | None = None,
        expected_generation: int | None = None,
        expected_revision: int | None = None,
        operator_detail: str | None = None,
    ) -> LifecycleSnapshot:
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            return self._transition_lifecycle_in_connection(
                conn,
                hotkey,
                target,
                reason,
                when,
                expected_generation=expected_generation,
                expected_revision=expected_revision,
                operator_detail=operator_detail,
            )

    def _materialize_expiry_in_connection(
        self, conn: sqlite3.Connection, hotkey: str, when: datetime
    ) -> LifecycleSnapshot:
        current = self._lifecycle_snapshot_from_row(
            self._lifecycle_row(conn, hotkey)
        )
        if (
            current.state is WorkerLifecycleState.ATTESTED
            and current.evidence_expires_at is not None
            and when >= current.evidence_expires_at
        ):
            return self._transition_lifecycle_in_connection(
                conn,
                hotkey,
                WorkerLifecycleState.STALE,
                LifecycleReason.EVIDENCE_EXPIRED,
                when,
                expected_generation=current.generation,
                expected_revision=current.revision,
            )
        return current

    def lifecycle_snapshot(
        self,
        hotkey: str,
        *,
        at: datetime | None = None,
        materialize_freshness: bool = True,
    ) -> LifecycleSnapshot:
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            self._advance_lifecycle_clock(conn, when)
            if materialize_freshness:
                return self._materialize_expiry_in_connection(conn, hotkey, when)
            return self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )

    def verified_attestation_record(self, hotkey: str) -> VerifiedAttestationRecord:
        """Return the exact verifier result on record, never caller-supplied claims."""

        with self._connect() as conn:
            row = conn.execute(
                "SELECT hotkey,chip_id,tier,verification_status,assurance_json "
                "FROM attestations WHERE hotkey=?",
                (hotkey,),
            ).fetchone()
        if (
            row is None
            or row["verification_status"] != "VERIFIED"
            or not isinstance(row["chip_id"], str)
            or not row["chip_id"]
            or not isinstance(row["tier"], str)
            or not row["tier"]
        ):
            raise LifecycleError("verified attestation record is unavailable")
        assurance = self._stored_assurance(row["assurance_json"])
        if not ATTESTATION_ADMISSION_POLICY.allows(assurance):
            raise LifecycleError("verified attestation record is unavailable")
        return VerifiedAttestationRecord(
            hotkey=row["hotkey"],
            chip_id=row["chip_id"],
            tier=row["tier"],
            assurance=assurance,
        )

    def record_attested_lifecycle(
        self,
        hotkey: str,
        attested: Attested,
        *,
        at: datetime | None = None,
        policy_registry_release: int | None = None,
        policy_registry_digest: str | None = None,
        expected_generation: int | None = None,
        expected_revision: int | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> LifecycleSnapshot:
        if not ATTESTATION_ADMISSION_POLICY.allows(attested.assurance):
            raise LifecycleError("attested lifecycle update requires typed admission claims")
        assert attested.assurance is not None
        verified_raw = attested.assurance.hardware.verified_at
        if not isinstance(verified_raw, str):
            raise LifecycleError("attested lifecycle update requires verification time")
        verified_at = _parse_iso_utc(verified_raw)
        expires_at = verified_at + timedelta(seconds=self.verification_ttl_seconds)

        def apply(conn: sqlite3.Connection, when: datetime) -> LifecycleSnapshot:
            if expires_at <= when:
                raise LifecycleError("attested lifecycle update evidence is already stale")
            return self._transition_lifecycle_in_connection(
                conn,
                hotkey,
                WorkerLifecycleState.ATTESTED,
                LifecycleReason.ATTESTATION_VERIFIED,
                when,
                evidence_verified_at=verified_at,
                evidence_expires_at=expires_at,
                measurement=attested.measurement,
                evidence_digest=attested.assurance.hardware.evidence_digest,
                policy_digest=attested.assurance.software.policy_digest,
                policy_registry_release=policy_registry_release,
                policy_registry_digest=policy_registry_digest,
                retry_count=0,
                expected_generation=expected_generation,
                expected_revision=expected_revision,
                inherit_policy_registry=False,
            )

        if connection is not None:
            return apply(connection, at or self._lifecycle_now())
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            return apply(conn, when)

    def record_refresh_failure(
        self,
        hotkey: str,
        *,
        attempt: int,
        maximum_attempts: int,
        at: datetime | None = None,
        retry_base_seconds: int = 5,
        retry_maximum_seconds: int = 300,
        retry_jitter_seconds: int = 5,
        operator_detail: str | None = None,
        expected_generation: int | None = None,
        expected_revision: int | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> LifecycleSnapshot:
        if (
            isinstance(attempt, bool)
            or not isinstance(attempt, int)
            or isinstance(maximum_attempts, bool)
            or not isinstance(maximum_attempts, int)
            or not 1 <= attempt <= maximum_attempts <= 32
        ):
            raise LifecycleError("worker lifecycle retry attempt is invalid")

        def apply(conn: sqlite3.Connection, when: datetime) -> LifecycleSnapshot:
            self._advance_lifecycle_clock(conn, when)
            current = self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )
            if expected_generation is not None and current.generation != expected_generation:
                raise LifecycleError("worker lifecycle generation changed")
            if expected_revision is not None and current.revision != expected_revision:
                raise LifecycleError("worker lifecycle revision changed")
            if current.state in TERMINAL_STATES or current.state in {
                WorkerLifecycleState.RETIRING,
                WorkerLifecycleState.FAILED,
            }:
                return current
            exhausted = attempt == maximum_attempts
            if exhausted:
                target = WorkerLifecycleState.FAILED
                reason = LifecycleReason.RETRY_EXHAUSTED
                next_retry = None
            else:
                if (
                    current.state is WorkerLifecycleState.ATTESTED
                    and current.evidence_expires_at is not None
                    and when < current.evidence_expires_at
                ):
                    target = WorkerLifecycleState.ATTESTED
                elif current.state is WorkerLifecycleState.PENDING:
                    target = WorkerLifecycleState.PENDING
                else:
                    target = WorkerLifecycleState.STALE
                reason = LifecycleReason.REFRESH_RETRY
                next_retry = when + timedelta(
                    seconds=retry_delay_seconds(
                        hotkey,
                        current.generation,
                        attempt,
                        base_seconds=retry_base_seconds,
                        maximum_seconds=retry_maximum_seconds,
                        jitter_seconds=retry_jitter_seconds,
                    )
                )
            return self._transition_lifecycle_in_connection(
                conn,
                hotkey,
                target,
                reason,
                when,
                retry_count=attempt,
                next_retry_at=next_retry,
                operator_detail=operator_detail,
                expected_generation=expected_generation,
                expected_revision=expected_revision,
            )

        if connection is not None:
            return apply(connection, at or self._lifecycle_now())
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            return apply(conn, when)

    def due_refreshes(
        self,
        *,
        at: datetime | None = None,
        refresh_ahead_seconds: int = 60,
    ) -> tuple[LifecycleSnapshot, ...]:
        if (
            isinstance(refresh_ahead_seconds, bool)
            or not isinstance(refresh_ahead_seconds, int)
            or refresh_ahead_seconds < 0
        ):
            raise LifecycleError("refresh-ahead window is invalid")
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            horizon = when + timedelta(seconds=refresh_ahead_seconds)
            self._advance_lifecycle_clock(conn, when)
            rows = conn.execute(
                "SELECT hotkey FROM worker_lifecycle_current ORDER BY hotkey"
            ).fetchall()
            snapshots = [
                self._materialize_expiry_in_connection(conn, row["hotkey"], when)
                for row in rows
            ]
            return tuple(
                snapshot
                for snapshot in snapshots
                if snapshot.state in NETWORK_ELIGIBLE_STATES
                and (
                    snapshot.next_retry_at is None
                    or snapshot.next_retry_at <= when
                )
                and (
                    snapshot.evidence_expires_at is None
                    or snapshot.evidence_expires_at <= horizon
                )
            )

    def apply_lifecycle_policy(
        self,
        allowed_measurements: set[str] | frozenset[str],
        *,
        at: datetime | None = None,
        policy_registry_release: int | None = None,
        policy_registry_digest: str | None = None,
    ) -> tuple[LifecycleSnapshot, ...]:
        if (
            not isinstance(allowed_measurements, (set, frozenset))
            or any(
                not isinstance(measurement, str) or not measurement
                for measurement in allowed_measurements
            )
        ):
            raise LifecycleError("lifecycle measurement policy is invalid")
        revoked: list[LifecycleSnapshot] = []
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            self._advance_lifecycle_clock(conn, when)
            rows = conn.execute(
                "SELECT * FROM worker_lifecycle_current ORDER BY hotkey"
            ).fetchall()
            for row in rows:
                current = self._lifecycle_snapshot_from_row(row)
                if (
                    current.state in NETWORK_ELIGIBLE_STATES
                    and current.measurement is not None
                    and current.measurement not in allowed_measurements
                ):
                    revoked.append(
                        self._transition_lifecycle_in_connection(
                            conn,
                            current.hotkey,
                            WorkerLifecycleState.REVOKED,
                            LifecycleReason.POLICY_REVOKED,
                            when,
                            policy_registry_release=policy_registry_release,
                            policy_registry_digest=policy_registry_digest,
                            expected_generation=current.generation,
                            expected_revision=current.revision,
                        )
                    )
        return tuple(revoked)

    def reenroll_lifecycle(
        self,
        hotkey: str,
        *,
        reason: LifecycleReason = LifecycleReason.REENROLLED,
        at: datetime | None = None,
        connection: sqlite3.Connection | None = None,
        operator: bool = False,
    ) -> LifecycleSnapshot:
        """Return a worker to PENDING.

        `operator=True` is required to bring a TERMINAL worker back, and defaults
        to False so any caller that has not thought about it fails closed.

        docs/LIFECYCLE.md: "failed, retired, and revoked do not resume
        automatically. Recovery requires explicit reenrollment." This did an
        unguarded UPDATE ... SET state='pending', unlike record_verdict and
        retire_lifecycle which both check TERMINAL_STATES. `RegistryStore.enroll`
        calls it whenever the endpoint URL changes, and the endpoint is entirely
        miner-supplied -- so a revoked or retired miner could return itself to
        PENDING and to the refresh set by re-enrolling on a different PORT, with
        no operator action (#85).

        That matters most for an operator-retired worker that is still
        hardware-valid (it re-attests and is fully back, defeating
        retire-without-firewall) and for a GPU identity-conflict revoked
        claimant, which could otherwise re-queue itself against an identity
        another worker already holds.

        RETIRING is not in TERMINAL_STATES but must be refused the same way:
        it is operator intent to stop the worker (docs/LIFECYCLE.md), and a
        retirement the miner can lift by re-enrolling is not a retirement.

        Chip contention is deliberately not in that set. A duplicate or
        already-bound chip_id is refused rather than revoked (#138), so those
        claimants stay non-terminal and re-queue on their own -- the chip gates
        run again every epoch and still admit only one hotkey per chip.
        """
        if reason not in {LifecycleReason.REENROLLED, LifecycleReason.ENDPOINT_CHANGED}:
            raise LifecycleError("reenrollment lifecycle reason is invalid")
        def apply(conn: sqlite3.Connection, when: datetime) -> LifecycleSnapshot:
            self._advance_lifecycle_clock(conn, when)
            current = self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )
            if (
                current.state in TERMINAL_STATES
                or current.state is WorkerLifecycleState.RETIRING
            ) and not operator:
                raise LifecycleError(
                    f"worker {hotkey!r} is {current.state.value}; it "
                    "cannot re-enroll itself. Recovery is an operator action: "
                    "`cathedral lifecycle reenroll --hotkey <hotkey>`")
            generation = current.generation + 1
            occurred = canonical_utc(when)
            cursor = conn.execute(
                """
                INSERT INTO worker_lifecycle_events(
                    hotkey, generation, revision, from_state, to_state, reason,
                    occurred_at, evidence_verified_at, evidence_expires_at,
                    measurement, evidence_digest, policy_digest,
                    policy_registry_release, policy_registry_digest, retry_count,
                    next_retry_at, operator_detail
                ) VALUES (?, ?, 1, ?, 'pending', ?, ?, NULL, NULL, NULL, NULL,
                          NULL, NULL, NULL, 0, NULL, NULL)
                """,
                (hotkey, generation, current.state.value, reason.value, occurred),
            )
            event_id = int(cursor.lastrowid)
            conn.execute(
                """
                UPDATE worker_lifecycle_current SET
                    state='pending', generation=?, revision=1, event_id=?,
                    reason=?, state_changed_at=?, evidence_verified_at=NULL,
                    evidence_expires_at=NULL, measurement=NULL,
                    evidence_digest=NULL, policy_digest=NULL,
                    policy_registry_release=NULL, policy_registry_digest=NULL,
                    retry_count=0, next_retry_at=NULL
                WHERE hotkey=?
                """,
                (generation, event_id, reason.value, occurred, hotkey),
            )
            return self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )

        if connection is not None:
            return apply(connection, at or self._lifecycle_now())
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            return apply(conn, when)

    def retire_lifecycle(
        self,
        hotkey: str,
        *,
        removed: bool = False,
        at: datetime | None = None,
    ) -> LifecycleSnapshot:
        if not isinstance(removed, bool):
            raise LifecycleError("removed must be a boolean")
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            self._advance_lifecycle_clock(conn, when)
            current = self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )
            if current.state in TERMINAL_STATES:
                return current
            if current.state is not WorkerLifecycleState.RETIRING:
                current = self._transition_lifecycle_in_connection(
                    conn,
                    hotkey,
                    WorkerLifecycleState.RETIRING,
                    LifecycleReason.OPERATOR_RETIRING,
                    when,
                    expected_generation=current.generation,
                    expected_revision=current.revision,
                )
            if removed:
                current = self._transition_lifecycle_in_connection(
                    conn,
                    hotkey,
                    WorkerLifecycleState.RETIRED,
                    LifecycleReason.WORKER_REMOVED,
                    when,
                    expected_generation=current.generation,
                    expected_revision=current.revision,
                )
            return current

    def lifecycle_history(
        self, hotkey: str, *, operator: bool = False
    ) -> tuple[dict[str, object], ...]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM worker_lifecycle_events WHERE hotkey = ? "
                "ORDER BY event_id",
                (hotkey,),
            ).fetchall()
        history: list[dict[str, object]] = []
        for row in rows:
            event: dict[str, object] = {
                "generation": row["generation"],
                "from_state": row["from_state"],
                "to_state": row["to_state"],
                "reason": row["reason"],
                "occurred_at": row["occurred_at"],
            }
            if operator:
                event.update(
                    {
                        "event_id": row["event_id"],
                        "revision": row["revision"],
                        "evidence_verified_at": row["evidence_verified_at"],
                        "evidence_expires_at": row["evidence_expires_at"],
                        "measurement": row["measurement"],
                        "evidence_digest": row["evidence_digest"],
                        "policy_digest": row["policy_digest"],
                        "policy_registry_release": row["policy_registry_release"],
                        "policy_registry_digest": row["policy_registry_digest"],
                        "retry_count": row["retry_count"],
                        "next_retry_at": row["next_retry_at"],
                        "operator_detail": row["operator_detail"],
                    }
                )
            history.append(event)
        return tuple(history)

    def enroll(
        self,
        hotkey: str,
        endpoint_url: str,
        *,
        nonce: str | None = None,
        request_digest: str | None = None,
        coldkey: str | None = None,
        requested_profile_id: str | None = None,
        max_endpoints_per_coldkey: int | None = None,
        max_total_enrollments: int | None = None,
        unique_endpoint: bool = False,
        refuse_terminal: bool = False,
    ) -> None:
        """Write or refresh one pending enrollment, inside the caps.

        Every cap is evaluated in the same ``BEGIN IMMEDIATE`` transaction as
        the write, so two concurrent enrollments cannot both observe capacity
        and then both take it. A retry that re-enrolls the same hotkey at the
        same endpoint consumes no additional capacity and stays idempotent.

        Raises ``EnrollmentRejected`` when a cap would be exceeded or the
        endpoint is already claimed by a different live worker.
        """
        ts = now_iso()
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._enforce_enrollment_caps(
                conn,
                hotkey=hotkey,
                endpoint_url=endpoint_url,
                coldkey=coldkey,
                max_endpoints_per_coldkey=max_endpoints_per_coldkey,
                max_total_enrollments=max_total_enrollments,
                unique_endpoint=unique_endpoint,
                refuse_terminal=refuse_terminal,
            )
            lifecycle_when = self._lifecycle_now()
            if nonce is not None:
                try:
                    conn.execute(
                        """
                        INSERT INTO enroll_nonces(hotkey, nonce, used_at_iso, request_digest)
                        VALUES (?, ?, ?, ?)
                        """,
                        (hotkey, nonce, ts, request_digest),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ValueError("enroll nonce already used") from exc

            # Detect whether the endpoint is changing before the upsert so we
            # can clear any stale attestation verdict in the same transaction.
            prior = conn.execute(
                "SELECT endpoint_url FROM enrollments WHERE hotkey = ?", (hotkey,)
            ).fetchone()
            endpoint_changed = prior is not None and prior["endpoint_url"] != endpoint_url

            conn.execute(
                """
                INSERT INTO enrollments(
                    hotkey, endpoint_url, enrolled_at_iso, updated_at_iso,
                    coldkey, requested_profile_id, endpoint_canonical, worker_token
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hotkey) DO UPDATE SET
                    endpoint_url=excluded.endpoint_url,
                    updated_at_iso=excluded.updated_at_iso,
                    coldkey=COALESCE(excluded.coldkey, enrollments.coldkey),
                    requested_profile_id=COALESCE(
                        excluded.requested_profile_id, enrollments.requested_profile_id
                    ),
                    endpoint_canonical=excluded.endpoint_canonical,
                    worker_token=COALESCE(enrollments.worker_token, excluded.worker_token)
                """,
                (
                    hotkey,
                    endpoint_url,
                    ts,
                    ts,
                    coldkey,
                    requested_profile_id,
                    canonical_endpoint_key(endpoint_url),
                    generate_worker_token(),
                ),
            )

            # Changed endpoint: clear the old attestation so the miner returns
            # to PENDING and a fresh probe is required.  Same endpoint: leave
            # the existing verdict intact (idempotent refresh).
            if endpoint_changed:
                conn.execute("DELETE FROM attestations WHERE hotkey = ?", (hotkey,))
                self.reenroll_lifecycle(
                    hotkey,
                    reason=LifecycleReason.ENDPOINT_CHANGED,
                    at=lifecycle_when,
                    connection=conn,
                )
            elif prior is None:
                self._advance_lifecycle_clock(conn, lifecycle_when)
                self._insert_initial_lifecycle(
                    conn,
                    hotkey,
                    WorkerLifecycleState.PENDING,
                    LifecycleReason.ENROLLED,
                    lifecycle_when,
                )

    def _enforce_enrollment_caps(
        self,
        conn: sqlite3.Connection,
        *,
        hotkey: str,
        endpoint_url: str,
        coldkey: str | None,
        max_endpoints_per_coldkey: int | None,
        max_total_enrollments: int | None,
        unique_endpoint: bool,
        refuse_terminal: bool,
    ) -> None:
        """Refuse an enrollment that would exceed a cap or steal an endpoint.

        What consumes capacity is deliberate, because both directions are
        exploitable:

        - ``RETIRED`` does not. Retirement is the operator's own act of
          freeing capacity (``enroll reconcile --remove``).
        - ``FAILED`` does not. A failed worker is never probed again
          (``NETWORK_ELIGIBLE_STATES`` excludes it) and cannot legally return
          to ``PENDING``, so counting it would let anyone permanently exhaust
          a shared cap with junk enrollments that cost one registration each.
        - ``REVOKED`` **does**. Revocation is a punishment; freeing its slot
          would hand the owner a fresh one to retry from.
        - ``PENDING``, ``ATTESTED``, ``STALE``, and ``RETIRING`` do, because
          each is a worker the validator still owes work to.

        Every check is off by default. The legacy enrollment path predates
        these rules and is left exactly as it was; only a request governed by
        an admission policy opts in.
        """
        consuming = set(CAPACITY_CONSUMING_STATES)
        live = ", ".join(f"'{state.value}'" for state in sorted(consuming, key=lambda s: s.value))
        # A worker with no lifecycle row yet (legacy data) counts as live.
        live_join = f"""
            FROM enrollments e
            LEFT JOIN worker_lifecycle_current c ON c.hotkey = e.hotkey
            WHERE (c.state IS NULL OR c.state IN ({live}))
        """

        if refuse_terminal:
            row = conn.execute(
                "SELECT state FROM worker_lifecycle_current WHERE hotkey = ?", (hotkey,)
            ).fetchone()
            terminal = {state.value for state in TERMINAL_STATES}
            if row is not None and row["state"] in terminal:
                # reenroll_lifecycle writes 'pending' directly and never
                # consults ALLOWED_TRANSITIONS, so without this a revoked or
                # retired worker rehabilitates itself by re-enrolling into its
                # own row. It would not mint weight, since every attestation
                # gate re-runs, but it would undo a revocation and put the
                # worker back in the probe queue and on the public board.
                raise EnrollmentRejected(
                    "worker is in a terminal lifecycle state",
                    reason=f"lifecycle_{row['state']}",
                )
            if row is not None and row["state"] == WorkerLifecycleState.RETIRING.value:
                # RETIRING is operator intent, not a terminal state, but the
                # same rehabilitation-by-re-enroll hole applies: refuse it
                # here too so the policy path returns a structured 403
                # instead of reenroll_lifecycle's LifecycleError escaping as
                # an unhandled 500.
                raise EnrollmentRejected(
                    "worker is retiring; re-enrollment is an operator action",
                    reason="lifecycle_retiring",
                )

        canonical = canonical_endpoint_key(endpoint_url)
        if unique_endpoint:
            claimant = conn.execute(
                f"SELECT e.hotkey {live_join} AND e.endpoint_canonical = ? AND e.hotkey != ?",
                (canonical, hotkey),
            ).fetchone()
            if claimant is not None:
                # Pre-attestation proxy for one physical machine. True platform
                # uniqueness is the chip-id gate at admission; this only stops
                # two hotkeys queueing probes against the same address.
                raise EnrollmentRejected(
                    "endpoint is already enrolled by another worker",
                    reason="endpoint_claimed",
                )

        if max_endpoints_per_coldkey is not None and coldkey is not None:
            rows = conn.execute(
                f"SELECT DISTINCT e.endpoint_canonical {live_join}"
                " AND e.coldkey = ? AND e.hotkey != ?",
                (coldkey, hotkey),
            ).fetchall()
            # Counted on the normal form, so the cap bounds machines rather
            # than spellings of one machine.
            held = {row["endpoint_canonical"] for row in rows}
            if canonical not in held and len(held) >= max_endpoints_per_coldkey:
                raise EnrollmentRejected(
                    "coldkey has reached its enrolled endpoint cap",
                    reason="coldkey_endpoint_cap",
                )

        if max_total_enrollments is not None:
            existing = conn.execute(
                f"SELECT COUNT(*) AS total {live_join} AND e.hotkey != ?", (hotkey,)
            ).fetchone()["total"]
            if existing >= max_total_enrollments:
                raise EnrollmentRejected(
                    "the subnet has reached its worker cap",
                    reason="total_worker_cap",
                )

    def check_and_record_hotkey_attempt(
        self, hotkey: str, *, limit: int, window_seconds: int
    ) -> bool:
        """Return False (without recording) if the hotkey exceeds its enrollment
        rate within *window_seconds*. Return True and record the attempt otherwise.

        Backed by SQLite so the bound is durable across process restarts and
        applies consistently across all app instances sharing the same DB file.
        This prevents a miner controlling many valid self-owned hotkeys from
        flooding the probe queue with rapid re-enrollments.
        """
        ts = now_iso()
        cutoff = (
            datetime.now(UTC) - timedelta(seconds=window_seconds)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        with self._connect() as conn:
            count = conn.execute(
                """
                SELECT COUNT(*) FROM hotkey_enroll_attempts
                WHERE hotkey = ? AND attempted_at_iso >= ?
                """,
                (hotkey, cutoff),
            ).fetchone()[0]
            if count >= limit:
                return False
            conn.execute(
                "INSERT INTO hotkey_enroll_attempts(hotkey, attempted_at_iso) VALUES (?, ?)",
                (hotkey, ts),
            )
        return True

    def enrollments(self) -> list[Enrollment]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT hotkey, endpoint_url FROM enrollments ORDER BY updated_at_iso, hotkey"
            ).fetchall()
        return [Enrollment(row["hotkey"], row["endpoint_url"]) for row in rows]

    def is_completed_enrollment(self, hotkey: str, nonce: str, request_digest: str) -> bool:
        """True when this exact signed request has already been completed.

        A retransmission is a signed request whose ``(hotkey, nonce)`` pair is
        already recorded AND whose endpoint still matches what is enrolled. The
        caller uses this to avoid charging the durable per-hotkey limiter for a
        request the miner already paid for; the replay itself is still refused.

        The endpoint match is what keeps this narrow. A miner that signs a
        *different* endpoint under an already-used nonce is not retransmitting,
        and is charged and refused exactly as before.
        """
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT request_digest FROM enroll_nonces
                WHERE hotkey = ? AND nonce = ?
                """,
                (hotkey, nonce),
            ).fetchone()
        return row is not None and row["request_digest"] == request_digest

    def worker_token(self, hotkey: str) -> str | None:
        """Return the bearer token minted for *hotkey* at enrollment.

        None for a hotkey that is not enrolled, and for rows written before
        the column existed. Both cases fall back to the operator's token file,
        so an existing deployment keeps working untouched.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT worker_token FROM enrollments WHERE hotkey = ?", (hotkey,)
            ).fetchone()
        if row is None:
            return None
        token = row["worker_token"]
        return token if _valid_worker_token(token) else None

    def remove_enrollment(self, hotkey: str) -> None:
        """Retire *hotkey* and clear its published attestation verdict.

        The worker lifecycle event ledger is append-only (delete triggers)
        and its rows are foreign-key children of ``enrollments``, so a
        physical enrollment-row delete is impossible by design. Terminal
        retirement plus verdict removal is the strongest removal the schema
        allows: the worker leaves the refresh set, the epoch target list,
        and the public verified count, while the audit trail survives.
        """
        self.retire_lifecycle(hotkey, removed=True)
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("DELETE FROM attestations WHERE hotkey = ?", (hotkey,))

    def record_probe_failure(
        self,
        hotkey: str,
        *,
        error: str | None = None,
        expected_generation: int | None = None,
        expected_revision: int | None = None,
        maximum_attempts: int = 3,
        retry_base_seconds: int = 5,
        retry_maximum_seconds: int = 300,
        retry_jitter_seconds: int = 5,
    ) -> LifecycleSnapshot:
        """Record a transient probe failure without bypassing bounded retries."""
        if (
            isinstance(maximum_attempts, bool)
            or not isinstance(maximum_attempts, int)
            or not 1 <= maximum_attempts <= 32
            or isinstance(retry_base_seconds, bool)
            or not isinstance(retry_base_seconds, int)
            or isinstance(retry_maximum_seconds, bool)
            or not isinstance(retry_maximum_seconds, int)
            or not 1 <= retry_base_seconds <= retry_maximum_seconds <= 86400
            or isinstance(retry_jitter_seconds, bool)
            or not isinstance(retry_jitter_seconds, int)
            or not 0 <= retry_jitter_seconds <= retry_maximum_seconds
        ):
            raise LifecycleError("worker lifecycle retry policy is invalid")
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            lifecycle_when = self._lifecycle_now()
            current = self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )
            attempt = min(current.retry_count + 1, maximum_attempts)
            conn.execute(
                """
                INSERT INTO attestations(
                    hotkey, chip_id, tier, verification_status, last_verified_iso,
                    error, assurance_json
                ) VALUES (?, NULL, NULL, 'FAILED', ?, ?, NULL)
                ON CONFLICT(hotkey) DO UPDATE SET
                    chip_id=NULL, tier=NULL, verification_status='FAILED',
                    last_verified_iso=excluded.last_verified_iso,
                    error=excluded.error, assurance_json=NULL
                """,
                (hotkey, now_iso(), error),
            )
            return self.record_refresh_failure(
                hotkey,
                attempt=attempt,
                maximum_attempts=maximum_attempts,
                at=lifecycle_when,
                retry_base_seconds=retry_base_seconds,
                retry_maximum_seconds=retry_maximum_seconds,
                retry_jitter_seconds=retry_jitter_seconds,
                operator_detail=error,
                expected_generation=(
                    current.generation
                    if expected_generation is None
                    else expected_generation
                ),
                expected_revision=(
                    current.revision
                    if expected_revision is None
                    else expected_revision
                ),
                connection=conn,
            )

    def record_verdict(
        self,
        hotkey: str,
        attested: Attested | None,
        *,
        error: str | None = None,
        expected_generation: int | None = None,
        expected_revision: int | None = None,
        policy_registry_release: int | None = None,
        policy_registry_digest: str | None = None,
        gpu_profile_valid_from: datetime | None = None,
        gpu_profile_valid_until: datetime | None = None,
        gpu_profile_registry_release: int | None = None,
        gpu_profile_registry_digest: str | None = None,
    ) -> None:
        gpu_profile_values = (
            gpu_profile_valid_from,
            gpu_profile_valid_until,
            gpu_profile_registry_release,
            gpu_profile_registry_digest,
        )
        if any(value is not None for value in gpu_profile_values):
            if any(value is None for value in gpu_profile_values):
                raise LifecycleError("GPU profile commit authority is incomplete")
            assert gpu_profile_valid_from is not None
            assert gpu_profile_valid_until is not None
            if (
                not isinstance(gpu_profile_valid_from, datetime)
                or not isinstance(gpu_profile_valid_until, datetime)
                or gpu_profile_valid_from.tzinfo is None
                or gpu_profile_valid_from.utcoffset() != timedelta(0)
                or gpu_profile_valid_until.tzinfo is None
                or gpu_profile_valid_until.utcoffset() != timedelta(0)
                or gpu_profile_valid_from >= gpu_profile_valid_until
                or isinstance(gpu_profile_registry_release, bool)
                or not isinstance(gpu_profile_registry_release, int)
                or gpu_profile_registry_release <= 0
                or not isinstance(gpu_profile_registry_digest, str)
                or re.fullmatch(
                    r"sha256:[0-9a-f]{64}", gpu_profile_registry_digest
                )
                is None
            ):
                raise LifecycleError("GPU profile commit authority is invalid")
        ts = now_iso()
        if attested is None:
            status = "FAILED"
            chip_id = None
            tier = None
            assurance_json = None
        else:
            status = attested.verification_status
            chip_id = attested.chip_id
            tier = attested.tier.value
            assurance_json = (
                json.dumps(
                    attested.assurance.to_dict(),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if attested.assurance is not None
                else None
            )
        if status == "VERIFIED" and not ATTESTATION_ADMISSION_POLICY.allows(
            attested.assurance if attested is not None else None
        ):
            status = "FAILED"
            chip_id = None
            tier = None
            error = "typed hardware and software assurance claims are required"
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            lifecycle_when = self._lifecycle_now()
            if any(value is not None for value in gpu_profile_values) and (
                status != "VERIFIED"
                or not gpu_profile_valid_from <= lifecycle_when < gpu_profile_valid_until
                or policy_registry_release != gpu_profile_registry_release
                or policy_registry_digest != gpu_profile_registry_digest
            ):
                raise LifecycleError(
                    "GPU profile is not active at lifecycle commit time"
                )
            if status == "VERIFIED" and chip_id is not None:
                conflict = self._chip_rotation_owner(conn, chip_id, hotkey)
                if conflict is not None:
                    # Refuse the verdict so a live chip binding stays with one
                    # hotkey, but treat it as an ordinary verification failure
                    # rather than an identity conflict. Contention for a chip_id
                    # is not proof of misuse: the PPID it derives from names a
                    # physical host shared by co-resident cloud guests (#138).
                    status = "FAILED"
                    chip_id = None
                    tier = None
                    error = f"chip_id already bound to hotkey {conflict}"
            conn.execute(
                """
                INSERT INTO attestations(
                    hotkey, chip_id, tier, verification_status, last_verified_iso, error,
                    assurance_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hotkey) DO UPDATE SET
                    chip_id=excluded.chip_id,
                    tier=excluded.tier,
                    verification_status=excluded.verification_status,
                    last_verified_iso=excluded.last_verified_iso,
                    error=excluded.error,
                    assurance_json=excluded.assurance_json
                """,
                (hotkey, chip_id, tier, status, ts, error, assurance_json),
            )
            current = self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )
            if status == "VERIFIED" and attested is not None:
                self.record_attested_lifecycle(
                    hotkey,
                    attested,
                    at=lifecycle_when,
                    expected_generation=(
                        current.generation
                        if expected_generation is None
                        else expected_generation
                    ),
                    expected_revision=(
                        current.revision
                        if expected_revision is None
                        else expected_revision
                    ),
                    policy_registry_release=policy_registry_release,
                    policy_registry_digest=policy_registry_digest,
                    connection=conn,
                )
            elif current.state not in TERMINAL_STATES and current.state is not WorkerLifecycleState.RETIRING:
                self._transition_lifecycle_in_connection(
                    conn,
                    hotkey,
                    WorkerLifecycleState.FAILED,
                    LifecycleReason.VERIFICATION_FAILED,
                    lifecycle_when,
                    operator_detail=error,
                    expected_generation=(
                        current.generation
                        if expected_generation is None
                        else expected_generation
                    ),
                    expected_revision=(
                        current.revision
                        if expected_revision is None
                        else expected_revision
                    ),
                )

    def chip_rotation_owner(self, chip_id: str, hotkey: str) -> str | None:
        """Return the other hotkey currently holding an effective VERIFIED

        binding for ``chip_id``, if any. Callers use this to reject a fresh
        attestation as a same-chip rotation Sybil attempt before admitting
        or scoring it, independent of whether ``record_verdict`` has run for
        this epoch yet.
        """
        with self._connect() as conn:
            return self._chip_rotation_owner(conn, chip_id, hotkey)

    def _chip_rotation_owner(
        self, conn: sqlite3.Connection, chip_id: str, hotkey: str
    ) -> str | None:
        existing = conn.execute(
            """
            SELECT hotkey, last_verified_iso FROM attestations
            WHERE chip_id = ?
              AND hotkey != ?
              AND verification_status = 'VERIFIED'
            ORDER BY last_verified_iso DESC
            LIMIT 1
            """,
            (chip_id, hotkey),
        ).fetchone()
        if existing is None:
            return None
        # Only block rotation when the competing binding is still effective
        # (within TTL). An expired/STALE binding allows a new hotkey to
        # legitimately claim the same physical chip after the previous
        # operator's verification has lapsed.
        now = datetime.now(UTC)
        effective = self._effective_status("VERIFIED", existing["last_verified_iso"], now)
        return existing["hotkey"] if effective == "VERIFIED" else None

    def _effective_status(self, status: str, last_verified_iso: str | None, now: datetime) -> str:
        if status != "VERIFIED":
            return status
        if last_verified_iso is None:
            return "STALE"
        try:
            verified_at = _parse_iso_utc(last_verified_iso)
        except ValueError:
            return "STALE"
        cutoff = now - timedelta(seconds=self.verification_ttl_seconds)
        if verified_at <= cutoff:
            return "STALE"
        return "VERIFIED"

    def board(self) -> dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    e.hotkey,
                    a.chip_id,
                    a.tier,
                    COALESCE(a.verification_status, 'PENDING') AS verification_status,
                    a.last_verified_iso,
                    a.assurance_json
                FROM enrollments e
                LEFT JOIN attestations a ON a.hotkey = e.hotkey
                ORDER BY e.updated_at_iso, e.hotkey
                """
            ).fetchall()

        miners = []
        verified_chips: set[str] = set()
        for row in rows:
            now = self._lifecycle_now()
            chip_id = row["chip_id"]
            tier = row["tier"]
            assurance = self._stored_assurance(row["assurance_json"])
            status = self._effective_status(
                row["verification_status"],
                row["last_verified_iso"],
                now,
            )
            lifecycle = self.lifecycle_snapshot(row["hotkey"])
            if status == "VERIFIED" and not ATTESTATION_ADMISSION_POLICY.allows(
                assurance
            ):
                status = "FAILED"
                chip_id = None
                tier = None
            if status == "VERIFIED" and chip_id is not None:
                verified_chips.add(chip_id)
            miners.append(
                {
                    "hotkey": row["hotkey"],
                    "chip_id_prefix": chip_id[:16] if chip_id else None,
                    "tier": tier,
                    "verification_status": status,
                    "last_verified_iso": row["last_verified_iso"],
                    "assurance": assurance.to_dict(include_digests=False),
                    "lifecycle": lifecycle.public_dict(),
                }
            )
        return {"count": len(verified_chips), "miners": miners}

    @staticmethod
    def _stored_assurance(raw: str | None) -> AssuranceClaims:
        claims = empty_assurance_claims()
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    claims = assurance_from_dict(parsed)
            except (json.JSONDecodeError, ValueError):
                pass
        return claims


class IpRateLimiter:
    def __init__(self, *, limit: int = 10, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        hits = self._hits[ip]
        cutoff = now - self.window_seconds
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True


class RegistryApp:
    def __init__(
        self,
        store: RegistryStore,
        limiter: IpRateLimiter | None = None,
        *,
        enroll_signature_ttl_seconds: int | None = None,
        registration_provider: object | None = None,
        coldkey_allowlist: object | None = None,
        admission_policy: object | None = None,
        production_mode: bool = False,
        trusted_proxy: bool = False,
        hotkey_enroll_limit: int = DEFAULT_HOTKEY_ENROLL_LIMIT,
        hotkey_enroll_window_seconds: int = DEFAULT_HOTKEY_ENROLL_WINDOW_SECONDS,
    ) -> None:
        self.store = store
        self.limiter = limiter if limiter is not None else IpRateLimiter()
        if enroll_signature_ttl_seconds is None:
            enroll_signature_ttl_seconds = _positive_int_from_env(
                ENROLL_SIGNATURE_TTL_ENV,
                DEFAULT_ENROLL_SIGNATURE_TTL_SECONDS,
            )
        if enroll_signature_ttl_seconds <= 0:
            raise ValueError("enroll_signature_ttl_seconds must be positive")
        self.enroll_signature_ttl_seconds = enroll_signature_ttl_seconds
        # Subnet registration gate — injectable so tests can pass stubs without
        # a live chain connection. See RegistrationProvider protocol above.
        self.registration_provider = registration_provider
        # Approved-coldkey gate: any object exposing
        # ``is_allowed(coldkey) -> bool | None`` (None fails closed), normally
        # a SignedColdkeyAllowlistProvider. When None in production_mode, all
        # enrollment is rejected; when None outside production_mode, the gate
        # is inactive so tests and SN292 development flows keep the current
        # open behavior.
        self.coldkey_allowlist = coldkey_allowlist
        # Signed admission policy (cathedral_admission_policy_v1): any object
        # exposing ``load() -> snapshot | None``. When configured it replaces
        # the standalone allowlist entirely and requires v2 enrollment
        # requests; the two cannot be configured together, because a service
        # answering to two approval artifacts has no single answer to "who is
        # approved right now".
        if admission_policy is not None and coldkey_allowlist is not None:
            raise ValueError(
                "configure either an admission policy or a coldkey allowlist, not both"
            )
        self.admission_policy = admission_policy
        # When True, enrollments are rejected if registration cannot be
        # confirmed even when no provider is configured.
        self.production_mode = production_mode
        # When False (default), HTTP_X_FORWARDED_FOR is ignored and rate
        # limiting uses REMOTE_ADDR only.  Set True only when the app runs
        # behind a reverse proxy that sets the header reliably.
        self.trusted_proxy = trusted_proxy
        self.hotkey_enroll_limit = hotkey_enroll_limit
        self.hotkey_enroll_window_seconds = hotkey_enroll_window_seconds

    def __call__(self, environ: dict[str, Any], start_response: Any) -> list[bytes]:
        try:
            method = environ.get("REQUEST_METHOD", "GET")
            path = environ.get("PATH_INFO", "")
            if method == "POST" and path == "/v1/enroll":
                return self._enroll(environ, start_response)
            if method == "GET" and path == "/v1/attested":
                return self._json(start_response, 200, self.store.board())
            return self._json(start_response, 404, {"error": "not found"})
        except ValueError as exc:
            return self._json(start_response, 400, {"error": str(exc)})
        except json.JSONDecodeError:
            return self._json(start_response, 400, {"error": "invalid json"})

    def _enroll(self, environ: dict[str, Any], start_response: Any) -> list[bytes]:
        # Never trust X-Forwarded-For unless the app is explicitly configured to
        # run behind a trusted reverse proxy.  A spoofed header lets any client
        # pick an arbitrary source IP and bypass the per-address rate limit.
        if self.trusted_proxy:
            ip = (
                environ.get("HTTP_X_FORWARDED_FOR", environ.get("REMOTE_ADDR", ""))
                .split(",")[0]
                .strip()
            )
        else:
            ip = environ.get("REMOTE_ADDR", "")
        if not self.limiter.allow(ip or "unknown"):
            return self._reject(
                start_response,
                429,
                "rate limit exceeded",
                hotkey=None,
                reason="ip_rate_limited",
            )

        payload = self._read_json(environ)

        # The admission policy, when configured, is the authority for mode,
        # binding, profiles, and caps. It is loaded before anything is parsed
        # so an unavailable policy rejects uniformly rather than leaking which
        # request shapes the service would otherwise have accepted.
        policy = None
        if self.admission_policy is not None:
            policy = self.admission_policy.load()
            if policy is None:
                return self._reject(
                    start_response,
                    403,
                    "admission policy unavailable",
                    hotkey=None,
                    reason="policy_unavailable",
                )

        hotkey = validate_hotkey(payload.get("hotkey"))
        # Production mode requires a public IP literal endpoint: see
        # validate_endpoint_url for why this replaces a pinned custom
        # connector as the fix for the DNS check/use gap.
        endpoint_url = validate_endpoint_url(
            payload.get("endpoint_url"), require_ip_literal=self.production_mode
        )
        nonce = validate_enroll_nonce(payload.get("nonce"))
        timestamp = validate_enroll_timestamp(
            payload.get("timestamp"),
            max_age_seconds=self.enroll_signature_ttl_seconds,
        )

        claimed_coldkey: str | None = None
        requested_profile_id: str | None = None
        if policy is None:
            signed_bytes = canonical_enroll_payload(
                hotkey, endpoint_url, nonce, timestamp
            )
            verify_enroll_signature(
                hotkey, signed_bytes, payload.get("signature_b64")
            )
        else:
            # v2 request. Every field the registry acts on is inside the
            # signature. There is no downgrade path: once a policy is
            # configured a v1 request cannot satisfy this verification,
            # because the signed byte strings cannot collide.
            claimed_coldkey = validate_hotkey(payload.get("coldkey"))
            network = validate_network(payload.get("network"))
            netuid = validate_netuid(payload.get("netuid"))
            requested_profile_id = validate_profile_id(payload.get("requested_profile_id"))
            expires_at = validate_enroll_expiry(
                payload.get("expires_at"),
                timestamp,
                max_ttl_seconds=self.enroll_signature_ttl_seconds,
            )
            signed_bytes = canonical_enroll_payload_v2(
                hotkey=hotkey,
                coldkey=claimed_coldkey,
                network=network,
                netuid=netuid,
                endpoint_url=endpoint_url,
                requested_profile_id=requested_profile_id,
                nonce=nonce,
                timestamp=timestamp,
                expires_at=expires_at,
            )
            verify_enroll_signature(
                hotkey, signed_bytes, payload.get("signature_b64")
            )
            # The signature proves the miner meant *this* subnet. The policy
            # verifier has already proven the artifact means this subnet. A
            # mismatch here is a request aimed somewhere else.
            if network != policy.network or netuid != policy.netuid:
                return self._reject(
                    start_response,
                    403,
                    "request is bound to a different network or netuid",
                    hotkey=hotkey,
                    reason="network_mismatch",
                )

        # Per-hotkey durable enrollment rate limit. Backed by SQLite so the
        # bound survives restarts and is consistent across app instances that
        # share the same DB.  This prevents a miner controlling many valid
        # self-owned hotkeys from creating an unbounded probe queue.
        #
        # This stays ahead of the registration and allowlist gates. Those gates
        # each read and verify an operator-controlled artifact (a snapshot stat
        # plus read, an Ed25519 verify, and a canonical re-serialization of the
        # allowlist), so a rejected request is not free. The in-memory IP
        # limiter is per-process and per-address and cannot bound a distributed
        # caller on its own; only this durable per-hotkey record can.
        # A retransmission of a request that already succeeded is still refused
        # for reusing its nonce, but it is not CHARGED to the durable per-hotkey
        # limiter. That is the whole fix: previously about twenty retries of a
        # request whose 200 was lost in flight consumed the hotkey's entire
        # enrollment budget, so the fresh request that would have recovered the
        # token was itself rate limited for the rest of the window.
        #
        # Deliberately not answered with the token. Replaying a captured signed
        # request would then disclose a bearer credential to whoever captured
        # it, inside the request's own expiry window. Refusing the replay and
        # sparing the budget lets the miner recover with a new nonce, which
        # costs one round trip and discloses nothing.
        request_digest = hashlib.sha256(signed_bytes).hexdigest()
        retransmission = self.store.is_completed_enrollment(hotkey, nonce, request_digest)
        if retransmission:
            logger.info("enroll retransmission hotkey=%s", hotkey)

        if not retransmission and not self.store.check_and_record_hotkey_attempt(
            hotkey,
            limit=self.hotkey_enroll_limit,
            window_seconds=self.hotkey_enroll_window_seconds,
        ):
            return self._reject(
                start_response,
                429,
                "hotkey enrollment rate limit exceeded",
                hotkey=hotkey,
                reason="hotkey_rate_limited",
            )

        # Subnet registration gate: fail closed when a provider is configured
        # or when production_mode=True with no provider.
        if self.registration_provider is not None:
            try:
                registered = self.registration_provider.is_registered(hotkey)
            except Exception:
                registered = None
            if registered is not True:
                return self._reject(
                    start_response,
                    403,
                    "hotkey not registered on subnet",
                    hotkey=hotkey,
                    reason="not_registered",
                )
        elif self.production_mode:
            return self._reject(
                start_response,
                403,
                "registration provider not configured",
                hotkey=hotkey,
                reason="registration_provider_missing",
            )

        if policy is not None:
            return self._enroll_under_policy(
                start_response,
                policy=policy,
                hotkey=hotkey,
                claimed_coldkey=claimed_coldkey,
                endpoint_url=endpoint_url,
                requested_profile_id=requested_profile_id,
                nonce=nonce,
                request_digest=request_digest,
            )

        # Approved-coldkey gate: active whenever an allowlist is configured,
        # and unconditionally in production_mode (where an unset allowlist
        # fails closed instead of open).
        if self.coldkey_allowlist is not None or self.production_mode:
            if self.coldkey_allowlist is None:
                return self._reject(
                    start_response,
                    403,
                    "enrollment allowlist not configured",
                    hotkey=hotkey,
                    reason="allowlist_missing",
                )
            coldkey = self._resolve_coldkey(hotkey)
            if coldkey is None:
                return self._reject(
                    start_response,
                    403,
                    "hotkey coldkey could not be resolved",
                    hotkey=hotkey,
                    coldkey="unresolvable",
                    reason="coldkey_unresolvable",
                )
            try:
                allowed = self.coldkey_allowlist.is_allowed(coldkey)
            except Exception:
                allowed = None
            if allowed is not True:
                return self._reject(
                    start_response,
                    403,
                    (
                        "coldkey is not approved for enrollment"
                        if allowed is False
                        else "enrollment allowlist unavailable"
                    ),
                    hotkey=hotkey,
                    coldkey=coldkey,
                    reason=(
                        "coldkey_not_allowlisted"
                        if allowed is False
                        else "allowlist_unavailable"
                    ),
                )

        try:
            self.store.enroll(
                hotkey, endpoint_url, nonce=nonce, request_digest=request_digest
            )
        except LifecycleError as exc:
            # A terminal worker (revoked / retired / retiring) may not
            # re-enroll itself by changing its endpoint; recovery is an
            # operator action (#85). 409:
            # the request is well-formed and authenticated, it conflicts with
            # durable state.
            logger.info("enroll refused hotkey=%s reason=terminal_state", hotkey)
            return self._reject(
                start_response, 409, "terminal_state",
                hotkey=hotkey, reason="terminal_state",
            )
        logger.info("enroll accepted hotkey=%s", hotkey)
        return self._json(
            start_response,
            200,
            self._with_worker_token({"status": "enrolled"}, hotkey),
        )

    def _enroll_under_policy(
        self,
        start_response: Any,
        *,
        policy: Any,
        hotkey: str,
        claimed_coldkey: str | None,
        endpoint_url: str,
        requested_profile_id: str | None,
        nonce: str,
        request_digest: str,
    ) -> list[bytes]:
        """Apply the admission policy and write the pending record.

        Enrollment is permission to be *tested*. Nothing decided here is
        admission, a score, or a reward: the strict measurement, TCB,
        channel-binding, and uniqueness gates run later and are identical in
        both modes.
        """
        if not policy.admits_profile(requested_profile_id):
            return self._reject(
                start_response,
                403,
                "requested profile is not offered by the current policy",
                hotkey=hotkey,
                reason="profile_not_offered",
            )

        # Ownership comes from the registration snapshot, never from the
        # request. The submitted coldkey is only ever compared against it.
        coldkey = self._resolve_coldkey(hotkey)
        if coldkey is None:
            return self._reject(
                start_response,
                403,
                "hotkey coldkey could not be resolved",
                hotkey=hotkey,
                coldkey="unresolvable",
                reason="coldkey_unresolvable",
            )
        if claimed_coldkey is not None and claimed_coldkey != coldkey:
            return self._reject(
                start_response,
                403,
                "submitted coldkey does not own this hotkey",
                hotkey=hotkey,
                coldkey=coldkey,
                reason="coldkey_mismatch",
            )

        # Selected mode consults the approval set. Open mode does not, and
        # relies on the registration gate that has already run above: an
        # unregistered hotkey never reaches this line in either mode.
        if not policy.admits_coldkey(coldkey):
            return self._reject(
                start_response,
                403,
                "coldkey is not approved for enrollment",
                hotkey=hotkey,
                coldkey=coldkey,
                reason="coldkey_not_selected",
            )

        try:
            self.store.enroll(
                hotkey,
                endpoint_url,
                nonce=nonce,
                request_digest=request_digest,
                coldkey=coldkey,
                requested_profile_id=requested_profile_id,
                max_endpoints_per_coldkey=policy.max_enrolled_endpoints_per_coldkey,
                max_total_enrollments=policy.max_admitted_workers_total,
                unique_endpoint=True,
                refuse_terminal=True,
            )
        except EnrollmentRejected as exc:
            return self._reject(
                start_response,
                403,
                str(exc),
                hotkey=hotkey,
                coldkey=coldkey,
                reason=exc.reason,
            )
        logger.info(
            "enroll accepted hotkey=%s coldkey=%s mode=%s profile=%s config_version=%d",
            hotkey,
            coldkey,
            policy.mode,
            requested_profile_id,
            policy.config_version,
        )
        # "pending" is the honest word: the worker is queued for testing and
        # holds no score, no weight, and no admission until it passes every
        # later gate.
        return self._json(
            start_response,
            200,
            self._with_worker_token(
                {
                    "status": "pending",
                    "lifecycle_state": WorkerLifecycleState.PENDING.value,
                    "admission_config_version": policy.config_version,
                },
                hotkey,
            ),
        )

    def _with_worker_token(self, body: dict[str, Any], hotkey: str) -> dict[str, Any]:
        """Attach the worker's bearer token to a successful enrollment response.

        The request that produced this response was signed by the hotkey, so
        only its owner can reach here. Returning the token on every successful
        enrollment (not just the first) is deliberate: a miner that lost it
        re-enrols to recover it rather than asking an operator, and the token
        itself does not change, so the validator's stored copy stays valid.
        """
        token = self.store.worker_token(hotkey)
        if token is not None:
            body = dict(body)
            body["worker_token"] = token
        return body

    def _resolve_coldkey(self, hotkey: str) -> str | None:
        """Resolve the coldkey owning *hotkey* via the registration provider.

        Fails closed (None) when no provider is configured, the provider
        cannot resolve coldkeys (hotkeys-only snapshot or no
        ``resolve_coldkey`` at all), or resolution raises.
        """
        resolve = getattr(self.registration_provider, "resolve_coldkey", None)
        if not callable(resolve):
            return None
        try:
            coldkey = resolve(hotkey)
        except Exception:
            return None
        if not isinstance(coldkey, str) or not coldkey:
            return None
        return coldkey

    def _reject(
        self,
        start_response: Any,
        status: int,
        error: str,
        *,
        hotkey: str | None,
        coldkey: str | None = None,
        reason: str,
    ) -> list[bytes]:
        # Rejections carry only public identity material (hotkey, coldkey,
        # reason); tokens, signatures, and endpoints stay out of the log.
        logger.warning(
            "enroll rejected status=%d reason=%s hotkey=%s coldkey=%s",
            status,
            reason,
            hotkey or "-",
            coldkey or "-",
        )
        return self._json(start_response, status, {"error": error})

    def _read_json(self, environ: dict[str, Any]) -> dict[str, Any]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length <= 0 or length > MAX_BODY:
            raise ValueError("invalid body size")
        body = environ["wsgi.input"].read(length)
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("json body must be an object")
        return payload

    @staticmethod
    def _json(start_response: Any, status: int, payload: dict[str, Any]) -> list[bytes]:
        reason = {
            200: "OK",
            400: "Bad Request",
            403: "Forbidden",
            404: "Not Found",
            429: "Too Many Requests",
        }.get(status, "OK")
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        start_response(
            f"{status} {reason}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
        )
        return [body]


def main() -> None:
    parser = argparse.ArgumentParser(description="Cathedral miner enrollment registry")
    parser.add_argument("--db", default="cathedral-enroll.sqlite")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--trusted-proxy",
        action="store_true",
        help="trust X-Forwarded-For for rate limiting (only when behind a trusted proxy)",
    )
    parser.add_argument(
        "--production-mode",
        action="store_true",
        help=(
            "launch policy: requires --registered-hotkeys-file and rejects "
            "hostname (non-IP-literal) endpoint_url values at enrollment"
        ),
    )
    parser.add_argument(
        "--registered-hotkeys-file",
        metavar="PATH",
        help=(
            "path to a JSON array, JSON {'hotkeys': [...]} object, or "
            "newline-delimited file of registered hotkeys; used as the "
            "RegistrationProvider. Mandatory when --production-mode is set."
        ),
    )
    parser.add_argument(
        "--registration-max-age-seconds",
        type=int,
        default=_DEFAULT_REGISTRATION_MAX_AGE_SECONDS,
        metavar="N",
        help="reject the hotkey file when its mtime is older than N seconds (default: 3600)",
    )
    parser.add_argument(
        "--enroll-allowlist",
        metavar="PATH",
        help=(
            "path to the signed approved-coldkey allowlist artifact "
            "(docs/ENROLLMENT_ALLOWLIST.md). Mandatory when --production-mode "
            "is set; enrollment fails closed without it."
        ),
    )
    parser.add_argument(
        "--enroll-allowlist-keys",
        metavar="PATH",
        help=(
            "JSON object of key id to base64 32-byte Ed25519 public key "
            "trusted to sign the allowlist. Required with --enroll-allowlist."
        ),
    )
    parser.add_argument(
        "--enroll-allowlist-keys-digest",
        metavar="sha256:HEX",
        help=(
            "pin the allowlist key file to this sha256 digest. "
            "Mandatory when --production-mode is set."
        ),
    )
    parser.add_argument(
        "--enroll-allowlist-digest",
        metavar="sha256:HEX",
        help=(
            "optionally pin the allowlist artifact itself to this digest; "
            "rotation then requires a restart with the new digest"
        ),
    )
    parser.add_argument(
        "--enroll-allowlist-max-age-seconds",
        type=int,
        default=DEFAULT_ALLOWLIST_MAX_AGE_SECONDS,
        metavar="N",
        help=(
            "reject the allowlist when its generated_at is older than "
            "N seconds (default: 86400)"
        ),
    )
    parser.add_argument(
        "--admission-policy",
        metavar="PATH",
        help=(
            "path to the signed admission policy artifact "
            "(docs/ADMISSION_POLICY.md). Replaces --enroll-allowlist and "
            "requires v2 enrollment requests; the two cannot be combined. "
            "Either this or --enroll-allowlist is mandatory in production."
        ),
    )
    parser.add_argument(
        "--admission-policy-keys",
        metavar="PATH",
        help=(
            "JSON object of key id to base64 32-byte Ed25519 public key "
            "trusted to sign the admission policy. Required with "
            "--admission-policy."
        ),
    )
    parser.add_argument(
        "--admission-policy-keys-digest",
        metavar="sha256:HEX",
        help="pin the admission policy key file to this sha256 digest",
    )
    parser.add_argument(
        "--admission-policy-digest",
        metavar="sha256:HEX",
        help=(
            "optionally pin the admission policy artifact itself to this "
            "digest. Note this conflicts with rotation: the staleness ceiling "
            "forces a re-sign, which changes the digest, so a pinned service "
            "stops accepting enrollment until it is restarted with the new "
            "value. Prefer --admission-policy-state for durable rollback "
            "resistance"
        ),
    )
    parser.add_argument(
        "--admission-policy-state",
        metavar="PATH",
        help=(
            "file recording the highest accepted config_version, so a "
            "rollback to a superseded but validly signed policy is refused "
            "across a restart. Mandatory when --production-mode is set"
        ),
    )
    parser.add_argument(
        "--admission-policy-max-age-seconds",
        type=int,
        default=DEFAULT_POLICY_MAX_AGE_SECONDS,
        metavar="N",
        help=(
            "reject the admission policy when its issued_at is older than "
            "N seconds (default: 86400)"
        ),
    )
    parser.add_argument(
        "--network",
        default="finney",
        help="network the admission policy must be bound to (default: finney)",
    )
    parser.add_argument(
        "--netuid",
        type=int,
        default=39,
        help="netuid the admission policy must be bound to (default: 39)",
    )
    args = parser.parse_args()

    if args.registration_max_age_seconds <= 0:
        parser.error("--registration-max-age-seconds must be a positive integer")
    if args.enroll_allowlist_max_age_seconds <= 0:
        parser.error("--enroll-allowlist-max-age-seconds must be a positive integer")
    if args.admission_policy_max_age_seconds <= 0:
        parser.error("--admission-policy-max-age-seconds must be a positive integer")

    if args.production_mode and not args.registered_hotkeys_file:
        parser.error("--production-mode requires --registered-hotkeys-file")
    if args.admission_policy and args.enroll_allowlist:
        parser.error("--admission-policy and --enroll-allowlist are mutually exclusive")
    if args.admission_policy and not args.admission_policy_keys:
        parser.error("--admission-policy requires --admission-policy-keys")
    if args.production_mode and not (args.admission_policy or args.enroll_allowlist):
        parser.error("--production-mode requires --admission-policy or --enroll-allowlist")
    # This listener speaks plaintext HTTP and its success response now carries
    # the worker's bearer token. Binding it anywhere but loopback in production
    # puts a credential on the wire in cleartext, where the hotkey signature on
    # the request protects nothing: it authenticates the sender, not the
    # response bytes. Terminate TLS in front and proxy to loopback.
    if args.production_mode and not _is_loopback_host(args.host):
        parser.error(
            f"--production-mode refuses to bind {args.host!r}: this listener is "
            "plaintext HTTP and its response carries the worker bearer token. "
            "Bind a loopback address and terminate TLS in front of it."
        )
    if args.production_mode and args.admission_policy:
        if not args.admission_policy_keys_digest:
            parser.error("--production-mode requires --admission-policy-keys-digest")
        # The key digest pins the root of trust, not the document. Without a
        # durable high-water mark the config_version guard resets on restart,
        # so a superseded but still validly signed policy could be replayed to
        # re-open a mode or restore a revoked coldkey.
        #
        # The state file rather than an artifact digest pin: the staleness
        # ceiling forces a re-sign, a re-sign changes issued_at and therefore
        # the digest, so a required artifact pin would make production refuse
        # every enrollment one ceiling later until someone restarted it.
        if not args.admission_policy_state:
            parser.error("--production-mode requires --admission-policy-state")
    if args.production_mode and args.enroll_allowlist and not args.enroll_allowlist_keys_digest:
        parser.error("--production-mode requires --enroll-allowlist-keys-digest")
    # The key digest pins the root of trust, not the document. Release
    # monotonicity alone is in-process and resets on restart, so a superseded
    # but still validly signed release could be replayed to re-admit a revoked
    # coldkey. Pinning the artifact digest is what makes revocation durable.
    if args.production_mode and args.enroll_allowlist and not args.enroll_allowlist_digest:
        parser.error("--production-mode requires --enroll-allowlist-digest")
    if args.enroll_allowlist and not args.enroll_allowlist_keys:
        parser.error("--enroll-allowlist requires --enroll-allowlist-keys")

    # Structured stdlib logging: every enrollment rejection is recorded with
    # hotkey, resolved coldkey, and reason (see RegistryApp._reject).
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    provider: RegistrationProvider | None = None
    if args.registered_hotkeys_file:
        provider = JsonHotkeyRegistrationProvider(
            args.registered_hotkeys_file,
            max_age_seconds=args.registration_max_age_seconds,
        )

    allowlist: SignedColdkeyAllowlistProvider | None = None
    if args.enroll_allowlist:
        allowlist = SignedColdkeyAllowlistProvider(
            args.enroll_allowlist,
            load_allowlist_keys(
                args.enroll_allowlist_keys,
                production_mode=args.production_mode,
                pinned_digest=args.enroll_allowlist_keys_digest,
            ),
            max_age_seconds=args.enroll_allowlist_max_age_seconds,
            pinned_digest=args.enroll_allowlist_digest,
        )

    admission: SignedAdmissionPolicyProvider | None = None
    if args.admission_policy:
        admission = SignedAdmissionPolicyProvider(
            args.admission_policy,
            load_policy_keys(
                args.admission_policy_keys,
                production_mode=args.production_mode,
                pinned_digest=args.admission_policy_keys_digest,
            ),
            network=args.network,
            netuid=args.netuid,
            max_age_seconds=args.admission_policy_max_age_seconds,
            pinned_digest=args.admission_policy_digest,
            state_path=args.admission_policy_state,
        )

    app = RegistryApp(
        RegistryStore(args.db),
        trusted_proxy=args.trusted_proxy,
        production_mode=args.production_mode,
        registration_provider=provider,
        coldkey_allowlist=allowlist,
        admission_policy=admission,
    )
    with make_server(args.host, args.port, app) as server:
        logger.info("serving registry on http://%s:%d", args.host, args.port)
        server.serve_forever()


if __name__ == "__main__":
    main()
