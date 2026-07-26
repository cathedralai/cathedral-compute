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
import hmac
import importlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import stat
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Protocol
from urllib.parse import urlparse
from wsgiref.simple_server import WSGIRequestHandler, make_server

from cathedral.assurance import (
    ATTESTATION_ADMISSION_POLICY,
    AssuranceClaims,
    assurance_from_dict,
    empty_assurance_claims,
)
from cathedral.coldkey_allowlist import (
    DEFAULT_ALLOWLIST_MAX_AGE_SECONDS,
    SignedColdkeyAllowlistProvider,
    load_allowlist_keys,
)
from cathedral.common import Attested, is_globally_routable
from cathedral.score_audience import validate_score_audience
from cathedral.lifecycle import (
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

# sr25519 verifier discovery.
#
# substrateinterface is the historical source of Keypair, but it is not
# installed in the deployed producer venv, which ships bittensor_wallet
# instead. Both expose the same verification contract
# (``Keypair(ss58_address=...).verify(message, signature) -> bool``), so try
# each in turn rather than hard-failing on one package name. Without this the
# module-level import failure was silent and turned every single enrollment
# into a 403 whose message ("sr25519 signature verifier unavailable") reads
# like a caller error.
SIGNATURE_VERIFIER_MODULES = ("substrateinterface", "bittensor_wallet")


def load_keypair_class(
    modules: tuple[str, ...] = SIGNATURE_VERIFIER_MODULES,
) -> tuple[str | None, Any]:
    """Return ``(module_name, Keypair)`` for the first importable verifier."""

    for name in modules:
        try:
            module = importlib.import_module(name)
        except Exception:  # noqa: BLE001 - any import problem means "try the next one"
            continue
        candidate = getattr(module, "Keypair", None)
        if candidate is not None and callable(candidate):
            return name, candidate
    return None, None


KEYPAIR_SOURCE, Keypair = load_keypair_class()


logger = logging.getLogger("cathedral.enroll")

HOTKEY_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,128}$")
ENROLL_NONCE_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")
MAX_BODY = 16 * 1024
DEFAULT_VERIFICATION_TTL_SECONDS = 60 * 60
DEFAULT_ENROLL_SIGNATURE_TTL_SECONDS = 10 * 60
VERIFICATION_TTL_ENV = "CATHEDRAL_VERIFICATION_TTL_SECONDS"
ENROLL_SIGNATURE_TTL_ENV = "CATHEDRAL_ENROLL_SIGNATURE_TTL_SECONDS"
REJECTED_HOSTS = {"localhost", "metadata.google.internal"}

DEFAULT_HOTKEY_ENROLL_LIMIT = 20
DEFAULT_HOTKEY_ENROLL_WINDOW_SECONDS = 3600
_DEFAULT_REGISTRATION_MAX_AGE_SECONDS = 3600

# Domain separation for the enrollment signature preimage. A miner signature
# is only ever valid for this protocol, on this network, for this subnet: the
# same wallet signs for other Bittensor protocols, and a bare
# hotkey/endpoint/nonce/timestamp document could be lifted from one of them
# (or from testnet SN292) and replayed here.
ENROLL_DOMAIN_TAG = "cathedral-enroll-v1"
DEFAULT_ENROLL_NETWORK = "finney"
DEFAULT_ENROLL_NETUID = 39

# Enrollment is a write on a database the epoch loop also writes. Waiting is
# correct up to a bound; hanging is not. Past the bound the caller gets a 503
# with Retry-After and the epoch loop keeps its write window.
#
# The default is deliberately 5000, which is exactly what every RegistryStore
# consumer already had: sqlite3.connect() defaults to timeout=5.0, which the
# driver applies as sqlite3_busy_timeout(5000). RegistryStore is shared with
# the epoch/evidence path (cathedral/runtime.py, prober.py, key_release.py),
# so the default here must not change their lock behavior. The enrollment
# service passes its own lower bound explicitly, because only it has a
# reverse-proxy read timeout to stay under.
DEFAULT_SQLITE_BUSY_TIMEOUT_MS = 5000
SQLITE_BUSY_TIMEOUT_ENV = "CATHEDRAL_ENROLL_SQLITE_BUSY_TIMEOUT_MS"
ENROLL_BUSY_RETRY_AFTER_SECONDS = 15

# The per-IP limiter is in-memory and its keys come from the network, so it
# needs its own ceiling: an unbounded dict is a remote memory-growth primitive
# once the endpoint is public.
DEFAULT_IP_LIMITER_MAX_KEYS = 4096

# Attempt rows are pruned per hotkey on every write, but a long-lived process
# that never sees a given hotkey again would keep its rows forever. This
# ceiling bounds the sweep so one request cannot pay for an unbounded delete.
HOTKEY_ATTEMPT_SWEEP_INTERVAL_SECONDS = 900

# Known-answer vector for the startup preflight. A verifier that cannot
# confirm this signature, or that confirms a corrupted one, is not a working
# sr25519 verifier and the service must not open a listener with it.
_PREFLIGHT_ADDRESS = "5Cvzb5veKov4TMvd5JVgecHYSphjGU3Dh4N2MGPPCoUJ7cZV"
_PREFLIGHT_MESSAGE = b"cathedral-enroll-verifier-preflight-v1"
_PREFLIGHT_SIGNATURE_B64 = (
    "ThgZ+GzZKIBrOALGgrh3pVkAi84HnQrjp7b6mq1aIWpGWW0DtEUFymbyQJhYpZRD"
    "+OaS6UDE9VBPHcqSeRcDjw=="
)

REGISTRATION_SNAPSHOT_SCHEMA = "cathedral_registration_snapshot_v2"
MAX_SNAPSHOT_BLOCK = 2**53
MAX_SNAPSHOT_FILE_BYTES = 1024 * 1024
# The SN39 metagraph contract (cathedral/evidence.py) tops out at 4,096.
MAX_SNAPSHOT_HOTKEYS = 4096


class SignatureVerifierUnavailable(RuntimeError):
    """No usable sr25519 verifier is importable in this interpreter."""


def preflight_signature_verifier(keypair_class: Any = None) -> str:
    """Prove the sr25519 verifier works, or raise before a listener opens.

    Returns the importable module the verifier came from. Checks both
    directions of the known-answer vector: a real signature must verify and a
    corrupted one must not. A stub that returns True for everything would
    admit any signature from any key, so "importable" alone is not enough.
    """

    candidate = Keypair if keypair_class is None else keypair_class
    if candidate is None:
        raise SignatureVerifierUnavailable(
            "no sr25519 verifier is importable; install one of "
            + ", ".join(SIGNATURE_VERIFIER_MODULES)
        )
    signature = base64.b64decode(_PREFLIGHT_SIGNATURE_B64, validate=True)
    corrupted = bytearray(signature)
    corrupted[0] ^= 0x01
    try:
        verifier = candidate(ss58_address=_PREFLIGHT_ADDRESS)
        accepted = verifier.verify(_PREFLIGHT_MESSAGE, signature)
        rejected = candidate(ss58_address=_PREFLIGHT_ADDRESS).verify(
            _PREFLIGHT_MESSAGE, bytes(corrupted)
        )
    except Exception as exc:  # noqa: BLE001 - any failure here is fatal
        raise SignatureVerifierUnavailable(
            "sr25519 verifier failed its startup known-answer check"
        ) from exc
    if accepted is not True or rejected is not False:
        raise SignatureVerifierUnavailable(
            "sr25519 verifier failed its startup known-answer check"
        )
    if keypair_class is None:
        return KEYPAIR_SOURCE or "unknown"
    return getattr(candidate, "__module__", "unknown")


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

    With ``strict=True`` (the production posture) none of the lenient formats
    are accepted. Only the ``cathedral_registration_snapshot_v2`` document is,
    and it must declare this exact network and netuid, a canonical
    ``generated_at`` that is neither stale nor in the future, and a finalized
    block that never moves backwards; the file must additionally be a regular
    non-symlink file owned by the expected uid and not group/world writable.
    """

    def __init__(
        self,
        path: str,
        *,
        max_age_seconds: int,
        strict: bool = False,
        network: str | None = None,
        netuid: int | None = None,
        expected_uid: int | None = None,
    ) -> None:
        if max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be a positive integer")
        if strict and (network is None or netuid is None):
            raise ValueError("strict snapshot verification requires network and netuid")
        self.path = path
        self.max_age_seconds = max_age_seconds
        # Strict mode is the production posture: only the signed-shape v2
        # document is accepted, its declared audience must equal ours, its
        # block must be finalized and must not go backwards, and the file
        # itself must be root-controlled and not a symlink. Every deviation
        # fails closed rather than degrading to a weaker check.
        self.strict = strict
        self.network = network
        self.netuid = netuid
        self.expected_uid = 0 if (strict and expected_uid is None) else expected_uid
        self._lock = threading.Lock()
        self._highest_block = 0

    def load_snapshot(self) -> tuple[set[str], dict[str, str] | None] | None:
        """Read and parse the snapshot, applying the freshness bound.

        Returns ``(hotkeys, coldkey_by_hotkey)`` where the mapping is ``None``
        for the hotkeys-only formats, or ``None`` overall when the file is
        missing, unreadable, stale, or malformed (fail closed).
        """
        try:
            content = self._read_checked()
        except OSError:
            return None  # missing or unreadable file; fail closed
        if content is None:
            return None
        if self.strict:
            return self._parse_strict(content)
        return self._parse(content)

    def _read_checked(self) -> str | None:
        """Read the snapshot with the file hygiene the mode requires.

        In strict mode the path must be a regular, non-symlink file owned by
        *expected_uid* and not writable by group or other, and the descriptor
        actually read must be the same inode that was checked. A snapshot the
        service does not control is a snapshot an attacker can use to declare
        their own hotkey registered.
        """
        if not self.strict:
            stat_result = os.stat(self.path)
            if time.time() - stat_result.st_mtime > self.max_age_seconds:
                return None  # stale snapshot; fail closed
            with open(self.path, "r", encoding="utf-8") as handle:
                return handle.read()

        before = os.lstat(self.path)
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            logger.warning("registration snapshot is not a regular file")
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(self.path, flags)
        try:
            after = os.fstat(descriptor)
            if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                logger.warning("registration snapshot changed underneath the read")
                return None
            if not stat.S_ISREG(after.st_mode):
                return None
            if self.expected_uid is not None and after.st_uid != self.expected_uid:
                logger.warning("registration snapshot is not owned by the expected user")
                return None
            if after.st_mode & 0o022:
                logger.warning("registration snapshot is group or world writable")
                return None
            if time.time() - after.st_mtime > self.max_age_seconds:
                return None  # stale snapshot; fail closed
            raw = os.read(descriptor, MAX_SNAPSHOT_FILE_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) > MAX_SNAPSHOT_FILE_BYTES:
            logger.warning("registration snapshot exceeds the maximum size")
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _parse_strict(self, content: str) -> tuple[set[str], dict[str, str]] | None:
        """Parse and fully verify the v2 registration snapshot.

        Fails closed on: wrong schema, wrong network or netuid, missing or
        non-canonical ``generated_at``, a stale or future ``generated_at``, a
        block that is not a bounded positive integer, a block that is not
        declared finalized, a block lower than one already accepted by this
        process, or a hotkeys shape that cannot prove ownership.
        """
        try:
            document = json.loads(content)
        except json.JSONDecodeError:
            return None
        if not isinstance(document, dict):
            return None
        if document.get("schema") != REGISTRATION_SNAPSHOT_SCHEMA:
            logger.warning("registration snapshot schema is unsupported")
            return None
        if document.get("network") != self.network or document.get("netuid") != self.netuid:
            logger.warning("registration snapshot declares a different network or netuid")
            return None
        generated_raw = document.get("generated_at")
        if not isinstance(generated_raw, str):
            return None
        try:
            generated = _parse_iso_utc(generated_raw)
        except ValueError:
            return None
        now = datetime.now(UTC)
        if generated > now + timedelta(minutes=5):
            logger.warning("registration snapshot generated_at is in the future")
            return None
        if (now - generated).total_seconds() > self.max_age_seconds:
            return None  # stale by its own declaration, not just by mtime
        if document.get("block_is_finalized") is not True:
            logger.warning("registration snapshot does not declare a finalized block")
            return None
        block = document.get("block")
        if isinstance(block, bool) or not isinstance(block, int) or not 0 < block <= MAX_SNAPSHOT_BLOCK:
            logger.warning("registration snapshot block is not a bounded positive integer")
            return None
        with self._lock:
            if block < self._highest_block:
                # An older capture replayed over a newer one would re-admit
                # hotkeys that have since deregistered.
                logger.warning("registration snapshot block moved backwards")
                return None
            self._highest_block = block
        mapping = document.get("hotkeys")
        if not isinstance(mapping, dict) or len(mapping) > MAX_SNAPSHOT_HOTKEYS:
            return None
        for hotkey, coldkey in mapping.items():
            if (
                not isinstance(hotkey, str)
                or HOTKEY_RE.fullmatch(hotkey) is None
                or not isinstance(coldkey, str)
                or HOTKEY_RE.fullmatch(coldkey) is None
            ):
                logger.warning("registration snapshot contains a malformed key")
                return None
        return set(mapping), dict(mapping)

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


def _is_sqlite_contention(exc: sqlite3.OperationalError) -> bool:
    """True when the error is lock contention rather than a real fault.

    SQLite reports both through OperationalError, and only contention is
    safe to answer with "come back in a moment". A schema or disk error must
    keep propagating.
    """
    message = str(exc).lower()
    return "locked" in message or "busy" in message


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


# Longest legitimate endpoint: scheme (8) + a full 253-byte DNS name + port.
MAX_ENDPOINT_URL_LENGTH = 300


def validate_endpoint_url(endpoint_url: object, *, require_ip_literal: bool = False) -> str:
    """Validate an enrollment endpoint URL.

    A path, query, or fragment is rejected in every mode: the prober appends
    its own path, so anything the miner puts there is either ignored (a silent
    mismatch between what was enrolled and what is probed) or a smuggling
    attempt. The endpoint is an origin, not a URL.

    :param require_ip_literal: when True (production mode), the endpoint must
        additionally be HTTPS, carry an explicit valid port, and name a public
        IP literal in its canonical textual form. The IP-literal rule closes
        the DNS check/use (TOCTOU) gap for launch without a pinned custom
        connector: a hostname resolved at enrollment time could resolve to a
        different, non-global address by the time the prober connects (DNS
        rebinding). An IP literal has no such gap because there is nothing
        left to resolve. Requiring the *canonical* form additionally rejects
        the aliases (``0177.0.0.1``, ``2130706433``, a compressible IPv6
        form) that make one address look like several. Non-production callers
        may still enroll a hostname endpoint; see ``prober.py`` for the
        matching probe-time gate.
    """
    if not isinstance(endpoint_url, str):
        raise ValueError("endpoint_url must be a string")
    if not endpoint_url or len(endpoint_url) > MAX_ENDPOINT_URL_LENGTH:
        raise ValueError("endpoint_url is empty or too long")
    if endpoint_url.strip() != endpoint_url or any(
        not 0x21 <= ord(character) <= 0x7E for character in endpoint_url
    ):
        raise ValueError("endpoint_url must be visible ASCII with no whitespace")
    parsed = urlparse(endpoint_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("endpoint_url must use http or https")
    if not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("endpoint_url must include a host and no credentials")
    if parsed.fragment:
        raise ValueError("endpoint_url must not include a fragment")
    if parsed.query:
        raise ValueError("endpoint_url must not include a query string")
    if parsed.path:
        raise ValueError("endpoint_url must not include a path")
    if parsed.params:
        raise ValueError("endpoint_url must not include URL parameters")
    host = parsed.hostname
    if host is None:
        raise ValueError("endpoint_url must include a host")
    normalized_host = host.rstrip(".").lower()
    if "%" in normalized_host or normalized_host in REJECTED_HOSTS:
        raise ValueError("endpoint_url host is not allowed")
    try:
        # Reading .port validates the numeric range for us and raises on a
        # non-numeric port; do it before anything else looks at the netloc.
        port = parsed.port
    except ValueError as exc:
        raise ValueError("endpoint_url port must be an integer from 1 to 65535") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("endpoint_url port must be an integer from 1 to 65535")
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
        if require_ip_literal:
            if str(ip) != normalized_host:
                raise ValueError("endpoint_url host must be a canonical IP literal")
            # IPv4-mapped and 6to4 forms are the same host spelled differently.
            # One endpoint must have one spelling or the chip-rotation and
            # duplicate-endpoint checks downstream compare strings that look
            # distinct while pointing at the same machine.
            if getattr(ip, "ipv4_mapped", None) is not None or getattr(ip, "sixtofour", None):
                raise ValueError("endpoint_url host must not be an IPv4-in-IPv6 alias")
    if require_ip_literal:
        if parsed.scheme != "https":
            raise ValueError("endpoint_url must use https in production mode")
        if port is None:
            raise ValueError("endpoint_url must carry an explicit port in production mode")
    return endpoint_url


def canonical_enroll_payload(
    hotkey: str,
    endpoint_url: str,
    nonce: str,
    timestamp: str,
    *,
    network: str = DEFAULT_ENROLL_NETWORK,
    netuid: int = DEFAULT_ENROLL_NETUID,
    domain: str = ENROLL_DOMAIN_TAG,
) -> bytes:
    """Canonical bytes miners sign before calling /v1/enroll.

    The domain tag, network, and netuid are inside the signed document, not
    just alongside it. A signature produced for SN292 on testnet, or by some
    other protocol that happens to sign a JSON object with these field names,
    therefore cannot be replayed against SN39 on finney.
    """

    payload = {
        "domain": domain,
        "endpoint_url": endpoint_url,
        "hotkey": hotkey,
        "netuid": netuid,
        "network": network,
        "nonce": nonce,
        "timestamp": timestamp,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def verify_enroll_signature(hotkey: str, message: bytes, signature_b64: object) -> None:
    if Keypair is None:
        raise SignatureVerifierUnavailable("sr25519 signature verifier unavailable")
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
        busy_timeout_ms: int | None = None,
    ) -> None:
        self.path = path
        if busy_timeout_ms is None:
            busy_timeout_ms = _positive_int_from_env(
                SQLITE_BUSY_TIMEOUT_ENV,
                DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
            )
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or busy_timeout_ms <= 0
        ):
            raise ValueError("busy_timeout_ms must be positive")
        # Every connection waits the same bounded time for the write lock.
        # Left at the default this is identical to the previous implicit
        # behavior; the enrollment service lowers it explicitly so a contended
        # request becomes a 503 with Retry-After before the reverse proxy's
        # own read timeout fires.
        self.busy_timeout_ms = busy_timeout_ms
        self._last_attempt_sweep = 0.0
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
        self._init()

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
        # timeout= covers the Python-level lock wait; busy_timeout covers the
        # SQLite-level one. Set both to the same bound so neither can outlive
        # the other and leave a request hanging.
        conn = sqlite3.connect(self.path, timeout=self.busy_timeout_ms / 1000.0)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_ms)}")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def journal_mode(self) -> str:
        with self._connect() as conn:
            return str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()

    def backup_to(self, destination: str) -> int:
        """Take a transaction-safe online copy and return its page count.

        Uses SQLite's backup API, which holds a read lock and copies committed
        pages. Copying the file with ``cp`` while another process is mid
        transaction produces a torn image whose rollback journal is not
        alongside it, so the copy can be unrecoverable exactly when it is
        needed.
        """
        if os.path.exists(destination):
            raise ValueError("backup destination already exists")
        source = self._connect()
        try:
            target = sqlite3.connect(destination)
            try:
                source.backup(target)
                pages = int(target.execute("PRAGMA page_count").fetchone()[0])
                integrity = str(target.execute("PRAGMA integrity_check").fetchone()[0])
                if integrity.lower() != "ok":
                    raise ValueError("backup failed its integrity check")
            finally:
                target.close()
        finally:
            source.close()
        descriptor = os.open(destination, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return pages

    def set_journal_mode(self, mode: str) -> tuple[str, str]:
        """Switch the journal mode, returning ``(before, after)``.

        WAL lets the enrollment reader/writer and the epoch writer overlap
        instead of serializing on a single file lock. The switch itself takes
        an exclusive lock briefly, which is why it is an operator action with
        a backup in front of it and never something the service does on start.
        """
        normalized = mode.strip().lower()
        if normalized not in {"delete", "wal", "truncate", "persist", "memory", "off"}:
            raise ValueError("unsupported sqlite journal mode")
        conn = self._connect()
        try:
            before = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            after = str(
                conn.execute(f"PRAGMA journal_mode = {normalized}").fetchone()[0]
            ).lower()
        finally:
            conn.close()
        if after != normalized:
            raise ValueError(f"sqlite refused the journal mode change (still {after})")
        return before, after

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
    ) -> LifecycleSnapshot:
        if reason not in {LifecycleReason.REENROLLED, LifecycleReason.ENDPOINT_CHANGED}:
            raise LifecycleError("reenrollment lifecycle reason is invalid")
        def apply(conn: sqlite3.Connection, when: datetime) -> LifecycleSnapshot:
            self._advance_lifecycle_clock(conn, when)
            current = self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )
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

    def enroll(self, hotkey: str, endpoint_url: str, *, nonce: str | None = None) -> None:
        ts = now_iso()
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            lifecycle_when = self._lifecycle_now()
            if nonce is not None:
                try:
                    conn.execute(
                        """
                        INSERT INTO enroll_nonces(hotkey, nonce, used_at_iso)
                        VALUES (?, ?, ?)
                        """,
                        (hotkey, nonce, ts),
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
                INSERT INTO enrollments(hotkey, endpoint_url, enrolled_at_iso, updated_at_iso)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(hotkey) DO UPDATE SET
                    endpoint_url=excluded.endpoint_url,
                    updated_at_iso=excluded.updated_at_iso
                """,
                (hotkey, endpoint_url, ts, ts),
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
            # BEGIN IMMEDIATE makes count-then-insert one atomic decision.
            # Read-then-write without it lets two concurrent requests both
            # observe limit-1 rows and both insert, so the durable bound the
            # docstring promises could be exceeded exactly under the load it
            # exists to bound.
            conn.execute("BEGIN IMMEDIATE")
            # Prune this hotkey's expired rows inside the same transaction:
            # rows outside the window can never affect a decision again, and
            # a public endpoint would otherwise grow this table without limit.
            conn.execute(
                "DELETE FROM hotkey_enroll_attempts WHERE hotkey = ? AND attempted_at_iso < ?",
                (hotkey, cutoff),
            )
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
        self._sweep_expired_attempts(window_seconds)
        return True

    def _sweep_expired_attempts(self, window_seconds: int) -> None:
        """Drop expired attempt rows for hotkeys that never came back.

        Per-hotkey pruning only touches hotkeys that keep enrolling. A caller
        that enrolls once from each of many hotkeys would leave rows behind
        forever, so sweep the whole table on a timer. Rate-limited so one
        request never pays for an unbounded delete.
        """
        now = time.monotonic()
        if now - self._last_attempt_sweep < HOTKEY_ATTEMPT_SWEEP_INTERVAL_SECONDS:
            return
        self._last_attempt_sweep = now
        cutoff = (
            datetime.now(UTC) - timedelta(seconds=window_seconds)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        try:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM hotkey_enroll_attempts WHERE attempted_at_iso < ?",
                    (cutoff,),
                )
        except sqlite3.OperationalError:
            # Housekeeping must never fail an enrollment that already
            # succeeded; the next sweep window retries.
            logger.warning("hotkey attempt sweep skipped: registry busy")

    def enrollments(self) -> list[Enrollment]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT hotkey, endpoint_url FROM enrollments ORDER BY updated_at_iso, hotkey"
            ).fetchall()
        return [Enrollment(row["hotkey"], row["endpoint_url"]) for row in rows]

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
            identity_conflict = False
            if status == "VERIFIED" and chip_id is not None:
                conflict = self._chip_rotation_owner(conn, chip_id, hotkey)
                if conflict is not None:
                    status = "FAILED"
                    chip_id = None
                    tier = None
                    error = f"chip_id already bound to hotkey {conflict}"
                    identity_conflict = True
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
                    (
                        WorkerLifecycleState.REVOKED
                        if identity_conflict
                        else WorkerLifecycleState.FAILED
                    ),
                    (
                        LifecycleReason.IDENTITY_CONFLICT
                        if identity_conflict
                        else LifecycleReason.VERIFICATION_FAILED
                    ),
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
    """Per-address request bound with a hard ceiling on tracked addresses.

    The key space is chosen by the caller, so on a public endpoint an
    unbounded dict is a remote memory-growth primitive: one request per source
    address from a large botnet, or from a spoofed-source flood, is enough.
    Expired buckets are dropped first; past *max_keys* the least recently used
    bucket is evicted. Eviction only ever forgets history, so an attacker who
    forces eviction buys themselves a fresh bucket, which is exactly what the
    durable per-hotkey bound in the database exists to catch.
    """

    def __init__(
        self,
        *,
        limit: int = 10,
        window_seconds: int = 60,
        max_keys: int = DEFAULT_IP_LIMITER_MAX_KEYS,
    ) -> None:
        if limit <= 0 or window_seconds <= 0 or max_keys <= 0:
            raise ValueError("limit, window_seconds, and max_keys must be positive")
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            self._evict(cutoff)
            hits = self._hits.get(ip)
            if hits is None:
                hits = deque()
                self._hits[ip] = hits
            else:
                self._hits.move_to_end(ip)
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def tracked_keys(self) -> int:
        with self._lock:
            return len(self._hits)

    def _evict(self, cutoff: float) -> None:
        # Drop fully expired buckets from the LRU end first; they carry no
        # decision value. Only then fall back to evicting live buckets.
        for key in [key for key, hits in self._hits.items() if not hits or hits[-1] < cutoff]:
            del self._hits[key]
        while len(self._hits) >= self.max_keys:
            self._hits.popitem(last=False)


class RegistryApp:
    def __init__(
        self,
        store: RegistryStore,
        limiter: IpRateLimiter | None = None,
        *,
        enroll_signature_ttl_seconds: int | None = None,
        registration_provider: object | None = None,
        coldkey_allowlist: object | None = None,
        production_mode: bool = False,
        trusted_proxy: bool = False,
        hotkey_enroll_limit: int = DEFAULT_HOTKEY_ENROLL_LIMIT,
        hotkey_enroll_window_seconds: int = DEFAULT_HOTKEY_ENROLL_WINDOW_SECONDS,
        network: str = DEFAULT_ENROLL_NETWORK,
        netuid: int = DEFAULT_ENROLL_NETUID,
    ) -> None:
        # Refuse to exist without a working verifier. Constructing an app that
        # cannot check a signature only defers the failure to every request,
        # where it looks like the caller's fault.
        preflight_signature_verifier()
        self.network, self.netuid = validate_score_audience(network, netuid)
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
        except sqlite3.OperationalError as exc:
            # The epoch loop holds the registry's write lock for a bounded
            # window every few minutes. Waiting past the busy timeout is a
            # capacity answer, not a caller error: say so and give a concrete
            # retry delay rather than hanging or corrupting anything.
            if not _is_sqlite_contention(exc):
                raise
            logger.warning("enroll deferred: registry busy")
            return self._json(
                start_response,
                503,
                {"error": "registry busy, retry shortly"},
                headers=[("Retry-After", str(ENROLL_BUSY_RETRY_AFTER_SECONDS))],
            )
        except ValueError as exc:
            return self._json(start_response, 400, {"error": str(exc)})
        except json.JSONDecodeError:
            return self._json(start_response, 400, {"error": "invalid json"})

    def _client_ip(self, environ: dict[str, Any]) -> str:
        """Resolve the rate-limit key from the request.

        Never trust X-Forwarded-For unless the app is explicitly configured to
        run behind a trusted reverse proxy: a spoofed header lets any client
        pick an arbitrary source IP and bypass the per-address rate limit.
        Even then, the trusted proxy is configured to *overwrite* the header
        with the peer address, so exactly one IP literal must be present. A
        list, or anything that is not an IP literal, means the header reached
        us unfiltered and is discarded in favour of REMOTE_ADDR.
        """
        remote = environ.get("REMOTE_ADDR", "")
        if not self.trusted_proxy:
            return remote
        forwarded = environ.get("HTTP_X_FORWARDED_FOR")
        if not isinstance(forwarded, str) or "," in forwarded:
            return remote
        candidate = forwarded.strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return remote
        return candidate

    def _enroll(self, environ: dict[str, Any], start_response: Any) -> list[bytes]:
        ip = self._client_ip(environ)
        if not self.limiter.allow(ip or "unknown"):
            return self._reject(
                start_response,
                429,
                "rate limit exceeded",
                hotkey=None,
                reason="ip_rate_limited",
            )

        payload = self._read_json(environ)
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
        # The audience is both an explicit request field and part of the
        # signed preimage. The explicit field turns a testnet or wrong-subnet
        # submission into a clear 403 instead of an opaque signature failure;
        # the signed copy is what actually stops the replay.
        network, netuid = validate_score_audience(
            payload.get("network"), payload.get("netuid")
        )
        if (network, netuid) != (self.network, self.netuid):
            return self._reject(
                start_response,
                403,
                "enrollment is for a different network or netuid",
                hotkey=hotkey,
                reason="wrong_audience",
            )
        try:
            verify_enroll_signature(
                hotkey,
                canonical_enroll_payload(
                    hotkey,
                    endpoint_url,
                    nonce,
                    timestamp,
                    network=network,
                    netuid=netuid,
                ),
                payload.get("signature_b64"),
            )
        except ValueError:
            # A signature that does not verify is an authentication failure,
            # not a malformed request: the body parsed fine.
            return self._reject(
                start_response,
                403,
                "enrollment signature did not verify",
                hotkey=hotkey,
                reason="signature_invalid",
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
        if not self.store.check_and_record_hotkey_attempt(
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

        self.store.enroll(hotkey, endpoint_url, nonce=nonce)
        logger.info("enroll accepted hotkey=%s", hotkey)
        # Not "enrolled". Worker token provisioning is still operator-assisted
        # (MINING.md step 7), so a bare success would tell a miner they are
        # ready to be scored when the validator cannot yet dispatch work to
        # them. Name the state that actually exists.
        return self._json(
            start_response,
            200,
            {
                "status": "enrolled_pending_secret",
                "hotkey": hotkey,
                "network": self.network,
                "netuid": self.netuid,
                "scored": False,
                "next_step": (
                    "the operator must provision the worker bearer token before "
                    "any work is dispatched; see MINING.md"
                ),
                "check_progress": "/v1/attested",
            },
        )

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
    def _json(
        start_response: Any,
        status: int,
        payload: dict[str, Any],
        *,
        headers: list[tuple[str, str]] | None = None,
    ) -> list[bytes]:
        reason = {
            200: "OK",
            400: "Bad Request",
            403: "Forbidden",
            404: "Not Found",
            429: "Too Many Requests",
            503: "Service Unavailable",
        }.get(status, "OK")
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        start_response(
            f"{status} {reason}",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                *(headers or []),
            ],
        )
        return [body]


class _QuietRequestHandler(WSGIRequestHandler):
    """Bounded, non-echoing request handler for the loopback listener.

    The default handler writes the raw request line to stderr, which puts
    caller-controlled bytes straight into the journal. It also has no socket
    timeout, and this is a deliberately single-process, single-threaded
    server, so one client that opens a connection and stops writing would
    stall every other enrollment. Neither is acceptable on a path that is
    reachable, through the proxy, from the public internet.
    """

    timeout = 10
    # HTTP/1.0 semantics: one request per connection, closed on completion.
    # Nothing here needs keep-alive, and not having it removes a way to hold
    # the single worker.
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        logger.info("http %s", format % args if args else format)

    def address_string(self) -> str:
        # Never reverse-resolve the peer: a DNS lookup per request is both a
        # latency amplifier and an outbound side channel.
        return self.client_address[0]

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except TimeoutError:
            self.close_connection = True


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
        "--network",
        default=DEFAULT_ENROLL_NETWORK,
        help="chain network this registry enrolls for (default: finney)",
    )
    parser.add_argument(
        "--netuid",
        type=int,
        default=DEFAULT_ENROLL_NETUID,
        help="subnet uid this registry enrolls for (default: 39)",
    )
    parser.add_argument(
        "--sqlite-busy-timeout-ms",
        type=int,
        default=None,
        metavar="N",
        help=(
            "bounded wait for the registry write lock before answering 503 "
            f"(default: {DEFAULT_SQLITE_BUSY_TIMEOUT_MS})"
        ),
    )
    parser.add_argument(
        "--development-allow-non-loopback",
        action="store_true",
        help=(
            "bind a non-loopback address. Never use in production: the "
            "service is designed to sit behind the reverse proxy that "
            "terminates TLS and overwrites X-Forwarded-For"
        ),
    )
    args = parser.parse_args()

    if args.registration_max_age_seconds <= 0:
        parser.error("--registration-max-age-seconds must be a positive integer")
    if args.enroll_allowlist_max_age_seconds <= 0:
        parser.error("--enroll-allowlist-max-age-seconds must be a positive integer")
    if args.sqlite_busy_timeout_ms is not None and args.sqlite_busy_timeout_ms <= 0:
        parser.error("--sqlite-busy-timeout-ms must be a positive integer")
    try:
        network, netuid = validate_score_audience(args.network, args.netuid)
    except ValueError as exc:
        parser.error(str(exc))

    # A public write endpoint must not own its own exposure. Binding loopback
    # keeps the rate limits, request bounds, and TLS in the reverse proxy
    # where they can be configured and audited independently.
    if not args.development_allow_non_loopback:
        try:
            bind_ip = ipaddress.ip_address(args.host)
        except ValueError:
            parser.error("--host must be a loopback IP literal")
        if not bind_ip.is_loopback:
            parser.error(
                "--host must be a loopback address; pass "
                "--development-allow-non-loopback to override"
            )

    if args.production_mode and not args.registered_hotkeys_file:
        parser.error("--production-mode requires --registered-hotkeys-file")
    if args.production_mode and not args.enroll_allowlist:
        parser.error("--production-mode requires --enroll-allowlist")
    if args.production_mode and not args.enroll_allowlist_keys_digest:
        parser.error("--production-mode requires --enroll-allowlist-keys-digest")
    # The key digest pins the root of trust, not the document. Release
    # monotonicity alone is in-process and resets on restart, so a superseded
    # but still validly signed release could be replayed to re-admit a revoked
    # coldkey. Pinning the artifact digest is what makes revocation durable.
    if args.production_mode and not args.enroll_allowlist_digest:
        parser.error("--production-mode requires --enroll-allowlist-digest")
    if args.enroll_allowlist and not args.enroll_allowlist_keys:
        parser.error("--enroll-allowlist requires --enroll-allowlist-keys")

    # Structured stdlib logging: every enrollment rejection is recorded with
    # hotkey, resolved coldkey, and reason (see RegistryApp._reject).
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    # Startup preflight. Without a working sr25519 verifier every enrollment
    # would return 403 with a message that reads like the miner's mistake.
    # Refusing to open the listener is the honest failure: it is loud, it is
    # visible in `systemctl status`, and it cannot be mistaken for policy.
    try:
        verifier_source = preflight_signature_verifier()
    except SignatureVerifierUnavailable as exc:
        parser.exit(2, f"refusing to serve: {exc}\n")
    logger.info("sr25519 verifier ready source=%s", verifier_source)

    provider: RegistrationProvider | None = None
    if args.registered_hotkeys_file:
        provider = JsonHotkeyRegistrationProvider(
            args.registered_hotkeys_file,
            max_age_seconds=args.registration_max_age_seconds,
            # Production mode accepts only the fully verified v2 snapshot.
            strict=args.production_mode,
            network=network,
            netuid=netuid,
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

    app = RegistryApp(
        RegistryStore(args.db, busy_timeout_ms=args.sqlite_busy_timeout_ms),
        trusted_proxy=args.trusted_proxy,
        production_mode=args.production_mode,
        registration_provider=provider,
        coldkey_allowlist=allowlist,
        network=network,
        netuid=netuid,
    )
    with make_server(args.host, args.port, app, handler_class=_QuietRequestHandler) as server:
        logger.info(
            "serving registry on http://%s:%d network=%s netuid=%d",
            args.host,
            args.port,
            network,
            netuid,
        )
        server.serve_forever()


if __name__ == "__main__":
    main()
