"""Signed, versioned coldkey allowlist gating SN39 enrollment approval.

The enrollment registry (cathedral/enroll.py) admits only miners whose owning
coldkey appears in an operator-signed allowlist artifact. The artifact follows
the policy registry's trust shape: canonical JSON, Ed25519 signature over the
unsigned document, strict top-level schema, bounded encoding, validity window,
publication-age staleness ceiling, and a sha256 digest over the canonical
document for pinning. Verification reuses the policy registry's parsing and
canonicalization primitives rather than introducing a second implementation.

See docs/ENROLLMENT_ALLOWLIST.md for the operator workflow.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.policy_registry import (
    MAX_SQLITE_INTEGER,
    canonical_json,
    canonical_signed_bytes,
    parse_registry_json,
)

ALLOWLIST_SCHEMA = "cathedral_coldkey_allowlist_v1"
MAX_ALLOWLIST_BYTES = 1024 * 1024
MAX_ALLOWLIST_COLDKEYS = 4096
DEFAULT_ALLOWLIST_MAX_AGE_SECONDS = 86400

_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "release",
        "generated_at",
        "valid_from",
        "valid_until",
        "signing_key_id",
        "coldkeys",
        "signature",
    }
)
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
# Same shape the enrollment endpoint enforces for hotkeys: base58 alphabet,
# bounded length. Kept local so this module never imports cathedral.enroll
# (enroll imports this module).
_SS58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,128}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class ColdkeyAllowlistError(ValueError):
    """An allowlist artifact failed schema, signature, or freshness checks."""


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise ColdkeyAllowlistError(f"{name} must be canonical UTC time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ColdkeyAllowlistError(f"{name} must be canonical UTC time") from exc


@dataclass(frozen=True)
class ColdkeyAllowlistSnapshot:
    """One verified allowlist release."""

    release: int
    generated_at: datetime
    valid_from: datetime
    valid_until: datetime
    signing_key_id: str
    digest: str
    coldkeys: frozenset[str]


def verify_allowlist(
    data: bytes | str,
    trusted_keys: Mapping[str, bytes],
    *,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_ALLOWLIST_MAX_AGE_SECONDS,
) -> ColdkeyAllowlistSnapshot:
    """Verify a signed allowlist artifact and return its snapshot.

    Raises ColdkeyAllowlistError (or PolicyRegistryError from the shared
    parser; both are ValueError) on any schema, signature, window, or
    staleness failure. Callers gating enrollment must treat every failure as
    fail-closed.
    """
    document = parse_registry_json(data)
    if frozenset(document) != _TOP_LEVEL_KEYS:
        raise ColdkeyAllowlistError("allowlist contains missing or unknown critical fields")
    if document["schema"] != ALLOWLIST_SCHEMA:
        raise ColdkeyAllowlistError("allowlist schema is unsupported")
    release = document["release"]
    if (
        isinstance(release, bool)
        or not isinstance(release, int)
        or not 0 < release <= MAX_SQLITE_INTEGER
    ):
        raise ColdkeyAllowlistError("allowlist release must be a bounded positive integer")
    key_id = document["signing_key_id"]
    if not isinstance(key_id, str) or _ID_RE.fullmatch(key_id) is None:
        raise ColdkeyAllowlistError("allowlist signing key id is invalid")
    key = trusted_keys.get(key_id)
    if not isinstance(key, bytes) or len(key) != 32:
        raise ColdkeyAllowlistError("allowlist signing key is not trusted")
    signature = document["signature"]
    if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
        raise ColdkeyAllowlistError("allowlist signature object is invalid")
    if signature["algorithm"] != "ed25519":
        raise ColdkeyAllowlistError("allowlist signature algorithm is unsupported")
    try:
        signature_bytes = base64.b64decode(signature["value_base64"], validate=True)
    except (TypeError, binascii.Error, ValueError) as exc:
        raise ColdkeyAllowlistError("allowlist signature is not canonical base64") from exc
    if (
        len(signature_bytes) != 64
        or base64.b64encode(signature_bytes).decode("ascii") != signature["value_base64"]
    ):
        raise ColdkeyAllowlistError("allowlist signature must be 64 bytes")
    signed = canonical_signed_bytes(document)
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature_bytes, signed)
    except (InvalidSignature, ValueError) as exc:
        raise ColdkeyAllowlistError("allowlist signature verification failed") from exc

    generated = _timestamp(document["generated_at"], "allowlist generated_at")
    valid_from = _timestamp(document["valid_from"], "allowlist valid_from")
    valid_until = _timestamp(document["valid_until"], "allowlist valid_until")
    if not valid_from < valid_until:
        raise ColdkeyAllowlistError("allowlist validity window is invalid")
    if generated >= valid_until:
        raise ColdkeyAllowlistError("allowlist publication time must precede expiry")
    check_time = now or datetime.now(UTC)
    if check_time.tzinfo is None or check_time.utcoffset() != timedelta(0):
        raise ColdkeyAllowlistError("allowlist verification time must be UTC")
    if not valid_from <= check_time < valid_until:
        raise ColdkeyAllowlistError("allowlist is outside its validity window")
    if generated > check_time + timedelta(minutes=5):
        raise ColdkeyAllowlistError("allowlist generation time is in the future")
    if (
        isinstance(max_age_seconds, bool)
        or not isinstance(max_age_seconds, int)
        or max_age_seconds <= 0
    ):
        raise ColdkeyAllowlistError("allowlist maximum age must be positive")
    if check_time - generated > timedelta(seconds=max_age_seconds):
        raise ColdkeyAllowlistError("allowlist is too stale for admission")

    coldkeys_raw = document["coldkeys"]
    # An empty list is a valid, deliberate state (approval paused): it
    # rejects every enrollment rather than failing open.
    if not isinstance(coldkeys_raw, list) or len(coldkeys_raw) > MAX_ALLOWLIST_COLDKEYS:
        raise ColdkeyAllowlistError("allowlist coldkeys must be a bounded list")
    if any(
        not isinstance(item, str) or _SS58_RE.fullmatch(item) is None for item in coldkeys_raw
    ):
        raise ColdkeyAllowlistError("allowlist coldkeys must be ss58-like strings")
    if len(set(coldkeys_raw)) != len(coldkeys_raw):
        raise ColdkeyAllowlistError("allowlist coldkeys cannot contain duplicates")

    canonical_document = canonical_json(document)
    return ColdkeyAllowlistSnapshot(
        release=release,
        generated_at=generated,
        valid_from=valid_from,
        valid_until=valid_until,
        signing_key_id=key_id,
        digest="sha256:" + hashlib.sha256(canonical_document).hexdigest(),
        coldkeys=frozenset(coldkeys_raw),
    )


def sign_allowlist(
    unsigned_document: Mapping[str, object], private_key: bytes
) -> dict[str, object]:
    """Attach an Ed25519 signature to an unsigned allowlist document."""
    if "signature" in unsigned_document:
        raise ColdkeyAllowlistError("unsigned allowlist must not contain signature")
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ColdkeyAllowlistError("Ed25519 private key seed must be 32 bytes")
    document = dict(unsigned_document)
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(canonical_json(document))
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return document


def load_allowlist_keys(
    path: str,
    *,
    production_mode: bool = False,
    pinned_digest: str | None = None,
) -> dict[str, bytes]:
    """Load trusted allowlist signing keys, optionally digest-pinned.

    Same file shape and pinning rule as the policy registry key file:
    a JSON object of key id to base64 32-byte Ed25519 public key, with the
    whole encoded file pinned by sha256 digest in production.
    """
    try:
        with Path(path).open("rb") as handle:
            encoded = handle.read(MAX_ALLOWLIST_BYTES + 1)
    except OSError as exc:
        raise ColdkeyAllowlistError("unable to load allowlist key file") from exc
    if len(encoded) > MAX_ALLOWLIST_BYTES:
        raise ColdkeyAllowlistError("allowlist key file exceeds the maximum encoded size")
    if production_mode and pinned_digest is None:
        raise ColdkeyAllowlistError("production allowlist keys require a pinned digest")
    if pinned_digest is not None:
        if _DIGEST_RE.fullmatch(pinned_digest) is None:
            raise ColdkeyAllowlistError("allowlist key digest is invalid")
        actual_digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
        if not hmac.compare_digest(actual_digest, pinned_digest):
            raise ColdkeyAllowlistError("allowlist key digest does not match")
    raw = parse_registry_json(encoded)
    keys: dict[str, bytes] = {}
    try:
        for key_id, encoded_key in raw.items():
            if not isinstance(key_id, str) or not key_id or not isinstance(encoded_key, str):
                raise ValueError
            key = base64.b64decode(encoded_key, validate=True)
            if len(key) != 32:
                raise ValueError
            keys[key_id] = key
    except (binascii.Error, ValueError):
        raise ColdkeyAllowlistError("allowlist keys must be 32-byte base64 values") from None
    if not keys:
        raise ColdkeyAllowlistError("allowlist key file cannot be empty")
    return keys


class SignedColdkeyAllowlistProvider:
    """Approval gate backed by a rotated, signed allowlist artifact.

    ``is_allowed`` returns True (approved), False (present artifact, coldkey
    not approved), or None (cannot decide right now). None always fails
    closed at the enrollment endpoint: missing/unreadable/oversized file,
    invalid signature or schema, expired validity window, stale publication
    time, a release lower than one already accepted by this process, or a
    pinned-digest mismatch.

    The artifact is re-read and re-verified on every call, matching the
    rotated registration snapshot: operators rotate the file in place and
    the staleness ceiling catches a stuck rotation within one interval.
    """

    def __init__(
        self,
        path: str,
        trusted_keys: Mapping[str, bytes],
        *,
        max_age_seconds: int = DEFAULT_ALLOWLIST_MAX_AGE_SECONDS,
        pinned_digest: str | None = None,
    ) -> None:
        if (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, int)
            or max_age_seconds <= 0
        ):
            raise ValueError("max_age_seconds must be a positive integer")
        if pinned_digest is not None and _DIGEST_RE.fullmatch(pinned_digest) is None:
            raise ValueError("pinned allowlist digest is invalid")
        self.path = path
        self.trusted_keys = dict(trusted_keys)
        self.max_age_seconds = max_age_seconds
        self.pinned_digest = pinned_digest
        self._lock = threading.Lock()
        # In-process rollback guard: once a release is accepted, a lower
        # release fails closed. Durable rollback resistance comes from the
        # pinned key digest plus operator rotation discipline.
        self._highest_release = 0

    def load(self) -> ColdkeyAllowlistSnapshot | None:
        try:
            with Path(self.path).open("rb") as handle:
                data = handle.read(MAX_ALLOWLIST_BYTES + 1)
        except OSError:
            return None  # missing or unreadable; fail closed
        if len(data) > MAX_ALLOWLIST_BYTES:
            return None
        try:
            snapshot = verify_allowlist(
                data, self.trusted_keys, max_age_seconds=self.max_age_seconds
            )
        except ValueError:
            return None  # malformed, unsigned, stale, or outside window; fail closed
        if self.pinned_digest is not None and not hmac.compare_digest(
            snapshot.digest, self.pinned_digest
        ):
            return None
        with self._lock:
            if snapshot.release < self._highest_release:
                return None  # rollback; fail closed
            self._highest_release = snapshot.release
        return snapshot

    def is_allowed(self, coldkey: str) -> bool | None:
        snapshot = self.load()
        if snapshot is None:
            return None
        return coldkey in snapshot.coldkeys
