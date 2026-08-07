"""Signed, versioned admission policy governing SN39 miner enrollment.

One artifact answers every question the enrollment door asks that is not
"does this key control this request":

- **mode** — ``selected`` admits only approved operator coldkeys;
  ``all_registered`` admits any hotkey currently registered on the subnet.
- **binding** — which network and netuid the policy speaks for.
- **profiles** — which policy-registry profile ids a miner may request.
- **caps** — how many endpoints one coldkey may enroll, and how many workers
  may exist at all.

The artifact follows the trust shape the policy registry and the coldkey
allowlist already use: canonical JSON, Ed25519 over the unsigned document,
strict top-level schema, bounded encoding, validity window, publication-age
ceiling, and a sha256 digest over the canonical document for pinning.
Verification reuses the policy registry's parsing and canonicalization
primitives rather than introducing a second implementation.

What this artifact is not: it is permission to be *tested*, never proof,
admission, a score, a reward, or an earning guarantee. Nothing here reaches
the scoring or weight path. A miner listed in ``coldkeys`` that never passes
attestation stays at zero exactly like a miner that was never listed. The
strict measurement, TCB, channel-binding, and uniqueness gates are unchanged
in both modes: ``all_registered`` widens who may ask, never what is accepted.

See docs/ADMISSION_POLICY.md for the operator workflow.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.launch_limits import MAX_LAUNCH_CANDIDATES
from cathedral.policy_registry import (
    MAX_SQLITE_INTEGER,
    canonical_json,
    canonical_signed_bytes,
    parse_registry_json,
)

ADMISSION_POLICY_SCHEMA = "cathedral_admission_policy_v1"

MODE_SELECTED = "selected"
MODE_ALL_REGISTERED = "all_registered"
ADMISSION_MODES = frozenset({MODE_SELECTED, MODE_ALL_REGISTERED})

MAX_POLICY_BYTES = 1024 * 1024
MAX_POLICY_COLDKEYS = 4096
MAX_REQUIRED_PROFILE_IDS = 32
# Ceiling on every operator-chosen cap. Caps exist to bound the validator's
# work, so a cap larger than this is a configuration mistake, not a policy.
#
# Pinned to the frozen launch cardinality rather than picked. A policy that
# authorized more workers than the launch grammar accepts would be a validly
# signed artifact whose population makes epoch completion raise, so no epoch
# closes and nobody is paid. The signed artifact must not be able to express
# that.
MAX_CAP_VALUE = MAX_LAUNCH_CANDIDATES
MAX_NETUID = 65_535
DEFAULT_POLICY_MAX_AGE_SECONDS = 86_400

_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "mode",
        "coldkeys",
        "network",
        "netuid",
        "required_profile_ids",
        "max_enrolled_endpoints_per_coldkey",
        "max_admitted_workers_total",
        "config_version",
        "issued_at",
        "expires_at",
        "signing_key_id",
        "signature",
    }
)
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})

# Same shape the enrollment endpoint enforces for hotkeys: base58 alphabet,
# bounded length. Kept local so this module never imports cathedral.enroll
# (enroll imports this module).
_SS58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,128}$")
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_NETWORK_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class AdmissionPolicyError(ValueError):
    """An admission policy failed schema, signature, binding, or freshness checks."""


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise AdmissionPolicyError(f"{name} must be canonical UTC time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AdmissionPolicyError(f"{name} must be canonical UTC time") from exc


def _bounded_cap(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdmissionPolicyError(f"{name} must be an integer")
    if not 0 < value <= MAX_CAP_VALUE:
        raise AdmissionPolicyError(f"{name} must be between 1 and {MAX_CAP_VALUE}")
    return value


@dataclass(frozen=True)
class AdmissionPolicySnapshot:
    """One verified admission policy."""

    config_version: int
    mode: str
    coldkeys: frozenset[str]
    network: str
    netuid: int
    required_profile_ids: tuple[str, ...]
    max_enrolled_endpoints_per_coldkey: int
    max_admitted_workers_total: int
    issued_at: datetime
    expires_at: datetime
    signing_key_id: str
    digest: str

    def admits_coldkey(self, coldkey: str) -> bool:
        """Whether *coldkey* may enroll under this policy.

        Open mode admits any coldkey that reached this call, which happens
        only after the registration gate has already proven the hotkey is
        registered on the subnet. This method never proves registration.
        """
        if self.mode == MODE_ALL_REGISTERED:
            return True
        return coldkey in self.coldkeys

    def admits_profile(self, profile_id: str) -> bool:
        return profile_id in self.required_profile_ids


def verify_admission_policy(
    data: bytes | str,
    trusted_keys: Mapping[str, bytes],
    *,
    network: str,
    netuid: int,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_POLICY_MAX_AGE_SECONDS,
) -> AdmissionPolicySnapshot:
    """Verify a signed admission policy bound to *network* and *netuid*.

    The expected network and netuid are caller-supplied and mandatory: a
    policy signed for a testnet, or for a different subnet, must never gate
    a mainnet SN39 service even when the same operator key signed it. Both
    the artifact and the service must agree.

    Raises AdmissionPolicyError (or PolicyRegistryError from the shared
    parser; both are ValueError) on any schema, signature, binding, window,
    or staleness failure. Callers gating enrollment must treat every failure
    as fail-closed.
    """
    if not isinstance(network, str) or _NETWORK_RE.fullmatch(network) is None:
        raise AdmissionPolicyError("expected network is invalid")
    if isinstance(netuid, bool) or not isinstance(netuid, int) or not 0 <= netuid <= MAX_NETUID:
        raise AdmissionPolicyError("expected netuid is invalid")

    document = parse_registry_json(data)
    if frozenset(document) != _TOP_LEVEL_KEYS:
        raise AdmissionPolicyError("policy contains missing or unknown critical fields")
    if document["schema"] != ADMISSION_POLICY_SCHEMA:
        raise AdmissionPolicyError("policy schema is unsupported")

    config_version = document["config_version"]
    if (
        isinstance(config_version, bool)
        or not isinstance(config_version, int)
        or not 0 < config_version <= MAX_SQLITE_INTEGER
    ):
        raise AdmissionPolicyError("policy config_version must be a bounded positive integer")

    key_id = document["signing_key_id"]
    if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
        raise AdmissionPolicyError("policy signing key id is invalid")
    key = trusted_keys.get(key_id)
    if not isinstance(key, bytes) or len(key) != 32:
        raise AdmissionPolicyError("policy signing key is not trusted")

    signature = document["signature"]
    if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
        raise AdmissionPolicyError("policy signature object is invalid")
    if signature["algorithm"] != "ed25519":
        raise AdmissionPolicyError("policy signature algorithm is unsupported")
    try:
        signature_bytes = base64.b64decode(signature["value_base64"], validate=True)
    except (TypeError, binascii.Error, ValueError) as exc:
        raise AdmissionPolicyError("policy signature is not canonical base64") from exc
    if (
        len(signature_bytes) != 64
        or base64.b64encode(signature_bytes).decode("ascii") != signature["value_base64"]
    ):
        raise AdmissionPolicyError("policy signature must be 64 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            signature_bytes, canonical_signed_bytes(document)
        )
    except (InvalidSignature, ValueError) as exc:
        raise AdmissionPolicyError("policy signature verification failed") from exc

    # Binding. Checked after the signature so an unsigned document can never
    # produce a binding-specific error that distinguishes real deployments.
    policy_network = document["network"]
    if not isinstance(policy_network, str) or _NETWORK_RE.fullmatch(policy_network) is None:
        raise AdmissionPolicyError("policy network is invalid")
    policy_netuid = document["netuid"]
    if (
        isinstance(policy_netuid, bool)
        or not isinstance(policy_netuid, int)
        or not 0 <= policy_netuid <= MAX_NETUID
    ):
        raise AdmissionPolicyError("policy netuid is invalid")
    if policy_network != network or policy_netuid != netuid:
        raise AdmissionPolicyError(
            "policy is bound to a different network or netuid than this service"
        )

    mode = document["mode"]
    if mode not in ADMISSION_MODES:
        raise AdmissionPolicyError("policy mode is unsupported")

    coldkeys_raw = document["coldkeys"]
    if not isinstance(coldkeys_raw, list) or len(coldkeys_raw) > MAX_POLICY_COLDKEYS:
        raise AdmissionPolicyError("policy coldkeys must be a bounded list")
    if any(
        not isinstance(item, str) or _SS58_RE.fullmatch(item) is None for item in coldkeys_raw
    ):
        raise AdmissionPolicyError("policy coldkeys must be ss58-like strings")
    if len(set(coldkeys_raw)) != len(coldkeys_raw):
        raise AdmissionPolicyError("policy coldkeys cannot contain duplicates")
    # In selected mode an empty list is a valid, deliberate state (approval
    # paused): it rejects every enrollment rather than failing open. In open
    # mode a populated list is refused outright, because an operator reading
    # it would reasonably believe those entries were gating something.
    if mode == MODE_ALL_REGISTERED and coldkeys_raw:
        raise AdmissionPolicyError(
            "open mode must carry an empty coldkey list; a populated list would "
            "read as a gate that this mode does not apply"
        )

    profile_ids = document["required_profile_ids"]
    if (
        not isinstance(profile_ids, list)
        or not profile_ids
        or len(profile_ids) > MAX_REQUIRED_PROFILE_IDS
    ):
        raise AdmissionPolicyError("policy required_profile_ids must be a bounded non-empty list")
    if any(
        not isinstance(item, str) or _PROFILE_ID_RE.fullmatch(item) is None
        for item in profile_ids
    ):
        raise AdmissionPolicyError("policy required_profile_ids must be identifiers")
    if len(set(profile_ids)) != len(profile_ids):
        raise AdmissionPolicyError("policy required_profile_ids cannot contain duplicates")

    per_coldkey = _bounded_cap(
        document["max_enrolled_endpoints_per_coldkey"],
        "max_enrolled_endpoints_per_coldkey",
    )
    total = _bounded_cap(document["max_admitted_workers_total"], "max_admitted_workers_total")

    issued_at = _timestamp(document["issued_at"], "policy issued_at")
    expires_at = _timestamp(document["expires_at"], "policy expires_at")
    if not issued_at < expires_at:
        raise AdmissionPolicyError("policy validity window is invalid")

    check_time = now or datetime.now(UTC)
    if check_time.tzinfo is None or check_time.utcoffset() != timedelta(0):
        raise AdmissionPolicyError("policy verification time must be UTC")
    if not issued_at <= check_time < expires_at:
        raise AdmissionPolicyError("policy is outside its validity window")
    if issued_at > check_time + timedelta(minutes=5):
        raise AdmissionPolicyError("policy issue time is in the future")
    if (
        isinstance(max_age_seconds, bool)
        or not isinstance(max_age_seconds, int)
        or max_age_seconds <= 0
    ):
        raise AdmissionPolicyError("policy maximum age must be positive")
    if check_time - issued_at > timedelta(seconds=max_age_seconds):
        raise AdmissionPolicyError("policy is too stale for admission")

    return AdmissionPolicySnapshot(
        config_version=config_version,
        mode=mode,
        coldkeys=frozenset(coldkeys_raw),
        network=policy_network,
        netuid=policy_netuid,
        required_profile_ids=tuple(profile_ids),
        max_enrolled_endpoints_per_coldkey=per_coldkey,
        max_admitted_workers_total=total,
        issued_at=issued_at,
        expires_at=expires_at,
        signing_key_id=key_id,
        digest="sha256:" + hashlib.sha256(canonical_json(document)).hexdigest(),
    )


def sign_admission_policy(
    unsigned_document: Mapping[str, object], private_key: bytes
) -> dict[str, object]:
    """Attach an Ed25519 signature to an unsigned admission policy."""
    if "signature" in unsigned_document:
        raise AdmissionPolicyError("unsigned policy must not contain signature")
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise AdmissionPolicyError("Ed25519 private key seed must be 32 bytes")
    document = dict(unsigned_document)
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(canonical_json(document))
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return document


def load_policy_keys(
    path: str,
    *,
    production_mode: bool = False,
    pinned_digest: str | None = None,
) -> dict[str, bytes]:
    """Load trusted admission-policy signing keys, optionally digest-pinned.

    Same file shape and pinning rule as the policy registry key file: a JSON
    object of key id to base64 32-byte Ed25519 public key, with the whole
    encoded file pinned by sha256 digest in production.
    """
    try:
        with Path(path).open("rb") as handle:
            encoded = handle.read(MAX_POLICY_BYTES + 1)
    except OSError as exc:
        raise AdmissionPolicyError("unable to load admission policy key file") from exc
    if len(encoded) > MAX_POLICY_BYTES:
        raise AdmissionPolicyError("admission policy key file exceeds the maximum encoded size")
    if production_mode and pinned_digest is None:
        raise AdmissionPolicyError("production admission policy keys require a pinned digest")
    if pinned_digest is not None:
        if _DIGEST_RE.fullmatch(pinned_digest) is None:
            raise AdmissionPolicyError("admission policy key digest is invalid")
        if not hmac.compare_digest(
            "sha256:" + hashlib.sha256(encoded).hexdigest(), pinned_digest
        ):
            raise AdmissionPolicyError("admission policy key digest does not match")
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
        raise AdmissionPolicyError(
            "admission policy keys must be 32-byte base64 values"
        ) from None
    if not keys:
        raise AdmissionPolicyError("admission policy key file cannot be empty")
    return keys


class SignedAdmissionPolicyProvider:
    """Admission policy backed by a rotated, signed artifact.

    ``load`` returns a verified snapshot or ``None``. ``None`` always fails
    closed at the enrollment endpoint: missing/unreadable/oversized file,
    invalid signature or schema, wrong network/netuid, expired window, stale
    issue time, a ``config_version`` lower than one already accepted by this
    process, or a pinned-digest mismatch.

    The artifact is re-read and re-verified on every call, matching the
    rotated registration snapshot and the coldkey allowlist: operators rotate
    the file in place and the staleness ceiling catches a stuck rotation
    within one interval.

    Rollback resistance is durable when ``state_path`` is given: the highest
    accepted ``config_version`` is written there and survives a restart.
    Without it the guard is in-process only and a restart forgets it.

    Pinning the artifact digest also resists rollback, but it cannot be the
    production answer on its own. The staleness ceiling forces a re-sign
    within ``max_age_seconds``; re-signing changes ``issued_at``, hence the
    canonical document, hence the digest — so a required artifact pin makes
    the service refuse every enrollment one day later until someone restarts
    it with a new digest. The durable high-water mark is what makes
    revocation survive a restart without that trap.
    """

    def __init__(
        self,
        path: str,
        trusted_keys: Mapping[str, bytes],
        *,
        network: str,
        netuid: int,
        max_age_seconds: int = DEFAULT_POLICY_MAX_AGE_SECONDS,
        pinned_digest: str | None = None,
        state_path: str | None = None,
    ) -> None:
        if (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, int)
            or max_age_seconds <= 0
        ):
            raise ValueError("max_age_seconds must be a positive integer")
        if pinned_digest is not None and _DIGEST_RE.fullmatch(pinned_digest) is None:
            raise ValueError("pinned admission policy digest is invalid")
        if not isinstance(network, str) or _NETWORK_RE.fullmatch(network) is None:
            raise ValueError("network must be a bounded lowercase identifier")
        if isinstance(netuid, bool) or not isinstance(netuid, int) or not 0 <= netuid <= MAX_NETUID:
            raise ValueError("netuid must be an integer within the subnet range")
        self.path = path
        self.trusted_keys = dict(trusted_keys)
        self.network = network
        self.netuid = netuid
        self.max_age_seconds = max_age_seconds
        self.pinned_digest = pinned_digest
        self.state_path = state_path
        self._lock = threading.Lock()
        self._highest_config_version = self._load_high_water()

    def _load_high_water(self) -> int:
        """Read the durable high-water mark, failing closed on damage.

        An unreadable or malformed state file is treated as the maximum
        version, which refuses every policy until an operator looks at it.
        Treating it as zero would silently restore the exact rollback window
        the file exists to close.
        """
        if self.state_path is None:
            return 0
        try:
            with Path(self.state_path).open("rb") as handle:
                raw = handle.read(64).decode("ascii").strip()
        except FileNotFoundError:
            return 0
        except (OSError, UnicodeDecodeError):
            return MAX_SQLITE_INTEGER
        if not raw.isdigit():
            return MAX_SQLITE_INTEGER
        try:
            return int(raw)
        except ValueError:
            return MAX_SQLITE_INTEGER

    def _persist_high_water(self, config_version: int) -> bool:
        """Durably record *config_version*; a failed write fails closed."""
        if self.state_path is None:
            return True
        target = Path(self.state_path)
        scratch = target.with_name(f".{target.name}.{os.getpid()}")
        try:
            descriptor = os.open(
                scratch,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(str(config_version).encode("ascii"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(scratch, target)
            parent = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        except OSError:
            try:
                scratch.unlink()
            except OSError:
                pass
            return False
        return True

    def load(self) -> AdmissionPolicySnapshot | None:
        try:
            with Path(self.path).open("rb") as handle:
                data = handle.read(MAX_POLICY_BYTES + 1)
        except OSError:
            return None  # missing or unreadable; fail closed
        if len(data) > MAX_POLICY_BYTES:
            return None
        try:
            snapshot = verify_admission_policy(
                data,
                self.trusted_keys,
                network=self.network,
                netuid=self.netuid,
                max_age_seconds=self.max_age_seconds,
            )
        except ValueError:
            return None  # malformed, unsigned, misbound, stale, or expired; fail closed
        if self.pinned_digest is not None and not hmac.compare_digest(
            snapshot.digest, self.pinned_digest
        ):
            return None
        with self._lock:
            if snapshot.config_version < self._highest_config_version:
                return None  # rollback; fail closed
            if snapshot.config_version > self._highest_config_version:
                if not self._persist_high_water(snapshot.config_version):
                    return None  # cannot record the advance; fail closed
                self._highest_config_version = snapshot.config_version
        return snapshot
