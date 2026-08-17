"""Provider-neutral contracts for future prepared confidential-compute capacity.

This module defines versioned, canonical control-plane records.  It does not
provision capacity, execute work, verify provider absence, mutate billing, or
publish Bittensor weights.  Callers must persist these records transactionally
and independently verify every provider assertion they rely on.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from types import MappingProxyType
from typing import Any, Protocol, Self


PROVIDER_IDENTITY_SCHEMA = "cathedral_provider_identity_v1"
CAPABILITY_SLOT_SCHEMA = "cathedral_provider_capability_slot_v1"
CAPABILITY_INVENTORY_SCHEMA = "cathedral_provider_capability_inventory_v1"
ATTEMPT_ASSIGNMENT_SCHEMA = "cathedral_attempt_assignment_v1"
ASSIGNMENT_PERMIT_SCHEMA = "cathedral_assignment_permit_v1"
ASSIGNMENT_LEDGER_BINDING_SCHEMA = "cathedral_assignment_ledger_binding_v1"
PROVIDER_DISPATCH_ENVELOPE_SCHEMA = "cathedral_provider_dispatch_envelope_v1"
ATTEMPT_TRANSITION_SCHEMA = "cathedral_attempt_transition_v1"
INTERRUPTION_OUTCOME_SCHEMA = "cathedral_interruption_outcome_v1"
CLEANUP_OUTCOME_SCHEMA = "cathedral_cleanup_outcome_v1"
CAP_RESERVATION_SCHEMA = "cathedral_customer_cap_reservation_v1"
SETTLEMENT_DECISION_SCHEMA = "cathedral_worker_settlement_decision_v1"
IDEMPOTENCY_BINDING_SCHEMA = "cathedral_submission_idempotency_v1"
UNASSIGNED_DISPATCH_OUTCOME_SCHEMA = "cathedral_unassigned_dispatch_outcome_v1"

MAX_CANONICAL_BYTES = 1024 * 1024
MAX_INVENTORY_SLOTS = 4096
MAX_MONEY_MICROS = 2**63 - 1

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_HOTKEY_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,128}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")


class ProviderRejectionCode(str, Enum):
    """Stable machine-readable rejection classes for contract vectors and callers."""

    CONTRACT_INVALID = "contract_invalid"
    DIGEST_MISMATCH = "digest_mismatch"
    PRIVATE_FIELD_FORBIDDEN = "private_field_forbidden"
    PERMIT_ASSIGNMENT_MISMATCH = "permit_assignment_mismatch"
    PERMIT_EXPIRED = "permit_expired"
    PERMIT_NOT_YET_VALID = "permit_not_yet_valid"
    PERMIT_REPLAY = "permit_replay"
    PERMIT_SEQUENCE = "permit_sequence"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    WORKER_SETTLEMENT_CONFLICT = "worker_settlement_conflict"


class ProviderContractError(ValueError):
    """A provider-control-plane record violates the public contract."""

    def __init__(
        self,
        message: str,
        code: ProviderRejectionCode = ProviderRejectionCode.CONTRACT_INVALID,
    ) -> None:
        super().__init__(message)
        self.code = code


class CanonicalDocument(Protocol):
    """A versioned record with an explicit canonical JSON document."""

    def to_document(self) -> Mapping[str, object]: ...


def _bounded_text(value: object, label: str, pattern: re.Pattern[str] = _ID_RE) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ProviderContractError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ProviderContractError(f"{label} must be a lowercase sha256 digest")
    return value


def _money_micros(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > MAX_MONEY_MICROS
    ):
        raise ProviderContractError(f"{label} must be bounded non-negative integer micros")
    return value


def _canonical_utc(value: datetime, label: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ProviderContractError(f"{label} must be a UTC datetime")
    return (
        f"{value.year:04d}-{value.month:02d}-{value.day:02d}T"
        f"{value.hour:02d}:{value.minute:02d}:{value.second:02d}."
        f"{value.microsecond:06d}Z"
    )


def _parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ProviderContractError(f"{label} must be canonical UTC time")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ProviderContractError(f"{label} must be canonical UTC time") from exc
    if _canonical_utc(parsed, label) != value:
        raise ProviderContractError(f"{label} must be canonical UTC time")
    return parsed


def _enum(value: object, enum_type: type[Enum], label: str) -> Any:
    if not isinstance(value, str):
        raise ProviderContractError(f"{label} is invalid")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ProviderContractError(f"{label} is invalid") from exc


def _require_keys(
    document: object,
    *,
    schema: str,
    keys: frozenset[str],
    label: str,
) -> Mapping[str, object]:
    if not isinstance(document, Mapping) or any(not isinstance(key, str) for key in document):
        raise ProviderContractError(f"{label} must be an object with string keys")
    if frozenset(document) != keys:
        raise ProviderContractError(f"{label} has missing or unknown fields")
    if document.get("schema") != schema:
        raise ProviderContractError(f"{label} schema is unsupported")
    return document


def _charge_canonical_budget(budget: list[int], amount: int) -> None:
    budget[0] -= amount
    if budget[0] < 0:
        raise ProviderContractError("canonical document exceeds the size limit")


def _normalize_canonical(
    value: object,
    *,
    depth: int = 0,
    budget: list[int],
) -> object:
    if depth > 64:
        raise ProviderContractError("canonical value is too deeply nested")
    if value is None:
        _charge_canonical_budget(budget, 4)
        return value
    if isinstance(value, str):
        _charge_canonical_budget(budget, len(value) + 2)
        return value
    if isinstance(value, bool):
        _charge_canonical_budget(budget, 4 if value else 5)
        return value
    if isinstance(value, int):
        digits_lower_bound = max(1, ((abs(value).bit_length() - 1) * 301) // 1000 + 1)
        _charge_canonical_budget(budget, digits_lower_bound + (1 if value < 0 else 0))
        return value
    if isinstance(value, float):
        raise ProviderContractError("floating-point values are not canonical")
    if isinstance(value, Mapping):
        _charge_canonical_budget(budget, 2 + max(0, len(value) - 1))
        normalized: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise ProviderContractError("canonical maps require string keys")
            _charge_canonical_budget(budget, len(key) + 3)
            normalized[key] = _normalize_canonical(
                child,
                depth=depth + 1,
                budget=budget,
            )
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        _charge_canonical_budget(budget, 2 + max(0, len(value) - 1))
        return [_normalize_canonical(child, depth=depth + 1, budget=budget) for child in value]
    to_document = getattr(value, "to_document", None)
    if callable(to_document):
        return _normalize_canonical(
            to_document(),
            depth=depth + 1,
            budget=budget,
        )
    raise ProviderContractError(f"value of type {type(value).__name__} is not canonical")


def canonical_json_bytes(value: object) -> bytes:
    """Return deterministic strict ASCII JSON and reject floats and non-string keys."""

    normalized = _normalize_canonical(value, budget=[MAX_CANONICAL_BYTES])
    try:
        encoded = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProviderContractError("value is not canonical JSON") from exc
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise ProviderContractError("canonical document exceeds the size limit")
    return encoded


def canonical_sha256(value: object) -> str:
    """Digest a record's exact canonical bytes."""

    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def parse_canonical_json(data: bytes | str) -> object:
    """Parse exact canonical ASCII JSON, rejecting duplicates, floats, and padding."""

    if isinstance(data, str):
        try:
            encoded = data.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ProviderContractError("canonical JSON must be ASCII") from exc
    elif isinstance(data, bytes):
        encoded = data
    else:
        raise ProviderContractError("canonical JSON must be bytes or text")
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise ProviderContractError("canonical document exceeds the size limit")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ProviderContractError(f"duplicate canonical JSON key {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(
            encoded.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ProviderContractError("floating-point values are not canonical")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ProviderContractError("non-finite values are not canonical")
            ),
        )
    except ProviderContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ProviderContractError("canonical JSON is invalid") from exc
    if canonical_json_bytes(document) != encoded:
        raise ProviderContractError("JSON bytes are not in canonical form")
    return document


class ProviderIdentityKind(str, Enum):
    CATHEDRAL_SEED = "cathedral_seed"
    SUBNET_HOTKEY = "subnet_hotkey"


@dataclass(frozen=True)
class ProviderIdentity:
    """A provider identity without assuming a particular infrastructure vendor."""

    kind: ProviderIdentityKind
    provider_id: str
    subnet_hotkey: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ProviderIdentityKind):
            raise ProviderContractError("provider identity kind is invalid")
        _bounded_text(self.provider_id, "provider_id")
        if self.kind is ProviderIdentityKind.CATHEDRAL_SEED:
            if self.subnet_hotkey is not None:
                raise ProviderContractError("a Cathedral seed must not claim a subnet hotkey")
        elif (
            not isinstance(self.subnet_hotkey, str)
            or _HOTKEY_RE.fullmatch(self.subnet_hotkey) is None
            or self.provider_id != self.subnet_hotkey
        ):
            raise ProviderContractError(
                "a subnet provider_id must be its bound canonical subnet hotkey"
            )

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": PROVIDER_IDENTITY_SCHEMA,
            "kind": self.kind.value,
            "provider_id": self.provider_id,
            "subnet_hotkey": self.subnet_hotkey,
        }

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=PROVIDER_IDENTITY_SCHEMA,
            keys=frozenset({"schema", "kind", "provider_id", "subnet_hotkey"}),
            label="provider identity",
        )
        return cls(
            kind=_enum(value["kind"], ProviderIdentityKind, "provider identity kind"),
            provider_id=_bounded_text(value["provider_id"], "provider_id"),
            subnet_hotkey=value["subnet_hotkey"],  # type: ignore[arg-type]
        )


class SupplyClass(str, Enum):
    SEED_PREEMPTIBLE = "seed_preemptible"
    SEED_NON_PREEMPTIBLE = "seed_non_preemptible"
    SUBNET_MINER = "subnet_miner"


@dataclass(frozen=True)
class CapabilitySlot:
    """One provider-advertised prepared slot and its immutable execution inputs."""

    provider: ProviderIdentity
    slot_id: str
    region: str
    zone: str
    execution_profile: str
    image_digest: str
    policy_version: str
    policy_digest: str
    supply_class: SupplyClass
    heartbeat_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.provider, ProviderIdentity):
            raise ProviderContractError("capability provider is invalid")
        for value, label in (
            (self.slot_id, "slot_id"),
            (self.region, "region"),
            (self.zone, "zone"),
        ):
            _bounded_text(value, label)
        _bounded_text(self.execution_profile, "execution_profile", _PROFILE_RE)
        _bounded_text(self.policy_version, "policy_version", _PROFILE_RE)
        _digest(self.image_digest, "image_digest")
        _digest(self.policy_digest, "policy_digest")
        if not isinstance(self.supply_class, SupplyClass):
            raise ProviderContractError("supply_class is invalid")
        if self.provider.kind is ProviderIdentityKind.CATHEDRAL_SEED:
            if self.supply_class is SupplyClass.SUBNET_MINER:
                raise ProviderContractError("a Cathedral seed cannot advertise subnet supply")
        elif self.supply_class is not SupplyClass.SUBNET_MINER:
            raise ProviderContractError("a subnet hotkey must advertise subnet supply")
        _canonical_utc(self.heartbeat_at, "heartbeat_at")

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": CAPABILITY_SLOT_SCHEMA,
            "provider": self.provider.to_document(),
            "slot_id": self.slot_id,
            "region": self.region,
            "zone": self.zone,
            "execution_profile": self.execution_profile,
            "image_digest": self.image_digest,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "supply_class": self.supply_class.value,
            "heartbeat_at": _canonical_utc(self.heartbeat_at, "heartbeat_at"),
        }

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=CAPABILITY_SLOT_SCHEMA,
            keys=frozenset(
                {
                    "schema",
                    "provider",
                    "slot_id",
                    "region",
                    "zone",
                    "execution_profile",
                    "image_digest",
                    "policy_version",
                    "policy_digest",
                    "supply_class",
                    "heartbeat_at",
                }
            ),
            label="capability slot",
        )
        return cls(
            provider=ProviderIdentity.from_document(value["provider"]),
            slot_id=_bounded_text(value["slot_id"], "slot_id"),
            region=_bounded_text(value["region"], "region"),
            zone=_bounded_text(value["zone"], "zone"),
            execution_profile=_bounded_text(
                value["execution_profile"], "execution_profile", _PROFILE_RE
            ),
            image_digest=_digest(value["image_digest"], "image_digest"),
            policy_version=_bounded_text(value["policy_version"], "policy_version", _PROFILE_RE),
            policy_digest=_digest(value["policy_digest"], "policy_digest"),
            supply_class=_enum(value["supply_class"], SupplyClass, "supply_class"),
            heartbeat_at=_parse_utc(value["heartbeat_at"], "heartbeat_at"),
        )


@dataclass(frozen=True)
class CapabilityInventory:
    """A provider-neutral snapshot of prepared capacity."""

    inventory_id: str
    generated_at: datetime
    slots: tuple[CapabilitySlot, ...]

    def __post_init__(self) -> None:
        _bounded_text(self.inventory_id, "inventory_id")
        _canonical_utc(self.generated_at, "generated_at")
        if (
            not isinstance(self.slots, tuple)
            or len(self.slots) > MAX_INVENTORY_SLOTS
            or any(not isinstance(slot, CapabilitySlot) for slot in self.slots)
        ):
            raise ProviderContractError("capability inventory slots are invalid")
        identities = {(slot.provider.provider_id, slot.slot_id) for slot in self.slots}
        if len(identities) != len(self.slots):
            raise ProviderContractError("capability inventory contains duplicate slots")
        if any(slot.heartbeat_at > self.generated_at for slot in self.slots):
            raise ProviderContractError("a slot heartbeat cannot be later than its inventory")

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": CAPABILITY_INVENTORY_SCHEMA,
            "inventory_id": self.inventory_id,
            "generated_at": _canonical_utc(self.generated_at, "generated_at"),
            "slots": [slot.to_document() for slot in self.slots],
        }

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=CAPABILITY_INVENTORY_SCHEMA,
            keys=frozenset({"schema", "inventory_id", "generated_at", "slots"}),
            label="capability inventory",
        )
        raw_slots = value["slots"]
        if not isinstance(raw_slots, list):
            raise ProviderContractError("capability inventory slots must be a list")
        if len(raw_slots) > MAX_INVENTORY_SLOTS:
            raise ProviderContractError("capability inventory exceeds the slot limit")
        return cls(
            inventory_id=_bounded_text(value["inventory_id"], "inventory_id"),
            generated_at=_parse_utc(value["generated_at"], "generated_at"),
            slots=tuple(CapabilitySlot.from_document(slot) for slot in raw_slots),
        )


@dataclass(frozen=True)
class AttemptAssignment:
    """Immutable provider-facing identity and execution inputs for one attempt."""

    attempt_id: str
    provider: ProviderIdentity
    slot_id: str
    provider_nonce: str
    workload_manifest_digest: str
    policy_digest: str
    image_digest: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.attempt_id, "attempt_id"),
            (self.slot_id, "slot_id"),
        ):
            _bounded_text(value, label)
        if not isinstance(self.provider, ProviderIdentity):
            raise ProviderContractError("assignment provider is invalid")
        _bounded_text(self.provider_nonce, "provider_nonce", _NONCE_RE)
        _digest(self.workload_manifest_digest, "workload_manifest_digest")
        _digest(self.policy_digest, "policy_digest")
        _digest(self.image_digest, "image_digest")

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": ATTEMPT_ASSIGNMENT_SCHEMA,
            "attempt_id": self.attempt_id,
            "provider": self.provider.to_document(),
            "slot_id": self.slot_id,
            "provider_nonce": self.provider_nonce,
            "workload_manifest_digest": self.workload_manifest_digest,
            "policy_digest": self.policy_digest,
            "image_digest": self.image_digest,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self)

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=ATTEMPT_ASSIGNMENT_SCHEMA,
            keys=frozenset(
                {
                    "schema",
                    "attempt_id",
                    "provider",
                    "slot_id",
                    "provider_nonce",
                    "workload_manifest_digest",
                    "policy_digest",
                    "image_digest",
                }
            ),
            label="attempt assignment",
        )
        return cls(
            attempt_id=_bounded_text(value["attempt_id"], "attempt_id"),
            provider=ProviderIdentity.from_document(value["provider"]),
            slot_id=_bounded_text(value["slot_id"], "slot_id"),
            provider_nonce=_bounded_text(value["provider_nonce"], "provider_nonce", _NONCE_RE),
            workload_manifest_digest=_digest(
                value["workload_manifest_digest"], "workload_manifest_digest"
            ),
            policy_digest=_digest(value["policy_digest"], "policy_digest"),
            image_digest=_digest(value["image_digest"], "image_digest"),
        )


@dataclass(frozen=True)
class AssignmentPermit:
    """Short-lived authorization for one immutable assignment."""

    assignment_digest: str
    sequence: int
    issued_at: datetime
    expires_at: datetime
    key_id: str
    authorization_digest: str

    def __post_init__(self) -> None:
        _digest(self.assignment_digest, "assignment_digest")
        if type(self.sequence) is not int or self.sequence < 1:
            raise ProviderContractError("permit sequence must be a positive integer")
        _canonical_utc(self.issued_at, "issued_at")
        _canonical_utc(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ProviderContractError("permit expiry must be later than issuance")
        _bounded_text(self.key_id, "key_id")
        _digest(self.authorization_digest, "authorization_digest")

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": ASSIGNMENT_PERMIT_SCHEMA,
            "assignment_digest": self.assignment_digest,
            "sequence": self.sequence,
            "issued_at": _canonical_utc(self.issued_at, "issued_at"),
            "expires_at": _canonical_utc(self.expires_at, "expires_at"),
            "key_id": self.key_id,
            "authorization_digest": self.authorization_digest,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self)

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=ASSIGNMENT_PERMIT_SCHEMA,
            keys=frozenset(
                {
                    "schema",
                    "assignment_digest",
                    "sequence",
                    "issued_at",
                    "expires_at",
                    "key_id",
                    "authorization_digest",
                }
            ),
            label="assignment permit",
        )
        sequence = value["sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int):
            raise ProviderContractError("permit sequence must be an integer")
        return cls(
            assignment_digest=_digest(value["assignment_digest"], "assignment_digest"),
            sequence=sequence,
            issued_at=_parse_utc(value["issued_at"], "issued_at"),
            expires_at=_parse_utc(value["expires_at"], "expires_at"),
            key_id=_bounded_text(value["key_id"], "key_id"),
            authorization_digest=_digest(
                value["authorization_digest"], "authorization_digest"
            ),
        )


def validate_assignment_permit(
    assignment: AttemptAssignment,
    permit: AssignmentPermit,
    observed_at: datetime,
) -> None:
    """Require the permit to authorize this assignment at the observation time."""

    if not isinstance(assignment, AttemptAssignment) or not isinstance(permit, AssignmentPermit):
        raise ProviderContractError("assignment permit inputs are invalid")
    _canonical_utc(observed_at, "observed_at")
    if permit.assignment_digest != assignment.digest:
        raise ProviderContractError(
            "permit authorizes a different assignment",
            ProviderRejectionCode.PERMIT_ASSIGNMENT_MISMATCH,
        )
    if observed_at < permit.issued_at:
        raise ProviderContractError(
            "permit is not yet valid",
            ProviderRejectionCode.PERMIT_NOT_YET_VALID,
        )
    if observed_at >= permit.expires_at:
        raise ProviderContractError("permit has expired", ProviderRejectionCode.PERMIT_EXPIRED)


def validate_permit_renewal(
    current: AssignmentPermit,
    candidate: AssignmentPermit,
    observed_at: datetime,
) -> None:
    """Accept exactly the next active permit for the same immutable assignment."""

    if not isinstance(current, AssignmentPermit) or not isinstance(candidate, AssignmentPermit):
        raise ProviderContractError("permit renewal inputs are invalid")
    _canonical_utc(observed_at, "observed_at")
    if candidate.assignment_digest != current.assignment_digest:
        raise ProviderContractError(
            "permit renewal changes the assignment digest",
            ProviderRejectionCode.PERMIT_ASSIGNMENT_MISMATCH,
        )
    if candidate.sequence == current.sequence:
        raise ProviderContractError("permit sequence replayed", ProviderRejectionCode.PERMIT_REPLAY)
    if candidate.sequence != current.sequence + 1:
        raise ProviderContractError(
            "permit renewal must use the next sequence",
            ProviderRejectionCode.PERMIT_SEQUENCE,
        )
    if candidate.issued_at <= current.issued_at:
        raise ProviderContractError(
            "permit renewal issuance did not advance",
            ProviderRejectionCode.PERMIT_SEQUENCE,
        )
    if observed_at < candidate.issued_at:
        raise ProviderContractError(
            "renewed permit is not yet valid",
            ProviderRejectionCode.PERMIT_NOT_YET_VALID,
        )
    if observed_at >= candidate.expires_at:
        raise ProviderContractError(
            "renewed permit has expired",
            ProviderRejectionCode.PERMIT_EXPIRED,
        )


@dataclass(frozen=True)
class AssignmentLedgerBinding:
    """Private ledger join for an opaque provider-facing assignment."""

    binding_id: str
    assignment_digest: str
    customer_id: str
    worker_id: str
    attempt_id: str
    attempt_number: int
    retry_parent_attempt_id: str | None
    reservation_id: str
    request_digest: str
    reserved_micros: int
    created_at: datetime

    def __post_init__(self) -> None:
        for value, label in (
            (self.binding_id, "binding_id"),
            (self.customer_id, "customer_id"),
            (self.worker_id, "worker_id"),
            (self.attempt_id, "attempt_id"),
            (self.reservation_id, "reservation_id"),
        ):
            _bounded_text(value, label)
        for value, label in (
            (self.assignment_digest, "assignment_digest"),
            (self.request_digest, "request_digest"),
        ):
            _digest(value, label)
        if type(self.attempt_number) is not int or self.attempt_number < 1:
            raise ProviderContractError("attempt_number must be a positive integer")
        if self.attempt_number == 1:
            if self.retry_parent_attempt_id is not None:
                raise ProviderContractError("attempt 1 must not name a retry parent")
        else:
            if self.retry_parent_attempt_id is None:
                raise ProviderContractError("a retry attempt must name its immediate parent")
            _bounded_text(self.retry_parent_attempt_id, "retry_parent_attempt_id")
            if self.retry_parent_attempt_id == self.attempt_id:
                raise ProviderContractError("a retry attempt cannot parent itself")
        _money_micros(self.reserved_micros, "reserved_micros")
        _canonical_utc(self.created_at, "created_at")

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": ASSIGNMENT_LEDGER_BINDING_SCHEMA,
            "binding_id": self.binding_id,
            "assignment_digest": self.assignment_digest,
            "customer_id": self.customer_id,
            "worker_id": self.worker_id,
            "attempt_id": self.attempt_id,
            "attempt_number": self.attempt_number,
            "retry_parent_attempt_id": self.retry_parent_attempt_id,
            "reservation_id": self.reservation_id,
            "request_digest": self.request_digest,
            "reserved_micros": self.reserved_micros,
            "created_at": _canonical_utc(self.created_at, "created_at"),
        }

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=ASSIGNMENT_LEDGER_BINDING_SCHEMA,
            keys=frozenset(
                {
                    "schema",
                    "binding_id",
                    "assignment_digest",
                    "customer_id",
                    "worker_id",
                    "attempt_id",
                    "attempt_number",
                    "retry_parent_attempt_id",
                    "reservation_id",
                    "request_digest",
                    "reserved_micros",
                    "created_at",
                }
            ),
            label="assignment ledger binding",
        )
        attempt_number = value["attempt_number"]
        if isinstance(attempt_number, bool) or not isinstance(attempt_number, int):
            raise ProviderContractError("attempt_number must be an integer")
        retry_parent = value["retry_parent_attempt_id"]
        if retry_parent is not None:
            retry_parent = _bounded_text(retry_parent, "retry_parent_attempt_id")
        return cls(
            binding_id=_bounded_text(value["binding_id"], "binding_id"),
            assignment_digest=_digest(value["assignment_digest"], "assignment_digest"),
            customer_id=_bounded_text(value["customer_id"], "customer_id"),
            worker_id=_bounded_text(value["worker_id"], "worker_id"),
            attempt_id=_bounded_text(value["attempt_id"], "attempt_id"),
            attempt_number=attempt_number,
            retry_parent_attempt_id=retry_parent,  # type: ignore[arg-type]
            reservation_id=_bounded_text(value["reservation_id"], "reservation_id"),
            request_digest=_digest(value["request_digest"], "request_digest"),
            reserved_micros=_money_micros(value["reserved_micros"], "reserved_micros"),
            created_at=_parse_utc(value["created_at"], "created_at"),
        )


_PROVIDER_FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "customer_id",
        "customer_subject",
        "customer_subject_digest",
        "worker_id",
        "logical_job_id",
        "reservation_id",
        "reserved_micros",
        "charged_micros",
        "budget_micros",
        "amount_micros",
        "protected_inputs",
        "secrets",
        "secret_env",
        "credentials",
        "bearer_token",
        "api_key",
    }
)


def _reject_provider_private_fields(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str) and key.lower() in _PROVIDER_FORBIDDEN_FIELD_NAMES:
                raise ProviderContractError(
                    f"provider dispatch field {key!r} is private or secret",
                    ProviderRejectionCode.PRIVATE_FIELD_FORBIDDEN,
                )
            _reject_provider_private_fields(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _reject_provider_private_fields(child)


def _frozen_canonical_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ProviderContractError(f"{label} must be a canonical object")
    copied = parse_canonical_json(canonical_json_bytes(value))
    if not isinstance(copied, dict):
        raise ProviderContractError(f"{label} must be a canonical object")
    frozen = _freeze_canonical_value(copied)
    if not isinstance(frozen, Mapping):
        raise ProviderContractError(f"{label} must be a canonical object")
    return frozen


def _freeze_canonical_value(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_canonical_value(child) for key, child in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_canonical_value(child) for child in value)
    return value


def _thaw_canonical_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_canonical_value(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_canonical_value(child) for child in value]
    return value


@dataclass(frozen=True)
class ProviderDispatchEnvelope:
    """The complete provider-visible dispatch document for one permit sequence."""

    assignment: AttemptAssignment
    workload_manifest: Mapping[str, object]
    policy_document: Mapping[str, object]
    permit: AssignmentPermit

    def __post_init__(self) -> None:
        if not isinstance(self.assignment, AttemptAssignment):
            raise ProviderContractError("dispatch assignment is invalid")
        if not isinstance(self.permit, AssignmentPermit):
            raise ProviderContractError("dispatch permit is invalid")
        workload_manifest = _frozen_canonical_mapping(
            self.workload_manifest, "workload_manifest"
        )
        policy_document = _frozen_canonical_mapping(self.policy_document, "policy_document")
        _reject_provider_private_fields(workload_manifest)
        _reject_provider_private_fields(policy_document)
        object.__setattr__(self, "workload_manifest", workload_manifest)
        object.__setattr__(self, "policy_document", policy_document)
        if canonical_sha256(workload_manifest) != self.assignment.workload_manifest_digest:
            raise ProviderContractError(
                "workload manifest digest does not match the assignment",
                ProviderRejectionCode.DIGEST_MISMATCH,
            )
        if canonical_sha256(policy_document) != self.assignment.policy_digest:
            raise ProviderContractError(
                "policy document digest does not match the assignment",
                ProviderRejectionCode.DIGEST_MISMATCH,
            )
        if self.permit.assignment_digest != self.assignment.digest:
            raise ProviderContractError(
                "dispatch permit authorizes a different assignment",
                ProviderRejectionCode.PERMIT_ASSIGNMENT_MISMATCH,
            )
        canonical_json_bytes(self.to_document())

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": PROVIDER_DISPATCH_ENVELOPE_SCHEMA,
            "assignment": self.assignment.to_document(),
            "workload_manifest": _thaw_canonical_value(self.workload_manifest),
            "policy_document": _thaw_canonical_value(self.policy_document),
            "permit": self.permit.to_document(),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_document())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_document())

    def validate(self, observed_at: datetime) -> None:
        validate_assignment_permit(self.assignment, self.permit, observed_at)

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=PROVIDER_DISPATCH_ENVELOPE_SCHEMA,
            keys=frozenset(
                {
                    "schema",
                    "assignment",
                    "workload_manifest",
                    "policy_document",
                    "permit",
                }
            ),
            label="provider dispatch envelope",
        )
        return cls(
            assignment=AttemptAssignment.from_document(value["assignment"]),
            workload_manifest=_frozen_canonical_mapping(
                value["workload_manifest"], "workload_manifest"
            ),
            policy_document=_frozen_canonical_mapping(
                value["policy_document"], "policy_document"
            ),
            permit=AssignmentPermit.from_document(value["permit"]),
        )

    @classmethod
    def from_bytes(cls, data: bytes | str) -> Self:
        return cls.from_document(parse_canonical_json(data))


def validate_assignment_slot(
    assignment: AttemptAssignment,
    slot: CapabilitySlot,
) -> None:
    """Require an assignment to use the exact advertised provider slot inputs."""

    if not isinstance(assignment, AttemptAssignment) or not isinstance(slot, CapabilitySlot):
        raise ProviderContractError("assignment capability inputs are invalid")
    expected = (
        slot.provider,
        slot.slot_id,
        slot.image_digest,
        slot.policy_digest,
    )
    observed = (
        assignment.provider,
        assignment.slot_id,
        assignment.image_digest,
        assignment.policy_digest,
    )
    if observed != expected:
        raise ProviderContractError("assignment does not match the advertised provider slot")


class AttemptState(str, Enum):
    DISPATCH_PENDING = "DISPATCH_PENDING"
    SLOT_CLAIMED = "SLOT_CLAIMED"
    ASSIGNMENT_SENT = "ASSIGNMENT_SENT"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    ATTESTING = "ATTESTING"
    RUNNING = "RUNNING"
    RESULT_RECEIVED = "RESULT_RECEIVED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    EVIDENCE_REJECTED = "EVIDENCE_REJECTED"
    SUCCESS_CLEANUP_PENDING = "SUCCESS_CLEANUP_PENDING"
    FAILURE_CLEANUP_PENDING = "FAILURE_CLEANUP_PENDING"
    CANCEL_CLEANUP_PENDING = "CANCEL_CLEANUP_PENDING"
    INTERRUPT_CLEANUP_PENDING = "INTERRUPT_CLEANUP_PENDING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    INTERRUPTED = "INTERRUPTED"


_ABORTABLE_BEFORE_RESULT = frozenset(
    {
        AttemptState.DISPATCH_PENDING,
        AttemptState.SLOT_CLAIMED,
        AttemptState.ASSIGNMENT_SENT,
        AttemptState.ACKNOWLEDGED,
        AttemptState.ATTESTING,
        AttemptState.RUNNING,
        AttemptState.RESULT_RECEIVED,
        AttemptState.EVIDENCE_VERIFIED,
        AttemptState.EVIDENCE_REJECTED,
        AttemptState.SUCCESS_CLEANUP_PENDING,
    }
)

_attempt_transitions: dict[AttemptState, frozenset[AttemptState]] = {
    AttemptState.DISPATCH_PENDING: frozenset({AttemptState.SLOT_CLAIMED}),
    AttemptState.SLOT_CLAIMED: frozenset({AttemptState.ASSIGNMENT_SENT}),
    AttemptState.ASSIGNMENT_SENT: frozenset({AttemptState.ACKNOWLEDGED}),
    AttemptState.ACKNOWLEDGED: frozenset({AttemptState.ATTESTING}),
    AttemptState.ATTESTING: frozenset({AttemptState.RUNNING}),
    AttemptState.RUNNING: frozenset({AttemptState.RESULT_RECEIVED}),
    AttemptState.RESULT_RECEIVED: frozenset(
        {AttemptState.EVIDENCE_VERIFIED, AttemptState.EVIDENCE_REJECTED}
    ),
    AttemptState.EVIDENCE_VERIFIED: frozenset({AttemptState.SUCCESS_CLEANUP_PENDING}),
    AttemptState.EVIDENCE_REJECTED: frozenset({AttemptState.FAILURE_CLEANUP_PENDING}),
    AttemptState.SUCCESS_CLEANUP_PENDING: frozenset({AttemptState.SUCCEEDED}),
    AttemptState.FAILURE_CLEANUP_PENDING: frozenset({AttemptState.FAILED}),
    AttemptState.CANCEL_CLEANUP_PENDING: frozenset({AttemptState.CANCELLED}),
    AttemptState.INTERRUPT_CLEANUP_PENDING: frozenset({AttemptState.INTERRUPTED}),
    AttemptState.SUCCEEDED: frozenset(),
    AttemptState.FAILED: frozenset(),
    AttemptState.CANCELLED: frozenset(),
    AttemptState.INTERRUPTED: frozenset(),
}

for _abortable_state in _ABORTABLE_BEFORE_RESULT:
    _attempt_transitions[_abortable_state] = frozenset(
        set(_attempt_transitions[_abortable_state])
        | {
            AttemptState.FAILURE_CLEANUP_PENDING,
            AttemptState.CANCEL_CLEANUP_PENDING,
            AttemptState.INTERRUPT_CLEANUP_PENDING,
        }
    )

ALLOWED_ATTEMPT_TRANSITIONS: Mapping[AttemptState, frozenset[AttemptState]] = MappingProxyType(
    dict(_attempt_transitions)
)
del _attempt_transitions

TERMINAL_ATTEMPT_STATES = frozenset(
    {
        AttemptState.SUCCEEDED,
        AttemptState.FAILED,
        AttemptState.CANCELLED,
        AttemptState.INTERRUPTED,
    }
)


class CleanupPath(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    CANCEL = "cancel"
    INTERRUPT = "interrupt"


class ProviderAbsenceStatus(str, Enum):
    PROVEN_ABSENT = "PROVEN_ABSENT"
    PRESENT = "PRESENT"
    NOT_PROVEN = "NOT_PROVEN"


class TerminalBasis(str, Enum):
    PROVIDER_ABSENCE = "provider_absence"
    CUSTOMER_CLEANUP_DEADLINE = "customer_cleanup_deadline"


class InterruptionKind(str, Enum):
    PREEMPTION_NOTICE = "preemption_notice"
    HEARTBEAT_TIMEOUT = "heartbeat_timeout"
    PROVIDER_REPORTED = "provider_reported"
    OPERATOR_REQUESTED = "operator_requested"


@dataclass(frozen=True)
class InterruptionOutcome:
    attempt_id: str
    assignment_digest: str
    provider: ProviderIdentity
    slot_id: str
    kind: InterruptionKind
    source_event_digest: str
    observed_at: datetime

    def __post_init__(self) -> None:
        _bounded_text(self.attempt_id, "attempt_id")
        _digest(self.assignment_digest, "assignment_digest")
        if not isinstance(self.provider, ProviderIdentity):
            raise ProviderContractError("interruption provider is invalid")
        _bounded_text(self.slot_id, "slot_id")
        if not isinstance(self.kind, InterruptionKind):
            raise ProviderContractError("interruption kind is invalid")
        _digest(self.source_event_digest, "source_event_digest")
        _canonical_utc(self.observed_at, "observed_at")

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": INTERRUPTION_OUTCOME_SCHEMA,
            "attempt_id": self.attempt_id,
            "assignment_digest": self.assignment_digest,
            "provider": self.provider.to_document(),
            "slot_id": self.slot_id,
            "kind": self.kind.value,
            "source_event_digest": self.source_event_digest,
            "observed_at": _canonical_utc(self.observed_at, "observed_at"),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self)

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=INTERRUPTION_OUTCOME_SCHEMA,
            keys=frozenset(
                {
                    "schema",
                    "attempt_id",
                    "assignment_digest",
                    "provider",
                    "slot_id",
                    "kind",
                    "source_event_digest",
                    "observed_at",
                }
            ),
            label="interruption outcome",
        )
        return cls(
            attempt_id=_bounded_text(value["attempt_id"], "attempt_id"),
            assignment_digest=_digest(value["assignment_digest"], "assignment_digest"),
            provider=ProviderIdentity.from_document(value["provider"]),
            slot_id=_bounded_text(value["slot_id"], "slot_id"),
            kind=_enum(value["kind"], InterruptionKind, "interruption kind"),
            source_event_digest=_digest(value["source_event_digest"], "source_event_digest"),
            observed_at=_parse_utc(value["observed_at"], "observed_at"),
        )


@dataclass(frozen=True)
class CleanupOutcome:
    """A cleanup observation.  The record does not prove its own assertion."""

    attempt_id: str
    assignment_digest: str
    provider: ProviderIdentity
    slot_id: str
    path: CleanupPath
    absence_status: ProviderAbsenceStatus
    requested_at: datetime
    observed_at: datetime
    observation_digest: str | None = None
    customer_cleanup_deadline_at: datetime | None = None

    def __post_init__(self) -> None:
        _bounded_text(self.attempt_id, "attempt_id")
        _digest(self.assignment_digest, "assignment_digest")
        if not isinstance(self.provider, ProviderIdentity):
            raise ProviderContractError("cleanup provider is invalid")
        _bounded_text(self.slot_id, "slot_id")
        if not isinstance(self.path, CleanupPath):
            raise ProviderContractError("cleanup path is invalid")
        if not isinstance(self.absence_status, ProviderAbsenceStatus):
            raise ProviderContractError("provider absence status is invalid")
        _canonical_utc(self.requested_at, "requested_at")
        _canonical_utc(self.observed_at, "observed_at")
        if self.observed_at < self.requested_at:
            raise ProviderContractError("cleanup observation precedes its request")
        if self.absence_status in {
            ProviderAbsenceStatus.PROVEN_ABSENT,
            ProviderAbsenceStatus.PRESENT,
        }:
            if self.observation_digest is None:
                raise ProviderContractError(
                    "proven absence or presence requires an observation digest"
                )
        if self.observation_digest is not None:
            _digest(self.observation_digest, "observation_digest")
        if self.customer_cleanup_deadline_at is not None:
            _canonical_utc(self.customer_cleanup_deadline_at, "customer_cleanup_deadline_at")
            if self.customer_cleanup_deadline_at < self.requested_at:
                raise ProviderContractError("customer cleanup deadline precedes cleanup request")

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": CLEANUP_OUTCOME_SCHEMA,
            "attempt_id": self.attempt_id,
            "assignment_digest": self.assignment_digest,
            "provider": self.provider.to_document(),
            "slot_id": self.slot_id,
            "path": self.path.value,
            "absence_status": self.absence_status.value,
            "requested_at": _canonical_utc(self.requested_at, "requested_at"),
            "observed_at": _canonical_utc(self.observed_at, "observed_at"),
            "observation_digest": self.observation_digest,
            "customer_cleanup_deadline_at": (
                _canonical_utc(
                    self.customer_cleanup_deadline_at,
                    "customer_cleanup_deadline_at",
                )
                if self.customer_cleanup_deadline_at is not None
                else None
            ),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self)

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=CLEANUP_OUTCOME_SCHEMA,
            keys=frozenset(
                {
                    "schema",
                    "attempt_id",
                    "assignment_digest",
                    "provider",
                    "slot_id",
                    "path",
                    "absence_status",
                    "requested_at",
                    "observed_at",
                    "observation_digest",
                    "customer_cleanup_deadline_at",
                }
            ),
            label="cleanup outcome",
        )
        observation_digest = value["observation_digest"]
        if observation_digest is not None:
            observation_digest = _digest(observation_digest, "observation_digest")
        deadline = value["customer_cleanup_deadline_at"]
        if deadline is not None:
            deadline = _parse_utc(deadline, "customer_cleanup_deadline_at")
        return cls(
            attempt_id=_bounded_text(value["attempt_id"], "attempt_id"),
            assignment_digest=_digest(value["assignment_digest"], "assignment_digest"),
            provider=ProviderIdentity.from_document(value["provider"]),
            slot_id=_bounded_text(value["slot_id"], "slot_id"),
            path=_enum(value["path"], CleanupPath, "cleanup path"),
            absence_status=_enum(
                value["absence_status"], ProviderAbsenceStatus, "provider absence status"
            ),
            requested_at=_parse_utc(value["requested_at"], "requested_at"),
            observed_at=_parse_utc(value["observed_at"], "observed_at"),
            observation_digest=observation_digest,  # type: ignore[arg-type]
            customer_cleanup_deadline_at=deadline,  # type: ignore[arg-type]
        )


_CLEANUP_PATH_FOR_TERMINAL = {
    AttemptState.SUCCEEDED: CleanupPath.SUCCESS,
    AttemptState.FAILED: CleanupPath.FAILURE,
    AttemptState.CANCELLED: CleanupPath.CANCEL,
    AttemptState.INTERRUPTED: CleanupPath.INTERRUPT,
}


def require_attempt_transition(current: AttemptState, target: AttemptState) -> None:
    if not isinstance(current, AttemptState) or not isinstance(target, AttemptState):
        raise ProviderContractError("attempt state is invalid")
    if target not in ALLOWED_ATTEMPT_TRANSITIONS[current]:
        raise ProviderContractError(f"illegal attempt transition {current.value} -> {target.value}")


@dataclass(frozen=True)
class AttemptTransitionEvent:
    event_id: str
    attempt_id: str
    assignment_digest: str
    current: AttemptState
    target: AttemptState
    occurred_at: datetime
    detail_digest: str
    cleanup_outcome_digest: str | None = None
    terminal_basis: TerminalBasis | None = None

    def __post_init__(self) -> None:
        _bounded_text(self.event_id, "event_id")
        _bounded_text(self.attempt_id, "attempt_id")
        _digest(self.assignment_digest, "assignment_digest")
        require_attempt_transition(self.current, self.target)
        _canonical_utc(self.occurred_at, "occurred_at")
        _digest(self.detail_digest, "detail_digest")
        if self.target in TERMINAL_ATTEMPT_STATES:
            if self.cleanup_outcome_digest is None or self.terminal_basis is None:
                raise ProviderContractError(
                    "a terminal transition requires cleanup outcome and terminal basis"
                )
            _digest(self.cleanup_outcome_digest, "cleanup_outcome_digest")
            if not isinstance(self.terminal_basis, TerminalBasis):
                raise ProviderContractError("terminal basis is invalid")
        elif self.cleanup_outcome_digest is not None or self.terminal_basis is not None:
            raise ProviderContractError(
                "only a terminal transition carries cleanup outcome and terminal basis"
            )

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": ATTEMPT_TRANSITION_SCHEMA,
            "event_id": self.event_id,
            "attempt_id": self.attempt_id,
            "assignment_digest": self.assignment_digest,
            "current": self.current.value,
            "target": self.target.value,
            "occurred_at": _canonical_utc(self.occurred_at, "occurred_at"),
            "detail_digest": self.detail_digest,
            "cleanup_outcome_digest": self.cleanup_outcome_digest,
            "terminal_basis": self.terminal_basis.value if self.terminal_basis else None,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self)

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=ATTEMPT_TRANSITION_SCHEMA,
            keys=frozenset(
                {
                    "schema",
                    "event_id",
                    "attempt_id",
                    "assignment_digest",
                    "current",
                    "target",
                    "occurred_at",
                    "detail_digest",
                    "cleanup_outcome_digest",
                    "terminal_basis",
                }
            ),
            label="attempt transition",
        )
        cleanup_digest = value["cleanup_outcome_digest"]
        if cleanup_digest is not None:
            cleanup_digest = _digest(cleanup_digest, "cleanup_outcome_digest")
        terminal_basis = value["terminal_basis"]
        if terminal_basis is not None:
            terminal_basis = _enum(terminal_basis, TerminalBasis, "terminal basis")
        return cls(
            event_id=_bounded_text(value["event_id"], "event_id"),
            attempt_id=_bounded_text(value["attempt_id"], "attempt_id"),
            assignment_digest=_digest(value["assignment_digest"], "assignment_digest"),
            current=_enum(value["current"], AttemptState, "current attempt state"),
            target=_enum(value["target"], AttemptState, "target attempt state"),
            occurred_at=_parse_utc(value["occurred_at"], "occurred_at"),
            detail_digest=_digest(value["detail_digest"], "detail_digest"),
            cleanup_outcome_digest=cleanup_digest,  # type: ignore[arg-type]
            terminal_basis=terminal_basis,  # type: ignore[arg-type]
        )


def validate_transition_assignment(
    assignment: AttemptAssignment,
    event: AttemptTransitionEvent,
) -> None:
    """Bind one state event to the exact immutable assignment."""

    if not isinstance(assignment, AttemptAssignment) or not isinstance(
        event, AttemptTransitionEvent
    ):
        raise ProviderContractError("transition assignment inputs are invalid")
    if event.attempt_id != assignment.attempt_id or event.assignment_digest != assignment.digest:
        raise ProviderContractError("transition event does not match its attempt assignment")


def validate_terminal_transition(
    event: AttemptTransitionEvent,
    cleanup: CleanupOutcome,
) -> None:
    """Bind a terminal transition to cleanup proof or an explicit customer deadline."""

    if event.target not in TERMINAL_ATTEMPT_STATES:
        raise ProviderContractError("terminal validation requires a terminal target")
    if event.attempt_id != cleanup.attempt_id:
        raise ProviderContractError("cleanup outcome belongs to another attempt")
    if event.assignment_digest != cleanup.assignment_digest:
        raise ProviderContractError("cleanup outcome belongs to another assignment")
    if event.occurred_at < cleanup.observed_at:
        raise ProviderContractError("terminal transition precedes its cleanup observation")
    if event.cleanup_outcome_digest != cleanup.digest:
        raise ProviderContractError("terminal transition does not bind the cleanup outcome")
    if cleanup.path is not _CLEANUP_PATH_FOR_TERMINAL[event.target]:
        raise ProviderContractError("cleanup path does not match the terminal state")
    if event.terminal_basis is TerminalBasis.PROVIDER_ABSENCE:
        if cleanup.absence_status is not ProviderAbsenceStatus.PROVEN_ABSENT:
            raise ProviderContractError("provider absence is not proven")
    elif event.terminal_basis is TerminalBasis.CUSTOMER_CLEANUP_DEADLINE:
        if event.target is AttemptState.SUCCEEDED:
            raise ProviderContractError(
                "an unproven cleanup deadline cannot produce a successful attempt"
            )
        if (
            cleanup.customer_cleanup_deadline_at is None
            or cleanup.observed_at < cleanup.customer_cleanup_deadline_at
        ):
            raise ProviderContractError("the customer cleanup deadline has not been reached")
        if cleanup.absence_status is ProviderAbsenceStatus.PROVEN_ABSENT:
            raise ProviderContractError(
                "proven absence must use the provider-absence terminal basis"
            )
    else:
        raise ProviderContractError("terminal basis is invalid")


class DuplicateDecision(str, Enum):
    NEW = "new"
    REPLAY = "replay"


def resolve_transition_duplicate(
    existing: AttemptTransitionEvent | None,
    candidate: AttemptTransitionEvent,
) -> DuplicateDecision:
    """Replay byte-identical event IDs and reject changed duplicate events."""

    if not isinstance(candidate, AttemptTransitionEvent):
        raise ProviderContractError("candidate transition event is invalid")
    if existing is None:
        return DuplicateDecision.NEW
    if not isinstance(existing, AttemptTransitionEvent):
        raise ProviderContractError("existing transition event is invalid")
    if existing.event_id != candidate.event_id:
        raise ProviderContractError("transition duplicate lookup used a different event ID")
    if canonical_json_bytes(existing) != canonical_json_bytes(candidate):
        raise ProviderContractError("changed duplicate transition event conflicts")
    return DuplicateDecision.REPLAY


@dataclass(frozen=True)
class CustomerCapReservation:
    customer_id: str
    worker_id: str
    reservation_id: str
    request_digest: str
    reserved_micros: int
    reserved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for value, label in (
            (self.customer_id, "customer_id"),
            (self.worker_id, "worker_id"),
            (self.reservation_id, "reservation_id"),
        ):
            _bounded_text(value, label)
        _digest(self.request_digest, "request_digest")
        _money_micros(self.reserved_micros, "reserved_micros")
        _canonical_utc(self.reserved_at, "reserved_at")
        _canonical_utc(self.expires_at, "expires_at")
        if self.expires_at <= self.reserved_at:
            raise ProviderContractError("cap reservation expiry must follow its creation")

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": CAP_RESERVATION_SCHEMA,
            "customer_id": self.customer_id,
            "worker_id": self.worker_id,
            "reservation_id": self.reservation_id,
            "request_digest": self.request_digest,
            "reserved_micros": self.reserved_micros,
            "reserved_at": _canonical_utc(self.reserved_at, "reserved_at"),
            "expires_at": _canonical_utc(self.expires_at, "expires_at"),
        }

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=CAP_RESERVATION_SCHEMA,
            keys=frozenset(
                {
                    "schema",
                    "customer_id",
                    "worker_id",
                    "reservation_id",
                    "request_digest",
                    "reserved_micros",
                    "reserved_at",
                    "expires_at",
                }
            ),
            label="customer cap reservation",
        )
        return cls(
            customer_id=_bounded_text(value["customer_id"], "customer_id"),
            worker_id=_bounded_text(value["worker_id"], "worker_id"),
            reservation_id=_bounded_text(value["reservation_id"], "reservation_id"),
            request_digest=_digest(value["request_digest"], "request_digest"),
            reserved_micros=_money_micros(value["reserved_micros"], "reserved_micros"),
            reserved_at=_parse_utc(value["reserved_at"], "reserved_at"),
            expires_at=_parse_utc(value["expires_at"], "expires_at"),
        )


def resolve_reservation_duplicate(
    existing: CustomerCapReservation | None,
    candidate: CustomerCapReservation,
) -> DuplicateDecision:
    """Replay an exact reservation ID and reject changed reservation contents."""

    if not isinstance(candidate, CustomerCapReservation):
        raise ProviderContractError("candidate cap reservation is invalid")
    if existing is None:
        return DuplicateDecision.NEW
    if not isinstance(existing, CustomerCapReservation):
        raise ProviderContractError("existing cap reservation is invalid")
    if existing.reservation_id != candidate.reservation_id:
        raise ProviderContractError("reservation duplicate lookup used a different ID")
    if canonical_json_bytes(existing) != canonical_json_bytes(candidate):
        raise ProviderContractError("changed duplicate cap reservation conflicts")
    return DuplicateDecision.REPLAY


def validate_assignment_reservation(
    assignment: AttemptAssignment,
    initial_permit: AssignmentPermit,
    binding: AssignmentLedgerBinding,
    reservation: CustomerCapReservation,
) -> None:
    """Bind an attempt assignment to the exact prior customer cap reservation."""

    if (
        not isinstance(assignment, AttemptAssignment)
        or not isinstance(initial_permit, AssignmentPermit)
        or not isinstance(binding, AssignmentLedgerBinding)
        or not isinstance(reservation, CustomerCapReservation)
    ):
        raise ProviderContractError("assignment reservation inputs are invalid")
    expected = (
        assignment.digest,
        assignment.attempt_id,
        reservation.customer_id,
        reservation.worker_id,
        reservation.reservation_id,
        reservation.request_digest,
        reservation.reserved_micros,
    )
    observed = (
        binding.assignment_digest,
        binding.attempt_id,
        binding.customer_id,
        binding.worker_id,
        binding.reservation_id,
        binding.request_digest,
        binding.reserved_micros,
    )
    if observed != expected:
        raise ProviderContractError("assignment binding does not match its cap reservation")
    if initial_permit.assignment_digest != assignment.digest or initial_permit.sequence != 1:
        raise ProviderContractError("initial permit does not authorize this assignment")
    if initial_permit.issued_at < reservation.reserved_at:
        raise ProviderContractError("attempt was created before its cap reservation")
    if initial_permit.issued_at >= reservation.expires_at:
        raise ProviderContractError("attempt used an expired cap reservation")
    if initial_permit.expires_at > reservation.expires_at:
        raise ProviderContractError("permit expiry exceeds its cap reservation expiry")
    if binding.created_at < reservation.reserved_at or binding.created_at > initial_permit.issued_at:
        raise ProviderContractError("assignment ledger binding time is outside its valid window")


def validate_cleanup_assignment(
    assignment: AttemptAssignment,
    cleanup: CleanupOutcome,
) -> None:
    """Bind cleanup facts to the exact attempt, provider, and slot assignment."""

    if not isinstance(assignment, AttemptAssignment) or not isinstance(cleanup, CleanupOutcome):
        raise ProviderContractError("cleanup assignment inputs are invalid")
    expected = (
        assignment.attempt_id,
        assignment.digest,
        assignment.provider,
        assignment.slot_id,
    )
    observed = (
        cleanup.attempt_id,
        cleanup.assignment_digest,
        cleanup.provider,
        cleanup.slot_id,
    )
    if observed != expected:
        raise ProviderContractError("cleanup outcome does not match its attempt assignment")


def validate_interruption_assignment(
    assignment: AttemptAssignment,
    interruption: InterruptionOutcome,
) -> None:
    """Bind an interruption observation to the exact provider assignment."""

    if not isinstance(assignment, AttemptAssignment) or not isinstance(
        interruption, InterruptionOutcome
    ):
        raise ProviderContractError("interruption assignment inputs are invalid")
    expected = (
        assignment.attempt_id,
        assignment.digest,
        assignment.provider,
        assignment.slot_id,
    )
    observed = (
        interruption.attempt_id,
        interruption.assignment_digest,
        interruption.provider,
        interruption.slot_id,
    )
    if observed != expected:
        raise ProviderContractError("interruption does not match its attempt assignment")


class UnassignedDispatchReason(str, Enum):
    NO_CAPACITY = "no_capacity"
    POLICY_INELIGIBLE = "policy_ineligible"
    RESERVATION_EXPIRED = "reservation_expired"


@dataclass(frozen=True)
class UnassignedDispatchOutcome:
    """Worker-level final dispatch fact created only when no attempt was assigned."""

    outcome_id: str
    worker_id: str
    request_digest: str
    reason: UnassignedDispatchReason
    routing_decision_digest: str
    observed_at: datetime

    def __post_init__(self) -> None:
        _bounded_text(self.outcome_id, "outcome_id")
        _bounded_text(self.worker_id, "worker_id")
        _digest(self.request_digest, "request_digest")
        if not isinstance(self.reason, UnassignedDispatchReason):
            raise ProviderContractError("unassigned dispatch reason is invalid")
        _digest(self.routing_decision_digest, "routing_decision_digest")
        _canonical_utc(self.observed_at, "observed_at")

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": UNASSIGNED_DISPATCH_OUTCOME_SCHEMA,
            "outcome_id": self.outcome_id,
            "worker_id": self.worker_id,
            "request_digest": self.request_digest,
            "reason": self.reason.value,
            "routing_decision_digest": self.routing_decision_digest,
            "observed_at": _canonical_utc(self.observed_at, "observed_at"),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self)

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=UNASSIGNED_DISPATCH_OUTCOME_SCHEMA,
            keys=frozenset(
                {
                    "schema",
                    "outcome_id",
                    "worker_id",
                    "request_digest",
                    "reason",
                    "routing_decision_digest",
                    "observed_at",
                }
            ),
            label="unassigned dispatch outcome",
        )
        return cls(
            outcome_id=_bounded_text(value["outcome_id"], "outcome_id"),
            worker_id=_bounded_text(value["worker_id"], "worker_id"),
            request_digest=_digest(value["request_digest"], "request_digest"),
            reason=_enum(value["reason"], UnassignedDispatchReason, "unassigned reason"),
            routing_decision_digest=_digest(
                value["routing_decision_digest"], "routing_decision_digest"
            ),
            observed_at=_parse_utc(value["observed_at"], "observed_at"),
        )


class SettlementAction(str, Enum):
    CHARGED = "charged"
    RELEASED = "released"
    HELD_PENDING_CLEANUP = "held_pending_cleanup"


@dataclass(frozen=True)
class WorkerSettlementDecision:
    """One Worker-scoped billing decision, never one decision per attempt."""

    decision_id: str
    sequence: int
    supersedes_digest: str | None
    customer_id: str
    worker_id: str
    reservation_id: str
    reserved_micros: int
    charged_micros: int
    action: SettlementAction
    winning_attempt_id: str | None
    worker_outcome_digest: str
    decided_at: datetime

    def __post_init__(self) -> None:
        for value, label in (
            (self.decision_id, "decision_id"),
            (self.customer_id, "customer_id"),
            (self.worker_id, "worker_id"),
            (self.reservation_id, "reservation_id"),
        ):
            _bounded_text(value, label)
        if type(self.sequence) is not int or self.sequence not in {1, 2}:
            raise ProviderContractError("settlement sequence must be 1 or 2")
        if self.sequence == 1 and self.supersedes_digest is not None:
            raise ProviderContractError("an initial settlement cannot supersede another decision")
        if self.sequence == 2:
            if self.supersedes_digest is None:
                raise ProviderContractError("a settlement resolution must bind the held decision")
            _digest(self.supersedes_digest, "supersedes_digest")
        _money_micros(self.reserved_micros, "reserved_micros")
        _money_micros(self.charged_micros, "charged_micros")
        if self.charged_micros > self.reserved_micros:
            raise ProviderContractError("settlement charge exceeds the reserved customer cap")
        if not isinstance(self.action, SettlementAction):
            raise ProviderContractError("settlement action is invalid")
        _digest(self.worker_outcome_digest, "worker_outcome_digest")
        _canonical_utc(self.decided_at, "decided_at")
        if self.action is SettlementAction.CHARGED:
            if self.sequence != 1 or self.charged_micros <= 0:
                raise ProviderContractError("a charged settlement must be an initial positive charge")
            if self.winning_attempt_id is None:
                raise ProviderContractError("a charged settlement requires a winning attempt")
            _bounded_text(self.winning_attempt_id, "winning_attempt_id")
        else:
            if self.charged_micros != 0:
                raise ProviderContractError("an uncharged settlement action must charge zero")
            if self.winning_attempt_id is not None:
                raise ProviderContractError("an uncharged settlement must not name a winner")
        if self.sequence == 2 and self.action is not SettlementAction.RELEASED:
            raise ProviderContractError("a held settlement resolves only by releasing the cap")

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": SETTLEMENT_DECISION_SCHEMA,
            "decision_id": self.decision_id,
            "sequence": self.sequence,
            "supersedes_digest": self.supersedes_digest,
            "customer_id": self.customer_id,
            "worker_id": self.worker_id,
            "reservation_id": self.reservation_id,
            "reserved_micros": self.reserved_micros,
            "charged_micros": self.charged_micros,
            "action": self.action.value,
            "winning_attempt_id": self.winning_attempt_id,
            "worker_outcome_digest": self.worker_outcome_digest,
            "decided_at": _canonical_utc(self.decided_at, "decided_at"),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self)

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=SETTLEMENT_DECISION_SCHEMA,
            keys=frozenset(
                {
                    "schema",
                    "decision_id",
                    "sequence",
                    "supersedes_digest",
                    "customer_id",
                    "worker_id",
                    "reservation_id",
                    "reserved_micros",
                    "charged_micros",
                    "action",
                    "winning_attempt_id",
                    "worker_outcome_digest",
                    "decided_at",
                }
            ),
            label="worker settlement decision",
        )
        sequence = value["sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int):
            raise ProviderContractError("settlement sequence must be an integer")
        supersedes = value["supersedes_digest"]
        if supersedes is not None:
            supersedes = _digest(supersedes, "supersedes_digest")
        winner = value["winning_attempt_id"]
        if winner is not None:
            winner = _bounded_text(winner, "winning_attempt_id")
        return cls(
            decision_id=_bounded_text(value["decision_id"], "decision_id"),
            sequence=sequence,
            supersedes_digest=supersedes,  # type: ignore[arg-type]
            customer_id=_bounded_text(value["customer_id"], "customer_id"),
            worker_id=_bounded_text(value["worker_id"], "worker_id"),
            reservation_id=_bounded_text(value["reservation_id"], "reservation_id"),
            reserved_micros=_money_micros(value["reserved_micros"], "reserved_micros"),
            charged_micros=_money_micros(value["charged_micros"], "charged_micros"),
            action=_enum(value["action"], SettlementAction, "settlement action"),
            winning_attempt_id=winner,  # type: ignore[arg-type]
            worker_outcome_digest=_digest(
                value["worker_outcome_digest"], "worker_outcome_digest"
            ),
            decided_at=_parse_utc(value["decided_at"], "decided_at"),
        )


def resolve_settlement_duplicate(
    existing: WorkerSettlementDecision | None,
    candidate: WorkerSettlementDecision,
) -> DuplicateDecision:
    if not isinstance(candidate, WorkerSettlementDecision):
        raise ProviderContractError("candidate settlement decision is invalid")
    if existing is None:
        return DuplicateDecision.NEW
    if not isinstance(existing, WorkerSettlementDecision):
        raise ProviderContractError("existing settlement decision is invalid")
    if existing.decision_id != candidate.decision_id:
        raise ProviderContractError("settlement duplicate lookup used a different decision ID")
    if canonical_json_bytes(existing) != canonical_json_bytes(candidate):
        raise ProviderContractError(
            "changed duplicate settlement decision conflicts",
            ProviderRejectionCode.WORKER_SETTLEMENT_CONFLICT,
        )
    return DuplicateDecision.REPLAY


def validate_settlement(
    reservation: CustomerCapReservation,
    decision: WorkerSettlementDecision,
) -> None:
    if not isinstance(reservation, CustomerCapReservation) or not isinstance(
        decision, WorkerSettlementDecision
    ):
        raise ProviderContractError("settlement inputs are invalid")
    expected = (
        reservation.customer_id,
        reservation.worker_id,
        reservation.reservation_id,
        reservation.reserved_micros,
    )
    observed = (
        decision.customer_id,
        decision.worker_id,
        decision.reservation_id,
        decision.reserved_micros,
    )
    if observed != expected:
        raise ProviderContractError("settlement does not match its cap reservation")
    if decision.decided_at < reservation.reserved_at:
        raise ProviderContractError("settlement precedes its cap reservation")
    if decision.decided_at >= reservation.expires_at and decision.action is not SettlementAction.RELEASED:
        raise ProviderContractError("an expired cap reservation must be released uncharged")


def validate_settlement_supersession(
    reservation: CustomerCapReservation,
    held: WorkerSettlementDecision,
    resolution: WorkerSettlementDecision,
) -> None:
    validate_settlement(reservation, held)
    validate_settlement(reservation, resolution)
    if held.sequence != 1 or held.action is not SettlementAction.HELD_PENDING_CLEANUP:
        raise ProviderContractError("only an initial held settlement can be resolved")
    if resolution.sequence != 2 or resolution.supersedes_digest != held.digest:
        raise ProviderContractError("settlement resolution does not supersede the held decision")
    if resolution.worker_outcome_digest != held.worker_outcome_digest:
        raise ProviderContractError("settlement resolution changes the Worker outcome")
    if resolution.decided_at <= held.decided_at:
        raise ProviderContractError("settlement resolution must follow the held decision")
    if resolution.decision_id == held.decision_id:
        raise ProviderContractError("settlement resolution requires a new decision ID")


def resolve_held_settlement(
    existing_resolution: WorkerSettlementDecision | None,
    reservation: CustomerCapReservation,
    held: WorkerSettlementDecision,
    candidate: WorkerSettlementDecision,
) -> DuplicateDecision:
    validate_settlement_supersession(reservation, held, candidate)
    if existing_resolution is None:
        return DuplicateDecision.NEW
    validate_settlement_supersession(reservation, held, existing_resolution)
    if canonical_json_bytes(existing_resolution) == canonical_json_bytes(candidate):
        return DuplicateDecision.REPLAY
    raise ProviderContractError(
        "held settlement already has a different resolution",
        ProviderRejectionCode.WORKER_SETTLEMENT_CONFLICT,
    )


@dataclass(frozen=True)
class SubmissionIdempotencyBinding:
    customer_id: str
    idempotency_key_digest: str
    request_digest: str
    worker_id: str

    def __post_init__(self) -> None:
        _bounded_text(self.customer_id, "customer_id")
        _digest(self.idempotency_key_digest, "idempotency_key_digest")
        _digest(self.request_digest, "request_digest")
        _bounded_text(self.worker_id, "worker_id")

    def to_document(self) -> Mapping[str, object]:
        return {
            "schema": IDEMPOTENCY_BINDING_SCHEMA,
            "customer_id": self.customer_id,
            "idempotency_key_digest": self.idempotency_key_digest,
            "request_digest": self.request_digest,
            "worker_id": self.worker_id,
        }

    @classmethod
    def from_document(cls, document: object) -> Self:
        value = _require_keys(
            document,
            schema=IDEMPOTENCY_BINDING_SCHEMA,
            keys=frozenset(
                {
                    "schema",
                    "customer_id",
                    "idempotency_key_digest",
                    "request_digest",
                    "worker_id",
                }
            ),
            label="submission idempotency binding",
        )
        return cls(
            customer_id=_bounded_text(value["customer_id"], "customer_id"),
            idempotency_key_digest=_digest(
                value["idempotency_key_digest"], "idempotency_key_digest"
            ),
            request_digest=_digest(value["request_digest"], "request_digest"),
            worker_id=_bounded_text(value["worker_id"], "worker_id"),
        )


def hash_idempotency_key(raw_key: bytes) -> str:
    """Hash one API Idempotency-Key after enforcing the 8-200 byte API contract."""

    if not isinstance(raw_key, bytes) or not 8 <= len(raw_key) <= 200:
        raise ProviderContractError("raw idempotency key must be 8 to 200 bytes")
    return "sha256:" + hashlib.sha256(raw_key).hexdigest()


class IdempotencyDecision(str, Enum):
    NEW = "new"
    REPLAY = "replay"


def resolve_submission_idempotency(
    existing: SubmissionIdempotencyBinding | None,
    candidate: SubmissionIdempotencyBinding,
) -> tuple[IdempotencyDecision, SubmissionIdempotencyBinding]:
    """Return the original job on replay and reject changed bytes for a reused key."""

    if not isinstance(candidate, SubmissionIdempotencyBinding):
        raise ProviderContractError("candidate idempotency binding is invalid")
    if existing is None:
        return IdempotencyDecision.NEW, candidate
    if not isinstance(existing, SubmissionIdempotencyBinding):
        raise ProviderContractError("existing idempotency binding is invalid")
    if (
        existing.customer_id != candidate.customer_id
        or existing.idempotency_key_digest != candidate.idempotency_key_digest
    ):
        raise ProviderContractError("idempotency lookup used a different customer or key")
    if existing.request_digest != candidate.request_digest:
        raise ProviderContractError(
            "idempotency key was reused with changed request bytes",
            ProviderRejectionCode.IDEMPOTENCY_CONFLICT,
        )
    return IdempotencyDecision.REPLAY, existing
