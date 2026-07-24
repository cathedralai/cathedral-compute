"""Full-provenance verification and recomputation for the SN39 weight vector.

The thin validator (in the subnet repo) fetches Cathedral's signed weight
vector and checks its signature, key identity, network/netuid, freshness,
policy identity, hotkey mapping, and forced-burn policy before submitting. It
trusts that the numbers inside the signed vector were themselves derived
correctly.

Full-provenance mode does not take that on trust. Given the public, signed,
content-addressed evidence for an epoch, it independently:

  * verifies the signed policy registry (Ed25519, monotonic release, validity);
  * verifies the signed score-class report against that registry
    (domain-separated report signature, report-id binding, key id, embedded
    policy_digest and verifier_digest, validity window, previous_report_id
    chain continuity);
  * verifies every referenced assurance receipt against the registry
    (canonical form, id binding, registry release+digest, validity window,
    measurement in an approved profile, receipt signature, work-unit binding);
  * recomputes each miner's share under the *versioned reward mechanism*
    deterministically from the verified work units;
  * and compares that recomputation against Cathedral's signed vector.

It NEVER treats a self-reported hardware string, a bare Cathedral assertion, or
a stale artifact as provenance. Every positive weight it would assign traces to
a verified receipt whose measurement is in the signed registry and whose work
status is "passed".

This module is transport-agnostic: callers supply already-fetched bytes. The
evidence store/CLI and the two-mode validator handle fetching and
content-addressing.
"""

from __future__ import annotations

import base64
import hashlib
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from cathedral.policy_registry import (
    PolicyRegistryError,
    PolicyRegistrySnapshot,
    canonical_json,
    parse_registry_json,
    verify_registry,
)
from cathedral.receipt import ReceiptError, parse_receipt_json, verify_receipt

REPORT_SCHEMA = "cathedral_score_class_report_v2"
RECEIPT_SCHEMA = "cathedral_assurance_receipt_v2"
_SNAPSHOT_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SNAPSHOT_HASH_RE = re.compile(r"^[0-9a-f]{64}$")

# Domain separation MUST match cathedral.score_class exactly; a report signed
# there is only verifiable here with the same prefixes.
REPORT_DOMAIN = b"cathedral-score-class-report-v1\x00"
REPORT_ID_DOMAIN = b"cathedral-score-class-id-v1\x00"

_REPORT_KEYS = frozenset(
    {
        "schema",
        "network",
        "netuid",
        "class_id",
        "source_id",
        "source_epoch",
        "generated_at",
        "valid_until",
        "valid_from_block",
        "valid_until_block",
        "complete",
        "policy_digest",
        "verifier_digest",
        "previous_report_id",
        "candidate_snapshot",
        "entries",
        "signing_key_id",
        "report_id",
        "signature",
    }
)
_ENTRY_KEYS = frozenset({"miner_hotkey", "metrics", "asserted_score", "reason_codes", "evidence"})


class ProvenanceError(Exception):
    """A provenance check failed. Full-provenance fails closed on any of these."""


# Assurance levels. Receipt/report recomputation alone is PARTIAL provenance:
# it proves Cathedral's signed statements are internally consistent, nothing
# more. Only a successful raw-evidence replay through the pinned verifier
# yields FULL provenance, and only FULL may ever be a submission authority.
ASSURANCE_FULL = "full"
ASSURANCE_RECEIPTS_ONLY = "receipts_only"


@dataclass(frozen=True)
class MinerProvenance:
    hotkey: str
    verified_work_units: Decimal
    receipt_id: str | None
    receipt_digest: str | None
    reason_codes: tuple[str, ...]
    receipt_verified: bool
    measurement: str | None = None
    issued_at: str | None = None
    hardware_evidence_digest: str | None = None
    work_verified: bool = False
    raw_verified: bool = False


@dataclass
class ProvenanceResult:
    report_id: str
    previous_report_id: str | None
    signing_key_id: str
    policy_release: int
    policy_digest: str
    verifier_digest: str
    mechanism_id: str
    source_epoch: int
    generated_at: str
    valid_until: str
    mechanism_revision: int = 1
    assurance_level: str = ASSURANCE_RECEIPTS_ONLY
    # Why a receipts_only result could not reach FULL (surfaced in the
    # NOT_PROVEN event/audit); empty for FULL results.
    not_proven_reasons: tuple[str, ...] = ()
    # The report's SIGNED candidate-snapshot binding ({digest, block,
    # block_hash, hotkeys}); the independent-oracle gate in
    # replay_positive_miners compares externally captured chain state
    # against exactly this.
    candidate_snapshot: dict[str, Any] | None = None
    miners: list[MinerProvenance] = field(default_factory=list)
    # Per-hotkey recomputed share BEFORE UID mapping and burn, summing to 1.0
    # across positive miners (or empty if no positive verified supply).
    recomputed_hotkey_weights: dict[str, float] = field(default_factory=dict)

    @property
    def positive_hotkeys(self) -> tuple[str, ...]:
        return tuple(sorted(self.recomputed_hotkey_weights))


def _digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ProvenanceError(f"{label} is not a string timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")  # noqa: DTZ007 - intentional fail-closed/UTC-text semantics
    except ValueError as exc:
        raise ProvenanceError(f"{label} is not a UTC report timestamp") from exc
    return parsed.replace(tzinfo=UTC)


def load_registry(
    registry_bytes: bytes,
    trusted_keys: Mapping[str, bytes],
    *,
    now: datetime | None = None,
    max_age_seconds: int = 86400,
) -> PolicyRegistrySnapshot:
    """Verify the signed policy registry and return its snapshot."""
    try:
        return verify_registry(
            registry_bytes,
            dict(trusted_keys),
            now=now,
            max_age_seconds=max_age_seconds,
        )
    except PolicyRegistryError as exc:
        raise ProvenanceError(f"policy registry failed verification: {exc}") from exc


# ---------------------------------------------------------------------------
# Versioned reward mechanisms
# ---------------------------------------------------------------------------
#
# A mechanism converts receipt-verified per-miner work into pre-burn hotkey
# shares. Mechanisms are identified by a frozen, versioned id; any change to
# the derivation MUST introduce a new id so an independent validator can pin
# exactly what it recomputes. The signed evidence manifest carries the id.


def _mechanism_validated_supply_v1(
    positive: list[tuple[str, Decimal]],
) -> dict[str, float]:
    """validated_supply_v1: verified miners share the external mass in
    proportion to their receipt-verified work units.

    This is byte-equivalent to the production pipeline (runtime score
    normalization by max, then publisher normalization over the sum): the
    max factor cancels, leaving units / sum(units). With equal units the
    result is an equal split. The 10% forced-burn floor is NOT applied here;
    it is applied at UID-mapping time from the signed vector's burn snapshot
    and separately validated by the validated_supply_v1 vector contract.
    """
    total = sum((units for _, units in positive), Decimal(0))
    if total <= 0:
        return {}
    return {hotkey: float(units / total) for hotkey, units in positive}


MECHANISMS: dict[str, Callable[[list[tuple[str, Decimal]]], dict[str, float]]] = {
    "validated_supply_v1": _mechanism_validated_supply_v1,
}

# Production dispatch is on the exact (id, revision) PAIR: the manifest's
# reward_mechanism carries both, and an independent validator recomputes only
# a pair frozen here. Any derivation change bumps the revision (or the id),
# so an unsupported pair fails BEFORE any recomputation or fence reservation.
MECHANISM_REVISIONS: dict[str, int] = {
    "validated_supply_v1": 1,
}


# ---------------------------------------------------------------------------
# Report verification
# ---------------------------------------------------------------------------


def _verify_report_signature(document: Mapping[str, Any], public_key: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    signature = document.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        raise ProvenanceError("score report signature is missing or not ed25519")
    value = signature.get("value_base64")
    if not isinstance(value, str):
        raise ProvenanceError("score report signature value is missing")
    try:
        raw_signature = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ProvenanceError("score report signature is not valid base64") from exc

    # report_id must bind the exact signed material (domain-separated).
    id_material = {k: v for k, v in document.items() if k not in {"report_id", "signature"}}
    expected_id = (
        "sha256:" + hashlib.sha256(REPORT_ID_DOMAIN + canonical_json(id_material)).hexdigest()
    )
    if document.get("report_id") != expected_id:
        raise ProvenanceError("score report id does not bind its signed body")

    body = {k: v for k, v in document.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            raw_signature, REPORT_DOMAIN + canonical_json(body)
        )
    except (InvalidSignature, ValueError) as exc:
        raise ProvenanceError("score report signature is invalid") from exc


def verify_report_structure(
    report_bytes: bytes,
    *,
    registry: PolicyRegistrySnapshot,
    expected_network: str,
    expected_netuid: int,
    expected_verifier_digest: str,
    report_signing_keys: Mapping[str, bytes],
    expected_previous_report_id: str | None = None,
    enforce_chain: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify the score-class report signature, key identity, and bindings.

    Returns the parsed report document on success; raises ProvenanceError on
    any failure. The report's embedded policy_digest must match the supplied
    registry, and verifier_digest must match what the operator pins. When
    ``enforce_chain`` is true, ``previous_report_id`` must equal
    ``expected_previous_report_id`` exactly (including None for a chain head).
    """
    try:
        document = parse_registry_json(report_bytes)  # strict parser, reused
    except PolicyRegistryError as exc:
        raise ProvenanceError(f"score report is not strict JSON: {exc}") from exc
    if canonical_json(document) != report_bytes:
        raise ProvenanceError("score report bytes are not canonical JSON")
    if frozenset(document) != _REPORT_KEYS:
        raise ProvenanceError("score report has missing or unknown fields")
    if document.get("schema") != REPORT_SCHEMA:
        raise ProvenanceError("score report has the wrong schema")
    if document.get("network") != expected_network or document.get("netuid") != expected_netuid:
        raise ProvenanceError("score report network/netuid does not match this validator")
    if document.get("complete") is not True:
        raise ProvenanceError("score report is not marked complete")

    source_epoch = document.get("source_epoch")
    if isinstance(source_epoch, bool) or not isinstance(source_epoch, int) or source_epoch < 0:
        raise ProvenanceError("score report source_epoch is invalid")

    generated_at = _parse_utc(document.get("generated_at"), "score report generated_at")
    valid_until = _parse_utc(document.get("valid_until"), "score report valid_until")
    if generated_at >= valid_until:
        raise ProvenanceError("score report validity window is empty")
    moment = now if now is not None else datetime.now(UTC)
    if moment >= valid_until:
        raise ProvenanceError("score report is stale (valid_until has passed)")
    if generated_at > moment:
        raise ProvenanceError("score report generated_at is in the future")

    from_block = document.get("valid_from_block")
    until_block = document.get("valid_until_block")
    if (
        isinstance(from_block, bool)
        or isinstance(until_block, bool)
        or not isinstance(from_block, int)
        or not isinstance(until_block, int)
        or from_block < 0
        or until_block <= from_block
    ):
        raise ProvenanceError("score report block window is invalid")

    policy_digest = document.get("policy_digest")
    if policy_digest != registry.digest:
        raise ProvenanceError(
            "score report policy_digest does not match the verified policy registry"
        )
    verifier_digest = document.get("verifier_digest")
    if verifier_digest != expected_verifier_digest:
        raise ProvenanceError(
            "score report verifier_digest does not match the pinned production verifier"
        )

    snapshot = document.get("candidate_snapshot")
    if not isinstance(snapshot, dict) or frozenset(snapshot) != {
        "digest",
        "block",
        "block_hash",
        "hotkeys",
    }:
        raise ProvenanceError("score report candidate_snapshot has missing or unknown fields")
    if (
        not isinstance(snapshot["digest"], str)
        or _SNAPSHOT_DIGEST_RE.fullmatch(snapshot["digest"]) is None
    ):
        raise ProvenanceError("score report candidate_snapshot digest is invalid")
    snapshot_block = snapshot["block"]
    if (
        isinstance(snapshot_block, bool)
        or not isinstance(snapshot_block, int)
        or snapshot_block < 0
    ):
        raise ProvenanceError("score report candidate_snapshot block is invalid")
    if (
        not isinstance(snapshot["block_hash"], str)
        or _SNAPSHOT_HASH_RE.fullmatch(snapshot["block_hash"]) is None
    ):
        raise ProvenanceError("score report candidate_snapshot block hash is invalid")
    if int(from_block) < snapshot_block:
        raise ProvenanceError(
            "score report valid_from_block precedes the anchored candidate "
            "snapshot block; the validity window cannot start before the "
            "finalized state the report was derived from"
        )
    snapshot_hotkeys = snapshot["hotkeys"]
    if (
        not isinstance(snapshot_hotkeys, list)
        or any(not isinstance(hotkey, str) or not hotkey for hotkey in snapshot_hotkeys)
        or len(set(snapshot_hotkeys)) != len(snapshot_hotkeys)
        or sorted(snapshot_hotkeys) != snapshot_hotkeys
    ):
        raise ProvenanceError(
            "score report candidate_snapshot hotkeys must be a sorted duplicate-free list"
        )

    previous = document.get("previous_report_id")
    if previous is not None and not isinstance(previous, str):
        raise ProvenanceError("score report previous_report_id is invalid")
    if enforce_chain and previous != expected_previous_report_id:
        raise ProvenanceError("score report previous_report_id breaks the recorded export chain")

    key_id = document.get("signing_key_id")
    if not isinstance(key_id, str) or key_id not in report_signing_keys:
        raise ProvenanceError("score report is signed by an unknown key id")
    _verify_report_signature(document, report_signing_keys[key_id])
    return document


def _entry_units(entry: Mapping[str, Any], hotkey: str) -> Decimal:
    metrics = entry.get("metrics")
    if not isinstance(metrics, dict):
        raise ProvenanceError(f"score report entry for {hotkey!r} has no metrics")
    units_text = metrics.get("verified_work_units")
    if not isinstance(units_text, str):
        raise ProvenanceError(f"verified_work_units for {hotkey!r} must be a string")
    try:
        units = Decimal(units_text)
    except (InvalidOperation, ValueError) as exc:
        raise ProvenanceError(f"invalid verified_work_units for {hotkey!r}") from exc
    if not units.is_finite() or units < 0:
        raise ProvenanceError(f"invalid verified_work_units for {hotkey!r}")
    return units


def verify_and_recompute(
    *,
    report_bytes: bytes,
    receipts_by_id: Mapping[str, bytes],
    registry_bytes: bytes,
    trusted_registry_keys: Mapping[str, bytes],
    report_signing_keys: Mapping[str, bytes],
    expected_network: str,
    expected_netuid: int,
    expected_verifier_digest: str,
    mechanism_id: str = "validated_supply_v1",
    mechanism_revision: int = 1,
    expected_previous_report_id: str | None = None,
    enforce_chain: bool = False,
    now: datetime | None = None,
    registry_max_age_seconds: int = 86400,
    candidate_set: Mapping[str, Any] | None = None,
    work_artifacts_by_receipt: Mapping[str, tuple[bytes, bytes]] | None = None,
    expected_class_id: str = "confidential_compute",
    expected_source_id: str = "cathedralconfidential",
    current_block: int | None = None,
) -> ProvenanceResult:
    """Independently verify the full published evidence chain and recompute.

    All key material is public. ``receipts_by_id`` maps each receipt id
    referenced by the report to its content-addressed bytes; a missing or
    digest-mismatched receipt for a positive miner fails closed.
    """
    mechanism = MECHANISMS.get(mechanism_id)
    pinned_revision = MECHANISM_REVISIONS.get(mechanism_id)
    if mechanism is None or pinned_revision is None:
        raise ProvenanceError(
            f"unknown reward mechanism {mechanism_id!r}; this validator only "
            f"recomputes {sorted(MECHANISMS)}"
        )
    if (
        isinstance(mechanism_revision, bool)
        or not isinstance(mechanism_revision, int)
        or mechanism_revision != pinned_revision
    ):
        raise ProvenanceError(
            f"unsupported mechanism pair ({mechanism_id!r}, revision="
            f"{mechanism_revision!r}); this validator recomputes exactly "
            f"({mechanism_id!r}, revision={pinned_revision})"
        )
    registry = load_registry(
        registry_bytes,
        trusted_registry_keys,
        now=now,
        max_age_seconds=registry_max_age_seconds,
    )
    document = verify_report_structure(
        report_bytes,
        registry=registry,
        expected_network=expected_network,
        expected_netuid=expected_netuid,
        expected_verifier_digest=expected_verifier_digest,
        report_signing_keys=report_signing_keys,
        expected_previous_report_id=expected_previous_report_id,
        enforce_chain=enforce_chain,
        now=now,
    )

    if (
        document.get("class_id") != expected_class_id
        or document.get("source_id") != expected_source_id
    ):
        raise ProvenanceError("score report class/source identity does not match the operator pins")
    if current_block is not None and not (
        int(document["valid_from_block"]) <= int(current_block) < int(document["valid_until_block"])
    ):
        raise ProvenanceError("current finalized block is outside the report's validity window")
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise ProvenanceError("score report has no entries list")

    # Exhaustive candidate accounting: the report's OWN signed snapshot
    # binding must exactly cover its entries (every historical candidate has
    # an explicit row; no entry outside the anchored set), and the manifest's
    # candidate_set must be the SAME anchored snapshot — identical block,
    # hash, and hotkey set. Report, manifest, and recomputation therefore
    # always range over one identical candidate universe.
    bound_snapshot = document["candidate_snapshot"]
    bound_hotkeys = set(bound_snapshot["hotkeys"])
    report_hotkeys = {entry.get("miner_hotkey") for entry in entries if isinstance(entry, dict)}
    omitted = bound_hotkeys - report_hotkeys
    if omitted:
        raise ProvenanceError(f"report omits anchored snapshot candidates: {sorted(omitted)}")
    stray = report_hotkeys - bound_hotkeys
    if stray:
        raise ProvenanceError(
            f"report carries entries outside its anchored snapshot: {sorted(stray)}"
        )

    candidate_outcomes: dict[str, str] = {}
    if candidate_set is not None:
        for row in candidate_set.get("candidates", []):
            candidate_outcomes[str(row["hotkey"])] = str(row["outcome"])
        manifest_hotkeys = set(candidate_outcomes)
        if manifest_hotkeys != bound_hotkeys:
            drift = sorted(manifest_hotkeys ^ bound_hotkeys)
            raise ProvenanceError(
                "manifest candidate_set does not equal the report's anchored "
                f"snapshot hotkey set (drift: {drift})"
            )
        manifest_hash = str(candidate_set.get("block_hash", "")).lower().removeprefix("0x")
        if (
            int(candidate_set.get("block", -1)) != int(bound_snapshot["block"])
            or manifest_hash != bound_snapshot["block_hash"]
        ):
            raise ProvenanceError(
                "manifest candidate_set block/hash does not match the report's anchored snapshot"
            )

    miners: list[MinerProvenance] = []
    positive: list[tuple[str, Decimal]] = []
    seen_hotkeys: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or frozenset(entry) != _ENTRY_KEYS:
            raise ProvenanceError("score report entry has missing or unknown fields")
        hotkey = entry.get("miner_hotkey")
        if not isinstance(hotkey, str) or not hotkey:
            raise ProvenanceError("score report entry has an invalid hotkey")
        if hotkey in seen_hotkeys:
            raise ProvenanceError(f"score report has a duplicate entry for {hotkey!r}")
        seen_hotkeys.add(hotkey)
        units = _entry_units(entry, hotkey)
        reasons_raw = entry.get("reason_codes")
        if not isinstance(reasons_raw, list) or not all(
            isinstance(reason, str) for reason in reasons_raw
        ):
            raise ProvenanceError(f"score report entry for {hotkey!r} has bad reasons")
        reasons = tuple(reasons_raw)
        evidence = entry.get("evidence")
        if not isinstance(evidence, list):
            raise ProvenanceError(f"score report entry for {hotkey!r} has bad evidence")

        receipt_id = None
        receipt_digest = None
        receipt_verified = False
        if candidate_outcomes:
            outcome = candidate_outcomes.get(hotkey)
            if units > 0 and outcome != "verified":
                raise ProvenanceError(f"positive entry {hotkey!r} is not a verified candidate")
            if units == 0 and outcome == "verified":
                raise ProvenanceError(f"verified candidate {hotkey!r} carries no verified work")
        if units > 0:
            # A positive miner must carry exactly one verifiable receipt.
            if len(evidence) != 1 or not isinstance(evidence[0], dict):
                raise ProvenanceError(
                    f"positive miner {hotkey!r} must carry exactly one receipt reference"
                )
            ref = evidence[0]
            if ref.get("kind") != RECEIPT_SCHEMA:
                raise ProvenanceError(
                    f"positive miner {hotkey!r} evidence kind is not {RECEIPT_SCHEMA}"
                )
            receipt_id = ref.get("id")
            receipt_digest = ref.get("digest")
            if not isinstance(receipt_id, str) or not isinstance(receipt_digest, str):
                raise ProvenanceError(f"positive miner {hotkey!r} has malformed evidence")
            body = receipts_by_id.get(receipt_id)
            if body is None:
                raise ProvenanceError(f"receipt {receipt_id} for {hotkey!r} was not provided")
            if _digest_bytes(body) != receipt_digest:
                raise ProvenanceError(f"receipt {receipt_id} content does not match its digest")
            # Full receipt verification against the signed registry: signature,
            # id binding, registry release+digest, validity window, measurement
            # in an approved profile.
            try:
                verify_receipt(body, registry)
            except ReceiptError as exc:
                raise ProvenanceError(f"receipt {receipt_id} failed verification: {exc}") from exc
            parsed = parse_receipt_json(body)
            if parsed.get("receipt_id") != receipt_id:
                raise ProvenanceError(f"receipt {receipt_id} id mismatch")
            if parsed.get("subject_hotkey") != hotkey:
                raise ProvenanceError(f"receipt {receipt_id} subject hotkey mismatch")
            if parsed.get("source_epoch") != document["source_epoch"]:
                raise ProvenanceError(
                    f"receipt {receipt_id} source epoch does not match the report"
                )
            work = parsed.get("work")
            if not isinstance(work, dict) or work.get("status") != "passed":
                raise ProvenanceError(f"receipt {receipt_id} work status is not passed")
            try:
                receipt_units = Decimal(str(work.get("work_units")))
            except (InvalidOperation, ValueError) as exc:
                raise ProvenanceError(f"receipt {receipt_id} work units are invalid") from exc
            if receipt_units != units:
                raise ProvenanceError(
                    f"receipt {receipt_id} work units {receipt_units} != report units {units}"
                )
            receipt_verified = True
            work_verified = False
            receipt_work = parsed.get("work") or {}
            if work_artifacts_by_receipt is not None:
                artifacts = work_artifacts_by_receipt.get(receipt_id)
                if artifacts is None:
                    raise ProvenanceError(
                        f"no published work artifacts for {receipt_id!r}; a "
                        "signer-only work assertion never earns"
                    )
                from cathedral.workproof import WorkProofError, verify_work_artifacts

                try:
                    verify_work_artifacts(
                        artifacts[0],
                        artifacts[1],
                        expected_manifest_digest=str(receipt_work.get("manifest_digest")),
                        expected_result_digest=str(receipt_work.get("result_digest")),
                        expected_challenge_id=str(receipt_work.get("challenge_id")),
                        expected_hotkey=hotkey,
                        expected_units=units,
                    )
                except WorkProofError as exc:
                    raise ProvenanceError(
                        f"independent work replay failed for {hotkey!r}: {exc}"
                    ) from exc
                work_verified = True
            receipt_measurement = parsed.get("measurement")
            receipt_issued_at = parsed.get("issued_at")
            receipt_hardware = ((parsed.get("assurance") or {}).get("claims") or {}).get(
                "hardware"
            ) or {}
            receipt_quote_digest = receipt_hardware.get("evidence_digest")
            positive.append((hotkey, units))
        else:
            work_verified = False
            receipt_measurement = None
            receipt_issued_at = None
            receipt_quote_digest = None
            if evidence:
                raise ProvenanceError(
                    f"zero-scored miner {hotkey!r} must not carry receipt evidence"
                )

        miners.append(
            MinerProvenance(
                hotkey=hotkey,
                verified_work_units=units,
                receipt_id=receipt_id,
                receipt_digest=receipt_digest,
                reason_codes=reasons,
                receipt_verified=receipt_verified,
                measurement=(receipt_measurement if isinstance(receipt_measurement, str) else None),
                issued_at=(receipt_issued_at if isinstance(receipt_issued_at, str) else None),
                hardware_evidence_digest=(
                    receipt_quote_digest if isinstance(receipt_quote_digest, str) else None
                ),
                work_verified=work_verified,
            )
        )

    recomputed = mechanism(positive)

    return ProvenanceResult(
        report_id=str(document["report_id"]),
        previous_report_id=document.get("previous_report_id"),
        signing_key_id=str(document["signing_key_id"]),
        policy_release=registry.release,
        policy_digest=registry.digest,
        verifier_digest=expected_verifier_digest,
        mechanism_id=mechanism_id,
        mechanism_revision=pinned_revision,
        source_epoch=int(document["source_epoch"]),
        generated_at=str(document["generated_at"]),
        valid_until=str(document["valid_until"]),
        candidate_snapshot=dict(document["candidate_snapshot"]),
        miners=miners,
        recomputed_hotkey_weights=recomputed,
    )


_VECTOR_ROW_FIELDS = frozenset(
    {"miner_hotkey", "weight", "base_component", "external_component", "uid"}
)
_VECTOR_ROW_REQUIRED = ("weight", "base_component", "external_component")
# The REAL signed subnet burn snapshot (scaffold/publisher/weights.py
# build_signed_vector + scaffold/validator_thin.py _validated_supply_meta):
# ``burn_uid`` is explicitly null (validators resolve the burn HOTKEY against
# the live metagraph and reject pinned historical UIDs), ``burn_hotkey`` is
# the nonempty configured destination, and ``forced_burn_percentage`` is the
# fixed 10.0 — for EVERY epoch shape. A zero-supply epoch keeps the signed
# 10% and burns 100% at UID-mapping time because no positive rows exist.
_BURN_SNAPSHOT_FIELDS = frozenset({"burn_uid", "burn_hotkey", "forced_burn_percentage"})
_VALIDATED_SUPPLY_POLICY_FIELDS = frozenset(
    {
        "contract_version",
        "intel_tdx_allocation",
        "verified_gpu_allocation",
        "verified_gpu_admitted",
        "burn_hotkey",
    }
)
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

# The validated_supply_v1 burn contract (docs/BUDGET.md): a FIXED 10% burn to
# the configured burn destination. The floor is part of the versioned
# mechanism id; changing it requires a new mechanism version pinned
# everywhere. The subnet validator enforces the same 10.0 exactly.
VALIDATED_SUPPLY_V1_BURN_FRACTION = 0.10
VALIDATED_SUPPLY_V1_BURN_PERCENTAGE = 10.0
VALIDATED_SUPPLY_V1_TDX_ALLOCATION = 0.90
VALIDATED_SUPPLY_V1_GPU_ALLOCATION = 0.10
VALIDATED_SUPPLY_CONTRACT_VERSION = "v1"
CONFIDENTIAL_SOURCE = "cathedral_confidential_tdx"
CONFIDENTIAL_SCORE_SOURCE = "confidential_primary:cathedral_confidential_tdx"


def _row_component(row: Mapping[str, Any], hotkey: str, name: str) -> float | str:
    """Return the validated finite nonnegative component, or an error note."""
    if name not in row:
        return f"signed vector row for {hotkey!r} lacks an explicit {name}"
    value = row[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return f"signed vector row for {hotkey!r} is not numeric ({name})"
    number = float(value)
    if not math.isfinite(number):
        return f"signed vector row for {hotkey!r} is non-finite ({name})"
    if number < 0.0:
        return f"signed vector row for {hotkey!r} is negative ({name})"
    return number


def _policy_number(value: object) -> float | None:
    """A finite float from signed policy metadata, or None when malformed."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _normalized_sha256_hex(value: object) -> str | None:
    """Lowercase 64-hex (optionally ``sha256:``-prefixed), or None."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower().removeprefix("sha256:")
    return text if _SHA256_HEX_RE.fullmatch(text) else None


def compare_with_vector(
    result: ProvenanceResult,
    signed_vector: Mapping[str, Any],
    *,
    wire_report_sha256: str | None = None,
    abs_tol: float = 1e-9,
) -> tuple[bool, list[str]]:
    """Validate the signed vector's complete ``validated_supply_v1`` contract
    against the REAL subnet wire shape and compare its confidential shares
    with the recomputation. Returns ``(agree, discrepancies)``.

    The contract is read from the actual producer/consumer pair
    (``scaffold/publisher/weights.py`` / ``scaffold/validator_thin.py``):

      * rows are PRE-burn: base_component is exactly 0, weight equals
        external_component, and positive supply sums to 1.0 — the subnet
        validator applies the 10% burn afterwards at UID-mapping time;
      * ``burn_snapshot`` is exactly ``{burn_uid: null, burn_hotkey,
        forced_burn_percentage: 10.0}`` for EVERY epoch shape — validators
        resolve the burn HOTKEY against the live metagraph, and a pinned
        historical integer burn uid is rejected, never required;
      * ``policy_metadata.validated_supply`` is the signed launch-locked
        90/10 block (contract v1, 0.90 Intel TDX, 0.10 Verified GPU, GPU
        not admitted, burn_hotkey matching the snapshot) and
        ``policy_metadata.confidential_primary`` must assert the epoch's
        confidential mass consistently;
      * the burn hotkey must never be reused as a paying miner hotkey.

    Epoch/report binding (fail-closed): agreement additionally requires the
    SIGNED ``policy_metadata.external_scores`` block to bind this exact
    verified epoch — ``latest_epoch`` equal to the evidence source_epoch and
    ``latest_complete`` true, backed by the publisher's one-report-per-epoch
    ingest immutability. ``wire_report_sha256`` (the evidence manifest's
    digest of the ingested wire report) is REQUIRED; when the signed block
    also carries ``latest_body_sha256`` (the raw ingest body digest — see
    docs/PROVENANCE.md for the subnet pin-advance) it must equal it. Same
    proportions NEVER prove the same epoch on their own.
    """
    if result.mechanism_id != "validated_supply_v1" or result.mechanism_revision != 1:
        return False, [
            (
                f"unsupported mechanism pair ({result.mechanism_id!r}, revision="
                f"{result.mechanism_revision!r}): this comparison validates the "
                "(validated_supply_v1, revision=1) vector contract only"
            )
        ]
    vector_rows = signed_vector.get("weights")
    if not isinstance(vector_rows, list):
        return False, ["signed vector has no weights list"]
    # EVERY row is validated BEFORE any comparison: a non-finite, negative,
    # duplicate, structurally malformed, unknown-field, or component-less row
    # fails the comparison outright - it can never be silently discarded
    # into "agreement".
    vector_ext: dict[str, float] = {}
    seen_hotkeys: set[str] = set()
    seen_uids: set[int] = set()
    total_weight = 0.0
    total_base = 0.0
    total_external = 0.0
    for row in vector_rows:
        if not isinstance(row, Mapping):
            return False, ["signed vector weight row is not an object"]
        unknown = {str(key) for key in row} - _VECTOR_ROW_FIELDS
        if unknown:
            return False, [f"signed vector row carries unknown fields: {sorted(unknown)}"]
        hotkey = row.get("miner_hotkey")
        if not isinstance(hotkey, str) or not hotkey:
            return False, ["signed vector weight row has no miner_hotkey"]
        if hotkey in seen_hotkeys:
            return False, [f"signed vector duplicates hotkey {hotkey!r}"]
        seen_hotkeys.add(hotkey)
        components: dict[str, float] = {}
        for name in _VECTOR_ROW_REQUIRED:
            value = _row_component(row, hotkey, name)
            if isinstance(value, str):
                return False, [value]
            components[name] = value
        weight = components["weight"]
        base = components["base_component"]
        external = components["external_component"]
        if not math.isclose(weight, base + external, rel_tol=0.0, abs_tol=abs_tol):
            return False, [
                (
                    f"signed vector row for {hotkey!r} does not compose: "
                    f"weight={weight!r} != base_component+external_component="
                    f"{base + external!r}"
                )
            ]
        if base != 0.0:
            return False, [
                (
                    f"signed vector row for {hotkey!r} has base_component "
                    f"{base!r}; under validated_supply_v1 the base share is "
                    "exactly zero (confidential_primary rows only)"
                )
            ]
        if "uid" in row:
            uid = row["uid"]
            if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
                return False, [f"signed vector row for {hotkey!r} has an invalid uid"]
            if uid in seen_uids:
                return False, [f"signed vector duplicates uid {uid}"]
            seen_uids.add(uid)
        total_weight += weight
        total_base += base
        total_external += external
        if external > 0.0:
            vector_ext[hotkey] = external

    # The signed validated_supply_v1 burn snapshot: the REAL wire grammar.
    burn_snapshot = signed_vector.get("burn_snapshot")
    if not isinstance(burn_snapshot, Mapping) or frozenset(burn_snapshot) != _BURN_SNAPSHOT_FIELDS:
        return False, [
            (
                "signed vector burn_snapshot is missing or malformed (exactly "
                "burn_uid, burn_hotkey, and forced_burn_percentage are required)"
            )
        ]
    if burn_snapshot["burn_uid"] is not None:
        return False, [
            (
                "signed vector burn_uid must be null: validated_supply_v1 "
                "resolves the burn destination by hotkey against the live "
                "metagraph, and validators reject a pinned historical burn uid"
            )
        ]
    burn_hotkey = burn_snapshot["burn_hotkey"]
    if not isinstance(burn_hotkey, str) or not burn_hotkey:
        return False, [
            ("signed vector burn_hotkey must be the nonempty configured burn destination hotkey")
        ]
    percentage = burn_snapshot["forced_burn_percentage"]
    if isinstance(percentage, bool) or not isinstance(percentage, (int, float)):
        return False, ["signed vector forced_burn_percentage is not numeric"]
    if not math.isclose(
        float(percentage), VALIDATED_SUPPLY_V1_BURN_PERCENTAGE, rel_tol=0.0, abs_tol=abs_tol
    ):
        return False, [
            (
                f"signed vector forced_burn_percentage {percentage!r} violates "
                f"the fixed validated_supply_v1 floor "
                f"{VALIDATED_SUPPLY_V1_BURN_PERCENTAGE:.1f} (signed for every "
                "epoch shape; a zero-supply epoch burns 100% because no "
                "positive rows exist)"
            )
        ]

    # The signed launch-locked policy blocks, exactly as the subnet
    # validator's validated_supply_v1 pin enforces them.
    metadata = signed_vector.get("policy_metadata")
    if not isinstance(metadata, Mapping):
        return False, [
            (
                "signed vector carries no policy_metadata; the "
                "validated_supply_v1 contract requires the signed "
                "validated_supply, confidential_primary, and external_scores "
                "policy blocks"
            )
        ]
    supply_policy = metadata.get("validated_supply")
    if not isinstance(supply_policy, Mapping):
        return False, ["signed vector policy_metadata.validated_supply block is missing"]
    if frozenset(supply_policy) != _VALIDATED_SUPPLY_POLICY_FIELDS:
        return False, ["signed vector validated_supply policy fields mismatch"]
    if supply_policy["contract_version"] != VALIDATED_SUPPLY_CONTRACT_VERSION:
        return False, [
            (
                "signed vector validated_supply contract_version "
                f"{supply_policy['contract_version']!r} is unsupported (v1 only)"
            )
        ]
    tdx_allocation = _policy_number(supply_policy["intel_tdx_allocation"])
    gpu_allocation = _policy_number(supply_policy["verified_gpu_allocation"])
    if (
        tdx_allocation is None
        or gpu_allocation is None
        or not math.isclose(
            tdx_allocation, VALIDATED_SUPPLY_V1_TDX_ALLOCATION, rel_tol=0.0, abs_tol=abs_tol
        )
        or not math.isclose(
            gpu_allocation, VALIDATED_SUPPLY_V1_GPU_ALLOCATION, rel_tol=0.0, abs_tol=abs_tol
        )
        or not math.isclose(tdx_allocation + gpu_allocation, 1.0, rel_tol=0.0, abs_tol=abs_tol)
    ):
        return False, [
            (
                "signed vector validated_supply allocations must be exactly "
                "0.90 Intel TDX + 0.10 Verified GPU"
            )
        ]
    if supply_policy["verified_gpu_admitted"] is not False:
        return False, ["signed vector validated_supply v1 cannot admit the Verified GPU class"]
    if supply_policy["burn_hotkey"] != burn_hotkey:
        return False, [
            (
                "signed vector validated_supply burn_hotkey does not match "
                "the burn_snapshot destination"
            )
        ]

    recomputed = result.recomputed_hotkey_weights
    confidential = metadata.get("confidential_primary")
    if not isinstance(confidential, Mapping):
        return False, [
            (
                "signed vector policy_metadata.confidential_primary block is "
                "missing; the validated_supply_v1 pin requires "
                "confidential_primary evidence"
            )
        ]
    if confidential.get("contract_version") != "v1":
        return False, ["signed vector confidential_primary contract_version is unsupported"]
    if confidential.get("source") != CONFIDENTIAL_SOURCE:
        return False, [f"signed vector confidential_primary source is not {CONFIDENTIAL_SOURCE}"]
    if _policy_number(confidential.get("base_mass")) != 0.0:
        return False, ["signed vector confidential_primary base_mass must be 0"]
    confidential_mass = _policy_number(confidential.get("confidential_mass"))
    expected_mass = 1.0 if recomputed else 0.0
    if confidential_mass != expected_mass:
        return False, [
            (
                f"signed vector confidential_primary confidential_mass "
                f"{confidential.get('confidential_mass')!r} does not match the "
                f"recomputed epoch supply (expected {expected_mass:.1f})"
            )
        ]
    if recomputed and not (
        confidential.get("mode") == "confidential_primary"
        and confidential.get("complete") is True
        and confidential.get("fresh") is True
        and confidential.get("confirmed") is True
    ):
        return False, [
            (
                "signed vector confidential_primary mass=1 requires "
                "mode=confidential_primary with complete/fresh/confirmed all true"
            )
        ]

    # Epoch/report binding: the SIGNED external_scores status must bind this
    # exact evidence epoch, and the manifest must carry the ingest digest.
    external_status = metadata.get("external_scores")
    if not isinstance(external_status, Mapping):
        return False, ["signed vector policy_metadata.external_scores block is missing"]
    if external_status.get("enabled") is not True:
        return False, ["signed vector external_scores.enabled is not true"]
    if external_status.get("source") != CONFIDENTIAL_SOURCE:
        return False, [f"signed vector external_scores source is not {CONFIDENTIAL_SOURCE}"]
    if external_status.get("mode") != "confidential_primary":
        return False, ["signed vector external_scores mode is not confidential_primary"]
    if external_status.get("latest_complete") is not True:
        return False, [
            (
                "signed vector external_scores.latest_complete is not true; "
                "only a complete ingested snapshot can back the vector"
            )
        ]
    latest_epoch = external_status.get("latest_epoch")
    if isinstance(latest_epoch, bool) or not isinstance(latest_epoch, int):
        return False, ["signed vector external_scores.latest_epoch is not an integer"]
    if int(latest_epoch) != int(result.source_epoch):
        return False, [
            (
                f"signed vector is bound to ingested source epoch "
                f"{latest_epoch}, not the verified evidence epoch "
                f"{result.source_epoch}; same proportions never prove the "
                "same epoch"
            )
        ]
    latest_report_digest = _normalized_sha256_hex(external_status.get("latest_report_sha256"))
    if latest_report_digest is None:
        return False, [
            (
                "signed vector external_scores.latest_report_sha256 is missing "
                "or malformed; the vector must identify its ingested report"
            )
        ]
    manifest_wire_digest = _normalized_sha256_hex(wire_report_sha256)
    if manifest_wire_digest is None:
        return False, [
            (
                "evidence manifest carries no publisher ingest report digest "
                "(wire_report_sha256); the signed vector cannot be bound to "
                "the verified epoch's ingest"
            )
        ]
    body_digest_raw = external_status.get("latest_body_sha256")
    if body_digest_raw is not None:
        body_digest = _normalized_sha256_hex(body_digest_raw)
        if body_digest is None or body_digest != manifest_wire_digest:
            return False, [
                (
                    "signed vector external_scores.latest_body_sha256 does not "
                    "match the evidence manifest's wire_report_sha256; the "
                    "vector was built from a DIFFERENT ingested report body"
                )
            ]
    if metadata.get("score_source") != CONFIDENTIAL_SCORE_SOURCE:
        return False, [f"signed vector score_source is not {CONFIDENTIAL_SCORE_SOURCE}"]

    # The burn destination must never double as a paying miner.
    if burn_hotkey in seen_hotkeys:
        return False, [
            (
                f"signed vector burn hotkey {burn_hotkey!r} is reused as a "
                "miner hotkey; the burn destination must never earn"
            )
        ]

    # Mass invariants for the REAL pre-burn rows: zero base mass always;
    # positive supply sums to exactly 1.0 (the validator applies the burn
    # after UID mapping); zero supply carries zero row mass.
    if not math.isclose(total_base, 0.0, rel_tol=0.0, abs_tol=abs_tol):
        return False, [
            (
                f"signed vector carries non-confidential base mass "
                f"{total_base:.9f}; validated_supply_v1 pays only the "
                "verified confidential class plus the fixed burn"
            )
        ]
    if recomputed:
        if not math.isclose(total_weight, 1.0, rel_tol=0.0, abs_tol=abs_tol):
            return False, [
                (
                    f"signed vector does not conserve emission: pre-burn "
                    f"weights sum to {total_weight:.9f}, not 1.0 (the 10% "
                    "burn is applied at UID-mapping time, never in the rows)"
                )
            ]
        if total_external <= 0.0:
            return False, [
                (
                    "signed vector assigns no confidential external mass while "
                    "the recomputation has verified supply"
                )
            ]
    elif not math.isclose(total_weight, 0.0, rel_tol=0.0, abs_tol=abs_tol):
        return False, [
            (
                f"signed vector carries positive mass {total_weight:.9f} while "
                "the recomputation has no verified supply; every row must be "
                "an explicit zero revocation"
            )
        ]

    # Shares: rows are pre-burn and sum to 1.0, the recomputed unit shares
    # sum to 1.0 — normalize by the external total for exactness and compare
    # symmetrically: an unverified earner and an omitted verified miner are
    # equally discrepancies.
    vector_share = (
        {hotkey: value / total_external for hotkey, value in vector_ext.items()}
        if total_external > 0.0
        else {}
    )
    discrepancies: list[str] = []
    for hotkey in sorted(set(recomputed) | set(vector_share)):
        mine = recomputed.get(hotkey, 0.0)
        theirs = vector_share.get(hotkey, 0.0)
        if not math.isclose(mine, theirs, rel_tol=0.0, abs_tol=abs_tol):
            discrepancies.append(
                f"{hotkey}: recomputed_share={mine:.9f} signed_external_share={theirs:.9f}"
            )
    return (not discrepancies), discrepancies


def replay_positive_miners(
    result: ProvenanceResult,
    *,
    registry: PolicyRegistrySnapshot,
    envelopes_by_hotkey: Mapping[str, bytes],
    attestation_bindings: Mapping[str, Mapping[str, Any]],
    verifier_binary: bytes,
    verifier_blob_digest: str,
    verifier_command: tuple[str, ...],
    verifier_artifacts: tuple[str, ...],
    candidate_outcomes: Mapping[str, str] | None = None,
    epoch_generated_at: str | None = None,
    max_evidence_age_seconds: float = 3600.0,
    deadline_monotonic: float | None = None,
    challenge_anchor: Mapping[str, Any] | None = None,
    independent_candidates: object = None,
    independent_block_hash: str | None = None,
) -> ProvenanceResult:
    """Upgrade a receipts-only result to FULL assurance via raw replay.

    FULL additionally REQUIRES an independent historical candidate oracle:
    ``independent_candidates`` (the exact hotkey set registered on the SN39
    metagraph AT the anchored block, captured by the VERIFIER's own chain
    access) and ``independent_block_hash`` (get_block_hash(block) from the
    same access). Two mutually consistent Cathedral-produced artifacts -
    the signed report and the manifest - are NOT an oracle: they could
    omit a real registered hotkey together. Equality with the report's
    signed snapshot binding is mandatory; a missing, malformed, or
    mismatched oracle fails closed before any replay.

    Every positive miner must have a controlled envelope whose bytes match
    the public manifest's ``envelope_digest``, reproduce the recorded
    evidence digest, and replay cleanly through the CANONICAL strict
    verifier path under the signed-registry policy evaluated at the
    receipt's issue time. Any gap is a hard ProvenanceError — the result is
    never silently left at receipts-only by this path.

    ``candidate_outcomes`` (the manifest's exhaustive per-candidate outcome
    map, hotkey -> verified|rejected|retired) is REQUIRED and gates the
    epoch-level claim: FULL asserts the WHOLE weight decision was
    independently proven, and a ``rejected`` outcome is a Cathedral-signed
    assertion with no independently replayable rejection evidence in the
    launch artifact model. Positive replays still run and are individually
    proven, but ANY active (non-retired) rejected candidate keeps the epoch
    at receipts_only (NOT PROVEN) — a compromised Cathedral rejecting a
    real miner must never be laundered into a FULL vector that inflates
    everyone else. Malformed or inconsistent outcome evidence (unknown
    outcome values, coverage drift against the anchored snapshot, a
    ``verified`` outcome without a verified receipt or vice versa) is a
    hard ProvenanceError, never a downgrade. A retired-only or otherwise
    zero-replay epoch also stays receipts_only, with the pinned verifier
    bytes still authenticated so fake pinned bytes surface here too.
    """
    from dataclasses import replace as dataclass_replace

    from cathedral.challenge import ChallengeError, normalize_block_hash
    from cathedral.replay import ReplayError, authenticate_verifier_bytes, replay_evidence

    bound_snapshot = result.candidate_snapshot
    if not isinstance(bound_snapshot, Mapping):
        raise ProvenanceError(
            "result carries no signed candidate-snapshot binding; verify the "
            "report before attempting a FULL upgrade"
        )
    if independent_candidates is None or independent_block_hash is None:
        raise ProvenanceError(
            "FULL provenance requires the INDEPENDENTLY captured historical "
            "candidate set and block hash for the anchored block; mutually "
            "consistent Cathedral artifacts are not an oracle"
        )
    independent_set = {str(hotkey) for hotkey in independent_candidates}
    if not independent_set or any(not hotkey for hotkey in independent_set):
        raise ProvenanceError("the independent historical candidate set is empty or malformed")
    try:
        normalized_independent_hash = normalize_block_hash(independent_block_hash)
    except ChallengeError as exc:
        raise ProvenanceError(f"the independent block hash is malformed: {exc}") from exc
    if normalized_independent_hash != str(bound_snapshot["block_hash"]):
        raise ProvenanceError(
            "the independently captured block hash does not match the "
            "report's anchored snapshot; a fabricated anchor never reaches FULL"
        )
    bound_hotkeys = set(bound_snapshot["hotkeys"])
    if independent_set != bound_hotkeys:
        omitted = sorted(independent_set - bound_hotkeys)
        fabricated = sorted(bound_hotkeys - independent_set)
        raise ProvenanceError(
            "the report's candidate snapshot does not equal the independent "
            f"historical oracle (omitted from report: {omitted}; not "
            f"registered at the anchored block: {fabricated})"
        )

    # Exhaustive outcome accounting: FULL is an epoch-level claim, so the
    # manifest's per-candidate outcomes must be present, well-formed, cover
    # exactly the anchored snapshot, and agree with the receipt evidence.
    if candidate_outcomes is None:
        raise ProvenanceError(
            "FULL provenance requires the manifest's exhaustive per-candidate "
            "outcomes; without them a rejected candidate cannot be "
            "distinguished from an omitted one"
        )
    outcomes = {str(hotkey): str(outcome) for hotkey, outcome in candidate_outcomes.items()}
    unknown_outcomes = sorted(set(outcomes.values()) - {"verified", "rejected", "retired"})
    if unknown_outcomes:
        raise ProvenanceError(
            f"candidate outcomes carry unknown values {unknown_outcomes}; "
            "malformed outcome evidence is a hard failure"
        )
    if set(outcomes) != bound_hotkeys:
        drift = sorted(set(outcomes) ^ bound_hotkeys)
        raise ProvenanceError(
            "candidate outcomes do not cover exactly the report's anchored "
            f"snapshot hotkeys (drift: {drift})"
        )
    for miner in result.miners:
        outcome = outcomes.get(miner.hotkey)
        if miner.receipt_verified and outcome != "verified":
            raise ProvenanceError(
                f"candidate outcome for {miner.hotkey!r} is {outcome!r} but a "
                "verified receipt backs the entry; inconsistent evidence"
            )
        if not miner.receipt_verified and outcome == "verified":
            raise ProvenanceError(
                f"candidate outcome for {miner.hotkey!r} claims verified "
                "without a verified receipt; inconsistent evidence"
            )

    upgraded: list[MinerProvenance] = []
    replayed_count = 0
    for miner in result.miners:
        if not miner.receipt_verified:
            upgraded.append(miner)
            continue
        replayed_count += 1
        binding = attestation_bindings.get(miner.hotkey)
        if not isinstance(binding, Mapping):
            raise ProvenanceError(f"manifest carries no attestation binding for {miner.hotkey!r}")
        envelope_digest = binding.get("envelope_digest")
        evidence_digest = binding.get("evidence_digest")
        if not isinstance(envelope_digest, str) or not envelope_digest:
            raise ProvenanceError(
                f"no controlled envelope was retained for {miner.hotkey!r}; "
                "full provenance is NOT PROVEN for this epoch"
            )
        if not isinstance(evidence_digest, str) or not evidence_digest:
            raise ProvenanceError(
                f"manifest attestation for {miner.hotkey!r} lacks an evidence digest"
            )
        challenge_digest = binding.get("challenge_digest")
        if not isinstance(challenge_digest, str) or not challenge_digest:
            raise ProvenanceError(
                f"no committed challenge randomness for {miner.hotkey!r}; freshness is NOT PROVEN"
            )
        if challenge_anchor is None:
            raise ProvenanceError(
                "no finalized-block challenge anchor; a derived, publicly "
                "verifiable challenge is required for FULL provenance"
            )
        from cathedral.challenge import expected_challenge_digest

        anchor_block = challenge_anchor.get("block")
        if isinstance(anchor_block, bool) or not isinstance(anchor_block, int):
            raise ProvenanceError(
                "challenge anchor lacks its finalized block height; the v2 "
                "derivation binds height AND hash"
            )
        derived_digest = expected_challenge_digest(
            block=anchor_block,
            block_hash=str(challenge_anchor["block_hash"]),
            network=str(challenge_anchor["network"]),
            netuid=int(challenge_anchor["netuid"]),
            source_epoch=result.source_epoch,
            miner_hotkey=miner.hotkey,
        )
        if derived_digest != challenge_digest:
            raise ProvenanceError(
                f"challenge commitment for {miner.hotkey!r} does not derive "
                "from the anchored finalized block; stale or issuer-chosen "
                "nonces never reach FULL"
            )
        envelope = envelopes_by_hotkey.get(miner.hotkey)
        if envelope is None:
            raise ProvenanceError(f"controlled envelope for {miner.hotkey!r} was not provided")
        if miner.measurement is None or miner.issued_at is None:
            raise ProvenanceError(
                f"receipt for {miner.hotkey!r} lacks measurement/issue-time bindings"
            )
        if epoch_generated_at is None:
            raise ProvenanceError(
                "positive replay requires the manifest epoch time; freshness "
                "windows are never optional"
            )
        if miner.hardware_evidence_digest is None:
            raise ProvenanceError(
                f"receipt for {miner.hotkey!r} carries no hardware evidence digest"
            )
        if not miner.work_verified:
            raise ProvenanceError(
                f"work for {miner.hotkey!r} was not independently replayed; a "
                "valid quote plus a signer-asserted work claim never reaches FULL"
            )
        try:
            issued_at = datetime.strptime(miner.issued_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=UTC
            )
        except ValueError as exc:
            raise ProvenanceError(f"receipt issue time for {miner.hotkey!r} is malformed") from exc
        if epoch_generated_at is not None:
            epoch_moment = _parse_utc(epoch_generated_at, "manifest generated_at")
            age = abs((epoch_moment - issued_at).total_seconds())
            if age > max_evidence_age_seconds:
                raise ProvenanceError(
                    f"evidence for {miner.hotkey!r} is outside the epoch age "
                    f"window ({age:.0f}s > {max_evidence_age_seconds:.0f}s)"
                )
        try:
            # Historical policy: the profile set that was live when the
            # evidence was collected, from the SAME signed registry the
            # receipt binds.
            policy = registry.to_policy(at=issued_at)
        except Exception as exc:
            raise ProvenanceError(
                f"signed registry yields no usable policy at the receipt time: {exc}"
            ) from exc
        timeout_override = None
        if deadline_monotonic is not None:
            import time as time_module

            remaining = deadline_monotonic - time_module.monotonic()
            if remaining <= 0:
                raise ProvenanceError("command deadline exhausted before raw-evidence replay")
            timeout_override = remaining
        try:
            replay_evidence(
                envelope,
                expected_envelope_digest=envelope_digest,
                expected_evidence_digest=evidence_digest,
                expected_hotkey=miner.hotkey,
                expected_measurement=miner.measurement,
                expected_quote_digest=miner.hardware_evidence_digest,
                expected_challenge_digest=challenge_digest,
                verifier_binary=verifier_binary,
                verifier_blob_digest=verifier_blob_digest,
                verifier_command=verifier_command,
                verifier_artifacts=verifier_artifacts,
                verifier_implementation_digest=result.verifier_digest,
                policy=policy,
                timeout_override=timeout_override,
            )
        except ReplayError as exc:
            raise ProvenanceError(
                f"raw-evidence replay failed for {miner.hotkey!r}: {exc}"
            ) from exc
        upgraded.append(dataclass_replace(miner, raw_verified=True))

    result.miners = upgraded
    rejected_candidates = sorted(
        hotkey for hotkey, outcome in outcomes.items() if outcome == "rejected"
    )
    if replayed_count == 0:
        # Nothing raw was replayed (all-rejected, retired-only, or empty).
        # The PINNED verifier bytes must still independently authenticate
        # against BOTH the content digest and the implementation digest: a
        # fake or unexercised binary must surface, never ride along.
        try:
            authenticate_verifier_bytes(
                verifier_binary,
                expected_blob_digest=verifier_blob_digest,
                declared_command=tuple(verifier_command),
                declared_artifacts=tuple(verifier_artifacts),
                expected_implementation_digest=result.verifier_digest,
            )
        except ReplayError as exc:
            raise ProvenanceError(f"pinned verifier bytes failed authentication: {exc}") from exc
    if rejected_candidates:
        # A rejection is a Cathedral-signed assertion; the launch artifact
        # model publishes no candidate-specific RAW rejection evidence an
        # independent verifier could replay. Whatever positives replayed
        # stay individually proven, but the EPOCH-level FULL claim is not:
        # the result remains receipts_only (NOT PROVEN) — fail closed; a
        # signed rejection alone never mints FULL.
        shown = rejected_candidates[:8]
        suffix = "" if len(rejected_candidates) <= 8 else f" (+{len(rejected_candidates) - 8} more)"
        result.assurance_level = ASSURANCE_RECEIPTS_ONLY
        result.not_proven_reasons = (
            (
                f"rejection of active candidate(s) {shown}{suffix} is asserted "
                "by Cathedral's signed chain but not independently replayable "
                "in the launch artifact model"
            ),
        )
        return result
    if replayed_count == 0:
        result.assurance_level = ASSURANCE_RECEIPTS_ONLY
        result.not_proven_reasons = (
            (
                "no positive raw replays: the epoch's active candidate set is "
                "empty or retired-only, so nothing raw could be proven"
            ),
        )
        return result
    result.assurance_level = ASSURANCE_FULL
    result.not_proven_reasons = ()
    return result
