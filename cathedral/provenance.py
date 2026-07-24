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

REPORT_SCHEMA = "cathedral_score_class_report_v1"
RECEIPT_SCHEMA = "cathedral_assurance_receipt_v2"

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
        "entries",
        "signing_key_id",
        "report_id",
        "signature",
    }
)
_ENTRY_KEYS = frozenset(
    {"miner_hotkey", "metrics", "asserted_score", "reason_codes", "evidence"}
)


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
    assurance_level: str = ASSURANCE_RECEIPTS_ONLY
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


# ---------------------------------------------------------------------------
# Report verification
# ---------------------------------------------------------------------------

def _verify_report_signature(
    document: Mapping[str, Any], public_key: bytes
) -> None:
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
    id_material = {
        k: v for k, v in document.items() if k not in {"report_id", "signature"}
    }
    expected_id = "sha256:" + hashlib.sha256(
        REPORT_ID_DOMAIN + canonical_json(id_material)
    ).hexdigest()
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

    previous = document.get("previous_report_id")
    if previous is not None and not isinstance(previous, str):
        raise ProvenanceError("score report previous_report_id is invalid")
    if enforce_chain and previous != expected_previous_report_id:
        raise ProvenanceError(
            "score report previous_report_id breaks the recorded export chain"
        )

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
    expected_previous_report_id: str | None = None,
    enforce_chain: bool = False,
    now: datetime | None = None,
    registry_max_age_seconds: int = 86400,
    candidate_set: Mapping[str, Any] | None = None,
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
    if mechanism is None:
        raise ProvenanceError(
            f"unknown reward mechanism {mechanism_id!r}; this validator only "
            f"recomputes {sorted(MECHANISMS)}"
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

    if document.get("class_id") != expected_class_id or document.get(
        "source_id"
    ) != expected_source_id:
        raise ProvenanceError(
            "score report class/source identity does not match the operator pins"
        )
    if current_block is not None and not (
        int(document["valid_from_block"])
        <= int(current_block)
        < int(document["valid_until_block"])
    ):
        raise ProvenanceError(
            "current finalized block is outside the report's validity window"
        )
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise ProvenanceError("score report has no entries list")

    # Exhaustive candidate accounting: every enrolled candidate must appear
    # in the report (verified with evidence or explicitly zero/rejected) and
    # the report must not smuggle entries outside the committed set. An
    # omitted honest miner can therefore never silently inflate another.
    candidate_outcomes: dict[str, str] = {}
    if candidate_set is not None:
        for row in candidate_set.get("candidates", []):
            candidate_outcomes[str(row["hotkey"])] = str(row["outcome"])
        report_hotkeys = {
            entry.get("miner_hotkey")
            for entry in entries
            if isinstance(entry, dict)
        }
        active = {
            hotkey
            for hotkey, outcome in candidate_outcomes.items()
            if outcome != "retired"
        }
        missing = active - report_hotkeys
        if missing:
            raise ProvenanceError(
                f"report omits committed candidates: {sorted(missing)}"
            )
        stray = report_hotkeys - set(candidate_outcomes)
        if stray:
            raise ProvenanceError(
                f"report carries entries outside the committed candidate set: "
                f"{sorted(stray)}"
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
                raise ProvenanceError(
                    f"positive entry {hotkey!r} is not a verified candidate"
                )
            if units == 0 and outcome == "verified":
                raise ProvenanceError(
                    f"verified candidate {hotkey!r} carries no verified work"
                )
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
                raise ProvenanceError(
                    f"receipt {receipt_id} for {hotkey!r} was not provided"
                )
            if _digest_bytes(body) != receipt_digest:
                raise ProvenanceError(
                    f"receipt {receipt_id} content does not match its digest"
                )
            # Full receipt verification against the signed registry: signature,
            # id binding, registry release+digest, validity window, measurement
            # in an approved profile.
            try:
                verify_receipt(body, registry)
            except ReceiptError as exc:
                raise ProvenanceError(
                    f"receipt {receipt_id} failed verification: {exc}"
                ) from exc
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
                raise ProvenanceError(
                    f"receipt {receipt_id} work units are invalid"
                ) from exc
            if receipt_units != units:
                raise ProvenanceError(
                    f"receipt {receipt_id} work units {receipt_units} != report units {units}"
                )
            receipt_verified = True
            receipt_measurement = parsed.get("measurement")
            receipt_issued_at = parsed.get("issued_at")
            receipt_hardware = (
                ((parsed.get("assurance") or {}).get("claims") or {}).get("hardware")
                or {}
            )
            receipt_quote_digest = receipt_hardware.get("evidence_digest")
            positive.append((hotkey, units))
        else:
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
                measurement=(
                    receipt_measurement
                    if isinstance(receipt_measurement, str)
                    else None
                ),
                issued_at=(
                    receipt_issued_at
                    if isinstance(receipt_issued_at, str)
                    else None
                ),
                hardware_evidence_digest=(
                    receipt_quote_digest
                    if isinstance(receipt_quote_digest, str)
                    else None
                ),
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
        source_epoch=int(document["source_epoch"]),
        generated_at=str(document["generated_at"]),
        valid_until=str(document["valid_until"]),
        miners=miners,
        recomputed_hotkey_weights=recomputed,
    )


def compare_with_vector(
    result: ProvenanceResult,
    signed_vector: Mapping[str, Any],
    *,
    abs_tol: float = 1e-9,
) -> tuple[bool, list[str]]:
    """Compare the recomputed per-hotkey weights against Cathedral's signed
    vector's external components. Returns ``(agree, discrepancies)``.

    The comparison is symmetric: a hotkey earning in the signed vector without
    verified provenance is exactly as much of a discrepancy as a verified
    hotkey the vector omits.
    """
    discrepancies: list[str] = []
    vector_rows = signed_vector.get("weights")
    if not isinstance(vector_rows, list):
        return False, ["signed vector has no weights list"]
    vector_ext: dict[str, float] = {}
    for row in vector_rows:
        if not isinstance(row, Mapping):
            return False, ["signed vector weight row is not an object"]
        hotkey = row.get("miner_hotkey")
        external = row.get("external_component", row.get("weight"))
        if not isinstance(hotkey, str):
            return False, ["signed vector weight row has no miner_hotkey"]
        try:
            external_value = float(external)
        except (TypeError, ValueError):
            return False, [f"signed vector row for {hotkey!r} is not numeric"]
        if external_value > 0.0:
            if hotkey in vector_ext:
                return False, [f"signed vector duplicates hotkey {hotkey!r}"]
            vector_ext[hotkey] = external_value

    recomputed = result.recomputed_hotkey_weights
    for hotkey in sorted(set(recomputed) | set(vector_ext)):
        mine = recomputed.get(hotkey, 0.0)
        theirs = vector_ext.get(hotkey, 0.0)
        if not math.isclose(mine, theirs, rel_tol=0.0, abs_tol=abs_tol):
            discrepancies.append(
                f"{hotkey}: recomputed={mine:.9f} signed_vector={theirs:.9f}"
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
    candidates_all_rejected: bool = False,
) -> ProvenanceResult:
    """Upgrade a receipts-only result to FULL assurance via raw replay.

    Every positive miner must have a controlled envelope whose bytes match
    the public manifest's ``envelope_digest``, reproduce the recorded
    evidence digest, and replay cleanly through the CANONICAL strict
    verifier path under the signed-registry policy evaluated at the
    receipt's issue time. Any gap is a hard ProvenanceError — the result is
    never silently left at receipts-only by this path.
    """
    from dataclasses import replace as dataclass_replace

    from cathedral.replay import ReplayError, replay_evidence

    upgraded: list[MinerProvenance] = []
    replayed_count = 0
    for miner in result.miners:
        if not miner.receipt_verified:
            upgraded.append(miner)
            continue
        replayed_count += 1
        binding = attestation_bindings.get(miner.hotkey)
        if not isinstance(binding, Mapping):
            raise ProvenanceError(
                f"manifest carries no attestation binding for {miner.hotkey!r}"
            )
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
        envelope = envelopes_by_hotkey.get(miner.hotkey)
        if envelope is None:
            raise ProvenanceError(
                f"controlled envelope for {miner.hotkey!r} was not provided"
            )
        if miner.measurement is None or miner.issued_at is None:
            raise ProvenanceError(
                f"receipt for {miner.hotkey!r} lacks measurement/issue-time bindings"
            )
        if miner.hardware_evidence_digest is None:
            raise ProvenanceError(
                f"receipt for {miner.hotkey!r} carries no hardware evidence digest"
            )
        try:
            issued_at = datetime.strptime(
                miner.issued_at, "%Y-%m-%dT%H:%M:%S.%fZ"
            ).replace(tzinfo=UTC)
        except ValueError as exc:
            raise ProvenanceError(
                f"receipt issue time for {miner.hotkey!r} is malformed"
            ) from exc
        try:
            # Historical policy: the profile set that was live when the
            # evidence was collected, from the SAME signed registry the
            # receipt binds.
            policy = registry.to_policy(at=issued_at)
        except Exception as exc:
            raise ProvenanceError(
                f"signed registry yields no usable policy at the receipt time: {exc}"
            ) from exc
        try:
            replay_evidence(
                envelope,
                expected_envelope_digest=envelope_digest,
                expected_evidence_digest=evidence_digest,
                expected_hotkey=miner.hotkey,
                expected_measurement=miner.measurement,
                expected_quote_digest=miner.hardware_evidence_digest,
                verifier_binary=verifier_binary,
                verifier_blob_digest=verifier_blob_digest,
                verifier_command=verifier_command,
                verifier_artifacts=verifier_artifacts,
                verifier_implementation_digest=result.verifier_digest,
                policy=policy,
            )
        except ReplayError as exc:
            raise ProvenanceError(
                f"raw-evidence replay failed for {miner.hotkey!r}: {exc}"
            ) from exc
        upgraded.append(dataclass_replace(miner, raw_verified=True))

    result.miners = upgraded
    if replayed_count == 0:
        # Nothing raw was replayed. A zero-positive vector is FULL only when
        # the manifest's exhaustive candidate accounting proves EVERY active
        # candidate was explicitly rejected/fail-closed for this epoch
        # (candidates_all_rejected, established by the caller from the
        # verified candidate set + report zero rows). That is the legitimate
        # provable all-burn revocation state. Anything less stays
        # receipts_only: an empty epoch is never vacuously FULL.
        result.assurance_level = (
            ASSURANCE_FULL if candidates_all_rejected else ASSURANCE_RECEIPTS_ONLY
        )
        return result
    result.assurance_level = ASSURANCE_FULL
    return result
