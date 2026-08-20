#!/usr/bin/env python3
"""Regenerate the checked-in golden vectors for the provider contract.

Every vector is built from the real dataclasses in
`cathedral/provider_contract.py` and `cathedral/provider_transcript.py`, then
serialized with the module's own canonical JSON encoder
(`canonical_json_bytes` / `to_document`). Nothing here invents a second wire
format: this script is a deterministic constructor, not a serializer.

Re-running this script must reproduce byte-identical output. Every timestamp,
identifier, and digest is a fixed constant or a pure function of a fixed
label. There is no `datetime.now()`, no `uuid4()`, and no other source of
nondeterminism.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.provider_contract import (
    AssignmentLedgerBinding,
    AssignmentPermit,
    AttemptAssignment,
    AttemptResult,
    AttemptState,
    AttemptTransitionEvent,
    CleanupOutcome,
    CleanupPath,
    CustomerCapReservation,
    InterruptionKind,
    InterruptionOutcome,
    ProviderAbsenceStatus,
    ProviderIdentity,
    ProviderIdentityKind,
    SettlementAction,
    SubmissionIdempotencyBinding,
    TerminalBasis,
    WorkerSettlementDecision,
    hash_idempotency_key,
)
from cathedral.provider_transcript import ProviderAttemptTranscript, WorkerExecutionTranscript


VECTOR_DIR = Path(__file__).resolve().parents[1] / "examples" / "provider-contract"

# Matches the fixed "now" already used by tests/test_provider_contract.py and
# tests/test_provider_transcript.py, so the vectors and the unit tests agree
# on what day it is.
NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=UTC)


def _vector_digest(label: str) -> str:
    """A fixed, reproducible sha256 digest derived from a fixed label."""

    return "sha256:" + hashlib.sha256(f"cathedral-provider-contract-vector:{label}".encode()).hexdigest()


def _provider() -> ProviderIdentity:
    return ProviderIdentity(kind=ProviderIdentityKind.CATHEDRAL_SEED, provider_id="seed-useast-1")


def _write_json(filename: str, document: object) -> None:
    path = VECTOR_DIR / filename
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii")
    print(f"wrote {path.relative_to(VECTOR_DIR.parents[1])}")


def _write_canonical(filename: str, canonical_bytes: bytes) -> None:
    path = VECTOR_DIR / filename
    path.write_bytes(canonical_bytes + b"\n")
    print(f"wrote {path.relative_to(VECTOR_DIR.parents[1])}")


# ---------------------------------------------------------------------------
# assignment-v1.json
# ---------------------------------------------------------------------------


def build_assignment_vector() -> None:
    assignment = AttemptAssignment(
        attempt_id="attempt-golden-001",
        provider=_provider(),
        slot_id="slot-useast1-a-001",
        provider_nonce="d" * 64,
        workload_manifest_digest=_vector_digest("assignment-golden:workload-manifest"),
        policy_digest=_vector_digest("assignment-golden:policy-document"),
        image_digest=_vector_digest("assignment-golden:image"),
    )
    document = {
        "assignment": assignment.to_document(),
        "expected_digest": assignment.digest,
    }
    _write_json("assignment-v1.json", document)


# ---------------------------------------------------------------------------
# attempt-result-v1.json
# ---------------------------------------------------------------------------


def build_attempt_result_vector() -> None:
    assignment = AttemptAssignment(
        attempt_id="attempt-result-golden-001",
        provider=_provider(),
        slot_id="slot-useast1-a-001",
        provider_nonce="e" * 64,
        workload_manifest_digest=_vector_digest("result-golden:workload-manifest"),
        policy_digest=_vector_digest("result-golden:policy-document"),
        image_digest=_vector_digest("result-golden:image"),
    )
    result = AttemptResult(
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        quote_digest=_vector_digest("result-golden:quote"),
        attested_nonce=assignment.provider_nonce,
        measurement_digest=assignment.image_digest,
        result_payload_digest=_vector_digest("result-golden:result-payload"),
        produced_at=NOW + timedelta(seconds=5, milliseconds=500),
        received_at=NOW + timedelta(seconds=6),
    )
    document = {
        "assignment": assignment.to_document(),
        "result": result.to_document(),
        "expected_digest": result.digest,
    }
    _write_json("attempt-result-v1.json", document)


# ---------------------------------------------------------------------------
# stale-quote-v1.json
# ---------------------------------------------------------------------------


def build_stale_quote_vector() -> None:
    """A quote produced for one assignment, relabeled and presented for a retry.

    This is the replay this record exists to reject.  The result record's own
    attempt_id and assignment_digest are exactly the retry's, the fields a
    dispatcher's bookkeeping would naturally carry forward, but the quote
    bytes behind it were produced earlier: the nonce the quote actually
    attests is still the first assignment's, not the fresh one the retry
    issued.  A record that only checked attempt_id and assignment_digest
    would accept this; checking the attested nonce is what rejects it.
    """

    label = "stale-quote-golden"
    first_assignment = AttemptAssignment(
        attempt_id="attempt-stale-quote-001",
        provider=_provider(),
        slot_id="slot-useast1-a-001",
        provider_nonce="f" * 64,
        workload_manifest_digest=_vector_digest(f"{label}:workload-manifest"),
        policy_digest=_vector_digest(f"{label}:policy-document"),
        image_digest=_vector_digest(f"{label}:image"),
    )
    second_assignment = AttemptAssignment(
        attempt_id="attempt-stale-quote-002",
        provider=_provider(),
        slot_id="slot-useast1-a-001",
        provider_nonce="0" * 64,
        workload_manifest_digest=first_assignment.workload_manifest_digest,
        policy_digest=first_assignment.policy_digest,
        image_digest=first_assignment.image_digest,
    )
    stale_quote_result = AttemptResult(
        attempt_id=second_assignment.attempt_id,
        assignment_digest=second_assignment.digest,
        quote_digest=_vector_digest(f"{label}:quote"),
        attested_nonce=first_assignment.provider_nonce,
        measurement_digest=second_assignment.image_digest,
        result_payload_digest=_vector_digest(f"{label}:result-payload"),
        produced_at=NOW + timedelta(seconds=5, milliseconds=500),
        received_at=NOW + timedelta(seconds=6),
    )
    document = {
        "first_assignment": first_assignment.to_document(),
        "second_assignment": second_assignment.to_document(),
        "stale_quote_result": stale_quote_result.to_document(),
        "expected_rejection_code": "result_nonce_mismatch",
    }
    _write_json("stale-quote-v1.json", document)


# ---------------------------------------------------------------------------
# Shared attempt-transcript construction
# ---------------------------------------------------------------------------


def _assignment(*, attempt_id: str, nonce: str, label: str) -> AttemptAssignment:
    return AttemptAssignment(
        attempt_id=attempt_id,
        provider=_provider(),
        slot_id="slot-useast1-a-001",
        provider_nonce=nonce,
        workload_manifest_digest=_vector_digest(f"{label}:workload-manifest"),
        policy_digest=_vector_digest(f"{label}:policy-document"),
        image_digest=_vector_digest(f"{label}:image"),
    )


def _permit(
    assignment: AttemptAssignment,
    *,
    label: str,
    sequence: int = 1,
    issued_at: datetime,
    expires_at: datetime,
) -> AssignmentPermit:
    return AssignmentPermit(
        assignment_digest=assignment.digest,
        sequence=sequence,
        issued_at=issued_at,
        expires_at=expires_at,
        key_id="broker-key-1",
        authorization_digest=_vector_digest(f"{label}:permit-authorization:{sequence}"),
    )


def _event(
    assignment: AttemptAssignment,
    *,
    event_id: str,
    current: AttemptState,
    target: AttemptState,
    occurred_at: datetime,
    label: str,
    detail_digest: str | None = None,
    cleanup: CleanupOutcome | None = None,
    terminal_basis: TerminalBasis | None = None,
) -> AttemptTransitionEvent:
    is_terminal = target in {
        AttemptState.SUCCEEDED,
        AttemptState.FAILED,
        AttemptState.CANCELLED,
        AttemptState.INTERRUPTED,
    }
    return AttemptTransitionEvent(
        event_id=event_id,
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        current=current,
        target=target,
        occurred_at=occurred_at,
        detail_digest=detail_digest or _vector_digest(f"{label}:event:{event_id}"),
        cleanup_outcome_digest=(cleanup.digest if is_terminal and cleanup is not None else None),
        terminal_basis=(terminal_basis or TerminalBasis.PROVIDER_ABSENCE) if is_terminal else None,
    )


def _result(
    assignment: AttemptAssignment,
    *,
    label: str,
    produced_at: datetime,
    received_at: datetime,
) -> AttemptResult:
    return AttemptResult(
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        quote_digest=_vector_digest(f"{label}:quote"),
        attested_nonce=assignment.provider_nonce,
        measurement_digest=assignment.image_digest,
        result_payload_digest=_vector_digest(f"{label}:result-payload"),
        produced_at=produced_at,
        received_at=received_at,
    )


def _linear_events(
    assignment: AttemptAssignment,
    *,
    label: str,
    transitions: tuple[tuple[AttemptState, AttemptState], ...],
    start_second: int = 1,
    result: AttemptResult | None = None,
) -> tuple[AttemptTransitionEvent, ...]:
    return tuple(
        _event(
            assignment,
            event_id=f"{label}-{index:02d}",
            current=current,
            target=target,
            occurred_at=NOW + timedelta(seconds=start_second + index - 1),
            label=label,
            detail_digest=(
                result.digest
                if result is not None and target is AttemptState.RESULT_RECEIVED
                else None
            ),
        )
        for index, (current, target) in enumerate(transitions, start=1)
    )


def build_success_transcript() -> ProviderAttemptTranscript:
    label = "transcript-success-golden"
    assignment = _assignment(attempt_id="attempt-001", nonce="1" * 64, label=label)
    result = _result(
        assignment,
        label=label,
        produced_at=NOW + timedelta(seconds=5, milliseconds=500),
        received_at=NOW + timedelta(seconds=6),
    )
    transitions = (
        (AttemptState.DISPATCH_PENDING, AttemptState.SLOT_CLAIMED),
        (AttemptState.SLOT_CLAIMED, AttemptState.ASSIGNMENT_SENT),
        (AttemptState.ASSIGNMENT_SENT, AttemptState.ACKNOWLEDGED),
        (AttemptState.ACKNOWLEDGED, AttemptState.ATTESTING),
        (AttemptState.ATTESTING, AttemptState.RUNNING),
        (AttemptState.RUNNING, AttemptState.RESULT_RECEIVED),
        (AttemptState.RESULT_RECEIVED, AttemptState.EVIDENCE_VERIFIED),
        (AttemptState.EVIDENCE_VERIFIED, AttemptState.SUCCESS_CLEANUP_PENDING),
    )
    events = _linear_events(assignment, label=label, transitions=transitions, result=result)
    cleanup = CleanupOutcome(
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        provider=assignment.provider,
        slot_id=assignment.slot_id,
        path=CleanupPath.SUCCESS,
        absence_status=ProviderAbsenceStatus.PROVEN_ABSENT,
        requested_at=NOW + timedelta(seconds=9),
        observed_at=NOW + timedelta(seconds=10),
        observation_digest=_vector_digest(f"{label}:cleanup-observation"),
    )
    terminal = _event(
        assignment,
        event_id=f"{label}-terminal",
        current=AttemptState.SUCCESS_CLEANUP_PENDING,
        target=AttemptState.SUCCEEDED,
        occurred_at=NOW + timedelta(seconds=11),
        label=label,
        cleanup=cleanup,
    )
    return ProviderAttemptTranscript(
        assignment=assignment,
        permits=(_permit(assignment, label=label, issued_at=NOW, expires_at=NOW + timedelta(seconds=30)),),
        events=events + (terminal,),
        cleanup=cleanup,
        result=result,
    )


def build_interrupted_transcript() -> ProviderAttemptTranscript:
    label = "transcript-interrupted-golden"
    assignment = _assignment(attempt_id="attempt-002", nonce="2" * 64, label=label)
    interruption = InterruptionOutcome(
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        provider=assignment.provider,
        slot_id=assignment.slot_id,
        kind=InterruptionKind.PREEMPTION_NOTICE,
        source_event_digest=_vector_digest(f"{label}:interruption-source-event"),
        observed_at=NOW + timedelta(seconds=6),
    )
    transitions = (
        (AttemptState.DISPATCH_PENDING, AttemptState.SLOT_CLAIMED),
        (AttemptState.SLOT_CLAIMED, AttemptState.ASSIGNMENT_SENT),
        (AttemptState.ASSIGNMENT_SENT, AttemptState.ACKNOWLEDGED),
        (AttemptState.ACKNOWLEDGED, AttemptState.ATTESTING),
        (AttemptState.ATTESTING, AttemptState.RUNNING),
        (AttemptState.RUNNING, AttemptState.INTERRUPT_CLEANUP_PENDING),
    )
    events = tuple(
        _event(
            assignment,
            event_id=f"{label}-{index:02d}",
            current=current,
            target=target,
            occurred_at=NOW + timedelta(seconds=index),
            label=label,
            detail_digest=(interruption.digest if index == len(transitions) else None),
        )
        for index, (current, target) in enumerate(transitions, start=1)
    )
    cleanup = CleanupOutcome(
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        provider=assignment.provider,
        slot_id=assignment.slot_id,
        path=CleanupPath.INTERRUPT,
        absence_status=ProviderAbsenceStatus.PROVEN_ABSENT,
        requested_at=NOW + timedelta(seconds=7),
        observed_at=NOW + timedelta(seconds=8),
        observation_digest=_vector_digest(f"{label}:cleanup-observation"),
    )
    terminal = _event(
        assignment,
        event_id=f"{label}-terminal",
        current=AttemptState.INTERRUPT_CLEANUP_PENDING,
        target=AttemptState.INTERRUPTED,
        occurred_at=NOW + timedelta(seconds=9),
        label=label,
        detail_digest=interruption.digest,
        cleanup=cleanup,
    )
    return ProviderAttemptTranscript(
        assignment=assignment,
        permits=(_permit(assignment, label=label, issued_at=NOW, expires_at=NOW + timedelta(seconds=30)),),
        events=events + (terminal,),
        cleanup=cleanup,
        interruption=interruption,
    )


def build_failed_transcript() -> ProviderAttemptTranscript:
    """An attempt aborted before a result: ATTESTING -> FAILURE_CLEANUP_PENDING -> FAILED."""

    label = "transcript-failed-golden"
    assignment = _assignment(attempt_id="attempt-failed-001", nonce="3" * 64, label=label)
    transitions = (
        (AttemptState.DISPATCH_PENDING, AttemptState.SLOT_CLAIMED),
        (AttemptState.SLOT_CLAIMED, AttemptState.ASSIGNMENT_SENT),
        (AttemptState.ASSIGNMENT_SENT, AttemptState.ACKNOWLEDGED),
        (AttemptState.ACKNOWLEDGED, AttemptState.ATTESTING),
        (AttemptState.ATTESTING, AttemptState.FAILURE_CLEANUP_PENDING),
    )
    events = _linear_events(assignment, label=label, transitions=transitions)
    cleanup = CleanupOutcome(
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        provider=assignment.provider,
        slot_id=assignment.slot_id,
        path=CleanupPath.FAILURE,
        absence_status=ProviderAbsenceStatus.PROVEN_ABSENT,
        requested_at=NOW + timedelta(seconds=6),
        observed_at=NOW + timedelta(seconds=7),
        observation_digest=_vector_digest(f"{label}:cleanup-observation"),
    )
    terminal = _event(
        assignment,
        event_id=f"{label}-terminal",
        current=AttemptState.FAILURE_CLEANUP_PENDING,
        target=AttemptState.FAILED,
        occurred_at=NOW + timedelta(seconds=8),
        label=label,
        cleanup=cleanup,
    )
    return ProviderAttemptTranscript(
        assignment=assignment,
        permits=(_permit(assignment, label=label, issued_at=NOW, expires_at=NOW + timedelta(seconds=30)),),
        events=events + (terminal,),
        cleanup=cleanup,
    )


def build_cancelled_transcript() -> ProviderAttemptTranscript:
    """An operator-cancelled attempt: ATTESTING -> CANCEL_CLEANUP_PENDING -> CANCELLED."""

    label = "transcript-cancelled-golden"
    assignment = _assignment(attempt_id="attempt-cancelled-001", nonce="4" * 64, label=label)
    transitions = (
        (AttemptState.DISPATCH_PENDING, AttemptState.SLOT_CLAIMED),
        (AttemptState.SLOT_CLAIMED, AttemptState.ASSIGNMENT_SENT),
        (AttemptState.ASSIGNMENT_SENT, AttemptState.ACKNOWLEDGED),
        (AttemptState.ACKNOWLEDGED, AttemptState.ATTESTING),
        (AttemptState.ATTESTING, AttemptState.CANCEL_CLEANUP_PENDING),
    )
    events = _linear_events(assignment, label=label, transitions=transitions)
    cleanup = CleanupOutcome(
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        provider=assignment.provider,
        slot_id=assignment.slot_id,
        path=CleanupPath.CANCEL,
        absence_status=ProviderAbsenceStatus.PROVEN_ABSENT,
        requested_at=NOW + timedelta(seconds=6),
        observed_at=NOW + timedelta(seconds=7),
        observation_digest=_vector_digest(f"{label}:cleanup-observation"),
    )
    terminal = _event(
        assignment,
        event_id=f"{label}-terminal",
        current=AttemptState.CANCEL_CLEANUP_PENDING,
        target=AttemptState.CANCELLED,
        occurred_at=NOW + timedelta(seconds=8),
        label=label,
        cleanup=cleanup,
    )
    return ProviderAttemptTranscript(
        assignment=assignment,
        permits=(_permit(assignment, label=label, issued_at=NOW, expires_at=NOW + timedelta(seconds=30)),),
        events=events + (terminal,),
        cleanup=cleanup,
    )


def build_evidence_rejected_transcript() -> ProviderAttemptTranscript:
    """Evidence rejected after a result, not aborted early:

    RESULT_RECEIVED -> EVIDENCE_REJECTED -> FAILURE_CLEANUP_PENDING -> FAILED.
    This exercises the EVIDENCE_REJECTED edge that the abort-path FAILED
    vector above never reaches.
    """

    label = "transcript-evidence-rejected-golden"
    assignment = _assignment(attempt_id="attempt-evidence-rejected-001", nonce="5" * 64, label=label)
    result = _result(
        assignment,
        label=label,
        produced_at=NOW + timedelta(seconds=5, milliseconds=500),
        received_at=NOW + timedelta(seconds=6),
    )
    transitions = (
        (AttemptState.DISPATCH_PENDING, AttemptState.SLOT_CLAIMED),
        (AttemptState.SLOT_CLAIMED, AttemptState.ASSIGNMENT_SENT),
        (AttemptState.ASSIGNMENT_SENT, AttemptState.ACKNOWLEDGED),
        (AttemptState.ACKNOWLEDGED, AttemptState.ATTESTING),
        (AttemptState.ATTESTING, AttemptState.RUNNING),
        (AttemptState.RUNNING, AttemptState.RESULT_RECEIVED),
        (AttemptState.RESULT_RECEIVED, AttemptState.EVIDENCE_REJECTED),
        (AttemptState.EVIDENCE_REJECTED, AttemptState.FAILURE_CLEANUP_PENDING),
    )
    events = _linear_events(assignment, label=label, transitions=transitions, result=result)
    cleanup = CleanupOutcome(
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        provider=assignment.provider,
        slot_id=assignment.slot_id,
        path=CleanupPath.FAILURE,
        absence_status=ProviderAbsenceStatus.PROVEN_ABSENT,
        requested_at=NOW + timedelta(seconds=9),
        observed_at=NOW + timedelta(seconds=10),
        observation_digest=_vector_digest(f"{label}:cleanup-observation"),
    )
    terminal = _event(
        assignment,
        event_id=f"{label}-terminal",
        current=AttemptState.FAILURE_CLEANUP_PENDING,
        target=AttemptState.FAILED,
        occurred_at=NOW + timedelta(seconds=11),
        label=label,
        cleanup=cleanup,
    )
    return ProviderAttemptTranscript(
        assignment=assignment,
        permits=(_permit(assignment, label=label, issued_at=NOW, expires_at=NOW + timedelta(seconds=30)),),
        events=events + (terminal,),
        cleanup=cleanup,
        result=result,
    )


# ---------------------------------------------------------------------------
# worker-transcript-success-v1.json
# ---------------------------------------------------------------------------


def build_worker_transcript() -> WorkerExecutionTranscript:
    """A single successful attempt settled with one CHARGED Worker decision."""

    label = "worker-transcript-golden"
    reservation = CustomerCapReservation(
        customer_id="customer-1",
        worker_id="worker-golden-001",
        reservation_id="reservation-golden-001",
        request_digest=_vector_digest(f"{label}:request"),
        reserved_micros=200_000,
        reserved_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=5),
    )
    assignment = _assignment(attempt_id="attempt-worker-golden-001", nonce="6" * 64, label=label)
    result = _result(
        assignment,
        label=label,
        produced_at=NOW + timedelta(seconds=5, milliseconds=500),
        received_at=NOW + timedelta(seconds=6),
    )
    transitions = (
        (AttemptState.DISPATCH_PENDING, AttemptState.SLOT_CLAIMED),
        (AttemptState.SLOT_CLAIMED, AttemptState.ASSIGNMENT_SENT),
        (AttemptState.ASSIGNMENT_SENT, AttemptState.ACKNOWLEDGED),
        (AttemptState.ACKNOWLEDGED, AttemptState.ATTESTING),
        (AttemptState.ATTESTING, AttemptState.RUNNING),
        (AttemptState.RUNNING, AttemptState.RESULT_RECEIVED),
        (AttemptState.RESULT_RECEIVED, AttemptState.EVIDENCE_VERIFIED),
        (AttemptState.EVIDENCE_VERIFIED, AttemptState.SUCCESS_CLEANUP_PENDING),
    )
    events = _linear_events(assignment, label=label, transitions=transitions, result=result)
    cleanup = CleanupOutcome(
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        provider=assignment.provider,
        slot_id=assignment.slot_id,
        path=CleanupPath.SUCCESS,
        absence_status=ProviderAbsenceStatus.PROVEN_ABSENT,
        requested_at=NOW + timedelta(seconds=9),
        observed_at=NOW + timedelta(seconds=10),
        observation_digest=_vector_digest(f"{label}:cleanup-observation"),
    )
    terminal = _event(
        assignment,
        event_id=f"{label}-terminal",
        current=AttemptState.SUCCESS_CLEANUP_PENDING,
        target=AttemptState.SUCCEEDED,
        occurred_at=NOW + timedelta(seconds=11),
        label=label,
        cleanup=cleanup,
    )
    permit = _permit(assignment, label=label, issued_at=NOW, expires_at=NOW + timedelta(seconds=30))
    attempt = ProviderAttemptTranscript(
        assignment=assignment,
        permits=(permit,),
        events=events + (terminal,),
        cleanup=cleanup,
        result=result,
    )
    binding = AssignmentLedgerBinding(
        binding_id="binding-worker-golden-001",
        assignment_digest=assignment.digest,
        customer_id=reservation.customer_id,
        worker_id=reservation.worker_id,
        attempt_id=assignment.attempt_id,
        attempt_number=1,
        retry_parent_attempt_id=None,
        reservation_id=reservation.reservation_id,
        request_digest=reservation.request_digest,
        reserved_micros=reservation.reserved_micros,
        created_at=NOW,
    )
    settlement = WorkerSettlementDecision(
        decision_id="settlement-worker-golden-001",
        sequence=1,
        supersedes_digest=None,
        customer_id=reservation.customer_id,
        worker_id=reservation.worker_id,
        reservation_id=reservation.reservation_id,
        reserved_micros=reservation.reserved_micros,
        charged_micros=125_000,
        action=SettlementAction.CHARGED,
        winning_attempt_id=assignment.attempt_id,
        worker_outcome_digest=attempt.digest,
        decided_at=NOW + timedelta(seconds=12),
    )
    return WorkerExecutionTranscript(
        reservation=reservation,
        bindings=(binding,),
        attempts=(attempt,),
        unassigned_dispatch=None,
        settlements=(settlement,),
    )


# ---------------------------------------------------------------------------
# idempotency-conflict-v1.json
# ---------------------------------------------------------------------------


def build_idempotency_conflict_vector() -> None:
    label = "idempotency-conflict-golden"
    key_digest = hash_idempotency_key(b"golden-vector-idempotency-key-01")
    existing = SubmissionIdempotencyBinding(
        customer_id="customer-1",
        idempotency_key_digest=key_digest,
        request_digest=_vector_digest(f"{label}:request-a"),
        worker_id="worker-golden-idem-001",
    )
    conflicting_candidate = SubmissionIdempotencyBinding(
        customer_id="customer-1",
        idempotency_key_digest=key_digest,
        request_digest=_vector_digest(f"{label}:request-b"),
        worker_id="worker-golden-idem-001",
    )
    document = {
        "existing": existing.to_document(),
        "conflicting_candidate": conflicting_candidate.to_document(),
        "expected_rejection_code": "idempotency_conflict",
    }
    _write_json("idempotency-conflict-v1.json", document)


# ---------------------------------------------------------------------------
# permit-renewal-v1.json
# ---------------------------------------------------------------------------


def build_permit_renewal_vector() -> None:
    label = "permit-renewal-golden"
    assignment = _assignment(attempt_id="attempt-permit-renewal-001", nonce="7" * 64, label=label)
    current = _permit(
        assignment,
        label=label,
        sequence=1,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
    )
    renewed = _permit(
        assignment,
        label=label,
        sequence=2,
        issued_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=3),
    )
    document = {
        "assignment": assignment.to_document(),
        "current_permit": current.to_document(),
        "renewed_permit": renewed.to_document(),
        "observed_at": renewed.to_document()["issued_at"],
        "expected_current_digest": current.digest,
        "expected_renewed_digest": renewed.digest,
    }
    _write_json("permit-renewal-v1.json", document)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> None:
    build_assignment_vector()
    build_attempt_result_vector()
    build_stale_quote_vector()

    success = build_success_transcript()
    _write_canonical("transcript-success-v1.json", success.canonical_bytes)
    print(f"  digest: {success.digest}")

    interrupted = build_interrupted_transcript()
    _write_canonical("transcript-interrupted-v1.json", interrupted.canonical_bytes)
    print(f"  digest: {interrupted.digest}")

    failed = build_failed_transcript()
    _write_canonical("transcript-failed-v1.json", failed.canonical_bytes)
    print(f"  digest: {failed.digest}")

    cancelled = build_cancelled_transcript()
    _write_canonical("transcript-cancelled-v1.json", cancelled.canonical_bytes)
    print(f"  digest: {cancelled.digest}")

    evidence_rejected = build_evidence_rejected_transcript()
    _write_canonical("transcript-evidence-rejected-v1.json", evidence_rejected.canonical_bytes)
    print(f"  digest: {evidence_rejected.digest}")

    worker = build_worker_transcript()
    _write_canonical("worker-transcript-success-v1.json", worker.canonical_bytes)
    print(f"  digest: {worker.digest}")

    build_idempotency_conflict_vector()
    build_permit_renewal_vector()


if __name__ == "__main__":
    main()
