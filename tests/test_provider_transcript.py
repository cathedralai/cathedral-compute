"""Whole-transcript validation for provider-neutral attempt records."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import Path

import pytest

from cathedral.provider_contract import (
    AssignmentLedgerBinding,
    AssignmentPermit,
    AttemptAssignment,
    AttemptState,
    AttemptTransitionEvent,
    CleanupOutcome,
    CleanupPath,
    CustomerCapReservation,
    InterruptionKind,
    InterruptionOutcome,
    ProviderAbsenceStatus,
    ProviderContractError,
    ProviderIdentity,
    ProviderIdentityKind,
    SettlementAction,
    TerminalBasis,
    UnassignedDispatchOutcome,
    UnassignedDispatchReason,
    WorkerSettlementDecision,
)
from cathedral.provider_transcript import ProviderAttemptTranscript, WorkerExecutionTranscript


NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=UTC)


def _digest(label: str) -> str:
    encoded = f"cathedral-provider-transcript:{label}".encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


WORKLOAD_DIGEST = _digest("workload")
POLICY_DIGEST = _digest("policy")
IMAGE_DIGEST = _digest("image")
REQUEST_DIGEST = _digest("customer-request")
SUCCESS_CLEANUP_OBSERVATION_DIGEST = _digest("success-cleanup-observation")
INTERRUPT_CLEANUP_OBSERVATION_DIGEST = _digest("interrupt-cleanup-observation")
INTERRUPTION_SOURCE_EVENT_DIGEST = _digest("interruption-source-event")
MISMATCH_DIGEST = _digest("intentional-mismatch")


def _provider() -> ProviderIdentity:
    return ProviderIdentity(
        kind=ProviderIdentityKind.CATHEDRAL_SEED,
        provider_id="seed-useast-1",
    )


def _assignment(
    *,
    attempt_id: str = "attempt-001",
    nonce: str = "1" * 64,
) -> AttemptAssignment:
    return AttemptAssignment(
        attempt_id=attempt_id,
        provider=_provider(),
        slot_id="slot-useast1-a-001",
        provider_nonce=nonce,
        workload_manifest_digest=WORKLOAD_DIGEST,
        policy_digest=POLICY_DIGEST,
        image_digest=IMAGE_DIGEST,
    )


def _permit(
    assignment: AttemptAssignment,
    *,
    sequence: int = 1,
    issued_at: datetime = NOW,
    expires_at: datetime = NOW + timedelta(seconds=30),
) -> AssignmentPermit:
    return AssignmentPermit(
        assignment_digest=assignment.digest,
        sequence=sequence,
        issued_at=issued_at,
        expires_at=expires_at,
        key_id="broker-key-1",
        authorization_digest=_digest(
            f"permit-authorization:{assignment.attempt_id}:{sequence}"
        ),
    )


def _reservation(
    *,
    reservation_id: str = "reservation-001",
) -> CustomerCapReservation:
    return CustomerCapReservation(
        customer_id="customer-1",
        worker_id="worker-001",
        reservation_id=reservation_id,
        request_digest=REQUEST_DIGEST,
        reserved_micros=200_000,
        reserved_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=5),
    )


def _binding(
    assignment: AttemptAssignment,
    *,
    attempt_number: int = 1,
    retry_parent_attempt_id: str | None = None,
    reservation_id: str = "reservation-001",
    created_at: datetime = NOW,
) -> AssignmentLedgerBinding:
    return AssignmentLedgerBinding(
        binding_id=f"binding-{assignment.attempt_id.removeprefix('attempt-')}",
        assignment_digest=assignment.digest,
        customer_id="customer-1",
        worker_id="worker-001",
        attempt_id=assignment.attempt_id,
        attempt_number=attempt_number,
        retry_parent_attempt_id=retry_parent_attempt_id,
        reservation_id=reservation_id,
        request_digest=REQUEST_DIGEST,
        reserved_micros=200_000,
        created_at=created_at,
    )


def _event(
    assignment: AttemptAssignment,
    *,
    event_id: str,
    current: AttemptState,
    target: AttemptState,
    second: int,
    detail_digest: str | None = None,
    cleanup: CleanupOutcome | None = None,
) -> AttemptTransitionEvent:
    terminal = target in {
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
        occurred_at=NOW + timedelta(seconds=second),
        detail_digest=detail_digest or _digest(f"event:{event_id}"),
        cleanup_outcome_digest=(cleanup.digest if terminal and cleanup is not None else None),
        terminal_basis=(TerminalBasis.PROVIDER_ABSENCE if terminal else None),
    )


def _success_transcript(
    *,
    permit_expires_at: datetime = NOW + timedelta(seconds=30),
    attempt_id: str = "attempt-001",
    nonce: str = "1" * 64,
    time_offset: int = 0,
) -> ProviderAttemptTranscript:
    assignment = _assignment(attempt_id=attempt_id, nonce=nonce)
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
    events = tuple(
        _event(
            assignment,
            event_id=f"success-{index:02d}",
            current=current,
            target=target,
            second=time_offset + index,
        )
        for index, (current, target) in enumerate(transitions, start=1)
    )
    cleanup = CleanupOutcome(
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        provider=assignment.provider,
        slot_id=assignment.slot_id,
        path=CleanupPath.SUCCESS,
        absence_status=ProviderAbsenceStatus.PROVEN_ABSENT,
        requested_at=NOW + timedelta(seconds=time_offset + 9),
        observed_at=NOW + timedelta(seconds=time_offset + 10),
        observation_digest=SUCCESS_CLEANUP_OBSERVATION_DIGEST,
    )
    terminal = _event(
        assignment,
        event_id="success-terminal",
        current=AttemptState.SUCCESS_CLEANUP_PENDING,
        target=AttemptState.SUCCEEDED,
        second=time_offset + 11,
        cleanup=cleanup,
    )
    return ProviderAttemptTranscript(
        assignment=assignment,
        permits=(
            _permit(
                assignment,
                issued_at=NOW + timedelta(seconds=time_offset),
                expires_at=permit_expires_at,
            ),
        ),
        events=events + (terminal,),
        cleanup=cleanup,
    )


def _interrupted_transcript(
    *,
    attempt_id: str = "attempt-002",
    nonce: str = "2" * 64,
    time_offset: int = 0,
) -> ProviderAttemptTranscript:
    assignment = _assignment(attempt_id=attempt_id, nonce=nonce)
    interruption = InterruptionOutcome(
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        provider=assignment.provider,
        slot_id=assignment.slot_id,
        kind=InterruptionKind.PREEMPTION_NOTICE,
        source_event_digest=INTERRUPTION_SOURCE_EVENT_DIGEST,
        observed_at=NOW + timedelta(seconds=time_offset + 6),
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
            event_id=f"interrupt-{index:02d}",
            current=current,
            target=target,
            second=time_offset + index,
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
        requested_at=NOW + timedelta(seconds=time_offset + 7),
        observed_at=NOW + timedelta(seconds=time_offset + 8),
        observation_digest=INTERRUPT_CLEANUP_OBSERVATION_DIGEST,
    )
    terminal = _event(
        assignment,
        event_id="interrupt-terminal",
        current=AttemptState.INTERRUPT_CLEANUP_PENDING,
        target=AttemptState.INTERRUPTED,
        second=time_offset + 9,
        detail_digest=interruption.digest,
        cleanup=cleanup,
    )
    return ProviderAttemptTranscript(
        assignment=assignment,
        permits=(
            _permit(
                assignment,
                issued_at=NOW + timedelta(seconds=time_offset),
                expires_at=NOW + timedelta(seconds=time_offset + 30),
            ),
        ),
        events=events + (terminal,),
        cleanup=cleanup,
        interruption=interruption,
    )


def _unsuccessful_transcript(
    target: AttemptState,
    *,
    attempt_id: str,
    nonce: str,
    time_offset: int = 0,
) -> ProviderAttemptTranscript:
    if target is AttemptState.FAILED:
        cleanup_path = CleanupPath.FAILURE
        cleanup_pending = AttemptState.FAILURE_CLEANUP_PENDING
    elif target is AttemptState.CANCELLED:
        cleanup_path = CleanupPath.CANCEL
        cleanup_pending = AttemptState.CANCEL_CLEANUP_PENDING
    else:
        raise AssertionError("helper supports failed and cancelled terminals")
    assignment = _assignment(attempt_id=attempt_id, nonce=nonce)
    transitions = (
        (AttemptState.DISPATCH_PENDING, AttemptState.SLOT_CLAIMED),
        (AttemptState.SLOT_CLAIMED, AttemptState.ASSIGNMENT_SENT),
        (AttemptState.ASSIGNMENT_SENT, AttemptState.ACKNOWLEDGED),
        (AttemptState.ACKNOWLEDGED, AttemptState.ATTESTING),
        (AttemptState.ATTESTING, cleanup_pending),
    )
    events = tuple(
        _event(
            assignment,
            event_id=f"{target.value.lower()}-{index:02d}",
            current=current,
            target=next_state,
            second=time_offset + index,
        )
        for index, (current, next_state) in enumerate(transitions, start=1)
    )
    cleanup = CleanupOutcome(
        attempt_id=assignment.attempt_id,
        assignment_digest=assignment.digest,
        provider=assignment.provider,
        slot_id=assignment.slot_id,
        path=cleanup_path,
        absence_status=ProviderAbsenceStatus.PROVEN_ABSENT,
        requested_at=NOW + timedelta(seconds=time_offset + 6),
        observed_at=NOW + timedelta(seconds=time_offset + 7),
        observation_digest=_digest(f"{target.value.lower()}-cleanup"),
    )
    terminal = _event(
        assignment,
        event_id=f"{target.value.lower()}-terminal",
        current=cleanup_pending,
        target=target,
        second=time_offset + 8,
        cleanup=cleanup,
    )
    return ProviderAttemptTranscript(
        assignment=assignment,
        permits=(
            _permit(
                assignment,
                issued_at=NOW + timedelta(seconds=time_offset),
                expires_at=NOW + timedelta(seconds=time_offset + 30),
            ),
        ),
        events=events + (terminal,),
        cleanup=cleanup,
    )


def _settlement(
    *,
    action: SettlementAction,
    outcome_digest: str,
    winner: str | None = None,
    decided_at: datetime = NOW + timedelta(seconds=30),
) -> WorkerSettlementDecision:
    return WorkerSettlementDecision(
        decision_id="settlement-worker-001",
        sequence=1,
        supersedes_digest=None,
        customer_id="customer-1",
        worker_id="worker-001",
        reservation_id="reservation-001",
        reserved_micros=200_000,
        charged_micros=125_000 if action is SettlementAction.CHARGED else 0,
        action=action,
        winning_attempt_id=winner,
        worker_outcome_digest=outcome_digest,
        decided_at=decided_at,
    )


def test_full_success_transcript_validates() -> None:
    assert _success_transcript().validate() is AttemptState.SUCCEEDED


def test_full_interruption_transcript_validates() -> None:
    assert _interrupted_transcript().validate() is AttemptState.INTERRUPTED


@pytest.mark.parametrize(
    ("target", "attempt_id", "nonce"),
    [
        (AttemptState.FAILED, "attempt-failed", "3" * 64),
        (AttemptState.CANCELLED, "attempt-cancelled", "4" * 64),
    ],
)
def test_every_other_terminal_attempt_path_validates(
    target: AttemptState,
    attempt_id: str,
    nonce: str,
) -> None:
    assert (
        _unsuccessful_transcript(target, attempt_id=attempt_id, nonce=nonce).validate()
        is target
    )


def test_interrupted_then_successful_retry_uses_one_reservation_and_one_charge() -> None:
    interrupted = _interrupted_transcript(
        attempt_id="attempt-retry-001",
        nonce="5" * 64,
    )
    succeeded = _success_transcript(
        attempt_id="attempt-retry-002",
        nonce="6" * 64,
        time_offset=10,
        permit_expires_at=NOW + timedelta(seconds=40),
    )
    transcript = WorkerExecutionTranscript(
        reservation=_reservation(),
        bindings=(
            _binding(interrupted.assignment),
            _binding(
                succeeded.assignment,
                attempt_number=2,
                retry_parent_attempt_id=interrupted.assignment.attempt_id,
                created_at=NOW + timedelta(seconds=9),
            ),
        ),
        attempts=(interrupted, succeeded),
        unassigned_dispatch=None,
        settlements=(
            _settlement(
                action=SettlementAction.CHARGED,
                outcome_digest=succeeded.digest,
                winner=succeeded.assignment.attempt_id,
            ),
        ),
    )

    assert transcript.validate() is SettlementAction.CHARGED
    assert transcript.final_settlement.charged_micros == 125_000
    assert len(transcript.attempts) == 2


def test_no_capacity_is_worker_level_unassigned_release_with_no_fake_attempt() -> None:
    outcome = UnassignedDispatchOutcome(
        outcome_id="unassigned-001",
        worker_id="worker-001",
        request_digest=REQUEST_DIGEST,
        reason=UnassignedDispatchReason.NO_CAPACITY,
        routing_decision_digest=_digest("routing-no-capacity"),
        observed_at=NOW + timedelta(seconds=1),
    )
    transcript = WorkerExecutionTranscript(
        reservation=_reservation(),
        bindings=(),
        attempts=(),
        unassigned_dispatch=outcome,
        settlements=(
            _settlement(
                action=SettlementAction.RELEASED,
                outcome_digest=outcome.digest,
                decided_at=NOW + timedelta(seconds=2),
            ),
        ),
    )

    assert transcript.validate() is SettlementAction.RELEASED
    assert transcript.attempts == ()


def test_worker_finalizer_rejects_retry_overlap_reused_nonce_and_wrong_parent() -> None:
    first = _interrupted_transcript(attempt_id="attempt-a", nonce="7" * 64)
    second = _success_transcript(
        attempt_id="attempt-b",
        nonce="8" * 64,
        time_offset=10,
        permit_expires_at=NOW + timedelta(seconds=40),
    )
    settlement = _settlement(
        action=SettlementAction.CHARGED,
        outcome_digest=second.digest,
        winner=second.assignment.attempt_id,
    )
    base = WorkerExecutionTranscript(
        reservation=_reservation(),
        bindings=(
            _binding(first.assignment),
            _binding(
                second.assignment,
                attempt_number=2,
                retry_parent_attempt_id=first.assignment.attempt_id,
                created_at=NOW + timedelta(seconds=9),
            ),
        ),
        attempts=(first, second),
        unassigned_dispatch=None,
        settlements=(settlement,),
    )
    assert base.validate() is SettlementAction.CHARGED

    overlapping = _success_transcript(
        attempt_id="attempt-b",
        nonce="8" * 64,
        time_offset=8,
        permit_expires_at=NOW + timedelta(seconds=40),
    )
    with pytest.raises(ProviderContractError, match="overlaps"):
        replace(
            base,
            attempts=(first, overlapping),
            bindings=(
                base.bindings[0],
                replace(
                    base.bindings[1],
                    assignment_digest=overlapping.assignment.digest,
                    created_at=NOW + timedelta(seconds=8),
                ),
            ),
            settlements=(
                replace(
                    settlement,
                    worker_outcome_digest=overlapping.digest,
                ),
            ),
        ).validate()

    reused_nonce = _success_transcript(
        attempt_id="attempt-b",
        nonce=first.assignment.provider_nonce,
        time_offset=10,
        permit_expires_at=NOW + timedelta(seconds=40),
    )
    with pytest.raises(ProviderContractError, match="reuse a provider nonce"):
        replace(
            base,
            attempts=(first, reused_nonce),
            bindings=(
                base.bindings[0],
                replace(
                    base.bindings[1],
                    assignment_digest=reused_nonce.assignment.digest,
                ),
            ),
            settlements=(
                replace(
                    settlement,
                    worker_outcome_digest=reused_nonce.digest,
                ),
            ),
        ).validate()

    with pytest.raises(ProviderContractError, match="immediate parent"):
        replace(
            base,
            bindings=(
                base.bindings[0],
                replace(base.bindings[1], retry_parent_attempt_id="attempt-other"),
            ),
        ).validate()


def test_worker_finalizer_rejects_multiple_successes_wrong_winner_and_unfinished_attempt() -> None:
    first = _success_transcript()
    second = _success_transcript(
        attempt_id="attempt-success-002",
        nonce="9" * 64,
        time_offset=12,
        permit_expires_at=NOW + timedelta(seconds=42),
    )
    with pytest.raises(ProviderContractError, match="multiple successful"):
        WorkerExecutionTranscript(
            reservation=_reservation(),
            bindings=(
                _binding(first.assignment),
                _binding(
                    second.assignment,
                    attempt_number=2,
                    retry_parent_attempt_id=first.assignment.attempt_id,
                    created_at=NOW + timedelta(seconds=11),
                ),
            ),
            attempts=(first, second),
            unassigned_dispatch=None,
            settlements=(
                _settlement(
                    action=SettlementAction.CHARGED,
                    outcome_digest=second.digest,
                    winner=second.assignment.attempt_id,
                    decided_at=NOW + timedelta(seconds=40),
                ),
            ),
        ).validate()

    valid = WorkerExecutionTranscript(
        reservation=_reservation(),
        bindings=(_binding(first.assignment),),
        attempts=(first,),
        unassigned_dispatch=None,
        settlements=(
            _settlement(
                action=SettlementAction.CHARGED,
                outcome_digest=first.digest,
                winner=first.assignment.attempt_id,
            ),
        ),
    )
    with pytest.raises(ProviderContractError, match="wrong winning attempt"):
        replace(
            valid,
            settlements=(replace(valid.settlements[0], winning_attempt_id="attempt-other"),),
        ).validate()

    with pytest.raises(ProviderContractError, match="end at a terminal state"):
        replace(
            valid,
            attempts=(replace(first, events=first.events[:-1]),),
        ).validate()


@pytest.mark.parametrize(
    "transcript",
    [_success_transcript(), _interrupted_transcript()],
    ids=["success", "interrupted"],
)
def test_transcript_fixture_independent_digests_are_distinct(
    transcript: ProviderAttemptTranscript,
) -> None:
    semantic_digests = {
        transcript.assignment.workload_manifest_digest,
        transcript.assignment.policy_digest,
        transcript.assignment.image_digest,
        transcript.permits[0].authorization_digest,
        transcript.cleanup.observation_digest,
    }
    ordinary_event_digests = {
        event.detail_digest
        for event in transcript.events
        if transcript.interruption is None or event.detail_digest != transcript.interruption.digest
    }
    if transcript.interruption is not None:
        semantic_digests.add(transcript.interruption.source_event_digest)

    assert len(semantic_digests) == (6 if transcript.interruption is not None else 5)
    assert semantic_digests.isdisjoint(ordinary_event_digests)
    assert len(ordinary_event_digests) == len(transcript.events) - (
        2 if transcript.interruption is not None else 0
    )


def test_transcript_fixtures_use_distinct_attempts_and_provider_nonces() -> None:
    success = _success_transcript()
    interrupted = _interrupted_transcript()

    assert success.assignment.attempt_id != interrupted.assignment.attempt_id
    assert success.assignment.provider_nonce != interrupted.assignment.provider_nonce


@pytest.mark.parametrize(
    "build_transcript",
    [_success_transcript, _interrupted_transcript],
    ids=["success", "interrupted"],
)
def test_transcript_canonical_round_trip_is_exact(build_transcript) -> None:
    transcript = build_transcript()

    parsed = ProviderAttemptTranscript.from_bytes(transcript.canonical_bytes)

    assert parsed == transcript
    assert parsed.canonical_bytes == transcript.canonical_bytes
    assert parsed.digest == transcript.digest


@pytest.mark.parametrize(
    ("filename", "expected_digest", "expected_state"),
    [
        (
            "transcript-success-v1.json",
            "sha256:b776ee5b4a6e53d2a51135b1f334cd95a6a98be0edbaa981c396fa4435e34e1c",
            AttemptState.SUCCEEDED,
        ),
        (
            "transcript-interrupted-v1.json",
            "sha256:69810b58be2b6784f1e4b17cddb2da7359d77f589bbf72d999af2bd416dddc7e",
            AttemptState.INTERRUPTED,
        ),
        (
            "transcript-failed-v1.json",
            "sha256:d54847bf71f91e165d2d438b17567481cbb014449f80e86cd8d8d39e15006f98",
            AttemptState.FAILED,
        ),
        (
            "transcript-cancelled-v1.json",
            "sha256:919dbe9e52b0ffff7b030dab111befd7da293db91ed6b1c9befb9884b4221dad",
            AttemptState.CANCELLED,
        ),
        (
            "transcript-evidence-rejected-v1.json",
            "sha256:598fbe56c6f2086b45000c8098612c1de6fde36a60535bc30a80ff90b2420844",
            AttemptState.FAILED,
        ),
    ],
)
def test_checked_in_transcript_golden_vectors_are_stable(
    filename: str,
    expected_digest: str,
    expected_state: AttemptState,
) -> None:
    vector_path = Path(__file__).parents[1] / "examples" / "provider-contract" / filename
    raw = vector_path.read_bytes()
    assert raw.endswith(b"\n")
    wire_bytes = raw[:-1]

    transcript = ProviderAttemptTranscript.from_bytes(wire_bytes)

    assert transcript.validate() is expected_state
    assert transcript.canonical_bytes == wire_bytes
    assert transcript.digest == expected_digest


def test_checked_in_worker_transcript_golden_vector_is_stable() -> None:
    vector_path = (
        Path(__file__).parents[1] / "examples" / "provider-contract" / "worker-transcript-success-v1.json"
    )
    raw = vector_path.read_bytes()
    assert raw.endswith(b"\n")
    wire_bytes = raw[:-1]

    transcript = WorkerExecutionTranscript.from_bytes(wire_bytes)

    assert transcript.validate() is SettlementAction.CHARGED
    assert transcript.canonical_bytes == wire_bytes
    assert (
        transcript.digest
        == "sha256:a57552b025c4e3129185b1a5bca496e92c4f71987688faa65713f1faf64d2f7f"
    )
    assert transcript.final_settlement.winning_attempt_id == transcript.attempts[-1].assignment.attempt_id


def test_transcript_document_rejects_unknown_fields() -> None:
    document = dict(_success_transcript().to_document())
    document["unknown"] = "field"

    with pytest.raises(ProviderContractError, match="missing, unknown, or unsupported"):
        ProviderAttemptTranscript.from_document(document)


def test_transcript_document_caps_events_before_parsing_them() -> None:
    document = dict(_success_transcript().to_document())
    document["events"] = [object()] * 33

    with pytest.raises(ProviderContractError, match="too many events"):
        ProviderAttemptTranscript.from_document(document)


def test_transcript_bytes_must_be_exact_canonical_json() -> None:
    raw = _success_transcript().canonical_bytes

    with pytest.raises(ProviderContractError, match="canonical form"):
        ProviderAttemptTranscript.from_bytes(raw + b"\n")


def test_transcript_loader_rejects_reordered_events() -> None:
    document = deepcopy(_success_transcript().to_document())
    events = document["events"]
    assert isinstance(events, list)
    events[3], events[4] = events[4], events[3]

    with pytest.raises(ProviderContractError, match="state chain is not continuous"):
        ProviderAttemptTranscript.from_document(document)


def test_transcript_loader_rejects_cross_attempt_substitution() -> None:
    document = deepcopy(_success_transcript().to_document())
    events = document["events"]
    assert isinstance(events, list)
    event = events[4]
    assert isinstance(event, dict)
    event["attempt_id"] = "attempt-other"

    with pytest.raises(ProviderContractError, match="does not match its attempt assignment"):
        ProviderAttemptTranscript.from_document(document)


def test_transcript_loader_rejects_changed_cleanup() -> None:
    document = deepcopy(_success_transcript().to_document())
    cleanup = document["cleanup"]
    assert isinstance(cleanup, dict)
    cleanup["slot_id"] = "slot-other"

    with pytest.raises(ProviderContractError, match="cleanup outcome does not match"):
        ProviderAttemptTranscript.from_document(document)


def test_transcript_loader_rejects_missing_interruption() -> None:
    document = deepcopy(_interrupted_transcript().to_document())
    document["interruption"] = None

    with pytest.raises(ProviderContractError, match="requires an interruption outcome"):
        ProviderAttemptTranscript.from_document(document)


def test_broken_state_chain_is_rejected() -> None:
    transcript = _success_transcript()
    events = list(transcript.events)
    events[3] = replace(
        events[3],
        current=AttemptState.ATTESTING,
        target=AttemptState.RUNNING,
    )

    with pytest.raises(ProviderContractError, match="state chain is not continuous"):
        replace(transcript, events=tuple(events)).validate()


def test_event_before_initial_permit_is_rejected() -> None:
    transcript = _success_transcript()
    events = list(transcript.events)
    events[0] = replace(
        events[0],
        occurred_at=transcript.permits[0].issued_at - timedelta(microseconds=1),
    )

    with pytest.raises(ProviderContractError, match="before its initial permit"):
        replace(transcript, events=tuple(events)).validate()


def test_to_document_rejects_invalid_transcript() -> None:
    transcript = _success_transcript()
    events = list(transcript.events)
    events[3] = replace(
        events[3],
        current=AttemptState.ATTESTING,
        target=AttemptState.RUNNING,
    )

    with pytest.raises(ProviderContractError, match="state chain is not continuous"):
        replace(transcript, events=tuple(events)).to_document()


def test_duplicate_event_ids_are_rejected() -> None:
    transcript = _success_transcript()
    events = list(transcript.events)
    events[1] = replace(events[1], event_id=events[0].event_id)

    with pytest.raises(ProviderContractError, match="duplicate event ID"):
        replace(transcript, events=tuple(events)).validate()


def test_cross_attempt_event_is_rejected() -> None:
    transcript = _success_transcript()
    events = list(transcript.events)
    events[4] = replace(events[4], attempt_id="attempt-other")

    with pytest.raises(ProviderContractError, match="does not match its attempt assignment"):
        replace(transcript, events=tuple(events)).validate()


def test_timestamp_reversal_is_rejected() -> None:
    transcript = _success_transcript()
    events = list(transcript.events)
    events[4] = replace(
        events[4],
        occurred_at=events[3].occurred_at - timedelta(microseconds=1),
    )

    with pytest.raises(ProviderContractError, match="timestamps are not nondecreasing"):
        replace(transcript, events=tuple(events)).validate()


@pytest.mark.parametrize(
    "expires_at",
    [
        NOW + timedelta(milliseconds=1500),
        NOW + timedelta(milliseconds=2500),
    ],
    ids=["dispatch-after-expiry", "ack-after-expiry"],
)
def test_expired_permit_dispatch_or_ack_is_rejected(expires_at: datetime) -> None:
    with pytest.raises(ProviderContractError, match="outside every permit window"):
        _success_transcript(permit_expires_at=expires_at).validate()


def test_nonterminal_last_event_is_rejected() -> None:
    transcript = _success_transcript()

    with pytest.raises(ProviderContractError, match="end at a terminal state"):
        replace(transcript, events=transcript.events[:-1]).validate()


def test_terminal_event_before_a_later_event_is_rejected() -> None:
    transcript = _success_transcript()
    later = _event(
        transcript.assignment,
        event_id="event-after-terminal",
        current=AttemptState.DISPATCH_PENDING,
        target=AttemptState.SLOT_CLAIMED,
        second=12,
    )

    with pytest.raises(ProviderContractError, match="state chain is not continuous"):
        replace(transcript, events=transcript.events + (later,)).validate()


def test_mismatched_cleanup_is_rejected() -> None:
    transcript = _success_transcript()

    with pytest.raises(ProviderContractError, match="cleanup outcome does not match"):
        replace(
            transcript,
            cleanup=replace(transcript.cleanup, slot_id="slot-other"),
        ).validate()


def test_attempt_transcript_has_no_customer_or_settlement_fields() -> None:
    transcript = _success_transcript()
    document = transcript.to_document()

    assert "settlement" not in document
    assert "reservation" not in document
    assert "binding" not in document
    assert "customer_id" not in transcript.canonical_bytes.decode("ascii")


def test_interrupted_transcript_requires_interruption_outcome() -> None:
    transcript = _interrupted_transcript()

    with pytest.raises(ProviderContractError, match="requires an interruption outcome"):
        replace(transcript, interruption=None).validate()


def test_success_transcript_rejects_unexpected_interruption_outcome() -> None:
    transcript = _success_transcript()
    interruption = InterruptionOutcome(
        attempt_id=transcript.assignment.attempt_id,
        assignment_digest=transcript.assignment.digest,
        provider=transcript.assignment.provider,
        slot_id=transcript.assignment.slot_id,
        kind=InterruptionKind.OPERATOR_REQUESTED,
        source_event_digest=INTERRUPTION_SOURCE_EVENT_DIGEST,
        observed_at=NOW + timedelta(seconds=6),
    )

    with pytest.raises(ProviderContractError, match="only an interrupted"):
        replace(transcript, interruption=interruption).validate()


def test_cleanup_request_before_cleanup_pending_is_rejected() -> None:
    transcript = _success_transcript()
    stale_cleanup = replace(
        transcript.cleanup,
        requested_at=transcript.events[-2].occurred_at - timedelta(microseconds=1),
    )
    events = transcript.events[:-1] + (
        replace(
            transcript.events[-1],
            cleanup_outcome_digest=stale_cleanup.digest,
        ),
    )
    with pytest.raises(ProviderContractError, match="before the attempt entered"):
        replace(
            transcript,
            events=events,
            cleanup=stale_cleanup,
        ).validate()


def test_interruption_before_dispatch_is_rejected() -> None:
    transcript = _interrupted_transcript()
    interruption = replace(
        transcript.interruption,
        observed_at=transcript.events[0].occurred_at - timedelta(microseconds=1),
    )
    events = list(transcript.events)
    events[-2] = replace(events[-2], detail_digest=interruption.digest)
    events[-1] = replace(events[-1], detail_digest=interruption.digest)

    with pytest.raises(ProviderContractError, match="outside the attempt event window"):
        replace(
            transcript,
            events=tuple(events),
            interruption=interruption,
        ).validate()


def test_interruption_after_cleanup_entry_is_rejected() -> None:
    transcript = _interrupted_transcript()
    interruption = replace(
        transcript.interruption,
        observed_at=transcript.events[-2].occurred_at + timedelta(microseconds=1),
    )
    events = list(transcript.events)
    events[-2] = replace(events[-2], detail_digest=interruption.digest)
    events[-1] = replace(events[-1], detail_digest=interruption.digest)

    with pytest.raises(ProviderContractError, match="outside the attempt event window"):
        replace(
            transcript,
            events=tuple(events),
            interruption=interruption,
        ).validate()


def test_interrupt_cleanup_entry_must_bind_interruption() -> None:
    transcript = _interrupted_transcript()
    events = list(transcript.events)
    events[-2] = replace(events[-2], detail_digest=MISMATCH_DIGEST)

    with pytest.raises(ProviderContractError, match="does not bind its interruption"):
        replace(transcript, events=tuple(events)).validate()
