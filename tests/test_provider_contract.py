"""Fail-closed vectors for the provider-neutral prepared-capacity contract."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cathedral.provider_contract import (
    ALLOWED_ATTEMPT_TRANSITIONS,
    MAX_CANONICAL_BYTES,
    MAX_INVENTORY_SLOTS,
    AssignmentLedgerBinding,
    AssignmentPermit,
    AttemptAssignment,
    AttemptState,
    AttemptTransitionEvent,
    CapabilityInventory,
    CapabilitySlot,
    CleanupOutcome,
    CleanupPath,
    CustomerCapReservation,
    DuplicateDecision,
    IdempotencyDecision,
    InterruptionKind,
    InterruptionOutcome,
    ProviderAbsenceStatus,
    ProviderContractError,
    ProviderIdentity,
    ProviderIdentityKind,
    ProviderDispatchEnvelope,
    ProviderRejectionCode,
    SettlementAction,
    SubmissionIdempotencyBinding,
    SupplyClass,
    TerminalBasis,
    UnassignedDispatchOutcome,
    UnassignedDispatchReason,
    WorkerSettlementDecision,
    canonical_json_bytes,
    canonical_sha256,
    hash_idempotency_key,
    parse_canonical_json,
    require_attempt_transition,
    resolve_submission_idempotency,
    resolve_held_settlement,
    resolve_reservation_duplicate,
    resolve_settlement_duplicate,
    resolve_transition_duplicate,
    validate_assignment_reservation,
    validate_assignment_permit,
    validate_assignment_slot,
    validate_cleanup_assignment,
    validate_interruption_assignment,
    validate_settlement,
    validate_settlement_supersession,
    validate_permit_renewal,
    validate_transition_assignment,
    validate_terminal_transition,
)


NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=UTC)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
DIGEST_E = "sha256:" + "e" * 64
HOTKEY = "5" * 48


class _NeverIteratedOversizedList(list[object]):
    def __len__(self) -> int:
        return MAX_CANONICAL_BYTES + 1

    def __iter__(self) -> Iterator[object]:
        raise AssertionError("oversized input must be rejected before iteration")


def _seed() -> ProviderIdentity:
    return ProviderIdentity(ProviderIdentityKind.CATHEDRAL_SEED, "seed-useast-1")


def _slot(**changes: object) -> CapabilitySlot:
    values: dict[str, object] = {
        "provider": _seed(),
        "slot_id": "slot-useast1-a-001",
        "region": "us-east1",
        "zone": "us-east1-b",
        "execution_profile": "cpu-tdx-fast-v1",
        "image_digest": DIGEST_C,
        "policy_version": "policy-v1",
        "policy_digest": DIGEST_B,
        "supply_class": SupplyClass.SEED_PREEMPTIBLE,
        "heartbeat_at": NOW,
    }
    values.update(changes)
    return CapabilitySlot(**values)  # type: ignore[arg-type]


def _assignment(**changes: object) -> AttemptAssignment:
    values: dict[str, object] = {
        "attempt_id": "attempt-001",
        "provider": _seed(),
        "slot_id": "slot-useast1-a-001",
        "provider_nonce": "d" * 64,
        "workload_manifest_digest": DIGEST_A,
        "policy_digest": DIGEST_B,
        "image_digest": DIGEST_C,
    }
    values.update(changes)
    return AttemptAssignment(**values)  # type: ignore[arg-type]


def _permit(
    assignment: AttemptAssignment | None = None,
    **changes: object,
) -> AssignmentPermit:
    bound_assignment = assignment or _assignment()
    values: dict[str, object] = {
        "assignment_digest": bound_assignment.digest,
        "sequence": 1,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=2),
        "key_id": "broker-key-1",
        "authorization_digest": DIGEST_E,
    }
    values.update(changes)
    return AssignmentPermit(**values)  # type: ignore[arg-type]


def _binding(
    assignment: AttemptAssignment | None = None,
    **changes: object,
) -> AssignmentLedgerBinding:
    bound_assignment = assignment or _assignment()
    values: dict[str, object] = {
        "binding_id": "binding-001",
        "assignment_digest": bound_assignment.digest,
        "customer_id": "customer-1",
        "worker_id": "worker-001",
        "attempt_id": bound_assignment.attempt_id,
        "attempt_number": 1,
        "retry_parent_attempt_id": None,
        "reservation_id": "reservation-001",
        "request_digest": DIGEST_A,
        "reserved_micros": 200_000,
        "created_at": NOW,
    }
    values.update(changes)
    return AssignmentLedgerBinding(**values)  # type: ignore[arg-type]


def _reservation(**changes: object) -> CustomerCapReservation:
    values: dict[str, object] = {
        "customer_id": "customer-1",
        "worker_id": "worker-001",
        "reservation_id": "reservation-001",
        "request_digest": DIGEST_A,
        "reserved_micros": 200_000,
        "reserved_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(changes)
    return CustomerCapReservation(**values)  # type: ignore[arg-type]


def _settlement(
    cleanup: CleanupOutcome | None = None,
    **changes: object,
) -> WorkerSettlementDecision:
    bound_cleanup = cleanup or _cleanup()
    values: dict[str, object] = {
        "decision_id": "settlement-001",
        "sequence": 1,
        "supersedes_digest": None,
        "customer_id": "customer-1",
        "worker_id": "worker-001",
        "reservation_id": "reservation-001",
        "reserved_micros": 200_000,
        "charged_micros": 125_000,
        "action": SettlementAction.CHARGED,
        "winning_attempt_id": "attempt-001",
        "worker_outcome_digest": bound_cleanup.digest,
        "decided_at": NOW + timedelta(seconds=30),
    }
    values.update(changes)
    if values["action"] is not SettlementAction.CHARGED:
        if "charged_micros" not in changes:
            values["charged_micros"] = 0
        if "winning_attempt_id" not in changes:
            values["winning_attempt_id"] = None
    return WorkerSettlementDecision(**values)  # type: ignore[arg-type]


def _cleanup(
    *,
    path: CleanupPath = CleanupPath.SUCCESS,
    absence: ProviderAbsenceStatus = ProviderAbsenceStatus.PROVEN_ABSENT,
    deadline: datetime | None = None,
    observed_at: datetime = NOW + timedelta(seconds=20),
) -> CleanupOutcome:
    return CleanupOutcome(
        attempt_id="attempt-001",
        assignment_digest=_assignment().digest,
        provider=_seed(),
        slot_id="slot-useast1-a-001",
        path=path,
        absence_status=absence,
        requested_at=NOW + timedelta(seconds=10),
        observed_at=observed_at,
        observation_digest=(DIGEST_D if absence is not ProviderAbsenceStatus.NOT_PROVEN else None),
        customer_cleanup_deadline_at=deadline,
    )


def _interruption(**changes: object) -> InterruptionOutcome:
    values: dict[str, object] = {
        "attempt_id": "attempt-001",
        "assignment_digest": _assignment().digest,
        "provider": _seed(),
        "slot_id": "slot-useast1-a-001",
        "kind": InterruptionKind.PREEMPTION_NOTICE,
        "source_event_digest": DIGEST_A,
        "observed_at": NOW + timedelta(seconds=5),
    }
    values.update(changes)
    return InterruptionOutcome(**values)  # type: ignore[arg-type]


def _terminal_event(
    cleanup: CleanupOutcome,
    *,
    current: AttemptState = AttemptState.SUCCESS_CLEANUP_PENDING,
    target: AttemptState = AttemptState.SUCCEEDED,
    basis: TerminalBasis = TerminalBasis.PROVIDER_ABSENCE,
    detail_digest: str = DIGEST_A,
) -> AttemptTransitionEvent:
    return AttemptTransitionEvent(
        event_id="event-terminal-001",
        attempt_id="attempt-001",
        assignment_digest=_assignment().digest,
        current=current,
        target=target,
        occurred_at=cleanup.observed_at,
        detail_digest=detail_digest,
        cleanup_outcome_digest=cleanup.digest,
        terminal_basis=basis,
    )


def test_checked_in_assignment_golden_vector_is_stable() -> None:
    vector_path = (
        Path(__file__).parents[1] / "examples" / "provider-contract" / "assignment-v1.json"
    )
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    assignment = AttemptAssignment.from_document(vector["assignment"])

    assert assignment.to_document() == vector["assignment"]
    assert assignment.digest == vector["expected_digest"]
    assert canonical_sha256(vector["assignment"]) == vector["expected_digest"]
    assert parse_canonical_json(canonical_json_bytes(assignment)) == vector["assignment"]


def test_canonical_json_rejects_floats_non_string_keys_duplicates_and_padding() -> None:
    with pytest.raises(ProviderContractError, match="floating-point"):
        canonical_json_bytes({"nested": [1, {"price": 0.2}]})
    with pytest.raises(ProviderContractError, match="string keys"):
        canonical_json_bytes({1: "value"})
    with pytest.raises(ProviderContractError, match="duplicate"):
        parse_canonical_json(b'{"a":1,"a":1}')
    with pytest.raises(ProviderContractError, match="canonical form"):
        parse_canonical_json(b'{ "a": 1 }')
    with pytest.raises(ProviderContractError, match="floating-point"):
        parse_canonical_json(b'{"a":1.0}')


def test_canonical_json_enforces_size_and_depth_limits() -> None:
    with pytest.raises(ProviderContractError, match="size limit"):
        canonical_json_bytes({"value": "x" * MAX_CANONICAL_BYTES})

    nested: object = "leaf"
    for _ in range(66):
        nested = [nested]
    with pytest.raises(ProviderContractError, match="deeply nested"):
        canonical_json_bytes(nested)

    with pytest.raises(ProviderContractError, match="size limit"):
        canonical_json_bytes(_NeverIteratedOversizedList())


def test_seed_and_subnet_identity_are_mutually_exclusive() -> None:
    seed = _seed()
    subnet = ProviderIdentity(ProviderIdentityKind.SUBNET_HOTKEY, HOTKEY, HOTKEY)

    assert seed.to_document()["subnet_hotkey"] is None
    assert subnet.to_document()["subnet_hotkey"] == HOTKEY
    with pytest.raises(ProviderContractError, match="must not claim"):
        ProviderIdentity(ProviderIdentityKind.CATHEDRAL_SEED, "seed-1", HOTKEY)
    with pytest.raises(ProviderContractError, match="bound canonical"):
        ProviderIdentity(ProviderIdentityKind.SUBNET_HOTKEY, "provider-1", HOTKEY)
    with pytest.raises(ProviderContractError, match="kind"):
        ProviderIdentity.from_document(
            {
                "schema": "cathedral_provider_identity_v1",
                "kind": "cloud_account",
                "provider_id": "provider-1",
                "subnet_hotkey": None,
            }
        )


def test_capability_inventory_binds_provider_slot_and_freshness() -> None:
    slot = _slot(slot_id="slot-1")
    inventory = CapabilityInventory(
        inventory_id="inventory-1",
        generated_at=NOW + timedelta(seconds=1),
        slots=(slot,),
    )

    assert inventory.to_document()["slots"][0]["provider"] == _seed().to_document()  # type: ignore[index]
    with pytest.raises(ProviderContractError, match="duplicate"):
        CapabilityInventory("inventory-2", NOW + timedelta(seconds=1), (slot, slot))
    with pytest.raises(ProviderContractError, match="later"):
        CapabilityInventory("inventory-3", NOW - timedelta(seconds=1), (slot,))
    with pytest.raises(ProviderContractError, match="subnet supply"):
        replace(slot, supply_class=SupplyClass.SUBNET_MINER)
    with pytest.raises(ProviderContractError, match="must advertise subnet"):
        replace(
            slot,
            provider=ProviderIdentity(ProviderIdentityKind.SUBNET_HOTKEY, HOTKEY, HOTKEY),
            supply_class=SupplyClass.SEED_PREEMPTIBLE,
        )


def test_capability_inventory_allows_empty_snapshot_and_caps_slot_count() -> None:
    empty = CapabilityInventory("inventory-empty", NOW, ())

    assert CapabilityInventory.from_document(empty.to_document()) == empty
    with pytest.raises(ProviderContractError, match="slots are invalid"):
        CapabilityInventory(
            "inventory-too-large",
            NOW,
            (_slot(),) * (MAX_INVENTORY_SLOTS + 1),
        )

    oversized_document = dict(empty.to_document())
    oversized_document["slots"] = _NeverIteratedOversizedList()
    with pytest.raises(ProviderContractError, match="slot limit"):
        CapabilityInventory.from_document(oversized_document)


def test_capability_slot_is_independently_versioned() -> None:
    document = _slot().to_document()

    assert document["schema"] == "cathedral_provider_capability_slot_v1"
    assert CapabilitySlot.from_document(document) == _slot()


def test_assignment_must_match_advertised_slot_inputs() -> None:
    assignment = _assignment()
    slot = CapabilitySlot(
        provider=_seed(),
        slot_id="slot-useast1-a-001",
        region="us-east1",
        zone="us-east1-b",
        execution_profile="cpu-tdx-fast-v1",
        image_digest=DIGEST_C,
        policy_version="policy-v1",
        policy_digest=DIGEST_B,
        supply_class=SupplyClass.SEED_PREEMPTIBLE,
        heartbeat_at=NOW,
    )

    validate_assignment_slot(assignment, slot)
    with pytest.raises(ProviderContractError, match="does not match"):
        validate_assignment_slot(assignment, replace(slot, image_digest=DIGEST_D))


@pytest.mark.parametrize(
    ("field", "bad_value", "message"),
    [
        ("workload_manifest_digest", "sha256:ABC", "sha256"),
        ("provider_nonce", "not-a-nonce", "nonce"),
        ("provider_nonce", "a" * 63, "nonce"),
        ("attempt_id", "spaces are invalid", "attempt_id"),
    ],
)
def test_assignment_rejects_malformed_bound_values(
    field: str, bad_value: object, message: str
) -> None:
    with pytest.raises(ProviderContractError, match=message):
        _assignment(**{field: bad_value})


def test_assignment_parser_rejects_unknown_fields_and_permit_rejects_noncanonical_time() -> None:
    document = dict(_assignment().to_document())
    document["unexpected"] = True
    with pytest.raises(ProviderContractError, match="unknown"):
        AttemptAssignment.from_document(document)

    document = dict(_permit().to_document())
    document["issued_at"] = "2026-08-17T12:00:00Z"
    with pytest.raises(ProviderContractError, match="canonical UTC"):
        AssignmentPermit.from_document(document)


def test_provider_assignment_exposes_no_stable_job_reservation_or_budget_amount() -> None:
    document = _assignment().to_document()

    assert "logical_job_id" not in document
    assert "worker_id" not in document
    assert "customer_id" not in document
    assert "reservation_id" not in document
    assert "reserved_micros" not in document
    assert "assignment_permit_digest" not in document
    assert "issued_at" not in document
    assert "expires_at" not in document


def test_permit_is_separate_and_renewal_rejects_replay_gap_expiry_and_rebinding() -> None:
    assignment = _assignment()
    current = _permit(assignment)
    renewal = _permit(
        assignment,
        sequence=2,
        issued_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=3),
    )

    validate_assignment_permit(assignment, current, NOW)
    validate_permit_renewal(current, renewal, NOW + timedelta(minutes=1))
    with pytest.raises(ProviderContractError) as replay:
        validate_permit_renewal(current, replace(current), NOW + timedelta(seconds=1))
    assert replay.value.code is ProviderRejectionCode.PERMIT_REPLAY
    with pytest.raises(ProviderContractError) as gap:
        validate_permit_renewal(current, replace(renewal, sequence=3), renewal.issued_at)
    assert gap.value.code is ProviderRejectionCode.PERMIT_SEQUENCE
    with pytest.raises(ProviderContractError) as expired:
        validate_assignment_permit(assignment, current, current.expires_at)
    assert expired.value.code is ProviderRejectionCode.PERMIT_EXPIRED
    with pytest.raises(ProviderContractError) as rebound:
        validate_assignment_permit(
            replace(assignment, attempt_id="attempt-other"),
            current,
            NOW,
        )
    assert rebound.value.code is ProviderRejectionCode.PERMIT_ASSIGNMENT_MISMATCH


def test_provider_dispatch_envelope_binds_exact_documents_and_rejects_private_fields() -> None:
    workload_manifest = {
        "schema": "cathedral_workload_manifest_v1",
        "command": ["python", "-V"],
        "max_output_bytes": 4096,
    }
    policy_document = {
        "schema": "cathedral_execution_policy_v1",
        "egress": "none",
        "max_runtime_seconds": 60,
    }
    assignment = _assignment(
        workload_manifest_digest=canonical_sha256(workload_manifest),
        policy_digest=canonical_sha256(policy_document),
    )
    permit = _permit(assignment)
    envelope = ProviderDispatchEnvelope(
        assignment=assignment,
        workload_manifest=workload_manifest,
        policy_document=policy_document,
        permit=permit,
    )

    envelope.validate(NOW)
    assert ProviderDispatchEnvelope.from_bytes(envelope.canonical_bytes).digest == envelope.digest
    assert "customer_id" not in envelope.canonical_bytes.decode("ascii")
    with pytest.raises(ProviderContractError) as mismatch:
        ProviderDispatchEnvelope(
            assignment=assignment,
            workload_manifest={**workload_manifest, "command": ["false"]},
            policy_document=policy_document,
            permit=permit,
        )
    assert mismatch.value.code is ProviderRejectionCode.DIGEST_MISMATCH
    private_policy = {**policy_document, "customer_id": "customer-1"}
    private_assignment = replace(assignment, policy_digest=canonical_sha256(private_policy))
    with pytest.raises(ProviderContractError) as private:
        ProviderDispatchEnvelope(
            assignment=private_assignment,
            workload_manifest=workload_manifest,
            policy_document=private_policy,
            permit=_permit(private_assignment),
        )
    assert private.value.code is ProviderRejectionCode.PRIVATE_FIELD_FORBIDDEN


def test_unassigned_dispatch_is_worker_level_and_has_no_provider_attempt_fields() -> None:
    outcome = UnassignedDispatchOutcome(
        outcome_id="unassigned-001",
        worker_id="worker-001",
        request_digest=DIGEST_A,
        reason=UnassignedDispatchReason.NO_CAPACITY,
        routing_decision_digest=DIGEST_B,
        observed_at=NOW,
    )

    document = outcome.to_document()
    assert UnassignedDispatchOutcome.from_document(document) == outcome
    assert "attempt_id" not in document
    assert "provider" not in document
    assert "slot_id" not in document


def test_all_wire_records_round_trip_and_fail_closed_on_shape_or_schema() -> None:
    cleanup = _cleanup()
    records = (
        (_seed(), ProviderIdentity),
        (_slot(), CapabilitySlot),
        (
            CapabilityInventory("inventory-1", NOW + timedelta(seconds=1), (_slot(),)),
            CapabilityInventory,
        ),
        (_assignment(), AttemptAssignment),
        (_permit(), AssignmentPermit),
        (_binding(), AssignmentLedgerBinding),
        (
            InterruptionOutcome(
                attempt_id="attempt-001",
                assignment_digest=_assignment().digest,
                provider=_seed(),
                slot_id="slot-useast1-a-001",
                kind=InterruptionKind.PREEMPTION_NOTICE,
                source_event_digest=DIGEST_A,
                observed_at=NOW,
            ),
            InterruptionOutcome,
        ),
        (cleanup, CleanupOutcome),
        (_terminal_event(cleanup), AttemptTransitionEvent),
        (_reservation(), CustomerCapReservation),
        (_settlement(cleanup), WorkerSettlementDecision),
        (
            SubmissionIdempotencyBinding(
                customer_id="customer-1",
                idempotency_key_digest=hash_idempotency_key(b"same-request-1"),
                request_digest=DIGEST_A,
                worker_id="worker-001",
            ),
            SubmissionIdempotencyBinding,
        ),
    )

    for record, record_type in records:
        document = record.to_document()
        assert record_type.from_document(document) == record

        unknown = dict(document)
        unknown["unexpected"] = "field"
        with pytest.raises(ProviderContractError, match="missing or unknown"):
            record_type.from_document(unknown)

        bad_schema = dict(document)
        bad_schema["schema"] = "cathedral_unknown_v1"
        with pytest.raises(ProviderContractError, match="unsupported"):
            record_type.from_document(bad_schema)


def test_canonical_time_preserves_four_digit_years_before_one_thousand() -> None:
    early = datetime(1, 1, 1, tzinfo=UTC)
    reservation = _reservation(
        reserved_at=early,
        expires_at=early + timedelta(seconds=1),
    )

    assert reservation.to_document()["reserved_at"] == "0001-01-01T00:00:00.000000Z"
    assert CustomerCapReservation.from_document(reservation.to_document()) == reservation


def test_attempt_transition_table_is_closed_over_every_state_pair() -> None:
    for current in AttemptState:
        for target in AttemptState:
            if target in ALLOWED_ATTEMPT_TRANSITIONS[current]:
                require_attempt_transition(current, target)
            else:
                with pytest.raises(ProviderContractError, match="illegal attempt"):
                    require_attempt_transition(current, target)


def test_attempt_transition_table_is_read_only_after_construction() -> None:
    with pytest.raises(TypeError):
        ALLOWED_ATTEMPT_TRANSITIONS[AttemptState.SUCCEEDED] = frozenset({AttemptState.FAILED})  # type: ignore[index]


def test_normal_success_requires_evidence_then_cleanup_then_terminal() -> None:
    path = (
        AttemptState.DISPATCH_PENDING,
        AttemptState.SLOT_CLAIMED,
        AttemptState.ASSIGNMENT_SENT,
        AttemptState.ACKNOWLEDGED,
        AttemptState.ATTESTING,
        AttemptState.RUNNING,
        AttemptState.RESULT_RECEIVED,
        AttemptState.EVIDENCE_VERIFIED,
        AttemptState.SUCCESS_CLEANUP_PENDING,
        AttemptState.SUCCEEDED,
    )
    for current, target in zip(path, path[1:]):
        require_attempt_transition(current, target)

    for forbidden in (
        AttemptState.RUNNING,
        AttemptState.RESULT_RECEIVED,
        AttemptState.EVIDENCE_VERIFIED,
    ):
        with pytest.raises(ProviderContractError, match="illegal attempt"):
            require_attempt_transition(forbidden, AttemptState.SUCCEEDED)


def test_rejected_evidence_cannot_enter_success_cleanup() -> None:
    with pytest.raises(ProviderContractError, match="illegal attempt"):
        require_attempt_transition(
            AttemptState.EVIDENCE_REJECTED,
            AttemptState.SUCCESS_CLEANUP_PENDING,
        )
    require_attempt_transition(
        AttemptState.EVIDENCE_REJECTED,
        AttemptState.FAILURE_CLEANUP_PENDING,
    )


@pytest.mark.parametrize(
    "current",
    [
        AttemptState.EVIDENCE_VERIFIED,
        AttemptState.EVIDENCE_REJECTED,
        AttemptState.SUCCESS_CLEANUP_PENDING,
    ],
)
@pytest.mark.parametrize(
    "target",
    [
        AttemptState.FAILURE_CLEANUP_PENDING,
        AttemptState.CANCEL_CLEANUP_PENDING,
        AttemptState.INTERRUPT_CLEANUP_PENDING,
    ],
)
def test_evidence_and_success_cleanup_states_have_abort_paths(
    current: AttemptState,
    target: AttemptState,
) -> None:
    require_attempt_transition(current, target)


@pytest.mark.parametrize(
    ("path", "current", "target"),
    [
        (CleanupPath.SUCCESS, AttemptState.SUCCESS_CLEANUP_PENDING, AttemptState.SUCCEEDED),
        (CleanupPath.FAILURE, AttemptState.FAILURE_CLEANUP_PENDING, AttemptState.FAILED),
        (CleanupPath.CANCEL, AttemptState.CANCEL_CLEANUP_PENDING, AttemptState.CANCELLED),
        (
            CleanupPath.INTERRUPT,
            AttemptState.INTERRUPT_CLEANUP_PENDING,
            AttemptState.INTERRUPTED,
        ),
    ],
)
def test_each_terminal_state_requires_matching_proven_absence(
    path: CleanupPath,
    current: AttemptState,
    target: AttemptState,
) -> None:
    cleanup = _cleanup(path=path)
    event = _terminal_event(cleanup, current=current, target=target)
    validate_terminal_transition(event, cleanup)

    not_proven = _cleanup(path=path, absence=ProviderAbsenceStatus.NOT_PROVEN)
    event = _terminal_event(not_proven, current=current, target=target)
    with pytest.raises(ProviderContractError, match="not proven"):
        validate_terminal_transition(event, not_proven)


def test_customer_deadline_path_is_explicit_and_preserves_not_proven_status() -> None:
    deadline = NOW + timedelta(seconds=15)
    cleanup = _cleanup(
        path=CleanupPath.FAILURE,
        absence=ProviderAbsenceStatus.NOT_PROVEN,
        deadline=deadline,
        observed_at=NOW + timedelta(seconds=20),
    )
    event = _terminal_event(
        cleanup,
        current=AttemptState.FAILURE_CLEANUP_PENDING,
        target=AttemptState.FAILED,
        basis=TerminalBasis.CUSTOMER_CLEANUP_DEADLINE,
    )

    validate_terminal_transition(event, cleanup)
    assert cleanup.to_document()["absence_status"] == "NOT_PROVEN"
    assert event.to_document()["terminal_basis"] == "customer_cleanup_deadline"

    too_early = _cleanup(
        path=CleanupPath.FAILURE,
        absence=ProviderAbsenceStatus.NOT_PROVEN,
        deadline=deadline,
        observed_at=NOW + timedelta(seconds=14),
    )
    with pytest.raises(ProviderContractError, match="deadline"):
        validate_terminal_transition(
            _terminal_event(
                too_early,
                current=AttemptState.FAILURE_CLEANUP_PENDING,
                target=AttemptState.FAILED,
                basis=TerminalBasis.CUSTOMER_CLEANUP_DEADLINE,
            ),
            too_early,
        )

    with pytest.raises(ProviderContractError, match="precedes cleanup request"):
        _cleanup(
            absence=ProviderAbsenceStatus.NOT_PROVEN,
            deadline=NOW,
            observed_at=NOW + timedelta(seconds=20),
        )


def test_customer_cleanup_deadline_never_produces_success() -> None:
    cleanup = _cleanup(
        absence=ProviderAbsenceStatus.NOT_PROVEN,
        deadline=NOW + timedelta(seconds=15),
    )
    event = _terminal_event(cleanup, basis=TerminalBasis.CUSTOMER_CLEANUP_DEADLINE)

    with pytest.raises(ProviderContractError, match="cannot produce a successful"):
        validate_terminal_transition(event, cleanup)


@pytest.mark.parametrize(
    "absence",
    [ProviderAbsenceStatus.PRESENT, ProviderAbsenceStatus.NOT_PROVEN],
)
def test_deadline_preserves_present_and_not_proven_as_distinct_residue_states(
    absence: ProviderAbsenceStatus,
) -> None:
    cleanup = _cleanup(
        path=CleanupPath.FAILURE,
        absence=absence,
        deadline=NOW + timedelta(seconds=15),
    )
    event = _terminal_event(
        cleanup,
        current=AttemptState.FAILURE_CLEANUP_PENDING,
        target=AttemptState.FAILED,
        basis=TerminalBasis.CUSTOMER_CLEANUP_DEADLINE,
    )

    validate_terminal_transition(event, cleanup)
    assert cleanup.to_document()["absence_status"] == absence.value


def test_proven_absence_requires_evidence_and_cannot_use_deadline_label() -> None:
    with pytest.raises(ProviderContractError, match="requires an observation digest"):
        _cleanup().__class__(
            attempt_id="attempt-001",
            assignment_digest=_assignment().digest,
            provider=_seed(),
            slot_id="slot-useast1-a-001",
            path=CleanupPath.SUCCESS,
            absence_status=ProviderAbsenceStatus.PROVEN_ABSENT,
            requested_at=NOW,
            observed_at=NOW,
        )

    cleanup = _cleanup(
        path=CleanupPath.FAILURE,
        deadline=NOW + timedelta(seconds=15),
    )
    event = _terminal_event(
        cleanup,
        current=AttemptState.FAILURE_CLEANUP_PENDING,
        target=AttemptState.FAILED,
        basis=TerminalBasis.CUSTOMER_CLEANUP_DEADLINE,
    )
    with pytest.raises(ProviderContractError, match="provider-absence"):
        validate_terminal_transition(event, cleanup)


def test_present_cleanup_requires_positive_observation_evidence() -> None:
    with pytest.raises(ProviderContractError, match="requires an observation digest"):
        CleanupOutcome(
            attempt_id="attempt-001",
            assignment_digest=_assignment().digest,
            provider=_seed(),
            slot_id="slot-useast1-a-001",
            path=CleanupPath.FAILURE,
            absence_status=ProviderAbsenceStatus.PRESENT,
            requested_at=NOW,
            observed_at=NOW,
        )


def test_terminal_transition_binds_exact_cleanup_attempt_digest_and_path() -> None:
    cleanup = _cleanup()
    validate_transition_assignment(_assignment(), _terminal_event(cleanup))
    validate_cleanup_assignment(_assignment(), cleanup)
    with pytest.raises(ProviderContractError, match="another attempt"):
        validate_terminal_transition(
            _terminal_event(cleanup),
            replace(cleanup, attempt_id="attempt-other"),
        )
    with pytest.raises(ProviderContractError, match="does not bind"):
        validate_terminal_transition(
            replace(_terminal_event(cleanup), cleanup_outcome_digest=DIGEST_A),
            cleanup,
        )
    with pytest.raises(ProviderContractError, match="another assignment"):
        validate_terminal_transition(
            replace(_terminal_event(cleanup), assignment_digest=DIGEST_A),
            cleanup,
        )
    with pytest.raises(ProviderContractError, match="precedes its cleanup"):
        validate_terminal_transition(
            replace(
                _terminal_event(cleanup), occurred_at=cleanup.observed_at - timedelta(seconds=1)
            ),
            cleanup,
        )
    with pytest.raises(ProviderContractError, match="does not match"):
        validate_terminal_transition(
            _terminal_event(
                cleanup,
                current=AttemptState.FAILURE_CLEANUP_PENDING,
                target=AttemptState.FAILED,
            ),
            cleanup,
        )


def test_cleanup_outcome_binds_exact_assignment_provider_and_slot() -> None:
    cleanup = _cleanup()

    for mismatched in (
        replace(cleanup, attempt_id="attempt-other"),
        replace(cleanup, assignment_digest=DIGEST_A),
        replace(
            cleanup,
            provider=ProviderIdentity(
                ProviderIdentityKind.CATHEDRAL_SEED,
                "seed-other",
            ),
        ),
        replace(cleanup, slot_id="slot-other"),
    ):
        with pytest.raises(ProviderContractError, match="does not match"):
            validate_cleanup_assignment(_assignment(), mismatched)


def test_interruption_outcome_binds_assignment_provider_slot_and_source_event() -> None:
    outcome = InterruptionOutcome(
        attempt_id="attempt-001",
        assignment_digest=_assignment().digest,
        provider=_seed(),
        slot_id="slot-useast1-a-001",
        kind=InterruptionKind.PREEMPTION_NOTICE,
        source_event_digest=DIGEST_A,
        observed_at=NOW,
    )

    validate_interruption_assignment(_assignment(), outcome)
    assert outcome.to_document()["kind"] == "preemption_notice"
    for mismatched in (
        replace(outcome, attempt_id="attempt-other"),
        replace(outcome, assignment_digest=DIGEST_A),
        replace(
            outcome,
            provider=ProviderIdentity(
                ProviderIdentityKind.CATHEDRAL_SEED,
                "seed-other",
            ),
        ),
        replace(outcome, slot_id="slot-other"),
    ):
        with pytest.raises(ProviderContractError, match="does not match"):
            validate_interruption_assignment(_assignment(), mismatched)
    with pytest.raises(ProviderContractError, match="kind"):
        replace(outcome, kind="spot_notice")  # type: ignore[arg-type]


def test_duplicate_transition_events_replay_only_when_every_byte_matches() -> None:
    event = AttemptTransitionEvent(
        event_id="event-001",
        attempt_id="attempt-001",
        assignment_digest=_assignment().digest,
        current=AttemptState.RUNNING,
        target=AttemptState.RESULT_RECEIVED,
        occurred_at=NOW,
        detail_digest=DIGEST_A,
    )

    assert resolve_transition_duplicate(None, event) is DuplicateDecision.NEW
    validate_transition_assignment(_assignment(), event)
    assert resolve_transition_duplicate(event, replace(event)) is DuplicateDecision.REPLAY
    with pytest.raises(ProviderContractError, match="changed duplicate"):
        resolve_transition_duplicate(event, replace(event, detail_digest=DIGEST_B))


def test_idempotency_replays_original_worker_and_rejects_changed_bytes() -> None:
    key_digest = hash_idempotency_key(b"same-request-1")
    existing = SubmissionIdempotencyBinding(
        customer_id="customer-1",
        idempotency_key_digest=key_digest,
        request_digest=DIGEST_A,
        worker_id="worker-original",
    )
    candidate = replace(existing, worker_id="worker-new-proposal")

    decision, binding = resolve_submission_idempotency(None, existing)
    assert decision is IdempotencyDecision.NEW
    assert binding is existing
    decision, binding = resolve_submission_idempotency(existing, candidate)
    assert decision is IdempotencyDecision.REPLAY
    assert binding.worker_id == "worker-original"
    with pytest.raises(ProviderContractError, match="changed request bytes") as caught:
        resolve_submission_idempotency(existing, replace(candidate, request_digest=DIGEST_B))
    assert caught.value.code is ProviderRejectionCode.IDEMPOTENCY_CONFLICT
    with pytest.raises(ProviderContractError, match="8 to 200"):
        hash_idempotency_key(b"short")


def test_reservation_and_settlement_duplicates_are_exactly_idempotent() -> None:
    reservation = _reservation()
    settlement = _settlement()

    assert resolve_reservation_duplicate(None, reservation) is DuplicateDecision.NEW
    assert (
        resolve_reservation_duplicate(reservation, replace(reservation)) is DuplicateDecision.REPLAY
    )
    with pytest.raises(ProviderContractError, match="changed duplicate"):
        resolve_reservation_duplicate(
            reservation,
            replace(reservation, reserved_micros=199_999),
        )

    assert resolve_settlement_duplicate(None, settlement) is DuplicateDecision.NEW
    assert resolve_settlement_duplicate(settlement, replace(settlement)) is DuplicateDecision.REPLAY
    with pytest.raises(ProviderContractError, match="changed duplicate"):
        resolve_settlement_duplicate(
            settlement,
            replace(settlement, charged_micros=124_999),
        )


def test_assignment_expiry_never_outlives_cap_reservation() -> None:
    assignment = _assignment()
    permit = _permit(assignment, expires_at=NOW + timedelta(minutes=6))

    with pytest.raises(ProviderContractError, match="expiry exceeds"):
        validate_assignment_reservation(
            assignment,
            permit,
            _binding(assignment),
            _reservation(),
        )


def test_expired_reservation_only_accepts_an_uncharged_release() -> None:
    reservation = _reservation()
    expired_at = reservation.expires_at

    with pytest.raises(ProviderContractError, match="expired cap reservation"):
        validate_settlement(
            reservation,
            _settlement(decided_at=expired_at),
        )
    with pytest.raises(ProviderContractError, match="expired cap reservation"):
        validate_settlement(
            reservation,
            _settlement(
                charged_micros=0,
                action=SettlementAction.HELD_PENDING_CLEANUP,
                decided_at=expired_at,
            ),
        )

    validate_settlement(
        reservation,
        _settlement(
            charged_micros=0,
            action=SettlementAction.RELEASED,
            decided_at=expired_at,
        ),
    )
    with pytest.raises(ProviderContractError, match="precedes"):
        validate_settlement(
            reservation,
            _settlement(decided_at=reservation.reserved_at - timedelta(microseconds=1)),
        )


def test_customer_cap_uses_integer_micros_and_settlement_cannot_exceed_it() -> None:
    assignment = _assignment()
    reservation = _reservation()
    decision = _settlement()

    validate_assignment_reservation(assignment, _permit(assignment), _binding(assignment), reservation)
    validate_settlement(reservation, decision)
    with pytest.raises(ProviderContractError, match="binding does not match"):
        validate_assignment_reservation(
            assignment,
            _permit(assignment),
            _binding(assignment),
            replace(reservation, reserved_micros=199_999),
        )
    with pytest.raises(ProviderContractError, match="exceeds"):
        replace(decision, charged_micros=200_001)
    with pytest.raises(ProviderContractError, match="charge zero"):
        replace(decision, action=SettlementAction.RELEASED)
    with pytest.raises(ProviderContractError, match="does not match"):
        validate_settlement(reservation, replace(decision, worker_id="worker-other"))
    with pytest.raises(ProviderContractError, match="integer micros"):
        replace(reservation, reserved_micros=True)  # type: ignore[arg-type]


def test_held_settlement_is_zero_charge_and_explicitly_pending_cleanup() -> None:
    cleanup = _cleanup(
        absence=ProviderAbsenceStatus.NOT_PROVEN,
        deadline=NOW + timedelta(minutes=1),
    )
    decision = _settlement(
        cleanup,
        charged_micros=0,
        action=SettlementAction.HELD_PENDING_CLEANUP,
    )

    assert decision.to_document()["action"] == "held_pending_cleanup"


def test_deadline_terminal_is_attempt_fact_and_worker_settlement_stays_separate() -> None:
    reservation = _reservation()
    cleanup = _cleanup(
        path=CleanupPath.FAILURE,
        absence=ProviderAbsenceStatus.PRESENT,
        deadline=NOW + timedelta(seconds=15),
    )
    event = _terminal_event(
        cleanup,
        current=AttemptState.FAILURE_CLEANUP_PENDING,
        target=AttemptState.FAILED,
        basis=TerminalBasis.CUSTOMER_CLEANUP_DEADLINE,
    )
    validate_terminal_transition(event, cleanup)
    held = _settlement(
        cleanup,
        action=SettlementAction.HELD_PENDING_CLEANUP,
    )
    validate_settlement(reservation, held)
    assert "attempt_id" not in held.to_document()
    assert "cleanup_outcome_digest" not in held.to_document()


def test_proven_success_settlement_may_charge_within_reserved_cap() -> None:
    reservation = _reservation()
    cleanup = _cleanup()
    decision = _settlement(
        cleanup,
        charged_micros=200_000,
    )

    validate_settlement(reservation, decision)
    assert decision.winning_attempt_id == "attempt-001"
    assert decision.worker_outcome_digest == cleanup.digest


def test_private_binding_rejects_cross_attempt_record_mixing() -> None:
    assignment = _assignment()
    binding = _binding(assignment)
    reservation = _reservation()
    permit = _permit(assignment)

    validate_assignment_reservation(assignment, permit, binding, reservation)

    with pytest.raises(ProviderContractError, match="binding does not match"):
        validate_assignment_reservation(
            assignment,
            permit,
            replace(binding, attempt_id="attempt-other"),
            reservation,
        )


@pytest.mark.parametrize(
    ("path", "current", "target"),
    [
        (CleanupPath.FAILURE, AttemptState.FAILURE_CLEANUP_PENDING, AttemptState.FAILED),
        (CleanupPath.CANCEL, AttemptState.CANCEL_CLEANUP_PENDING, AttemptState.CANCELLED),
        (
            CleanupPath.INTERRUPT,
            AttemptState.INTERRUPT_CLEANUP_PENDING,
            AttemptState.INTERRUPTED,
        ),
    ],
)
def test_unsuccessful_terminal_attempts_release_and_never_charge(
    path: CleanupPath,
    current: AttemptState,
    target: AttemptState,
) -> None:
    reservation = _reservation()
    cleanup = _cleanup(path=path)
    interruption = _interruption() if target is AttemptState.INTERRUPTED else None
    event = _terminal_event(
        cleanup,
        current=current,
        target=target,
        detail_digest=(interruption.digest if interruption is not None else DIGEST_A),
    )
    validate_terminal_transition(event, cleanup)

    released = _settlement(
        cleanup,
        action=SettlementAction.RELEASED,
    )
    validate_settlement(reservation, released)
    assert released.charged_micros == 0
    assert released.winning_attempt_id is None


def test_interruption_outcome_binds_exact_assignment_and_terminal_cleanup() -> None:
    assignment = _assignment()
    cleanup = _cleanup(path=CleanupPath.INTERRUPT)
    interruption = _interruption()
    event = _terminal_event(
        cleanup,
        current=AttemptState.INTERRUPT_CLEANUP_PENDING,
        target=AttemptState.INTERRUPTED,
        detail_digest=interruption.digest,
    )
    validate_interruption_assignment(assignment, interruption)
    validate_terminal_transition(event, cleanup)
    with pytest.raises(ProviderContractError, match="does not match"):
        validate_interruption_assignment(
            assignment,
            replace(interruption, slot_id="slot-other"),
        )


def test_attempt_assignment_has_no_settlement_or_reservation_fields() -> None:
    assignment_document = _assignment().to_document()

    assert "settlement" not in assignment_document
    assert "reservation" not in assignment_document
    assert "customer_id" not in assignment_document


def test_held_settlement_has_one_exact_uncharged_resolution() -> None:
    reservation = _reservation()
    cleanup = _cleanup(
        path=CleanupPath.FAILURE,
        absence=ProviderAbsenceStatus.NOT_PROVEN,
        deadline=NOW + timedelta(seconds=15),
    )
    held = _settlement(
        cleanup,
        charged_micros=0,
        action=SettlementAction.HELD_PENDING_CLEANUP,
    )
    resolution = replace(
        held,
        decision_id="settlement-resolution-001",
        sequence=2,
        supersedes_digest=held.digest,
        action=SettlementAction.RELEASED,
        decided_at=reservation.expires_at + timedelta(seconds=1),
    )

    validate_settlement_supersession(reservation, held, resolution)
    assert resolve_held_settlement(None, reservation, held, resolution) is DuplicateDecision.NEW
    assert (
        resolve_held_settlement(
            resolution,
            reservation,
            held,
            replace(resolution),
        )
        is DuplicateDecision.REPLAY
    )

    conflicting = replace(
        resolution,
        decision_id="settlement-resolution-002",
        decided_at=resolution.decided_at + timedelta(seconds=1),
    )
    with pytest.raises(ProviderContractError, match="different resolution"):
        resolve_held_settlement(
            resolution,
            reservation,
            held,
            conflicting,
        )
    with pytest.raises(ProviderContractError, match="does not supersede"):
        validate_settlement_supersession(
            reservation,
            held,
            replace(resolution, supersedes_digest=DIGEST_A),
        )
    with pytest.raises(ProviderContractError, match="changes the Worker outcome"):
        validate_settlement_supersession(
            reservation,
            held,
            replace(resolution, worker_outcome_digest=DIGEST_B),
        )


def test_settlement_sequence_rejects_float_construction() -> None:
    with pytest.raises(ProviderContractError, match="sequence must be 1 or 2"):
        _settlement(sequence=1.0)
