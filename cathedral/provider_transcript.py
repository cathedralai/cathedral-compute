"""Composition validators for attempt facts and final Worker settlement.

The provider attempt transcript contains provider-attempt facts only. Customer,
reservation, and settlement records appear only in the private Worker
transcript. Neither record provisions capacity, verifies attestation, proves
cleanup evidence, or mutates a billing ledger.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self

from cathedral.provider_contract import (
    AssignmentLedgerBinding,
    AssignmentPermit,
    AttemptAssignment,
    AttemptResult,
    AttemptState,
    AttemptTransitionEvent,
    CleanupOutcome,
    CustomerCapReservation,
    InterruptionOutcome,
    ProviderAbsenceStatus,
    ProviderContractError,
    SettlementAction,
    TerminalBasis,
    TERMINAL_ATTEMPT_STATES,
    UnassignedDispatchOutcome,
    WorkerSettlementDecision,
    canonical_json_bytes,
    canonical_sha256,
    parse_canonical_json,
    validate_assignment_permit,
    validate_assignment_reservation,
    validate_cleanup_assignment,
    validate_interruption_assignment,
    validate_permit_renewal,
    validate_result_assignment,
    validate_settlement,
    validate_settlement_supersession,
    validate_terminal_transition,
    validate_transition_assignment,
)


PROVIDER_ATTEMPT_TRANSCRIPT_SCHEMA = "cathedral_provider_attempt_transcript_v1"
WORKER_EXECUTION_TRANSCRIPT_SCHEMA = "cathedral_worker_execution_transcript_v1"
MAX_TRANSCRIPT_EVENTS = 32
MAX_WORKER_ATTEMPTS = 16
_CLEANUP_PENDING_STATES = frozenset(
    {
        AttemptState.SUCCESS_CLEANUP_PENDING,
        AttemptState.FAILURE_CLEANUP_PENDING,
        AttemptState.CANCEL_CLEANUP_PENDING,
        AttemptState.INTERRUPT_CLEANUP_PENDING,
    }
)
_ATTEMPT_KEYS = frozenset(
    {"schema", "assignment", "permits", "events", "cleanup", "interruption", "result"}
)
_WORKER_KEYS = frozenset(
    {
        "schema",
        "reservation",
        "bindings",
        "attempts",
        "unassigned_dispatch",
        "settlements",
    }
)


@dataclass(frozen=True)
class ProviderAttemptTranscript:
    """One immutable provider attempt with no customer or billing fields."""

    assignment: AttemptAssignment
    permits: tuple[AssignmentPermit, ...]
    events: tuple[AttemptTransitionEvent, ...]
    cleanup: CleanupOutcome
    interruption: InterruptionOutcome | None = None
    result: AttemptResult | None = None

    def to_document(self) -> Mapping[str, object]:
        self.validate()
        return {
            "schema": PROVIDER_ATTEMPT_TRANSCRIPT_SCHEMA,
            "assignment": self.assignment.to_document(),
            "permits": [permit.to_document() for permit in self.permits],
            "events": [event.to_document() for event in self.events],
            "cleanup": self.cleanup.to_document(),
            "interruption": (
                self.interruption.to_document() if self.interruption is not None else None
            ),
            "result": self.result.to_document() if self.result is not None else None,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_document())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def terminal_state(self) -> AttemptState:
        return self.validate()

    @property
    def terminal_event(self) -> AttemptTransitionEvent:
        self.validate()
        return self.events[-1]

    @classmethod
    def from_document(cls, document: object) -> Self:
        if (
            not isinstance(document, Mapping)
            or any(not isinstance(key, str) for key in document)
            or frozenset(document) != _ATTEMPT_KEYS
            or document.get("schema") != PROVIDER_ATTEMPT_TRANSCRIPT_SCHEMA
        ):
            raise ProviderContractError(
                "provider attempt transcript has missing, unknown, or unsupported fields"
            )
        raw_permits = document["permits"]
        raw_events = document["events"]
        if not isinstance(raw_permits, list):
            raise ProviderContractError("provider attempt transcript permits must be a list")
        if not isinstance(raw_events, list):
            raise ProviderContractError("provider attempt transcript events must be a list")
        if len(raw_events) > MAX_TRANSCRIPT_EVENTS:
            raise ProviderContractError("provider attempt transcript has too many events")
        interruption_document = document["interruption"]
        result_document = document["result"]
        transcript = cls(
            assignment=AttemptAssignment.from_document(document["assignment"]),
            permits=tuple(AssignmentPermit.from_document(item) for item in raw_permits),
            events=tuple(AttemptTransitionEvent.from_document(item) for item in raw_events),
            cleanup=CleanupOutcome.from_document(document["cleanup"]),
            interruption=(
                InterruptionOutcome.from_document(interruption_document)
                if interruption_document is not None
                else None
            ),
            result=(
                AttemptResult.from_document(result_document)
                if result_document is not None
                else None
            ),
        )
        transcript.validate()
        return transcript

    @classmethod
    def from_bytes(cls, data: bytes | str) -> Self:
        return cls.from_document(parse_canonical_json(data))

    def validate(self) -> AttemptState:
        if not isinstance(self.assignment, AttemptAssignment):
            raise ProviderContractError("transcript assignment is invalid")
        if (
            not isinstance(self.permits, tuple)
            or len(self.permits) == 0
            or any(not isinstance(permit, AssignmentPermit) for permit in self.permits)
        ):
            raise ProviderContractError("transcript permits are invalid")
        if self.permits[0].sequence != 1:
            raise ProviderContractError("transcript permit history must begin at sequence 1")
        for permit in self.permits:
            validate_assignment_permit(self.assignment, permit, permit.issued_at)
        for current, candidate in zip(self.permits, self.permits[1:]):
            validate_permit_renewal(current, candidate, candidate.issued_at)

        if not isinstance(self.cleanup, CleanupOutcome):
            raise ProviderContractError("transcript cleanup is invalid")
        if self.interruption is not None and not isinstance(self.interruption, InterruptionOutcome):
            raise ProviderContractError("transcript interruption is invalid")
        if (
            not isinstance(self.events, tuple)
            or len(self.events) == 0
            or len(self.events) > MAX_TRANSCRIPT_EVENTS
            or any(not isinstance(event, AttemptTransitionEvent) for event in self.events)
        ):
            raise ProviderContractError("transcript events are invalid")
        if self.events[0].current is not AttemptState.DISPATCH_PENDING:
            raise ProviderContractError("transcript must begin at DISPATCH_PENDING")
        if self.events[0].occurred_at < self.permits[0].issued_at:
            raise ProviderContractError("transcript begins before its initial permit")

        seen_event_ids: set[str] = set()
        for event in self.events:
            if event.event_id in seen_event_ids:
                raise ProviderContractError("transcript contains a duplicate event ID")
            seen_event_ids.add(event.event_id)
            validate_transition_assignment(self.assignment, event)
        for previous_event, next_event in zip(self.events, self.events[1:]):
            if next_event.current is not previous_event.target:
                raise ProviderContractError("transcript state chain is not continuous")
            if next_event.occurred_at < previous_event.occurred_at:
                raise ProviderContractError("transcript event timestamps are not nondecreasing")

        for event in self.events:
            if event.target in {AttemptState.ASSIGNMENT_SENT, AttemptState.ACKNOWLEDGED}:
                if not any(
                    permit.issued_at <= event.occurred_at < permit.expires_at
                    for permit in self.permits
                ):
                    raise ProviderContractError(
                        "assignment dispatch event falls outside every permit window"
                    )

        cleanup_entry_times = [
            event.occurred_at
            for event in self.events
            if event.target in _CLEANUP_PENDING_STATES | TERMINAL_ATTEMPT_STATES
        ]
        if cleanup_entry_times:
            first_cleanup_at = min(cleanup_entry_times)
            if any(permit.issued_at >= first_cleanup_at for permit in self.permits[1:]):
                raise ProviderContractError("a permit was renewed after cleanup began")

        for event in self.events[:-1]:
            if event.target in TERMINAL_ATTEMPT_STATES:
                raise ProviderContractError("only the final transcript event may be terminal")
        last_event = self.events[-1]
        if last_event.target not in TERMINAL_ATTEMPT_STATES:
            raise ProviderContractError("transcript must end at a terminal state")
        if len(self.events) < 2:
            raise ProviderContractError("transcript terminal event lacks a cleanup entry")

        cleanup_entry_event = self.events[-2]
        if self.cleanup.requested_at < cleanup_entry_event.occurred_at:
            raise ProviderContractError(
                "cleanup was requested before the attempt entered cleanup-pending"
            )
        validate_cleanup_assignment(self.assignment, self.cleanup)
        validate_terminal_transition(last_event, self.cleanup)

        if self.result is not None and not isinstance(self.result, AttemptResult):
            raise ProviderContractError("transcript result is invalid")
        result_events = [
            event for event in self.events if event.target is AttemptState.RESULT_RECEIVED
        ]
        if len(result_events) > 1:
            raise ProviderContractError("transcript reached RESULT_RECEIVED more than once")
        if result_events:
            if self.result is None:
                raise ProviderContractError(
                    "a RESULT_RECEIVED transition requires a matching result record"
                )
            validate_result_assignment(self.assignment, self.result)
            if result_events[0].detail_digest != self.result.digest:
                raise ProviderContractError(
                    "RESULT_RECEIVED transition does not bind its result record"
                )
            if result_events[0].occurred_at < self.result.received_at:
                raise ProviderContractError(
                    "RESULT_RECEIVED transition occurred before its result was received"
                )
        elif self.result is not None:
            raise ProviderContractError(
                "only an attempt that received a result may carry a result record"
            )

        if last_event.target is AttemptState.INTERRUPTED:
            if self.interruption is None:
                raise ProviderContractError(
                    "an interrupted transcript requires an interruption outcome"
                )
            validate_interruption_assignment(self.assignment, self.interruption)
            if cleanup_entry_event.detail_digest != self.interruption.digest:
                raise ProviderContractError(
                    "interrupt cleanup entry does not bind its interruption outcome"
                )
            if last_event.detail_digest != self.interruption.digest:
                raise ProviderContractError(
                    "interrupted terminal transition does not bind its interruption outcome"
                )
            if not (
                self.events[0].occurred_at
                <= self.interruption.observed_at
                <= cleanup_entry_event.occurred_at
            ):
                raise ProviderContractError(
                    "interruption observation falls outside the attempt event window"
                )
            if self.interruption.observed_at > self.cleanup.requested_at:
                raise ProviderContractError("interruption observation follows cleanup request")
        elif self.interruption is not None:
            raise ProviderContractError(
                "only an interrupted transcript accepts an interruption outcome"
            )

        return last_event.target


@dataclass(frozen=True)
class WorkerExecutionTranscript:
    """Mandatory private finalizer for one logical Worker and all of its attempts."""

    reservation: CustomerCapReservation
    bindings: tuple[AssignmentLedgerBinding, ...]
    attempts: tuple[ProviderAttemptTranscript, ...]
    unassigned_dispatch: UnassignedDispatchOutcome | None
    settlements: tuple[WorkerSettlementDecision, ...]

    def to_document(self) -> Mapping[str, object]:
        self.validate()
        return {
            "schema": WORKER_EXECUTION_TRANSCRIPT_SCHEMA,
            "reservation": self.reservation.to_document(),
            "bindings": [binding.to_document() for binding in self.bindings],
            "attempts": [attempt.to_document() for attempt in self.attempts],
            "unassigned_dispatch": (
                self.unassigned_dispatch.to_document()
                if self.unassigned_dispatch is not None
                else None
            ),
            "settlements": [settlement.to_document() for settlement in self.settlements],
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_document())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def final_settlement(self) -> WorkerSettlementDecision:
        self.validate()
        return self.settlements[-1]

    @classmethod
    def from_document(cls, document: object) -> Self:
        if (
            not isinstance(document, Mapping)
            or any(not isinstance(key, str) for key in document)
            or frozenset(document) != _WORKER_KEYS
            or document.get("schema") != WORKER_EXECUTION_TRANSCRIPT_SCHEMA
        ):
            raise ProviderContractError(
                "worker execution transcript has missing, unknown, or unsupported fields"
            )
        bindings = document["bindings"]
        attempts = document["attempts"]
        settlements = document["settlements"]
        if not isinstance(bindings, list) or not isinstance(attempts, list):
            raise ProviderContractError("worker attempts and bindings must be lists")
        if not isinstance(settlements, list):
            raise ProviderContractError("worker settlements must be a list")
        if len(attempts) > MAX_WORKER_ATTEMPTS:
            raise ProviderContractError("worker transcript has too many attempts")
        unassigned_document = document["unassigned_dispatch"]
        transcript = cls(
            reservation=CustomerCapReservation.from_document(document["reservation"]),
            bindings=tuple(AssignmentLedgerBinding.from_document(item) for item in bindings),
            attempts=tuple(ProviderAttemptTranscript.from_document(item) for item in attempts),
            unassigned_dispatch=(
                UnassignedDispatchOutcome.from_document(unassigned_document)
                if unassigned_document is not None
                else None
            ),
            settlements=tuple(
                WorkerSettlementDecision.from_document(item) for item in settlements
            ),
        )
        transcript.validate()
        return transcript

    @classmethod
    def from_bytes(cls, data: bytes | str) -> Self:
        return cls.from_document(parse_canonical_json(data))

    def validate(self) -> SettlementAction:
        if not isinstance(self.reservation, CustomerCapReservation):
            raise ProviderContractError("worker reservation is invalid")
        if (
            not isinstance(self.attempts, tuple)
            or len(self.attempts) > MAX_WORKER_ATTEMPTS
            or any(not isinstance(attempt, ProviderAttemptTranscript) for attempt in self.attempts)
        ):
            raise ProviderContractError("worker attempts are invalid")
        if (
            not isinstance(self.bindings, tuple)
            or any(not isinstance(binding, AssignmentLedgerBinding) for binding in self.bindings)
        ):
            raise ProviderContractError("worker bindings are invalid")
        if (len(self.attempts) == 0) == (self.unassigned_dispatch is None):
            raise ProviderContractError(
                "worker transcript requires either attempts or one unassigned outcome"
            )
        if self.attempts and len(self.bindings) != len(self.attempts):
            raise ProviderContractError("every attempt requires one private ledger binding")
        if self.unassigned_dispatch is not None and self.bindings:
            raise ProviderContractError("an unassigned Worker cannot have attempt bindings")
        if (
            not isinstance(self.settlements, tuple)
            or len(self.settlements) not in {1, 2}
            or any(
                not isinstance(settlement, WorkerSettlementDecision)
                for settlement in self.settlements
            )
        ):
            raise ProviderContractError("worker finalizer requires one final settlement")

        terminal_states = [attempt.validate() for attempt in self.attempts]
        attempt_ids = [attempt.assignment.attempt_id for attempt in self.attempts]
        provider_nonces = [attempt.assignment.provider_nonce for attempt in self.attempts]
        if len(set(attempt_ids)) != len(attempt_ids):
            raise ProviderContractError("worker attempts reuse an attempt ID")
        if len(set(provider_nonces)) != len(provider_nonces):
            raise ProviderContractError("worker attempts reuse a provider nonce")

        for index, (binding, attempt) in enumerate(zip(self.bindings, self.attempts), start=1):
            validate_assignment_reservation(
                attempt.assignment,
                attempt.permits[0],
                binding,
                self.reservation,
            )
            if binding.attempt_number != index:
                raise ProviderContractError("worker attempt numbers are not contiguous")
            expected_parent = None if index == 1 else self.attempts[index - 2].assignment.attempt_id
            if binding.retry_parent_attempt_id != expected_parent:
                raise ProviderContractError("retry attempt does not name its immediate parent")
            for permit in attempt.permits:
                if permit.issued_at < self.reservation.reserved_at:
                    raise ProviderContractError("permit predates the Worker reservation")
                if permit.expires_at > self.reservation.expires_at:
                    raise ProviderContractError("permit outlives the Worker reservation")

        for previous, candidate in zip(self.attempts, self.attempts[1:]):
            previous_terminal_at = previous.events[-1].occurred_at
            if candidate.permits[0].issued_at < previous_terminal_at:
                raise ProviderContractError("retry permit overlaps the prior attempt")
            if candidate.events[0].occurred_at < previous_terminal_at:
                raise ProviderContractError("retry attempt overlaps the prior attempt")

        success_indexes = [
            index for index, state in enumerate(terminal_states) if state is AttemptState.SUCCEEDED
        ]
        if len(success_indexes) > 1:
            raise ProviderContractError("a Worker cannot have multiple successful attempts")
        if success_indexes and success_indexes[0] != len(self.attempts) - 1:
            raise ProviderContractError("only the final Worker attempt may succeed")

        for settlement in self.settlements:
            validate_settlement(self.reservation, settlement)
        if len({settlement.decision_id for settlement in self.settlements}) != len(
            self.settlements
        ):
            raise ProviderContractError("worker settlement IDs are not unique")
        if len(self.settlements) == 2:
            validate_settlement_supersession(
                self.reservation,
                self.settlements[0],
                self.settlements[1],
            )
        elif self.settlements[0].action is SettlementAction.HELD_PENDING_CLEANUP:
            raise ProviderContractError("a held Worker settlement is not final")
        final = self.settlements[-1]
        if final.action is SettlementAction.HELD_PENDING_CLEANUP:
            raise ProviderContractError("worker finalizer cannot end with a held settlement")

        if self.unassigned_dispatch is not None:
            outcome = self.unassigned_dispatch
            if outcome.worker_id != self.reservation.worker_id:
                raise ProviderContractError("unassigned outcome belongs to another Worker")
            if outcome.request_digest != self.reservation.request_digest:
                raise ProviderContractError("unassigned outcome changes the Worker request")
            if self.settlements[0].action is SettlementAction.HELD_PENDING_CLEANUP:
                raise ProviderContractError("an unassigned Worker cannot hold settlement")
            if final.action is not SettlementAction.RELEASED:
                raise ProviderContractError("an unassigned Worker must release its reservation")
            if final.worker_outcome_digest != outcome.digest:
                raise ProviderContractError("settlement does not bind the unassigned outcome")
            if final.decided_at < outcome.observed_at:
                raise ProviderContractError("settlement precedes the unassigned outcome")
            return final.action

        last_attempt = self.attempts[-1]
        last_terminal_at = last_attempt.events[-1].occurred_at
        if final.decided_at < last_terminal_at:
            raise ProviderContractError("settlement precedes a child attempt terminal event")
        if final.action is SettlementAction.CHARGED:
            if len(success_indexes) != 1:
                raise ProviderContractError("a charged Worker requires one successful attempt")
            winner = last_attempt
            if final.winning_attempt_id != winner.assignment.attempt_id:
                raise ProviderContractError("settlement names the wrong winning attempt")
            if final.worker_outcome_digest != winner.digest:
                raise ProviderContractError("settlement does not bind the winning transcript")
            if winner.events[-1].terminal_basis is not TerminalBasis.PROVIDER_ABSENCE:
                raise ProviderContractError("a charged winner requires provider-absence cleanup")
            if winner.cleanup.absence_status is not ProviderAbsenceStatus.PROVEN_ABSENT:
                raise ProviderContractError("a charged winner lacks proven cleanup")
        else:
            if success_indexes:
                raise ProviderContractError("a successful Worker must settle against its winner")
            if final.worker_outcome_digest != last_attempt.digest:
                raise ProviderContractError("released settlement does not bind the final attempt")
        return final.action
