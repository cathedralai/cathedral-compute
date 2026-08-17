# Provider-neutral capacity contract

This document defines Cathedral's versioned control-plane records for future
prepared confidential-compute capacity. The implementation is in
`cathedral/provider_contract.py`. It is a contract layer only.

The contract does not:

- provision, start, stop, or delete a VM;
- run a customer job;
- prove a provider's cleanup assertion by itself;
- mutate a customer balance or invoice;
- enforce a dollar limit in Intel TDX hardware;
- send Bittensor weights or change reward policy; or
- support a public speed claim.

Those outcomes require separate durable services, independent evidence
verification, live infrastructure, and measured acceptance gates.

## Why this boundary exists

A logical customer job and a provider execution attempt have different
lifecycles. One customer request keeps one logical job ID. Retry creates a new
attempt ID. It never rewrites the prior attempt or loses its cleanup state.

The records bind each attempt to:

- one provider identity and prepared slot;
- a fresh nonce;
- exact workload, policy, and image digests;
- one opaque, assignment-scoped permit whose private ledger binding names the
  customer cap reservation in integer micros; and
- canonical issue and expiry times.

Every transition, interruption, and cleanup record carries the assignment
digest. Finalization checks the attempt ID, provider identity, slot, reservation,
cleanup, terminal event, and settlement against the same immutable assignment.

The record is provider-neutral. A Cathedral seed and a subnet miner use the
same assignment format. Infrastructure-vendor project IDs, instance names,
credentials, and metadata never enter this public contract.

## Schemas

| Record | Schema | Purpose |
| --- | --- | --- |
| Provider identity | `cathedral_provider_identity_v1` | Distinguishes Cathedral seed supply from a subnet hotkey |
| Capability slot | `cathedral_provider_capability_slot_v1` | Binds one prepared slot to region, zone, profile, image, policy, supply class, and heartbeat |
| Capability inventory | `cathedral_provider_capability_inventory_v1` | Carries a bounded snapshot of zero or more capability slots |
| Attempt assignment | `cathedral_attempt_assignment_v1` | Gives a provider an opaque, expiring permit for one attempt and slot |
| Attempt result | `cathedral_attempt_result_v1` | Binds a provider's returned result and its attestation quote to the exact assignment, fresh nonce, and image digest it answers |
| Assignment ledger binding | `cathedral_assignment_ledger_binding_v1` | Privately joins an assignment to customer, logical job, reservation, and cap facts |
| Attempt transition | `cathedral_attempt_transition_v1` | Records one fail-closed state transition |
| Interruption outcome | `cathedral_interruption_outcome_v1` | Binds a preemption, timeout, provider event, or operator event to an assignment |
| Cleanup outcome | `cathedral_cleanup_outcome_v1` | Preserves provider absence as proven, present, or not proven |
| Cap reservation | `cathedral_customer_cap_reservation_v1` | Records the ledger ceiling reserved for one attempt |
| Settlement decision | `cathedral_customer_settlement_decision_v1` | Charges, releases, or holds a reservation without exceeding it |
| Idempotency binding | `cathedral_submission_idempotency_v1` | Binds customer and key to request bytes and the original logical job |
| Attempt transcript | `cathedral_provider_attempt_transcript_v1` | Composes one assignment, private ledger binding, ordered event chain, cleanup result, settlement, and any interruption |

Every wire record has a fail-closed `from_document` parser and an exact schema
tag. The Python dataclasses emit strict ASCII JSON with sorted keys and compact
separators. SHA-256 digests use the `sha256:<64 lowercase hex>` form. Signed or
hashed material rejects floating-point values, duplicate JSON keys, maps with
non-string keys, malformed timestamps, malformed identifiers, unknown enum
values, documents larger than 1 MiB, and structures deeper than 64 levels.
Non-Python consumers must reproduce these exact ASCII JSON rules. Integer
fields are signed 64-bit values and must not pass through an imprecise
floating-point representation.

The assignment golden vector is
`examples/provider-contract/assignment-v1.json`. Its expected digest is fixed.
Tests fail if field names, serialization, or binding semantics drift.

Complete success and interruption transcript vectors are checked in at
`examples/provider-contract/transcript-success-v1.json` and
`examples/provider-contract/transcript-interrupted-v1.json`. These files are
the exact canonical wire bytes followed by one repository line terminator.
Their fixed SHA-256 digests and strict loader tests reject reordered events,
cross-attempt substitution, changed cleanup, missing interruption evidence,
unknown fields, and noncanonical JSON.

The `FAILED`, `CANCELLED`, and `EVIDENCE_REJECTED` transcript paths, a
`WorkerExecutionTranscript` example, an idempotency-conflict vector, a
permit-renewal vector, an attempt-result vector, and a stale-quote vector are
checked in alongside them. Every vector is wired to a test that exercises the
invariant it pins rather than only parsing the file. A vector that merely
round-trips proves nothing about the rule it represents.

Regenerate all vectors with `scripts/generate_provider_contract_vectors.py`.
The generator builds each record from the live dataclasses and is deterministic:
no wall-clock time, no random identifiers, so a second run is byte-identical.
Never hand-edit a vector. Change the contract, rerun the generator, and let the
digest assertions record the change.

### This repository is canonical for the wire format

Earlier design drafts of this contract are in circulation. Where any of them
disagrees with this repository, this repository wins, because it is the artifact
the tests execute. The differences below are deliberate, not drift:

- Field names are `provider_nonce` and `workload_manifest_digest`. Drafts using
  `nonce` and `workload_digest` are superseded.
- `budget_micros` is refused inside `workload_manifest` and `policy_document`.
  A provider does not need the customer's budget to execute one bounded job, and
  the permit binds the assignment without it. Any draft that puts a budget on
  the provider-facing document is superseded.
- Every failure routes through a cleanup-pending state, and the post-result
  states carry abort edges. A draft that lets a state reach `FAILED` directly,
  or that gives `SUCCESS_CLEANUP_PENDING` no abort edge, cannot represent its
  own cleanup deadline rule. Here an unproven cleanup deadline ends `FAILED`
  with a refund and can never produce a success.

Implementers should build against this repository.

The composed attempt transcript contains the private ledger binding,
reservation, settlement, customer ID, and logical job ID. It is an internal
broker and audit record. Never send it to a provider. The opaque attempt
assignment remains the provider-facing document.

## Provider identity

`cathedral_seed` names Cathedral-controlled bootstrap capacity. It has no
subnet hotkey.

`subnet_hotkey` names miner capacity. Its provider ID equals the bound subnet
hotkey. A seed cannot present itself as a miner. A miner cannot advertise a
seed supply class.

This identity is a routing and audit binding. It does not verify ownership,
the SS58 checksum, or attestation by itself. Enrollment must validate and bind
the canonical hotkey before constructing the identity. Evidence verification
remains separate.

## Capability inventory

Every advertised slot binds:

- provider identity;
- slot ID;
- region and zone;
- execution profile;
- immutable image digest;
- policy version and digest;
- supply class; and
- canonical UTC heartbeat.

An inventory accepts zero slots so a provider can state zero capacity. It caps
one snapshot at 4,096 slots, rejects duplicate provider and slot pairs, and
rejects a slot heartbeat later than the inventory generation time. Freshness
policy belongs to the future capacity router. A heartbeat is a provider
statement, not proof that an attested guest is ready.

## Logical jobs, attempts, and idempotency

The customer's logical job ID survives retry. Every provider execution has a
new attempt ID. The provider-facing assignment does not carry the customer ID,
logical job ID, reservation ID, or reserved amount. It carries only the attempt
ID and one opaque `assignment_permit_digest`.

The private assignment-ledger binding joins the assignment digest and permit
digest to the exact customer, logical job, attempt, reservation, request, and
reserved amount. The combined finalization validator follows this private join
before accepting an event, cleanup, or settlement. A provider cannot reuse one
valid success record as a voucher for a different attempt.

The permit must be fresh for each attempt, secret-derived, and unlinkable from
customer or cap values. A retry gets a new attempt ID, assignment nonce, and
permit. This module checks record bindings. The future durable dispatcher must
enforce permit and nonce uniqueness transactionally.

Submission idempotency follows one rule:

- same customer, key, and request digest returns the original logical job;
- same customer and key with different request bytes is a conflict; and
- a retry uses a new attempt ID under the original logical job.

A duplicate transition event, reservation, or settlement decision ID replays
only when every canonical field is identical. Changed duplicate contents fail
closed.

These helpers express the invariant. A production dispatcher still needs a
transactional durable store with unique constraints. An in-memory check is not
sufficient for crash recovery or concurrent requests.

## Loading the dispatched workload manifest

`ProviderDispatchEnvelope.workload_manifest` is typed as a generic canonical
object. The envelope itself only checks that it is canonical JSON, that its
digest matches the assignment's `workload_manifest_digest`, and that it
carries no forbidden private field name. That is a shape check, not a
manifest check: an empty object with a matching digest satisfies it.

`cathedral/workload.py` defines what a manifest actually is:
`WorkloadManifest` and its schema, `cathedral_workload_manifest_v1`.
`parse_workload_manifest_document` and `load_dispatch_workload_manifest`
parse a dispatch envelope's `workload_manifest` against that real schema and
return the typed `WorkloadManifest` object, so a dispatcher gets the exact
policy-checked manifest that passed admission instead of an unvalidated blob
that merely hashes to the right value. The loader:

- requires the exact field set `WorkloadManifest.document()` defines, so a
  missing, extra, or renamed field is rejected rather than silently ignored;
- independently re-applies the private-field rule, so a manifest that
  otherwise satisfies the real schema but also carries a forbidden field
  (for example `budget_micros`) is still rejected; and
- rejects a document whose redundant image fields (`registry`, `repository`,
  `image_digest`) disagree with its `image_reference`, by reconstructing the
  manifest and requiring its canonical bytes to match the input exactly.

This loader does not run admission policy or signature verification. Those
already happened, before this document was ever placed on the wire; this
only confirms the wire copy is the same typed object, not a re-check of
whether it should have been admitted.

## Attempt lifecycle

The exact normal success path is:

```text
DISPATCH_PENDING
  -> SLOT_CLAIMED
  -> ASSIGNMENT_SENT
  -> ACKNOWLEDGED
  -> ATTESTING
  -> RUNNING
  -> RESULT_RECEIVED
  -> EVIDENCE_VERIFIED
  -> SUCCESS_CLEANUP_PENDING
  -> SUCCEEDED
```

Rejected evidence follows:

```text
RESULT_RECEIVED
  -> EVIDENCE_REJECTED
  -> FAILURE_CLEANUP_PENDING
  -> FAILED
```

Failure, cancellation, and interruption from an active attempt enter their
matching cleanup-pending state. No active state transitions directly to a
terminal state. Receiving output does not make an attempt successful.

`EVIDENCE_VERIFIED`, `EVIDENCE_REJECTED`, and
`SUCCESS_CLEANUP_PENDING` also retain paths to failure, cancellation, and
interruption cleanup. This prevents verified output or withheld cleanup proof
from deadlocking an attempt. An unproven cleanup deadline moves through one of
those non-success cleanup paths before reaching a terminal state.

The four terminal states are:

- `SUCCEEDED` after `SUCCESS_CLEANUP_PENDING`;
- `FAILED` after `FAILURE_CLEANUP_PENDING`;
- `CANCELLED` after `CANCEL_CLEANUP_PENDING`; and
- `INTERRUPTED` after `INTERRUPT_CLEANUP_PENDING`.

## Attempt result and quote binding

`RESULT_RECEIVED` used to carry only an opaque `detail_digest` on the
transition event, with no schema defining what it pointed at. Nothing bound
that digest to a nonce, an attestation quote, or a result payload, so a stale
quote, one produced for an earlier or different attempt, satisfied it as well
as a fresh one.

`cathedral_attempt_result_v1` closes that gap. It binds the assignment
digest, the attempt ID, the quote bytes digest, the nonce the quote actually
attests, the measurement (image) digest the quote reports, the result
payload digest, and the canonical `produced_at` / `received_at` times. A
transcript that reaches `RESULT_RECEIVED` must carry a matching result
record, and the transition's `detail_digest` must equal that record's
digest. `validate_result_assignment` then enforces, fail-closed:

- the quote's attested nonce must equal the assignment's `provider_nonce`,
  so a quote produced for a previous attempt cannot satisfy a new one, even
  when it is otherwise correctly relabeled with the new attempt ID and
  assignment digest;
- the reported measurement must equal the assignment's `image_digest`; and
- the result's own `attempt_id` and `assignment_digest` must match the
  assignment it is checked against.

An attempt that aborts before `RUNNING` never produces a result and must not
carry one. `RESULT_RECEIVED` is reachable at most once per attempt, and its
transition cannot be logged before the result it reports on was received.

This record treats a quote as opaque bytes plus the fields it claims. It
does **not**:

- verify Intel DCAP evidence or parse a real quote structure;
- prove the measurement is genuine, only that the claimed value matches the
  assignment's pinned digest;
- prove the result payload is correct, only that its digest is bound to this
  attempt; or
- replace the independent attestation verification the promotion
  requirements below still call for.

The golden vector is `examples/provider-contract/attempt-result-v1.json`.
`examples/provider-contract/stale-quote-v1.json` pins the exact replay this
record exists to reject: a result record correctly addressed to a retry
(matching attempt ID and assignment digest) whose quote still attests the
prior assignment's nonce.

## Cleanup and provider absence

A cleanup record preserves one of three statuses:

- `PROVEN_ABSENT`;
- `PRESENT`; or
- `NOT_PROVEN`.

`PROVEN_ABSENT` and `PRESENT` require an observation digest. The contract
validates the record shape and binding. It does not independently verify the
provider API, disk inventory, guest teardown, or evidence behind that digest.

A terminal transition normally uses `provider_absence` and requires
`PROVEN_ABSENT`.

A separate `customer_cleanup_deadline` basis exists for a bounded customer
response when cleanup remains unresolved. The cleanup record must include the
deadline and an observation at or after it. Its absence status stays `PRESENT`
or `NOT_PROVEN`. The deadline path never relabels an unproven cleanup as proven.
It never produces `SUCCEEDED`, successful output, or a successful receipt. It
ends customer waiting only as `FAILED`, `CANCELLED`, or `INTERRUPTED`.

`PRESENT` and `NOT_PROVEN` are different operational facts. `PRESENT` means a
provider observation still found residue and requires a higher-severity cleanup
alarm. `NOT_PROVEN` means the absence check was unavailable or inconclusive.
Neither status permits a success or customer charge at the deadline.
Background reconciliation and residue alarms remain required after the
customer-facing attempt reaches a terminal state through this path.

## Interruption

The interruption record binds the assignment digest, attempt, provider, slot,
source event digest, and observation time. Supported sources are:

- provider preemption notice;
- heartbeat timeout;
- provider-reported interruption; and
- explicit operator request.

An `INTERRUPTED` terminal settlement requires this record. The terminal
transition's detail digest binds the complete interruption outcome. The outcome
then binds the underlying provider or operator source-event digest. The
interruption observation must precede its cleanup request. Other terminal
states reject an attached interruption record.

The source record does not decide retry safety. Retry policy must consider
egress, external side effects, volumes, output publication, and customer
policy. The first prepared-capacity beta should retry only explicitly safe,
side-effect-free jobs.

## Customer cap and settlement

Money uses integer micros. Booleans and floating-point values are rejected.

The cap reservation binds customer, logical job, attempt, request digest,
reservation ID, amount, and expiry. These facts stay in the private ledger.
The provider assignment carries only the opaque assignment permit. The private
assignment-ledger binding must match the assignment digest, permit, customer,
logical job, attempt, reservation, request, and amount before dispatch or
settlement.

An assignment must be issued during the reservation window. Its expiry cannot
outlive reservation expiry. A settlement before reservation creation is
invalid. At or after reservation expiry, the only accepted settlement is an
uncharged release.

An initial settlement has sequence 1, a unique decision ID, and no superseded
decision. It has three actions:

- `charged`, with a charge no greater than the reservation;
- `released`, with zero charge; and
- `held_pending_cleanup`, with zero charge until reconciliation releases.

The validation helper checks the exact reservation binding and ceiling. A held
decision has one permitted sequence-2 resolution. The resolution must use a
new decision ID, bind the held decision digest, occur later, and release the
cap with zero charge. Exact replays return the prior resolution. A competing
resolution fails closed.

A future billing ledger must enforce decision IDs, reservation IDs, and one
resolution per held digest with durable unique constraints and an atomic
transaction. Intel TDX isolates guest memory. It does not meter dollars,
reserve customer funds, or halt a CPU at a currency boundary.

Customer finalization uses the combined terminal-settlement validator. A
cleanup-deadline terminal state accepts only `released` or
`held_pending_cleanup`, both with zero charge. A proven-absence success accepts
`charged` within the cap or `released` for a free run. A proven-absence failure,
cancellation, or interruption releases the cap with zero charge. Settlement
never turns unresolved cleanup into a billable success.

## Bittensor boundary

Prepared-capacity routing and customer settlement are asynchronous from subnet
scoring. This module imports no Bittensor code and changes no score or reward
path. Future miner attempts must earn only after the validator verifies the
applicable work and evidence under a separately versioned policy.

Cathedral seed capacity never becomes miner work merely by using this contract.
If seed and miner capacity share a router, their identity and supply class stay
explicit in every inventory, assignment, and receipt-facing record.

## Promotion requirements

Before a live provider agent consumes these records, the platform still needs:

1. durable attempt, transition, idempotency, reservation, and outbox storage;
2. authenticated assignment transport and replay protection;
3. independent attestation and cleanup-evidence verification;
4. provider-specific reconcilers behind the provider-neutral interface;
5. interruption and crash recovery tests;
6. billing-ledger atomicity and refund tests;
7. residue detection and alerting; and
8. externally measured admission, start, completion, duplicate, and residue gates.

Until those gates pass, this contract is local implementation evidence. It is
not proof of live capacity, live teardown, customer billing safety, miner
rewards, or blazing-fast sandbox performance.
