# Independent provenance verification (cathedral-compute)

Public claim under proof: **"SN39 mainnet: validated Intel TDX CPU
compute."** Nothing broader. This document describes how ANY third party
reproduces a scoring decision from public, signed, content-addressed
evidence — and exactly what each outcome means.

> **Status honesty.** The public evidence surface is now deployed. That proves
> availability, not freshness or `FULL` assurance. The complete immutable
> public pin bundle, controlled positive package, real-ELF replay on the
> supported release, and clean outside-operator reproduction remain launch
> gates. Locally green code and a signed receipt chain are not substitutes.

> **Current compatibility: `AGREE` (2026-08-07).** Publisher, validator,
> verifier and release pins converged: the deployed vector carries the
> `fixed_burn_allocation` contract and exact body binding, and this
> repository's end-to-end comparison passes against it. `BUILD_STATUS.md`
> carries the same result and is the file to trust if the two ever disagree.
>
> The earlier `FAIL` recorded here (audited 2026-07-25) is superseded. It
> described a v1 vector advertising `verified_gpu_allocation` with no
> `external_scores.latest_body_sha256`, which is no longer what is deployed.
>
> A validator pinned to `validated_supply_v1` accepts v2 evidence
> (`MECHANISM_ACCEPTED` in the validator scaffold), and the burn contract is
> always looked up from the operator's own pinned mechanism rather than from
> the id a manifest claims, so widening acceptance cannot move the burn. New
> evidence is emitted as v2; v1 is retired only once no live validator pins it
> and no historical release needs reproducing.

## Reproduction contract

The command below becomes independently runnable only when the supported
release notes replace every placeholder with immutable artifacts and digests.
Until then it is the exact contract the release must satisfy, not a public
one-command quick start.

From a clean machine (fresh venv, no Cathedral infrastructure access):

```bash
python -m pip install --upgrade 'pip>=26.1.2'
pip install <pinned cathedral-compute release>

# Capture the candidate oracle with YOUR OWN chain access (from the
# cathedralsubnet package): the anchored block is printed by the manifest.
cathedral-candidate-snapshot --network finney --netuid 39 \
  --block <anchored block> --output independent-snapshot.json

cathedral provenance verify \
  --evidence-url https://api.cathedral.computer/v1/evidence \
  --network finney --netuid 39 \
  --registry-keys pins/registry-keys.json --registry-keys-digest sha256:... \
  --report-keys pins/report-keys.json   --report-keys-digest sha256:... \
  --index-keys pins/index-keys.json     --index-keys-digest sha256:... \
  --verifier-digest sha256:... --source-revision <pinned commit> \
  --controlled-dir ./controlled \
  --independent-candidate-snapshot independent-snapshot.json \
  --production --current-block <finalized block> \
  --state-file ./verifier-state.json \
  --jsonl audit.jsonl --audit-out audit.json
```

Every pin (key digests, verifier implementation digest, source revision)
comes from the release notes — never from anything the evidence surface
serves. If the release notes do not publish every required pin, stop with
`NOT_PROVEN`; never copy a missing trust root from the service being verified.

## What FULL verifies

1. Signed policy registry (Ed25519, monotonic release, 86400s freshness
   ceiling, durable anti-rollback state).
2. Signed `cathedral_score_class_report_v2` under that registry: exact
   field set, block window (`valid_from_block >= candidate_snapshot.block`),
   report-id binding, chain continuity, and the SIGNED candidate-snapshot
   binding (digest, block, hash, full sorted hotkey set).
3. Every assurance receipt, and per positive miner: the SAT work artifacts
   replay under the ONE producer contract (recomputed challenge id from
   canonical instance+seed, producer bounds) with units re-derived under
   the versioned `sat_work_units_v1` rule — no signer or miner claim.
4. The controlled envelope's raw quote replays through the pinned verifier
   under the challenge-v2 derived nonce
   (`sha256("cathedral-tdx-challenge-v2\0" || canonical{block, block_hash,
   network, netuid, source_epoch, miner_hotkey})`).
5. **The independent candidate oracle.** FULL requires an independently
   captured historical candidate set + block hash for the anchored block,
   EXACTLY equal to the report's signed binding. Two mutually consistent
   Cathedral artifacts are never an oracle: an omitted registered hotkey
   or a fabricated anchor fails closed before any replay.
6. The recomputed vector under the exact frozen mechanism pair
   `(validated_supply_v1, revision=1)` — the manifest carries both halves
   and verification dispatches on the pair, refusing any other id or
   revision BEFORE recomputation and before any fence reservation
   (units-proportional shares; the fixed 10% burn floor is applied at
   UID-mapping time and validated by the subnet vector contract — see
   `docs/BUDGET.md`).

## Acceptance semantics

| Outcome | Meaning | Submission basis? |
|---|---|---|
| `PASS` + `assurance=full` | Every check above held, EVERY independently anchored candidate has a verified outcome and raw replay, oracle equality proven | Yes (authority mode) |
| `NOT_PROVEN` (`receipts_only`) | Signed chain internally consistent; the epoch was not FULLY replayed: missing controlled package, missing oracle, a zero-positive epoch, or ANY independently anchored candidate carrying a non-verified outcome (`rejected` or `retired`) — those labels are Cathedral-signed assertions and the launch artifact model publishes no independently replayable negative evidence. A departed hotkey is absent from the independent anchored candidate universe; relabelling it does not prove absence. | Never |
| `FAIL` | A signature, binding, bound, freshness, equivocation, replay, or malformed/inconsistent-evidence check failed (including outcome/receipt inconsistency and reservation conflicts) | Never — fail closed |

Exit code 0 requires `PASS` at `assurance=full` (or the explicit
`--allow-receipts-only` acknowledgement, which still records NOT_PROVEN).
The durable anti-rollback fences are reserved atomically BEFORE the
terminal `PROVENANCE_RESULT` event is emitted and before the audit file
reports acceptance: a reservation conflict aborts the run with a terminal
`FAIL` only — no accepting event or audit record can precede a failed
reservation.

An explicitly requested `--source-epoch` that resolves to an epoch other
than the index's current latest pointer is a historical audit, not a
frontier observation: it passes or fails on that epoch's own evidence, and
it is never classified as a report or policy rollback merely for naming an
epoch older than a previously recorded fence. A historical audit neither
lowers nor establishes any fence: it may only advance or reconfirm an
existing report or policy fence, and it never writes the index fence,
because a historical run never fetches or checks the latest pointer's
manifest. The index high-water advances only on a run that verified the
latest pointer. Equal-epoch equivocation and the sequential forward-chain
rule still hold unconditionally in historical mode, so a stale or
rolled-back report is still rejected and sequential catch-up through
repeated `--source-epoch` runs still advances the report fence one epoch
at a time.

## Signed-vector comparison binding (`--publisher-url`)

`compare_with_vector` reports agreement ONLY when the signed subnet vector
is bound to the verified evidence epoch, never from matching proportions
alone. The REAL `validated_supply_v1` wire contract (read from
`scaffold/publisher/weights.py` and `scaffold/validator_thin.py` in the
subnet repo) is enforced in full: pre-burn rows (base 0, weight ==
external, positive supply summing to 1.0), `burn_snapshot == {burn_uid:
null, burn_hotkey, forced_burn_percentage: 10.0}` (validators resolve the
burn HOTKEY against the live metagraph; a pinned historical integer burn
uid is rejected, never required), the signed
`policy_metadata.validated_supply` launch block (contract v2, 0.90 Intel
TDX, fixed 0.10 burn, matching burn hotkey), the
`confidential_primary` mass assertions, no burn-hotkey reuse as a miner,
and the signed `external_scores` binding: `latest_epoch` equal to the
verified `source_epoch` with `latest_complete=true`, backed by the
publisher's one-report-per-epoch ingest immutability. Exact report identity
is mandatory: the manifest's `wire_report_sha256` and the signed vector's
`external_scores.latest_body_sha256` must both be canonical SHA-256 values
and match exactly. `latest_report_sha256` remains the normalized semantic
epoch identity; it is intentionally distinct from the raw authenticated
body identity. Absence, malformation, or mismatch fails comparison.

## Logs

Two synchronized surfaces from one hardened `EventLogger`: a colored TTY
stream and stable JSONL (`--jsonl`; `tail -f audit.jsonl | jq .`). Every
value passes recursive redaction (sensitive field NAMES at every nesting
level including top-level, credential grammar, control-character
neutralization); JSONL files are 0600 `O_NOFOLLOW`. OS errors surface as
stable errno codes without filesystem paths or usernames.

## Related

- `docs/MRTD.md` — measurement/TCB policy, approval, rollback.
- `docs/BUDGET.md` — fixed spend and burn controls, security exceptions.
- `docs/LAUNCH_CANDIDATE.md` — dated 2026-07-24 implementation checkpoint.
- `BUILD_STATUS.md` — current public status and historical acceptance boundary.
