# Independent provenance verification (cathedralconfidential)

Public claim under proof: **"SN39 mainnet: validated Intel TDX CPU
compute."** Nothing broader. This document describes how ANY third party
reproduces a scoring decision from public, signed, content-addressed
evidence — and exactly what each outcome means.

> **Status honesty.** Everything below is implemented and adversarially
> tested locally (see `docs/LAUNCH_CANDIDATE.md` for the exact matrix).
> Locally green code is NOT live proof: the live evidence surface, key
> bundle, and real-ELF replay remain NOT PROVEN until the deploy gates
> pass independent review.

## One-command clean reproduction

From a clean machine (fresh venv, no Cathedral infrastructure access):

```bash
python -m pip install --upgrade 'pip>=26.1.2'
pip install <pinned cathedralconfidential release>

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
serves. The key bundle does not exist until deploy; its digests cannot be
pinned here yet (`docs/LAUNCH_CANDIDATE.md`, NOT PROVEN item 5).

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
| `PASS` + `assurance=full` | Every check above held, EVERY active candidate's outcome independently proven (all positives raw-replayed, no unproven rejection), oracle equality proven | Yes (authority mode) |
| `NOT_PROVEN` (`receipts_only`) | Signed chain internally consistent; the epoch was not FULLY replayed: missing controlled package, missing oracle, a zero-positive epoch, or ANY active candidate carrying a `rejected` outcome — a rejection is a Cathedral-signed assertion and the artifact model publishes no independently replayable rejection evidence, so a mixed positive/rejected epoch is NOT PROVEN even when every positive replays | Never |
| `FAIL` | A signature, binding, bound, freshness, equivocation, replay, or malformed/inconsistent-evidence check failed (including outcome/receipt inconsistency and reservation conflicts) | Never — fail closed |

Exit code 0 requires `PASS` at `assurance=full` (or the explicit
`--allow-receipts-only` acknowledgement, which still records NOT_PROVEN).
The durable anti-rollback fences are reserved atomically BEFORE the
terminal `PROVENANCE_RESULT` event is emitted and before the audit file
reports acceptance: a reservation conflict aborts the run with a terminal
`FAIL` only — no accepting event or audit record can precede a failed
reservation.

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
`policy_metadata.validated_supply` launch block (contract v1, 0.90 Intel
TDX, 0.10 Verified GPU, GPU not admitted, matching burn hotkey), the
`confidential_primary` mass assertions, no burn-hotkey reuse as a miner,
and the signed `external_scores` binding: `latest_epoch` equal to the
verified `source_epoch` with `latest_complete=true`, backed by the
publisher's one-report-per-epoch ingest immutability, checked against the
manifest's `wire_report_sha256` presence.

**Residual gap (subnet pin-advance required).** The subnet's signed
`latest_report_sha256` digests its NORMALIZED ingest row, while the
evidence manifest's `wire_report_sha256` digests the raw posted body —
different byte domains, so byte-exact report binding cannot be checked
today and the epoch binding above is the strongest signed link. The exact
subnet change: store `sha256(raw ingest body)` at ingest and echo it as
`external_scores.latest_body_sha256` in the signed vector metadata. The
comparator ALREADY enforces equality with `wire_report_sha256` whenever
that field is present, so the subnet change lands without a confidential
release. Until then, same-epoch report substitution inside the publisher
is NOT PROVEN by this comparison.

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
- `docs/LAUNCH_CANDIDATE.md` — the authoritative PROVEN/NOT-PROVEN matrix.
