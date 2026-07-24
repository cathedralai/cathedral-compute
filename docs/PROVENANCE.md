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
6. The recomputed `validated_supply_v1` vector (units-proportional shares;
   the fixed 10% burn floor is applied at UID-mapping time and validated
   by the subnet vector contract — see `docs/BUDGET.md`).

## Acceptance semantics

| Outcome | Meaning | Submission basis? |
|---|---|---|
| `PASS` + `assurance=full` | Every check above held, raw evidence replayed, oracle equality proven | Yes (authority mode) |
| `NOT_PROVEN` (`receipts_only`) | Signed chain internally consistent; raw evidence NOT replayed (missing controlled package, missing oracle, or a zero-positive epoch — the artifact model publishes no raw rejection evidence) | Never |
| `FAIL` | A signature, binding, bound, freshness, equivocation, or replay check failed | Never — fail closed |

Exit code 0 requires `PASS` at `assurance=full` (or the explicit
`--allow-receipts-only` acknowledgement, which still records NOT_PROVEN).

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
