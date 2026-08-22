# Build and evidence status

Evidence record last updated: 2026-07-24

Documentation and public-surface audit: 2026-07-25

> **Public phase: mainnet live testing.**
>
> This file records implementation evidence and historical acceptance tests. It
> is not a live leaderboard and does not prove that a miner is currently
> eligible. The first positive Intel TDX vector reached SN39 historically, but
> the supported tagged validator release, outside reproduction, and
> self-service provider path remain separate launch gates.

Current state must be checked through the live
[signed vector](https://api.cathedral.computer/v1/validator/weights/next) and
[evidence index](https://api.cathedral.computer/v1/evidence/index.json), then
verified for signature, freshness, policy, and provenance. A report with no
positive entries must resolve fail-closed; it must not inherit this document's
historical positive worker.

**Current public contract comparison: `AGREE` (2026-08-07).** The deployed
vector carries the v2 shape (`policy_metadata.validated_supply` with
`fixed_burn_allocation` and `intel_tdx_allocation`, no `verified_gpu_allocation`)
and reproduces against the current verifier. The 2026-07-28 redeploy converged
production; the prior `FAIL` banner described the pre-redeploy state and was
left stale for ten days, so treat a banner here as dated until re-derived.

What still blocks the independent-reproduction claim is publication, not the
contract: there is no tagged release and no published key-bundle digests, so
`docs/PROVENANCE.md` still carries placeholder pins and an outside validator
cannot assemble the one-command reproduction. See
[`docs/LAUNCH_CANDIDATE.md`](docs/LAUNCH_CANDIDATE.md) items 4 and 5.

Testnet SN292 remains the non-paying dry-run integration lane.

## Implemented and historically proven

- Cathedral Confidential is the primary verified-supply score source under
  `validated_supply_v1`. The validator independently enforces the versioned
  burn contract; miners cannot choose the allocation.
- The worker serves credential-free, bounded `POST /v1/evidence` collection
  and authenticated `POST /v1/sat-work`. It returns real Intel TDX hardware
  quotes (8000-byte quotes in the recorded hardware run, with
  `intel_verified=true` and `report_data_match=true`).
- The scorer enrolls workers, issues fresh challenges, verifies TDX evidence and
  hotkey binding, runs deterministic validator-dispatched audit work, derives
  the score itself, and publishes a complete signed score vector.
- On testnet SN292, a dedicated thin validator repeatedly accepted fresh signed
  vectors, mapped the proven worker hotkey to UID 41, and computed dry-run
  UID41 = 1.0.
- On mainnet SN39, validator UID 30 submitted a historical validated-supply
  acceptance vector in extrinsic
  `0x4ef1307460f6bcdf3acc17dc7a1070f0918cf1080d74fb9409897353fe6cb371`
  at block 8694350 (block hash
  `0x657b6b05db6a13dc4d215ed1fe7c7846522999aeebbbc193a8873522283c4016`).
  A historical chain query at that block returns exactly
  `[(163, 65535), (204, 7282)]` for validator UID 30: the admitted Intel TDX
  worker plus the fixed burn destination.
- The recorded policy is `validated_supply_v1`: up to 90% for validated Intel
  TDX CPU supply and exactly 10% forced burn. The recorded positive worker had
  validator-dispatched verified work. Attestation alone still pays nothing.
- Controlled positive-worker evidence replays through the pinned Intel TDX
  verifier. Whole-epoch FULL provenance remains `NOT_PROVEN`: zero-scored
  candidates have explicit zero rows but not candidate-specific replayable
  negative evidence.
- Hardware epochs run on a 60-second cycle; each verified epoch produces 20
  validator-derived work units at score 1.0.
- Post-migration foreign-key integrity is clean.
- Repository test suite: 1929 tests collected. (Collected, not passing: the
  TDX and SEV-SNP suites skip unless the hardware and CATHEDRAL_RUN_TDX_HW /
  CATHEDRAL_RUN_SNP_HW are present, so a passing total differs between a laptop
  and the TDX box. tests/test_documented_counts.py holds this number to the suite.)

## Operator: pretty epoch logs

Add `--pretty` to `runtime run-epoch` for a timestamped, single-line-per-worker
summary instead of JSON. JSON remains the default.

```
# Pretty mode (human-readable)
cathedral runtime run-epoch \
  --registry-db /data/registry.sqlite \
  --ledger-db /data/ledger.sqlite \
  --measurements-file /etc/cathedral/measurements.json \
  --canary-hotkey $CANARY_HOTKEY \
  --canary-endpoint $CANARY_ENDPOINT \
  --source-epoch 7 \
  --pretty
```

Example output (one header, one line per worker, one footer):

```
[2026-07-13T15:23:01Z] EPOCH START  source=7  ep=1
[2026-07-13T15:23:09Z] OK    5Aaaa..aaaa  ep=7/1  admit=Y  work=verified               wu=   20.00  score=1.000  pub=NO  ch=ababab..ababab
[2026-07-13T15:23:09Z] ZERO  5Bbbb..bbbb  ep=7/1  admit=Y  work=sat_failed             wu=    0.00  score=0.000  pub=NO  ch=cdcdcd..cdcdcd  err=invalid SAT certificate
[2026-07-13T15:23:09Z] FAIL  5Cccc..cccc  ep=7/1  admit=N  work=attestation_failed     wu=    0.00  score=0.000  pub=NO  err=worker returned HTTP 401
[2026-07-13T15:23:09Z] EPOCH END  ep=7/1  status=complete  published=NO  workers=3  ok=1  zeros=1  fail=1
```

Indicators: `OK` = scored, `ZERO` = admitted but no verified work, `FAIL` = not
admitted. An aborted epoch appends `!! EPOCH FAILED` to the footer.

`retry-publish --pretty` emits a single acknowledgement line:

```
[2026-07-13T15:25:01Z] PUBLISH  epoch=1  ok  ack=accepted
```

JSON is always the default; omit `--pretty` in automated pipelines.

Both default JSON and `--pretty` output redact credential-shaped values
(`bearer=`, `token=`, `secret=`, `hmac=`, `api_key=`, `Authorization: Bearer ...`)
from any embedded error text before printing, and the same redaction applies
to top-level CLI exception output.

## Operator recovery: abandon-complete

A `complete` epoch is frozen and unpublished. Normally the operator publishes
it with `retry-publish`, which always resends the exact same immutable report
bytes. If the downstream ingest service permanently rejects that report (for
example, its `generated_at` has aged past the ingest service's first-publish
freshness window), `retry-publish` can never succeed for that epoch and it
will block `begin_epoch` forever.

`runtime abandon-complete` is the audited recovery: it transitions the epoch
from `complete` to a terminal `abandoned` status and unblocks `begin_epoch`.
It never mutates the frozen `report_body`/`report_digest`, requires a
nonempty `--reason`, and records that reason with a timestamp in the ledger.
Abandoned work can never become payable: `mark_published` only accepts a
`complete` epoch, and the trailing score window only reads `published`
epochs, so an abandoned epoch is excluded from both permanently. Only a
`complete` epoch can be abandoned; every other transition (running, aborted,
published, already abandoned) is rejected.

```bash
cathedral runtime abandon-complete \
  --ledger-db /data/ledger.sqlite \
  --epoch-id 42 \
  --reason "report generated_at exceeds ingest service's 24h first-publish window"
```

```json
{"abandoned_at": "2026-07-13T18:02:11.123456+00:00", "abandoned_epoch_id": 42, "reason": "report generated_at exceeds ingest service's 24h first-publish window"}
```

Older on-disk ledgers created before this status existed are migrated
automatically (in place, preserving all rows) the first time they are opened.

## Network boundary

### Mainnet SN39

Mainnet broadcast has passed limited historical acceptance tests. The validator
used for those tests:

1. requires the signed `validated_supply_v1` policy;
2. verifies the `finney` / netuid 39 envelope and freshness;
3. maps every positive hotkey against the live metagraph; and
4. submits the complete confidential vector.

The first monitored all-burn submission succeeded on 2026-07-13. The first
monitored positive validated-supply submission above succeeded on 2026-07-24.
The historical block and extrinsic are independently queryable from a Finney
archive node. These facts prove that the mechanism reached chain at those
points; they do not prove the current vector, a generally released validator,
or future emissions.

### Testnet SN292

SN292 remains dry-run. It verifies real worker evidence, work, scoring, signed
publication, and UID mapping, but does not submit weights or pay emissions.

## Remaining acceptance work

1. On the final tagged release, make a previously admitted miner stale or fail
   evidence and confirm its prior positive weight is revoked to zero on chain.
2. Obtain an independent outside-operator reproduction of the signed release,
   historical metagraph, exact extrinsic, public evidence recomputation, and
   controlled positive TDX replay.
3. Publish candidate-specific replayable negative evidence before claiming
   whole-epoch FULL provenance.
4. Replace the operator-assisted beta deployment with a reproducible
   production HTTPS/channel-bound package and self-service signed enrollment.
