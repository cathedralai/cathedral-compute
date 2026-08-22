# SN39 launch-candidate status and evidence matrix (2026-07-24)

> **Dated implementation checkpoint.** This matrix records what was known on
> 2026-07-24 and is preserved for audit history. Some deployment facts changed
> afterward. It is not the current onboarding or launch-status page. Use
> [`../BUILD_STATUS.md`](../BUILD_STATUS.md), then verify the live signed
> vector and evidence index directly.

Claim under proof: **"SN39 mainnet: validated Intel TDX CPU compute."**
Nothing broader. This file states exactly what is PROVEN locally, what is
implemented-but-unproven, and what is NOT PROVEN, per launch item.

## Evidence matrix

| Item | Status | Evidence |
|---|---|---|
| 1. Evidence bundle + retention + controlled disclosure | IMPLEMENTED, locally tested | mandatory production retention (preflight + admission + ledger gates), TDX-only token-free envelopes, `runtime export-evidence`, `provenance export-controlled`; suites in tests/test_evidence.py, test_replay.py, test_ledger_envelope_migration.py |
| 2. Concurrent thin + full-provenance modes | IMPLEMENTED, locally tested | subnet two-mode validator: shadow = single-flight background worker (timing-proven ≥10s audit cannot delay thin ticks); authority requires FULL assurance, derives its own UID vector, and RESERVES its durable fence (index+policy+report lines and chain identity, one flock hold) BEFORE any PASS is emitted; candidate membership is proven by EXACT equality against the HISTORICAL metagraph at the anchored block via the validator's own chain queries (current-metagraph drift is not an input; unavailable history is NOT_PROVEN) |
| 3. Versioned reward mechanisms | IMPLEMENTED | `validated_supply_v1` (units-proportional shares + fixed 10% burn) pinned in manifests, provenance recompute, and validator config; work units derive under the versioned `sat_work_units_v1` rule shared VERBATIM by the producer lane and the independent replayer (canonical audit work = clause count; customer jobs = fixed CUSTOMER_SAT_WORK_UNITS) — never a signer or miner claim; replayed work items must satisfy the FULL producer contract (recomputed challenge_id from canonical instance+seed, clause/total-literal/per-clause/seed/size bounds) |
| 4. Public artifact/index surfaces | IMPLEMENTED, NOT DEPLOYED | content-addressed store + signed index with full recent-row validation and verified history carry; manifests carry a versioned `candidate_set` anchored to an independently fetched SN39 metagraph snapshot (`cathedral_candidate_snapshot_v1`: network/netuid/block/block_hash + exact hotkeys, no machine identity); deploy blocked pending review |
| 5. TTY + JSONL logs | IMPLEMENTED, locally tested | hardened EventLoggers both repos (recursive redaction, control-char neutralization, 0600 O_NOFOLLOW) |
| 6. Adversarial + live proof | PARTIAL | adversarial suites green (confidential 1929 tests collected; subnet two-mode 24 incl. work-replay, derived-challenge, and fence counterexamples); LIVE mainnet proof NOT PROVEN (deploy blocked) |
| 7. Clean external reproduction | NOT PROVEN | docs/PROVENANCE.md documents the one-command path; requires deployed evidence surface + published key bundle |
| 8. Operator/release docs + checklist | THIS FILE + docs/PROVENANCE.md (one-command reproduction + acceptance semantics) + docs/MRTD.md (measurement/TCB policy + rollback) + docs/BUDGET.md (fixed spend/burn controls + security exceptions); reference integrity enforced by tests/test_docs_integrity.py; release pinning pending review |

## Precise NOT PROVEN items (blocking launch acceptance)

1. **Full-chain replay on a real ELF verifier.** The strict-claims execution
   matrix runs through the canonical path with a script fixture
   (authentication stubbed and labeled); verifier-bytes authentication has
   its own ELF adversarial matrix. The end-to-end FULL PASS with a genuine
   static x86-64 ELF verifier must be proven on a Linux host (the production
   VM) — it cannot execute on this development Mac.
2. **Live evidence surface.** No epoch bundle, signed index, controlled
   package, or nginx route exists in production yet; `latest_fresh` provenance
   against api.cathedral.computer is unproven.
3. **Real retained envelope → replay.** Production has never retained an
   envelope (retention ships with this candidate); the first live epoch after
   deploy must prove retention → export → controlled package → FULL replay.
4. **External validator reproduction** (item 7) end to end on mainnet.
5. **Key bundle publication** (report/index signing keys do not exist until
   deploy; their digests cannot be pinned in docs yet).
6. **Live two-mode positive → revoked → restored** transitions in both modes
   with chain/dashboard/log evidence.
7. **Full-authority revocation (all-burn) state.** A zero-positive epoch is
   deliberately `receipts_only` and this is now ENFORCED in
   `replay_positive_miners`: zero raw replays can never mint FULL. An
   all-rejected claim additionally hard-fails unless the pinned verifier
   bytes independently authenticate (content digest + implementation
   digest), and even then the upgrade is WITHHELD because the artifact
   model does not publish exhaustive per-candidate raw rejection
   evidence. A `retired` label for a hotkey still present in the
   independently anchored candidate set is treated the same way; departure
   is proven only by absence from that independent universe. Authority mode
   therefore fails closed on revocation epochs
   (the chain retains the last vector; the thin/shadow default carries
   revocation to burn). Making the revoked state FULL requires an
   exhaustive candidate-set artifact with independently replayable
   rejection evidence — designed, not built.
8. **pip 26.1.2 upgrade** in every managed venv. Clean installs and the
   production venvs must run `python -m pip install --upgrade 'pip>=26.1.2'`
   (fixes PYSEC-2026-196/2875/2876) before installing packages; this is a
   deploy-checklist step because it needs the production hosts.

## Dependency advisory record (do not suppress)

**ecdsa 0.19.2 — PYSEC-2026-1325 (Minerva timing, P-256 sign/keygen/ECDH).**
Dependency-path evidence, collected 2026-07-24 on the launch venvs:
`pip show ecdsa` → `Required-by: substrate-interface` ONLY, and only in the
cathedral-compute enrollment-service or *dev* extra venv (the subnet validator
venv does not install it; `bittensor` uses its own sr25519/ed25519 stacks). `grep -rn
"import ecdsa|from ecdsa" cathedral/ scaffold/` → zero hits: no launch-path
code imports it directly. substrate-interface uses ecdsa only for
ECDSA-type keypairs (`KeypairType.ECDSA`); every SN39 wallet operation is
SR25519 and every launch artifact signature is Ed25519 (`cryptography`),
so the vulnerable P-256 signing path has no caller in this program.
Verification-only use is unaffected per the advisory. Mitigations: the
dependency stays out of the shipped validator distribution's required
set; upstream fix adoption is tracked in the release checklist; any
future ECDSA keypair use requires a new security review. This is a
recorded, justified exception — not a silent suppression.

## Public freshness and candidate accountability (round-three hardening)

- **Derived challenges (v2).** The 32-byte TDX challenge nonce is DERIVED,
  not issuer-random: `sha256("cathedral-tdx-challenge-v2\0" ||
  canonical{block, block_hash, network, netuid, source_epoch,
  miner_hotkey})` (`cathedral/challenge.py`) — the normalized finalized
  block HEIGHT is bound alongside the hash, network, and netuid at every
  site (producer/runtime, digest, verifier, replay). Anyone can recompute
  it from finalized SN39 chain state; cross-epoch evidence reuse fails
  cryptographically with no replay cache involved. Production CPU scoring
  REFUSES to start without a challenge anchor, and report validity windows
  cannot start before the anchored block
  (valid_from_block >= candidate_snapshot.block, enforced by producer and
  verifier).
- **Independent candidate set.** The finalized-block challenge anchor is
  persisted ON THE EPOCH at `begin_epoch` (validated block+hash pair with
  its audience); nonce derivation and the durable record are read-back
  asserted equal. `runtime export-score-class` requires the
  `cathedral_candidate_snapshot_v1` the epoch observed (captured with the
  supported `cathedral-candidate-snapshot` command), refuses any snapshot
  whose block/hash differ from the epoch's stored anchor, accounts for
  EVERY historically registered hotkey with an explicit row, and binds the
  snapshot's digest/block/hash/full sorted hotkey set into the SIGNED
  report. `runtime export-evidence` must reuse that exact snapshot (digest
  equality) — a later, unrelated snapshot can never be substituted. Full
  validators verify candidates by EXACT equality against
  `Subtensor.metagraph(netuid, block=anchored_block)` +
  `get_block_hash(block)` from their own chain connection; unavailable or
  malformed history is NOT_PROVEN, omission or fabrication FAILS.

## Deployment preconditions (all blocked pending independent review)

Registry freshness hotfix (owner-managed, separate); confidential branch
`feature/sn39-launch`; subnet branch `feature/sn39-provenance-launch`
(provenance extra pinned to the immutable confidential commit); epoch-loop
update (export-score-class + export-evidence + retention env; per-epoch
`cathedral-candidate-snapshot --network finney --netuid 39 --block <final>`
feeding BOTH `--challenge-anchor-block/--challenge-anchor-hash` at epoch
begin and `--candidate-snapshot` at export time — the exporter enforces
that they agree); nginx `/v1/evidence/` location; score-class/index signing
keys created on the VM; key bundle + digests published into docs and
`config/provenance/`.
