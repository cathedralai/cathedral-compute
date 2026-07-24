# SN39 launch-candidate status and evidence matrix (2026-07-24)

Claim under proof: **"SN39 mainnet: validated Intel TDX CPU compute."**
Nothing broader. This file states exactly what is PROVEN locally, what is
implemented-but-unproven, and what is NOT PROVEN, per launch item.

## Evidence matrix

| Item | Status | Evidence |
|---|---|---|
| 1. Evidence bundle + retention + controlled disclosure | IMPLEMENTED, locally tested | mandatory production retention (preflight + admission + ledger gates), TDX-only token-free envelopes, `runtime export-evidence`, `provenance export-controlled`; suites in tests/test_evidence.py, test_replay.py, test_ledger_envelope_migration.py |
| 2. Concurrent thin + full-provenance modes | IMPLEMENTED, locally tested | subnet two-mode validator: shadow = single-flight background worker (timing-proven ≥10s audit cannot delay thin ticks); authority requires FULL assurance and derives its own UID vector; ONE metagraph snapshot per tick supplies the UID map, the current block, and the independent candidate-membership set; authority state fences are one atomic flock check-and-reserve (two-thread counterexample in tests) |
| 3. Versioned reward mechanisms | IMPLEMENTED | `validated_supply_v1` (units-proportional shares + fixed 10% burn) pinned in manifests, provenance recompute, and validator config |
| 4. Public artifact/index surfaces | IMPLEMENTED, NOT DEPLOYED | content-addressed store + signed index with full recent-row validation and verified history carry; manifests carry a versioned `candidate_set` anchored to an independently fetched SN39 metagraph snapshot (`cathedral_candidate_snapshot_v1`: network/netuid/block/block_hash + exact hotkeys, no machine identity); deploy blocked pending review |
| 5. TTY + JSONL logs | IMPLEMENTED, locally tested | hardened EventLoggers both repos (recursive redaction, control-char neutralization, 0600 O_NOFOLLOW) |
| 6. Adversarial + live proof | PARTIAL | adversarial suites green (confidential 1162 passed / 1 skipped; subnet two-mode 24 incl. work-replay, derived-challenge, and fence counterexamples); LIVE mainnet proof NOT PROVEN (deploy blocked) |
| 7. Clean external reproduction | NOT PROVEN | docs/PROVENANCE.md documents the one-command path; requires deployed evidence surface + published key bundle |
| 8. Operator/release docs + checklist | THIS FILE + docs/PROVENANCE.md + MRTD/BUDGET docs; release pinning pending review |

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
   deliberately `receipts_only`: the artifact model does not yet publish
   exhaustive per-candidate rejection/revocation evidence, so a FULL claim
   for "everyone revoked" would be vacuous. Authority mode therefore fails
   closed on revocation epochs (the chain retains the last vector; the
   thin/shadow default carries revocation to burn). Making the revoked
   state FULL requires an exhaustive candidate-set artifact with
   independently replayable rejection evidence — designed, not built.
8. **pip 26.1.2 upgrade** in every managed venv. Clean installs and the
   production venvs must run `python -m pip install --upgrade 'pip>=26.1.2'`
   (fixes PYSEC-2026-196/2875/2876) before installing packages; this is a
   deploy-checklist step because it needs the production hosts.

## Dependency advisory record (do not suppress)

**ecdsa 0.19.2 — PYSEC-2026-1325 (Minerva timing, P-256 sign/keygen/ECDH).**
Dependency-path evidence, collected 2026-07-24 on the launch venvs:
`pip show ecdsa` → `Required-by: substrate-interface` ONLY, and only in the
cathedralconfidential *dev* extra venv (the subnet validator venv does not
install it; `bittensor` uses its own sr25519/ed25519 stacks). `grep -rn
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

- **Derived challenges.** The 32-byte TDX challenge nonce is DERIVED, not
  issuer-random: `sha256("cathedral-tdx-challenge-v1\0" ||
  canonical{block_hash, network, netuid, source_epoch, miner_hotkey})`
  (`cathedral/challenge.py`). Anyone can recompute it from the finalized
  SN39 block hash; cross-epoch evidence reuse fails cryptographically with
  no replay cache involved. Production CPU scoring REFUSES to start without
  a challenge anchor.
- **Independent candidate set.** `runtime export-evidence` requires a
  `cathedral_candidate_snapshot_v1` file (independently fetched SN39
  metagraph: network/netuid/block/block_hash + exact registered hotkeys)
  and accounts for EVERY registered hotkey (verified/rejected/retired).
  Full validators re-fetch the metagraph themselves and reject manifests
  whose candidates are not registered on chain or whose anchored block hash
  does not match the independently queried chain.

## Deployment preconditions (all blocked pending independent review)

Registry freshness hotfix (owner-managed, separate); confidential branch
`feature/sn39-launch`; subnet branch `feature/sn39-provenance-launch`
(provenance extra pinned to the immutable confidential commit); epoch-loop
update (export-score-class + export-evidence + retention env, plus per-epoch
`--challenge-anchor-block/--challenge-anchor-hash` from the finalized SN39
block and a freshly fetched `--candidate-snapshot` metagraph artifact);
nginx `/v1/evidence/` location; score-class/index signing keys created on
the VM; key bundle + digests published into docs and `config/provenance/`.
