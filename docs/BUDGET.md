# Fixed spend and burn controls (BUDGET)

The economic invariants of the SN39 launch program and the resource
ceilings every component enforces. These values are CONTRACTS: changing
any of them requires a new reviewed mechanism or an explicit owner
decision recorded in the decision log — never a config drift.

> **Status honesty.** Enforcement below is implemented and locally
> tested; live economic behavior on mainnet is NOT PROVEN until the
> deploy gates in `docs/LAUNCH_CANDIDATE.md` pass.

## Burn controls (on-chain emission)

- **Fixed 10% burn floor.** `validated_supply_v1` allocates
  units-proportional shares to verified miners with a FIXED 10% burn to
  the configured burn hotkey (`MECHANISM_BURN_FRACTION = 0.10` in the
  subnet validator; validated again by the thin vector contract). The
  floor is part of the versioned mechanism id: changing it requires a new
  mechanism version, pinned everywhere.
- **Empty verified set → 100% burn.** No verified supply means the whole
  vector goes to the burn destination — never to an unverified hotkey.
- **Revocation epochs.** An all-rejected epoch is NOT_PROVEN for full
  authority (no raw rejection evidence artifact exists); authority
  refuses to submit and the thin/shadow default carries revocation to
  burn. See `docs/LAUNCH_CANDIDATE.md` NOT PROVEN item 7.

## Operational spend controls

- **Fixed spend ceiling.** The launch program runs under a hard $10
  incremental-spend guard: no new paid infrastructure, no instance-class
  changes, no new managed services. Raising the ceiling is an owner
  decision, not an executor one.
- **Existing-infrastructure rule.** Proof work reuses the existing
  production VM and services; anything that needs new capacity is
  recorded as NOT PROVEN instead of provisioned.

## Resource ceilings (denial-of-service budget)

Every remote operation runs under ONE command-wide budget: a single
monotonic deadline (recomputed after DNS and before every connect, TLS,
header, and body-read phase), aggregate byte and artifact caps, bounded
DNS through a process-global resolver slot pool, bounded local reads
(`O_NOFOLLOW`, post-open regular-file verification, max+1 reads), bounded
subprocess execution for the verifier, and size caps on every artifact
class (registry, report, receipts, envelopes, verifier binary, vectors,
work items). FULL-mode LOCAL inputs — the independent candidate snapshot,
every controlled envelope (streamed one at a time, never a retained
multi-envelope set), and an operator-supplied verifier binary — are
charged to the SAME artifact/byte/deadline budget as public evidence
reads.

## Evidence byte budget (coherence contract)

The manifest grammar and the verifier's aggregate budget are ONE derived
contract (`cathedral/evidence.py`): every per-kind cap is enforced at
export/retention (a producer can never publish an artifact the verifier
must refuse) and at every verify read site, and the supported verified
cardinality is DERIVED so a maximal valid epoch always fits the 64 MiB
aggregate under one total command deadline.

| Artifact class | Cap |
|---|---|
| Evidence index | 256 KiB |
| Epoch manifest | 2 MiB |
| Policy registry | 1 MiB |
| Score-class report | 2 MiB |
| Assurance receipt | 64 KiB |
| Work item (SAT grammar worst case ~410 KiB) | 512 KiB |
| Work result | 64 KiB |
| Controlled envelope (enforced at retention) | 256 KiB |
| Independent candidate snapshot | 1 MiB |
| Publisher signed vector | 1 MiB |
| Pinned verifier binary | 32 MiB |
| **Aggregate per verify command** | **64 MiB** |

Derived cardinality: fixed overhead (index + manifest + registry +
report + verifier + vector + snapshot) plus `N x (receipt + work item +
work result + envelope)` must fit the aggregate, giving
`MAX_MANIFEST_RECEIPTS = 28` verified candidates and
`MAX_MANIFEST_CANDIDATES = 1024` candidate rows (any outcome; candidate
rows cost manifest bytes only and 1024 covers the SN39 metagraph with
margin). The manifest grammar rejects a 29th receipt row or a 29th
`verified` outcome outright, so an epoch the grammar accepts can never be
starved by the aggregate cap; the cap only ever stops non-compliant
input. Raising any number here is a reviewed contract change, never a
config drift — and never a multi-gigabyte cap.

## Rollback

Economic rollback follows the same monotonic rules as policy rollback
(`docs/MRTD.md`): mechanisms are versioned and pinned in manifests,
recomputation, and validator config; the subnet's cathedralconfidential
dependency is an immutable full-sha pin, so reverting code is an explicit
reviewed re-pin, and durable anti-rollback fences prevent any older
signed state from verifying again.

## Security exceptions (recorded, never silent)

The dependency advisory record lives in `docs/LAUNCH_CANDIDATE.md`
("Dependency advisory record"): ecdsa 0.19.2 / PYSEC-2026-1325 (no
launch-path caller; Ed25519/SR25519 everywhere) and the pip >= 26.1.2
deploy-checklist requirement. Any new exception must be added there with
dependency-path evidence and a mitigation, and re-reviewed.

## Acceptance

Budget and burn checks report through the same PASS / FAIL / NOT_PROVEN
semantics as `docs/PROVENANCE.md`: a vector violating the burn contract,
a non-finite/negative/duplicate/unknown row, or an over-budget fetch is
FAIL — fail closed, nothing submitted.
