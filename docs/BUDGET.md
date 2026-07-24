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
work items).

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
