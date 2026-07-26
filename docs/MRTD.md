# Measurement and TCB policy (MRTD)

How Intel TDX measurements are approved, pinned, verified, and rolled
back for the claim **"SN39 mainnet: validated Intel TDX CPU compute."**

> **Status honesty.** The policy machinery is implemented, adversarially tested,
> and has been exercised in a historical live-hardware acceptance run. A
> policy entry or old receipt is not proof of current eligibility. Verify the
> current signed registry, freshness, revocation state, and supported release;
> otherwise report `NOT_PROVEN`.

## Policy source of truth

The signed policy registry (`cathedral_policy_registry_v1`, see
`docs/POLICY_REGISTRY.md`) is the ONLY measurement authority:

- Per-profile `measurements` (MRTD values) and `runtime_measurements`,
  each with `status`, validity windows, and `retire_at`.
- TCB gates: `min_tcb`, `tdx_allowed_tcb_statuses` (production strict
  mode accepts `UpToDate`-class statuses only), `tdx_allowed_advisories`.
- Ed25519-signed, monotonic `release`, `generated_at` monotonicity
  (`PolicyRegistryState` durable anti-rollback), and a HARD 86400-second
  freshness ceiling: staleness is repaired by same-policy reissues at
  higher releases, never by widening the ceiling.

Production runtimes require a strict signed CPU policy and a live
registry refresher; a mid-epoch authority or policy change aborts the
epoch. Compatibility mode never scores production work.

## Learning your own measurement

A prospective miner reads the same value the verifier will, on their own
machine, before enrolling and without any Cathedral credential:

```bash
cathedral worker self-check
```

It collects a real quote through `cathedral.attest.collect_tdx` and derives the
measurement with `cathedral.verify.tdx_quote.parse_tdx_quote`. That derivation
and the production Go verifier's `measurementID` are pinned against each other
by tests on both sides: a shared field-value vector, and one real production
quote from which both derive the identical measurement and TCB SVN. Neither is
a live-hardware demonstration, and no claim is made that a given machine's
quote will verify or that its measurement will be approved; the command reports
what the machine produces so a human can ask.

There is no approved list in this repository, deliberately. The signed registry
is the authority, so the self-check compares against a list supplied by the
caller and reports without classifying when none is given.

Where the machine came from is
[the reproducible instance recipe](TDX_LAUNCH.md#reproducing-an-approved-miner-image);
what to do with an unapproved value is "Getting a new measurement approved" in
[MINING.md](../MINING.md).

## Approving a new measurement

Use the auditable approval tool — never hand-edit the registry:

```bash
python scripts/cathedral_measurement_approval.py --help
```

It records who approved which MRTD from which quote evidence, and emits
the registry change for signing. Every approval lands as a NEW registry
release; the receipt chain records the release+digest each verdict was
issued under, so any later dispute replays against the exact policy that
was in force.

## Verification path

Admission and replay verify quotes through the pinned external verifier:
content-digest AND implementation-digest pinned
(`cathedral-tdx-verifier-implementation-v1` domain over command,
artifacts, environment, and the exact binary bytes), static x86-64 ELF
enforced, executed under bounded subprocess limits. The measurement in
the receipt must be inside the signed registry profile that was active at
receipt time — at admission and again at independent replay.

## Rollback

- **Compromised/withdrawn measurement:** publish a new registry release
  with the entry revoked (`status`/`revoked_at`). Monotonicity means the
  old release can never verify again once any consumer has seen the new
  one (durable fences in both the confidential verifier state and the
  subnet validator state file).
- **Bad policy release:** publish a corrected HIGHER release. Lower
  releases are refused by every durable high-water fence; there is no
  in-place mutation path, and `generated_at` can never move backwards.
- **Bad code release:** the subnet consumes cathedralconfidential only
  through an immutable full-sha pin (`docs/BUDGET.md`); rolling back
  means pinning the previous reviewed sha — an explicit, reviewed commit.

## Acceptance

Measurement checks report through the same PASS / FAIL / NOT_PROVEN
semantics as `docs/PROVENANCE.md`: an unknown MRTD, revoked entry, stale
registry, or TCB status outside the allowlist is FAIL (fail closed);
missing evidence is NOT_PROVEN, never a silent pass.
