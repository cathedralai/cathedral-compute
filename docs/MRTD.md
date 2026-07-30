# Measurement and TCB policy (MRTD)

How Intel TDX measurements are approved, pinned, verified, and rolled
back for the claim **"SN39 mainnet: validated Intel TDX CPU compute."**

> **Status honesty.** The policy machinery is implemented, adversarially tested,
> and has been exercised in a historical live-hardware acceptance run. A
> policy entry or old receipt is not proof of current eligibility. Verify the
> current signed registry, freshness, revocation state, and supported release;
> otherwise report `NOT_PROVEN`.

## The approved measurement is NOT an MRTD

This document is named MRTD for historical reasons and the name is misleading.
Read this before approving anything.

`ParsedQuote.measurement` (`cathedral/verify/tdx_quote.py`) is a SHA-256 over
**eight** fields, of which `mr_td` is one:

    domain ‖ td_attributes ‖ xfam ‖ mr_td ‖ mr_config_id ‖ mr_owner
          ‖ mr_owner_config ‖ rtmr0 ‖ rtmr1 ‖ rtmr2 ‖ rtmr3

**All four RTMRs are inside it.** RTMR1 conventionally measures the kernel and
initrd, so **anything that regenerates initramfs changes the approved
measurement** — a kernel upgrade, yes, but also installing a single package that
triggers an initramfs rebuild.

A true MRTD would not behave this way: it is the static initial-TD measurement
and does not move when you install software. That difference is exactly what
makes the old name dangerous, because it invites the assumption that an approval
survives routine patching. It does not.

Measured on a real Intel TDX CVM (GCP `c3-standard-4`, stock Ubuntu 24.04),
across three boots:

| Boot | Measurement | `mr_td` / `rtmr0` |
|---|---|---|
| fresh image | `4574b60b…` | constant |
| after `apt full-upgrade` + install Docker | **`f81c672a…`** | **constant** |
| two further reboots, no changes | `f81c672a…` (byte-identical) | constant |

So the value IS deterministic — same machine, same software, same measurement
across reboots. It is simply sensitive to far more than the boot image. `mr_td`
and `rtmr0` never moved, which is what proves the change came from RTMR1 and not
from the image or the GCP virtual firmware.

### What moves it, and what does not

Measured on the same real TDX CVM. The distinction matters more than the list,
because the two triggers behave differently for an operator:

| Event | Measurement | Controllable by the provider? |
|---|---|---|
| `apt full-upgrade` + install Docker (initramfs regenerated) | **changes** | yes — freeze the image |
| reboot, no changes | unchanged (byte-identical) | — |
| **full stop + cold start** of the GCP instance | **unchanged** (`mr_td`, `rtmr0`, `rtmr1`, `rtmr2` and TCB SVN all constant) | — |
| landing on a host with *different* guest firmware (TDVF) | changes | **no** |

The stop/start result is worth stating explicitly because it is easy to assume
otherwise: on GCP, cycling an instance does **not** by itself move the
measurement.

**Two independent stop/starts now**, both byte-identical, with `mr_td`, `rtmr0`
and the TCB SVN constant across all three boots.

A caution on how much that proves, because the obvious reading is wrong. Each
boot came up with a **different external IP**, which looks like evidence of
landing on different hosts — it is not. A GCP *ephemeral* external IP is
released and reallocated on every full stop/start regardless of placement (this
is the same mechanism as cathedral-compute#61, where it invalidated a worker's
single-SAN certificate on every restart). So the IP changing is guaranteed by
the stop/start itself and carries no information about the host or its firmware.

What the two samples establish is narrower and still useful: **a stop/start does
not itself move the measurement.** Neither sample demonstrates surviving an
actual TDVF change, because none was observed — and a TDVF roll cannot be
triggered on demand, so that case stays unexercised.

That leaves exactly one uncontrollable trigger — a TDVF rollout underneath you —
and it is occasional rather than routine. So a frozen image plus re-approval on
the rare firmware change is a workable posture, and the operational load is far
lower than "any restart might de-approve you" would suggest.

**The gap that follows from this, and it is not more sampling.** Because no TDVF
roll has been observed, the re-approval path has never actually been run against
a genuinely changed measurement — only reasoned about. The useful next step is to
exercise `scripts/cathedral_measurement_approval.py approve` deliberately, before
an incident needs it, rather than accumulating more stop/start samples that all
test the same benign case. A second thing worth doing is recording the
measurement plus `mr_td` and `rtmr0` on each boot, so that when a roll does
happen it is *detected* rather than inferred from a provider dropping out.

Freezing is the provider's half of it: mask `unattended-upgrades` and hold the
boot-critical packages, so nothing regenerates initramfs without a decision.

`runtime_measurements` is a separate registry field, and its existence does NOT
mean the runtime-varying part is held separately: the runtime registers are
already folded into the value above.

### What a provider sees when it drifts

`cathedral verify` reports `{"valid": false, "category": "policy", "error": …}`
with a message saying the measurement is well-formed but not approved. It used
to report `category: "schema"` / "receipt measurement is invalid", which read as
a malformed receipt and sent operators to inspect the wrong artifact entirely.

### Open: freeze, or re-approve?

**The mechanics already exist; the policy does not.**

`scripts/cathedral_measurement_approval.py approve` is a working re-approval
path: it captures the candidate measurement live from the named worker through
the pinned production verifier, records provenance to an append-only approval
log, and emits the next monotonic signed registry release. It is operator-gated
— it needs the registry signing key, an `--operator` and a `--reason`, and it
does not deploy — so a provider can never re-approve itself.

What is undecided is whether routine patching SHOULD be an approvable event, and
at what cadence. Every patched machine currently requires an operator to run an
approval and ship a signed registry release, which is an operational load
question at fleet scale rather than a security one. Tracked in
cathedral-compute#88. Until it is settled, do not assume an approval outlives an
`apt upgrade`.

## Policy source of truth

The signed policy registry (`cathedral_policy_registry_v1`, see
`docs/POLICY_REGISTRY.md`) is the ONLY measurement authority:

- Per-profile `measurements` (launch measurement values — see above, these are
  NOT bare MRTDs) and `runtime_measurements`, each with `status`, validity
  windows, and `retire_at`.
- TCB gates: `min_tcb`, `tdx_allowed_tcb_statuses` (production strict
  mode accepts `UpToDate`-class statuses only), `tdx_allowed_advisories`.
- Ed25519-signed, monotonic `release`, `generated_at` monotonicity
  (`PolicyRegistryState` durable anti-rollback), and a HARD 86400-second
  freshness ceiling: staleness is repaired by same-policy reissues at
  higher releases, never by widening the ceiling.

Production runtimes require a strict signed CPU policy and a live
registry refresher; a mid-epoch authority or policy change aborts the
epoch. Compatibility mode never scores production work.

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

`approve` requires `--profile-id` and applies the measurement to exactly
that profile. A registry retains every prior profile after a rollover
(`rollover` appends the successor), so the approval target is never
inferred from list position: naming a profile that is absent, duplicated,
not `cpu_tdx`, or not `active` fails before the live capture runs, and the
emitted release is refused if any other profile changed. `show` prints
every profile with its status rather than one positional entry.

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
