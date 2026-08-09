# Warm Supply: where this mechanism is going

**The mission: the fastest sandbox fleet on earth, built out of machines that
prove what they run.**

Every other sandbox provider buys its fleet: datacenters, capacity contracts,
capex in every region. This network recruits its fleet. A miner who keeps a
hot, attested Intel TDX worker standing by is an edge node of one distributed
machine, and the mechanism's job is to make the economically rational miner
behavior and the fastest possible customer experience be the same behavior.

Idle costs the platform nothing, so the fleet can afford to be warm everywhere,
all the time. What the mechanism will pay for, in phases, is exactly that:
verified work, delivered fast, from capacity that already exists before anyone
asks for it.

## The honesty rule, first

Nothing in this document pays today unless the section says so. This repo has
already once removed an advertised bonus that was computed but never reached
the reward path (#116, de-advertised in #120), and it does not repeat that
mistake. Every phase below arms only through an explicit versioned contract
re-pin that validators must adopt; no phase can turn itself on quietly.

**What pays today: verified work units under `validated_supply_v2`, exactly as
the [README](../README.md) describes. Nothing else.**

## What will be measured (when the phases arm)

- **Latency.** Producer-clocked only: the validator stamps its own monotonic
  clock at dispatch and at certificate verification. Miner-reported timestamps
  appear nowhere. A fast wrong answer earns zero; only verified completion
  counts.
- **Warmth.** Probes arrive wire-indistinguishable from customer jobs, on a
  commit-revealed schedule no miner can precompute and no producer can grind.
  The only way to score well is to actually be fast for everything, always.
- **Capacity.** From the attested vCPU/memory profile, not from declared slots.
  Splitting one machine into many hotkeys buys nothing.
- **Grades, not cliffs.** Slow costs a multiplier, never an epoch zero.
  Explicit zeros stay reserved for fraud: invalid certificates, schedule
  inconsistency, replay, revoked attestation.

## The phases

| Phase | What happens | Pays? |
|---|---|---|
| M0 shadow capture | The producer records dispatch-to-verified timing per challenge (`work_timing` ledger table). Scoring untouched; v2 exports byte-identical. | No |
| M1 worker image v3 | New measured image: reserved probe slot, keep-alive channel. Required before any probe scoring exists. | No |
| M2 dark scoring | The latency lane computes in parallel with v2 and is diffed off-chain. Nothing on-chain changes. | No |
| M3 contract re-pin | `warm_supply_v1` arms at low blend weight by coordinated validator re-pin. Latency multipliers reach payout. | Yes, from here |
| M4 demand coupling | Verified serving of real customer jobs weighs more than probes, gated on push assignment and demonstrated demand. | Yes, gated |

Each phase holds indefinitely if the one after it is not ready. The calibration
data for every threshold comes from M0 capture across the live fleet, never
from one-off observations.

## What this means for an operator today

- Keep your worker warm and answering. When probe scoring arms, the historical
  behavior that will already have been rational (a hot machine that verifies
  fast) is the behavior that pays.
- Do not build probe detection. Probes are designed to be indistinguishable
  from customer work, and the schedule is committed before it is drawn, so the
  profitable strategy and the honest strategy are the same strategy.
- Capacity claims come from your attested profile. Provision real cores.

## What will never be built

- Cryptographic cold-boot proofs on current TDX. RTMRs are runtime-extendable,
  so a warm guest can forge a fresh-boot claim; fresh-boot latency will only
  ever be published as a measured statistic, never a proven guarantee.
- First-byte latency scoring. A warm fronting proxy games it; only verified
  completion is scored.
- Rewards for uptime, registration, or self-reported anything. Admission is
  attestation; payment is verified work. That does not change in any phase.
