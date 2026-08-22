<div align="center">
  <h1>⚡ Cathedral</h1>
  <p><strong>Bittensor SN39 · Racing to build the fastest sandbox fleet on earth, from machines that prove what they run.</strong></p>
  <p><a href="https://cathedral.computer">cathedral.computer</a> · <a href="MINING.md">Mine</a> · <a href="https://github.com/cathedralai/cathedral/blob/main/VALIDATOR.md">Validate</a> · <a href="https://github.com/cathedralai/cathedral-distill">Distill track</a></p>
</div>

<!-- VIDEO SLOT -----------------------------------------------------------
Walkthrough video goes here, matching cathedral-distill's README.
To publish: drag the file into any GitHub issue comment, copy the
user-attachments URL it produces, paste it as `src` below, then delete
these comment markers.

<div align="center">
  <video controls width="800" src="PASTE_GITHUB_USER_ATTACHMENTS_URL_HERE"></video>
  <p><a href="PASTE_YOUTUBE_URL_HERE">Watch on YouTube</a></p>
</div>
------------------------------------------------------------------------ -->

## Intro

AI agents need sandboxes: isolated machines they can spawn in milliseconds,
use, and throw away. Every provider selling them buys its fleet with capital.
This subnet recruits one with incentives: a miner who keeps a hot, attested
Intel TDX worker standing by becomes an edge node of a single distributed
machine that hands an agent a sandbox that already exists before it asks.

Three rules keep it honest:

| Rule | Meaning |
|---|---|
| Attestation is admission, not payment | Registration, uptime, a valid quote, hardware ownership, or self-reported volume never earns weight. Only verified work does. |
| Supply follows demand | The network does not pay for capacity nobody uses. Miners onboard through an approval gate that opens as real demand arrives: the distill track, subnet partnerships that need attested sandboxes in their stack, and paying customers. |
| Nothing is advertised before it pays | Every future mechanism phase is labeled with whether it pays, and none arms without a versioned contract re-pin. |

## Incentive mechanism

**What pays today: verified work under `validated_supply_v2`.**

1. The validator derives a fresh challenge from finalized SN39 chain state and
   your hotkey. Your worker answers with an Intel TDX quote bound to that
   challenge; an unknown measurement is rejected no matter how valid the quote.
2. Admitted workers receive bounded work. The validator verifies the returned
   result and derives work units from the task itself, never from your claimed
   score.
3. Every epoch produces a signed, complete score report: verified credit or an
   explicit zero for every candidate. An independent validator re-verifies the
   report before any weight reaches the chain.

**Where it is going: [docs/WARM_SUPPLY.md](docs/WARM_SUPPLY.md).** The
mechanism's next revisions pay for being fast and warm: producer-clocked
latency scoring on probes indistinguishable from customer work, capacity from
your attested profile, grades instead of cliffs. Shadow measurement is designed
and under review, not running: it lands with M0. Nothing in it pays until
validators adopt the re-pinned contract, and the phase table says exactly which
phase pays.

Deep dive (architecture, deployed-versus-designed status, trust boundary):
[docs/EVIDENCE_LANE.md](docs/EVIDENCE_LANE.md). Live state: the
[signed vector](https://api.cathedral.computer/v1/validator/weights/next) and
[public evidence index](https://api.cathedral.computer/v1/evidence/index.json).

## Miner setup

<details>
<summary><strong>The five things to know, then the full guide</strong></summary>

1. **Hardware:** an Intel TDX-capable CPU host. Nothing else is admitted today.
2. **Apply before you provision.** Admission requires your worker's measurement
   to already be on the signed policy registry, and no reproducible image is
   published yet, so you cannot build a matching one yourself. Do not buy or
   rent a machine before approval.
3. **Only verified work pays.** Not registration, not uptime, not a valid
   quote. One miner earns on mainnet today; positive weight and emissions are
   never guaranteed.
4. **Start:** open a [miner beta issue](https://github.com/cathedralai/cathedral-compute/issues)
   with your public hotkey, intended TDX hardware class, provider, and broad
   region. Then read [MINING.md](MINING.md) in full.
5. **Never post credentials.** No seeds, keys, tokens, IPs, or instance
   identifiers in any issue, ever.

Full onboarding: [MINING.md](MINING.md) ·
Enrollment gate: [docs/ENROLLMENT_ALLOWLIST.md](docs/ENROLLMENT_ALLOWLIST.md) ·
Workload admission: [docs/WORKLOAD_ADMISSION.md](docs/WORKLOAD_ADMISSION.md) ·
Worker lifecycle: [docs/LIFECYCLE.md](docs/LIFECYCLE.md)

</details>

## Validator setup

Validators verify the signed epoch report and independently map hotkeys to UIDs
before any chain decision; the producer can never pay itself unchecked.

Start at [`cathedral/VALIDATOR.md`](https://github.com/cathedralai/cathedral/blob/main/VALIDATOR.md),
then this repo's [provenance contract](docs/PROVENANCE.md),
[policy registry](docs/POLICY_REGISTRY.md), and
[receipts](docs/RECEIPTS.md). Assurance claims and their limits:
[docs/ASSURANCE.md](docs/ASSURANCE.md).

Verify the software yourself (Python 3.11+):

```bash
git clone https://github.com/cathedralai/cathedral-compute.git
cd cathedral-compute
python3.11 -m venv .venv && . .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
```

The suite collects 1929 tests, and `tests/test_documented_counts.py` holds that
number to this file, so it cannot quietly drift. Passing proves software
behavior against test doubles; it does not prove live hardware, deployment, or
an on-chain write. Details: [docs/TESTING.md](docs/TESTING.md) and the dated
evidence record in [BUILD_STATUS.md](BUILD_STATUS.md).

---

<sub>Previously named `cathedralconfidential`; old links redirect and
validator commit pins stay valid. Design docs
([DESIGN.md](docs/DESIGN.md), [GPU_ATTESTATION.md](docs/GPU_ATTESTATION.md),
[KEY_RELEASE.md](docs/KEY_RELEASE.md)) describe intended capability, not
deployed availability. [docs/history/](docs/history/) is provenance, not
onboarding. License: [MIT](LICENSE).</sub>
