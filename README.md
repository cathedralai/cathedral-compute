<div align="center">
  <h1>⚡ Cathedral Compute</h1>
  <p><strong>The fastest sandbox fleet on earth, built from machines that prove what they run.</strong></p>
  <p><code>MAINNET LIVE TESTING</code></p>
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

Every other provider buys its fleet. This network recruits one. A hot,
attested Intel TDX worker is an edge node of a single distributed machine
whose job is to hand an AI agent a sandbox that already exists before it
asks.

## Mining: the five things to know

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

## Three rules keep it honest

| Rule | Meaning |
|---|---|
| Attestation is admission, not payment | Registration, uptime, a valid quote, hardware ownership, or self-reported volume never earns weight. Only verified work does. |
| Supply follows demand | The network does not pay for capacity nobody uses. Miners onboard through an approval gate that opens as real demand arrives: the distill track, subnet partnerships that need attested sandboxes in their stack, and paying customers. |
| Nothing is advertised before it pays | What pays today is verified work under `validated_supply_v2`. The latency-paid direction is [docs/WARM_SUPPLY.md](docs/WARM_SUPPLY.md), every phase labeled with whether it pays. |

## Choose your path

| Role | Start here |
|---|---|
| Provide Intel TDX CPU compute | [MINING.md](MINING.md) |
| Use Cathedral Computer as a customer | [Product and API documentation](https://cathedral.computer/docs/) |
| Compete in the Distill (CyberGym) track | [`cathedral-distill`](https://github.com/cathedralai/cathedral-distill) |
| Run or audit a validator | [`cathedral/VALIDATOR.md`](https://github.com/cathedralai/cathedral/blob/main/VALIDATOR.md), plus [this repo's provenance contract](docs/PROVENANCE.md) |
| Understand the architecture and trust boundary | [docs/EVIDENCE_LANE.md](docs/EVIDENCE_LANE.md) |
| Contribute to protocol code | [`cathedral` issues](https://github.com/cathedralai/cathedral/issues), [this repo's issues](https://github.com/cathedralai/cathedral-compute/issues) |

How the evidence lane works, what is deployed versus designed, the admission
boundary in full, and exactly what attestation does and does not prove:
[docs/EVIDENCE_LANE.md](docs/EVIDENCE_LANE.md). Current live state: the
[signed vector](https://api.cathedral.computer/v1/validator/weights/next) and
[public evidence index](https://api.cathedral.computer/v1/evidence/index.json).

## Verify the software yourself

Requires Python 3.11 or newer:

```bash
git clone https://github.com/cathedralai/cathedral-compute.git
cd cathedral-compute

python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pytest -q
```

The suite collects 1640 tests, and `tests/test_documented_counts.py` holds that
number to this file, so it cannot quietly drift. The collected count is stated
rather than a passing count, because the TDX and SEV-SNP suites skip unless the
hardware is present. Passing proves software behavior against test doubles; it
does not prove live Intel hardware, deployment, a current eligible miner, or an
on-chain write. Per-command breakdown: [docs/TESTING.md](docs/TESTING.md).

## Documentation

### Current operator and assurance documents

- [Build and evidence status](BUILD_STATUS.md)
- [Mining and provider onboarding](MINING.md)
- [Evidence lane: architecture, status, trust boundary](docs/EVIDENCE_LANE.md)
- [Warm supply: where the mechanism is going](docs/WARM_SUPPLY.md)
- [Assurance claims](docs/ASSURANCE.md)
- [Intel TDX launch path](docs/TDX_LAUNCH.md)
- [Public and controlled provenance](docs/PROVENANCE.md)
- [Enrollment allowlist](docs/ENROLLMENT_ALLOWLIST.md)
- [Policy registry](docs/POLICY_REGISTRY.md)
- [Receipts](docs/RECEIPTS.md)
- [Cathedral Computer customer receipts](docs/CUSTOMER_RECEIPTS.md)
- [Worker lifecycle](docs/LIFECYCLE.md)
- [Workload admission](docs/WORKLOAD_ADMISSION.md)

### Design and future capability

- [Architecture and roadmap](docs/DESIGN.md)
- [GPU attestation foundation](docs/GPU_ATTESTATION.md)
- [Key-release design](docs/KEY_RELEASE.md)

Design documents describe intended capability, not deployed availability.

### Historical

[docs/history/](docs/history/) holds superseded build plans and commissioning
handoffs. They are kept for provenance and **must not** be used as current
onboarding instructions. Start at [MINING.md](MINING.md) instead.

> This repository was previously named `cathedralconfidential`. Old links
> redirect here. The installed Python package and its console command keep the
> historical `cathedral` identifier, and downstream validators pin this
> repository by commit, so a rename cannot invalidate those pins.

## Licensing

See [LICENSE](LICENSE).
