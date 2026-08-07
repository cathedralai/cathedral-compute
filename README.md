# Cathedral Compute

**Intel TDX CPU evidence and verified-work scoring for Cathedral SN39.**

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

Attestation is admission, not payment. Registration, uptime, a valid quote,
hardware ownership, or self-reported volume never earns weight on its own. Only
verified work does, and positive weight and emissions are never guaranteed.

> This repository was previously named `cathedralconfidential`. Old links
> redirect here. The installed Python package and its console command keep the
> historical `cathedral` identifier, and downstream validators pin this
> repository by commit, so a rename cannot invalidate those pins.

This repository is the confidential-compute supply side of Cathedral. It is the
evidence lane, not the publisher of final weights:

1. a worker produces fresh, vendor-backed Intel TDX evidence;
2. Cathedral verifies the evidence, worker identity, and measured policy, then
   dispatches bounded work and verifies the result;
3. a signed, complete score report gives every candidate either verified credit
   or an explicit zero; and
4. an independent SN39 validator checks that report and decides whether to set
   weights.

> **Status: mainnet live testing, operator-assisted.**
>
> Observed 2026-08-01, the live signed vector carries one positively scored
> Intel TDX miner. That is evidence the producer-to-signed-vector path works end
> to end. It is not a promise about any future epoch, and it does not prove that
> an authorized validator put that vector on chain, which is a separate step the
> feed does not show. Zero positive miners and a burn-only vector remain valid
> fail-closed outcomes.
>
> Miner onboarding requires maintainer approval at several steps, the final
> public validator release has separate gates, and testnet SN292 is non-paying.

For current state, inspect the live
[signed vector](https://api.cathedral.computer/v1/validator/weights/next) and
[public evidence index](https://api.cathedral.computer/v1/evidence/index.json).
A reachable endpoint or a historical receipt does not prove current freshness or
eligibility.

## Choose your path

| Role | Start here |
|---|---|
| Provide Intel TDX CPU compute | [The mining guide in this repository](MINING.md) |
| Use Cathedral Computer as a customer | [Product and API documentation](https://cathedral.computer/docs/) |
| Compete in the Distill (CyberGym) track | [`cathedral-distill`](https://github.com/cathedralai/cathedral-distill) |
| Run or audit a validator | [`cathedral/VALIDATOR.md`](https://github.com/cathedralai/cathedral/blob/main/VALIDATOR.md), plus [this repo's provenance contract](docs/PROVENANCE.md) |
| Contribute to protocol code | [`cathedral` issues](https://github.com/cathedralai/cathedral/issues), [this repo's issues](https://github.com/cathedralai/cathedral-compute/issues) |

## What is supported

| Capability | Current status |
|---|---|
| Intel TDX CPU evidence collection and strict verification | Proven on live hardware |
| Fresh challenge, worker, channel, measurement, and policy binding | Implemented |
| Validator-dispatched bounded SAT work | Current scored-work path |
| Complete signed score reports with explicit zero revocation | Implemented |
| Public evidence index | Deployed |
| Deployed vector vs independent verifier | **Not converged.** The 2026-07-25 comparison recorded `FAIL` on the v1 shape, and as of 2026-08-01 the live payload still mixes `contract_version` v1 and v2 metadata blocks. [BUILD_STATUS.md](BUILD_STATUS.md) is the dated evidence record |
| Mainnet SN39 | Live testing, operator-assisted |
| Testnet SN292 | Non-paying integration lane |
| Self-service miner enrollment | Not deployed; onboarding is maintainer-assisted |
| Reproducible worker image you can build yourself | Not published yet |
| AMD SEV-SNP scoring | Not enabled |
| NVIDIA confidential-GPU subnet scoring | Not admitted |
| General customer containers or CVMs through this repository | Not live |

Cathedral Computer may expose separate GPU preview profiles. Those customer
profiles do not imply that a GPU miner is admitted or rewarded by this subnet.

## The admission boundary

This is the gate that stops most first attempts, and nothing else you configure
correctly works around it.

Cathedral admits a worker only if its TDX measurement is already listed in the
signed policy registry. The verifier compares the measurement in your quote
against the active profile's approved list and rejects anything not on it. A
cryptographically valid TDX quote with an unknown measurement is still rejected.
Because no reproducible image is published yet, you cannot build a matching
measurement yourself, so **apply before registering or provisioning a paid
machine.** Production enrollment is additionally gated by a signed allowlist
(see [docs/ENROLLMENT_ALLOWLIST.md](docs/ENROLLMENT_ALLOWLIST.md)).

Read [MINING.md](MINING.md) in full before exposing a worker.

## How scoring works

1. Cathedral derives a fresh challenge from finalized SN39 chain state and the
   candidate hotkey.
2. The worker returns an Intel TDX quote bound to that challenge, hotkey, and
   protected channel.
3. The verifier checks vendor collateral, TCB status, measurement policy, debug
   state, freshness, and binding.
4. Cathedral dispatches bounded work only after admission.
5. The validator verifies the returned witness and derives work units from the
   task itself, never from a worker's claimed score.
6. The producer freezes and signs a complete epoch report, including explicit
   zero rows for missing, stale, failed, or revoked candidates.
7. The SN39 validator verifies the report and independently maps public hotkeys
   to UIDs before any chain decision.

The reward mechanism is versioned and both registered ids stay verifiable. New
evidence is emitted as `validated_supply_v2`, which scores the current epoch's
receipt-verified work alone and exports exactly those units, so the published
bundle reproduces the on-chain allocation. `validated_supply_v1` remains
registered so already-signed historical evidence keeps verifying; it summed a
trailing window of prior epochs into the score while exporting current-epoch
units only. The burn contract and class allocation are policy inputs verified by
validators, not miner-controlled fields.

## Trust boundary

Attestation proves that vendor-backed evidence matched an approved measured
environment and policy. It does not by itself prove application correctness,
every output, or confidentiality outside the measured boundary. Cathedral
separately verifies each supported workload result.

Public provenance includes commitments, signed registries, receipts, reports,
candidate sets, and digests. Raw TDX quotes are shared only through controlled
disclosure because they can carry platform-identifying material. A validator
without the controlled package can audit the public receipt chain, but must
report that narrower result as `NOT_PROVEN`, not `FULL`.

## Provider safety

- Never share wallet seeds, coldkey or hotkey private keys, bearer tokens, TLS
  private keys, cloud credentials, or SSH credentials. Never put any of them in
  a public issue.
- A public beta issue may contain the public hotkey, preferred network, current
  or intended Intel TDX hardware class, provider and broad region, and an
  optional public contact handle. Never an IP, instance identifier, or
  credential.
- Plain HTTP with `--development-allow-non-loopback` is a development exception,
  not the production security boundary and not a mainnet onboarding recipe.
- Production evidence uses credential-free collection over HTTPS with the TLS
  key terminating inside the measured environment; authenticated work follows
  only after channel verification.

## Run the hardware-free suite

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

The suite collects 1603 tests, and `tests/test_documented_counts.py` holds that
number to this file, so it cannot quietly drift. The collected count is stated
rather than a passing count, because the TDX and SEV-SNP suites skip unless the
hardware is present, which means the passing total differs between a laptop and
the TDX box.

The default suite uses test doubles behind the real verifier interface, so
passing it proves software behavior. It does not prove live Intel hardware,
deployment, a current eligible miner, or an on-chain write.

Per-command breakdown: [docs/TESTING.md](docs/TESTING.md).

## Documentation

### Current operator and assurance documents

- [Build and evidence status](BUILD_STATUS.md)
- [Mining and provider onboarding](MINING.md)
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

## Licensing

See [LICENSE](LICENSE).
