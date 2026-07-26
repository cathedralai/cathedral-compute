# Cathedral Confidential

**Intel TDX evidence and verified-work scoring for Cathedral SN39.**

This repository is the confidential-compute supply side of Cathedral:

- a worker produces fresh, vendor-backed Intel TDX evidence;
- Cathedral verifies the evidence, worker identity, and measured policy;
- the validator dispatches bounded work and verifies the result;
- a signed, complete score report gives every candidate either verified credit
  or an explicit zero; and
- an independent SN39 validator checks the report before deciding whether to
  set weights.

Attestation is admission, not payment. Registration, uptime, a valid quote, or
self-reported volume alone never earns weight.

> **Status: mainnet live testing**
>
> Cathedral has recorded a historical SN39 submission containing positively
> scored Intel TDX work. That is a limited chain-acceptance milestone, not a
> claim that a miner is positive now or that the subnet is generally launched.
> Miner onboarding remains operator-assisted, the final public validator
> release has separate gates, and testnet SN292 remains non-paying.

For current state, inspect the live
[signed vector](https://api.cathedral.computer/v1/validator/weights/next) and
[public evidence index](https://api.cathedral.computer/v1/evidence/index.json).
A reachable endpoint or historical receipt does not prove current freshness or
eligibility. Zero positive miners and a burn-only vector are valid fail-closed
outcomes.

## Choose your path

| Role | Start here |
|---|---|
| Cathedral Computer customer | [Product and API documentation](https://cathedral.computer/docs/) |
| Intel TDX compute provider | [Operator-assisted mining guide](MINING.md) |
| SN39 validator | [Validator guide](https://github.com/cathedralai/cathedral/blob/main/VALIDATOR.md) |
| Independent auditor | [Public provenance contract](docs/PROVENANCE.md) |
| Protocol developer | [Design and current boundaries](docs/DESIGN.md) |

## What is supported

| Capability | Current status |
|---|---|
| Intel TDX CPU evidence collection and strict verification | Proven on live hardware |
| Fresh challenge, worker, channel, measurement, and policy binding | Implemented |
| Validator-dispatched bounded SAT work | Current scored-work path |
| Complete signed score reports with explicit zero revocation | Implemented |
| Public evidence index | Deployed; current vector/verifier contract comparison is `FAIL` pending v1/v2 convergence |
| Mainnet SN39 | Live testing; historical chain acceptance exists |
| Testnet SN292 | Non-paying integration lane |
| Self-service miner enrollment | Not deployed |
| Production HTTPS onboarding for arbitrary miners | Not yet self-service |
| AMD SEV-SNP scoring | Not enabled |
| NVIDIA confidential-GPU subnet scoring | Not admitted |
| General customer containers or CVMs through this repository | Not live |

Cathedral Computer may expose separate GPU preview profiles. Those customer
profiles do not imply that a GPU miner is admitted or rewarded by this subnet.

## How scoring works

1. Cathedral derives a fresh challenge from finalized SN39 chain state and the
   candidate hotkey.
2. The worker returns an Intel TDX quote bound to that challenge, hotkey, and
   protected channel.
3. The verifier checks vendor collateral, TCB status, measurement policy,
   debug state, freshness, and binding.
4. Cathedral dispatches bounded work only after admission.
5. The validator verifies the returned witness and derives work units from the
   task itself, never from a miner's claimed score.
6. The producer freezes and signs a complete epoch report, including explicit
   zero rows for missing, stale, failed, or revoked candidates.
7. The SN39 validator verifies the report and independently maps public hotkeys
   to UIDs before any chain decision.

The reward mechanism is versioned, and both registered ids stay verifiable.
New evidence is emitted as `validated_supply_v2`, which scores the current
epoch's receipt-verified work alone and exports exactly those units, so the
published bundle reproduces the on-chain allocation. `validated_supply_v1`
remains registered so already-signed historical evidence keeps verifying; it
summed a trailing window of prior epochs into the score while exporting
current-epoch units only. The burn contract and class allocation are policy
inputs verified by validators, not miner-controlled fields.

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
  private keys, cloud credentials, or SSH credentials.
- A public beta issue may contain the public hotkey, preferred network,
  current or intended Intel TDX hardware class, provider and broad region, and
  an optional public contact handle, never an IP, instance identifier, or
  credential.
- Plain HTTP with `--development-allow-non-loopback` is a development
  exception, not the production security boundary and not a mainnet onboarding
  recipe.
- Production evidence uses credential-free collection over HTTPS with the TLS
  key terminating inside the measured environment; authenticated work follows
  only after channel verification.
- Positive weight and emissions are never guaranteed.

Read [MINING.md](MINING.md) before exposing a worker.

## Run the hardware-free suite

Requires Python 3.11 or newer:

```bash
git clone https://github.com/cathedralai/cathedralconfidential.git
cd cathedralconfidential

python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pytest -q
```

The default suite uses test doubles behind the real verifier interface. Passing
it proves software behavior, not live Intel hardware, deployment, a current
eligible miner, or an on-chain write.

## Documentation

### Current operator and assurance documents

- [Build and evidence status](BUILD_STATUS.md)
- [Mining and provider onboarding](MINING.md)
- [Assurance claims](docs/ASSURANCE.md)
- [Intel TDX launch path](docs/TDX_LAUNCH.md)
- [Public and controlled provenance](docs/PROVENANCE.md)
- [Policy registry](docs/POLICY_REGISTRY.md)
- [Receipts](docs/RECEIPTS.md)
- [Worker lifecycle](docs/LIFECYCLE.md)
- [Workload admission](docs/WORKLOAD_ADMISSION.md)

### Design and future capability

- [Architecture and roadmap](docs/DESIGN.md)
- [GPU attestation foundation](docs/GPU_ATTESTATION.md)
- [Key-release design](docs/KEY_RELEASE.md)

Design documents describe intended capability, not deployed availability.
Historical handoffs and dated launch-candidate records must not be used as
current onboarding instructions.

## Licensing

See [LICENSE](LICENSE).
