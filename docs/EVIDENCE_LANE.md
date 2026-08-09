# The evidence lane: architecture, status, and trust boundary

This is the deep half of the [README](../README.md): how the supply side works,
what is deployed versus designed, and exactly what the attestation does and
does not prove. Miners start at [MINING.md](../MINING.md); this page is for
validators, auditors, and anyone deciding how much to trust a number.

## What this repository is

The confidential-compute supply side of Cathedral. It is the evidence lane, not
the publisher of final weights:

1. a worker produces fresh, vendor-backed Intel TDX evidence;
2. Cathedral verifies the evidence, worker identity, and measured policy, then
   dispatches bounded work and verifies the result;
3. a signed, complete score report gives every candidate either verified credit
   or an explicit zero; and
4. an independent SN39 validator checks that report and decides whether to set
   weights.

## Status: mainnet live testing, operator-assisted

Observed 2026-08-01, the live signed vector carries one positively scored Intel
TDX miner. That is evidence the producer-to-signed-vector path works end to
end. It is not a promise about any future epoch, and it does not prove that an
authorized validator put that vector on chain, which is a separate step the
feed does not show. Zero positive miners and a burn-only vector remain valid
fail-closed outcomes.

Miner onboarding requires maintainer approval at several steps, the final
public validator release has separate gates, and testnet SN292 is non-paying.

For current state, inspect the live
[signed vector](https://api.cathedral.computer/v1/validator/weights/next) and
[public evidence index](https://api.cathedral.computer/v1/evidence/index.json).
A reachable endpoint or a historical receipt does not prove current freshness
or eligibility.

## What is supported

| Capability | Current status |
|---|---|
| Intel TDX CPU evidence collection and strict verification | Proven on live hardware |
| Fresh challenge, worker, channel, measurement, and policy binding | Implemented |
| Validator-dispatched bounded SAT work | Current scored-work path |
| Complete signed score reports with explicit zero revocation | Implemented |
| Public evidence index | Deployed |
| Deployed vector vs independent verifier | **Not converged.** The 2026-07-25 comparison recorded `FAIL` on the v1 shape, and as of 2026-08-01 the live payload still mixes `contract_version` v1 and v2 metadata blocks. [BUILD_STATUS.md](../BUILD_STATUS.md) is the dated evidence record |
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
(see [ENROLLMENT_ALLOWLIST.md](ENROLLMENT_ALLOWLIST.md)).

Read [MINING.md](../MINING.md) in full before exposing a worker.

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
