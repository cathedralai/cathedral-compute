# Assurance receipts

Cathedral assurance receipts are small, signed records for one worker and one
validator-issued work challenge. They preserve the exact assurance result at
the time it was produced without publishing raw attestation evidence, customer
payloads, credentials, endpoints, or a reusable physical-machine identifier.

A receipt is evidence for the claims it contains. It is not a general promise
that an application is bug-free, that arbitrary output is correct, or that a
customer handled its own keys securely. The signed epoch score vector remains
the accounting source used by score-stream consumers; receipts do not replace
or change that contract.

## What each claim means

| Claim | `passed` means | It does not mean |
|---|---|---|
| `hardware` | Fresh vendor-backed evidence identified an accepted confidential CPU and security state. | The approved Cathedral software ran or produced correct work. |
| `software` | The measured software matched the named signed policy snapshot. | The result was correct or the connection was protected. |
| `channel` | The live worker endpoint controlled the channel key bound into the attestation evidence. | The application result was correct. |
| `work` | The named challenge result passed the validator's lane-specific verification. | Every possible output or external side effect was correct. |

Statuses are `not_evaluated`, `passed`, `failed`, `stale`, or `revoked`.
Every evaluated claim has an evidence digest, policy digest, canonical UTC
verification time, and a safe reason category when it did not pass.
`not_evaluated` has `null` for all four audit fields. There is deliberately no
single overall-verification flag.

## Version 2 schema

The schema identifier issued by the current runtime is
`cathedral_assurance_receipt_v2`.

| Field | Meaning |
|---|---|
| `receipt_id` | SHA-256 identifier of the canonical body before `receipt_id` and `signature` are added. |
| `epoch_id`, `source_epoch` | Local immutable epoch row and external source epoch. |
| `subject_hotkey` | Worker identity to which the challenge was assigned. |
| `platform_pseudonym` | Source-epoch-scoped SHA-256 pseudonym; not the raw hardware identity. |
| `policy_registry_release`, `policy_registry_digest` | Exact signed registry snapshot used for admission. |
| `policy_profile_ids` | Exact active CPU profiles selected from that snapshot. |
| `measurement` | Approved software measurement returned by attestation verification. |
| `tcb` | Vendor TCB audit version, exact SVN, status, advisory IDs, debug state, and collateral-current result. Strict TDX receipts enforce the registry status/advisory policy and require a canonical SVN, debug disabled, and current collateral. Raw TDX SVN is recorded for audit and is not treated as a scalar ordering rule; its legacy scalar `version` field is therefore `0`. |
| `channel` | Channel claim status and its evidence digest. |
| `work` | Claim status, challenge ID, canonical workload-manifest digest, result digest, and decimal work units. Non-passing work always records `"0"`; passed work can still receive zero credit when a separate eligibility claim is unsatisfied. |
| `assurance` | The four independent typed claims and their component digests. |
| `lifecycle` | Receipt state plus the exact attested worker generation, revision, event ID, safe transition reason, and evidence-expiry boundary used for eligibility. Version 2 accepts only an eligible `attested` worker snapshot and an `issued` receipt with a `null` revocation reference. |
| `issued_at` | UTC issuance time with exactly six fractional digits. |
| `signing_key_id`, `signature` | Registry-anchored Ed25519 key and signature over all other receipt fields. |
| `platform` | Optional cross-repo extension block; see below. Absent from receipts issued by this runtime. |

Unknown or missing fields fail closed. A new critical field or lifecycle state
requires a new schema version; verifiers do not silently ignore it.

### The optional `platform` extension block

`platform` is the single declared top-level extension point, shared with the
cathedral-distill compute lane, which names the confidential CPU TEE a receipt
attests. It is optional and version-2 only: receipts without it are
byte-for-byte unchanged, version 1 rejects it outright, and any other unknown
top-level key still fails closed. Because `receipt_id` and the Ed25519
signature cover every field except themselves, a `platform` block can never be
stripped from, injected into, or mutated inside a signed receipt: the id stops
matching its canonical body, and recomputing the id leaves a signature that
does not verify.

When present the block must be exactly:

```json
{"class": "confidential_cpu", "cpu_tee": "intel_tdx"}
```

Nothing else is accepted. Specifically:

- the key set is exact: an unknown, missing, or extra nested key fails closed,
  and arbitrary nested data is never carried through;
- `cpu_tee` must be in the attestable set (`intel_tdx`, `amd_sev_snp`), the
  set of CPU TEEs that expose an attestation interface at all. Plain SEV
  (`amd_sev`, what the live G4 GCP profile emits) exposes none and is
  therefore never admitted, nor is anything outside the set;
- `amd_sev_snp` is attestable but still refused here, because this repo's
  measurement and TCB evidence grammar is Intel TDX only: the label would not
  describe the body that was validated. An SEV-SNP body grammar is a separate,
  deliberate change;
- the composite `confidential_gpu` class is refused for the same reason: it
  asserts GPU evidence (confidential-compute mode, VBIOS measurement, report
  digest, guest binding) that this repo does not verify inside a receipt.

This runtime does not emit `platform`: deployed verifiers of earlier releases
reject any receipt that carries it, so issuance is a separate, deliberate
rollout decision taken only after verifier-side acceptance has shipped
everywhere. Accepting the extension and emitting it are independent steps.

Historical `cathedral_assurance_receipt_v1` bytes remain verifiable. Version 1
predates exact worker-state binding and contains only the receipt issuance
state. The runtime no longer issues new version 1 receipts; converting or
re-signing historical bytes is forbidden.

## What work units bind

`work.work_units` is the field lane credit is computed from, so it is worth
stating precisely what a receipt proves about it and what it does not. A
signature proves who ASSERTED a number, not that the number was derived.

Bound today, inside this repository:

- the runtime never signs a miner's claimed units. The lane re-derives them
  under the versioned `sat_work_units_v1` rule
  ([`cathedral/lanes/sat.py`](../cathedral/lanes/sat.py)) purely from the
  committed work item, and credits only certificates that passed
  verification, once per challenge, matched to the challenge owner;
- the ledger refuses to record verified work that is not validator-derived
  ([`cathedral/ledger.py`](../cathedral/ledger.py));
- full provenance re-derives the units independently from the published,
  content-addressed work artifacts with the same rule the producer used, and
  requires equality with the receipt's signed units
  ([`cathedral/workproof.py`](../cathedral/workproof.py)). A positive miner
  with no published artifacts never reaches FULL: a valid quote plus a
  signer-asserted work claim is refused.

Not bound, at the receipt boundary itself:

- `ReceiptIssuer.issue()` signs the units it is handed, and receipt
  verification checks only that they are canonical decimal and that
  non-passing work records `"0"`. A consumer holding the receipt ALONE, with
  no work artifacts, cannot distinguish a derived number from an inflated
  one. The receipt does not name the derivation rule that produced it.

That gap is why the durable work artifacts exist, and why FULL provenance
requires them. It is pinned as executable behavior in
[`tests/test_work_unit_binding.py`](../tests/test_work_unit_binding.py).

### DECISION NEEDED: the cross-repo derivation contract

Consumers in other repositories currently accept the signed units verbatim.
The cathedral-distill compute lane validates decimal syntax, forwards the
value as the lane contribution, and composition normalizes it; the validator
seam that drives it credits the result. Neither requires the work artifacts,
so across repository boundaries Compute units are signer-asserted. This is
pinned in
[`tests/test_cross_repo_receipt_v2_contract.py`](../tests/test_cross_repo_receipt_v2_contract.py).

Resolving it is an owner decision, not something this repository can close
unilaterally, because it determines what a Compute contribution means to every
consumer. The safe options are:

1. independent derivation: require the published manifest and result artifacts
   at the consumer and re-derive units there, exactly as FULL provenance does
   here, so a receipt without replayable artifacts earns nothing;
2. a versioned derivation or cap rule the consumer applies: the receipt names
   its unit rule, and the consumer enforces that rule's bound before crediting,
   so an out-of-rule number is refused rather than trusted;
3. an explicit owner decision to keep the trusted-issuer model for Compute,
   with the contract copy corrected everywhere to say that units are asserted
   by an authorized signer rather than independently derived.

No option is adopted here, and no unit economics are implied by this document.

## Canonical bytes and durable storage

Receipts use JSON with keys sorted, ASCII escaping enabled, separators `,` and
`:` and no insignificant whitespace. Floating-point JSON, duplicate keys,
non-finite numbers, out-of-range integers, noncanonical timestamps, excessive
nesting, and documents over 256 KiB are rejected. Work units are decimal
strings so values such as zero have one representation.

The runtime signs one receipt after every dispatched challenge, including a
failed result with explicit zero credit. Challenge resolution and insertion of
the exact receipt bytes happen in one SQLite transaction. A crash therefore
leaves both present or leaves the challenge unresolved with no receipt. Stored
receipts are returned as their original bytes and are never reconstructed from
later mutable state.

The repository keeps deterministic golden receipts for both the historical
[`version 1`](../tests/fixtures/assurance-receipt-v1.json) contract and current
[`version 2`](../tests/fixtures/assurance-receipt-v2.json) contract. Their keys
and measurements are test-only.

## Offline verification

Verification needs two trust inputs:

1. the historical signed policy registry whose release and digest are named in
   the receipt; and
2. a locally pinned registry trust root.

For compromise-aware verification, also supply the newest authenticated
registry available. It carries the current receipt-key retirement or
revocation state. Omitting it verifies against the historical snapshot only
and cannot discover a later compromise declaration.

```bash
cathedral receipt verify \
  --receipt receipt.json \
  --policy-registry historical-registry.json \
  --trusted-keys trusted-policy-keys.json \
  --key-registry current-registry.json
```

Success and failure are JSON. Failures use stable categories: `schema`,
`policy`, `key`, `signature`, `lifecycle`, or `policy_registry`. Verification
checks the exact registry release/digest, eligible profiles and measurement,
claim timestamps and policy digests, work/channel consistency, receipt ID,
signing-key state, and Ed25519 signature.

## Receipt-signing key lifecycle

Receipt public keys are entries in the signed policy registry. Each entry fixes
its key ID, Ed25519 public key, `assurance_receipt` purpose, validity window,
state, transition time, optional replacement, and metadata. A key ID can never
change public-key bytes across releases, and a published key cannot disappear.

| Key state | Verification behavior |
|---|---|
| `active` | May sign and verify receipts inside its validity window. |
| `retired` | Cannot sign; receipts issued before the retirement time still verify. |
| `revoked` | All receipts using the key fail verification. Use for suspected key compromise. |

Normal rotation publishes old and replacement keys together, moves the old key
to `retired`, and keeps both historical records. Compromise recovery moves the
old key to `revoked`; it intentionally invalidates earlier signatures because
the verifier can no longer know which were produced by the legitimate holder.
Registry rollback, same-release equivocation, key deletion, key-material
replacement, reactivation, and future-dated transitions are rejected.

The signing seed is a 32-byte value stored as base64 in a regular non-symlink
file. In production the file must be owned by the runtime user and must not be
group- or world-accessible. Configure
both `--receipt-signing-key-id` and `--receipt-signing-key-file`; issuance is
available only when the runtime is also using the signed policy registry.

## Privacy and retention

The public receipt includes the hotkey, source-epoch-scoped platform
pseudonym, measurements, bounded TCB facts, and cryptographic digests. It does
not include raw quotes, certificate chains, bearer tokens, customer data or
data keys, private endpoints, or the operator's stable physical-machine ID.
The pseudonym changes with `source_epoch`, limiting cross-epoch hardware
linkability; the public hotkey remains intentionally linkable.

Operator-only evidence may be retained under separate access controls for
incident response. It is not required to verify the public signature and must
not be copied into the public receipt. Cathedral performs no automatic receipt
deletion: operators must retain exact receipt bytes plus the referenced policy
registries and trust roots for the promised audit period. Deleting any of
those inputs makes later independent verification incomplete.

Rollback disables new issuance but preserves all existing bytes, historical
registries, and verification keys. Publishing receipts can therefore be rolled
back without changing scoring or rewriting history.

If the policy registry or receipt key expires while an epoch is running,
issuance fails closed and the epoch attempt is aborted without a partial
challenge/receipt commit. Operators must load a fresh registry and retry.
