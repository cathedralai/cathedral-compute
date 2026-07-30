# Validator-signed work requests (design draft)

Companion draft for issue #60. **Nothing here is implemented.** This document
fixes the wire format and the verification order so that the implementation
is a mechanical exercise, and so that the parts that are genuinely undecided
are visible as decisions rather than discovered as surprises.

## What exists today

Per-request auth from validator to miner is a shared bearer token. The miner
generates it, sends it to the operator out of band, and the operator writes
`hotkey -> token` into a file on the validator (`cathedral/cli.py:704`
`_load_tokens`, bridged at `cli.py:934` as `token_provider=tokens.get`,
consumed per-enrollment at `runtime.py:651`). The validator sends it
(`remote.py:338`), the worker compares it (`worker.py:304`).

`/v1/evidence` is deliberately credential-free (`worker.py:333-339`). The
token gates **work dispatch and capabilities**, not attestation polling. Any
replacement inherits that boundary.

## Why replace it

The system already proves identity cryptographically at enrollment, with an
sr25519 signature over a nonce, then falls back to a shared secret for the
recurring path. The validator already holds a hotkey it uses to set weights,
so it can sign each request and let the worker verify against a public
address. Nothing secret would need to be exchanged, stored on two machines,
or rotated by hand.

The strongest driver is **multiple validators**. Pairwise shared secrets are
O(miners x validators) and stop working at the second validator. Signatures
plus an on-chain permit check scale.

## Why this is not free, stated before the design

- Signatures are public and replayable inside their freshness window.
  Preventing that needs replay state **inside the worker**, which grows the
  measured TD image and forces every miner to rebuild and re-measure.
- Key distribution inverts rather than disappearing: miners must know which
  validator keys to trust, so rotating the validator hotkey still touches
  every miner config. The win is that the distributed material is no longer
  secret.
- The manual token exchange is currently acting as the de facto approval
  gate. It must not be removed before an explicit gate exists. The signed
  admission policy proposed in PR #78 is that gate; this draft assumes it has
  landed, and is deliberately not stacked on it so the two can be reviewed
  independently.

## Wire format

```json
{
  "schema": "cathedral_work_request_v2",
  "validator_hotkey": "<ss58>",
  "worker_hotkey": "<ss58>",
  "endpoint_url": "https://<ip literal>:<port>",
  "workload_digest": "sha256:<64 hex>",
  "network": "finney",
  "netuid": 39,
  "epoch": <monotonic integer>,
  "session": "<16-byte hex>",
  "nonce": "<32-byte hex>",
  "issued_at": "<ISO-8601 UTC>",
  "expires_at": "<ISO-8601 UTC>",
  "policy_registry_release": <integer>,
  "policy_registry_digest": "sha256:<64 hex>",
  "profile_id": "cpu-tdx-sn39-v2",
  "signature": {"algorithm": "sr25519", "value_base64": "<64 bytes>"}
}
```

Signed bytes are the canonical JSON of the document without `signature`,
using the same canonicalization as every other artifact in this repository
(`policy_registry.canonical_json`: sorted keys, `(",", ":")` separators,
ASCII, no NaN). The `schema` member is inside the signed document, so a
work request can never be confused with an enrollment request, a receipt, or
a policy artifact.

### What each binding is for

| Field | Prevents |
|---|---|
| `worker_hotkey` + `endpoint_url` | replaying one worker's request against another |
| `workload_digest` | substituting the work after the request was authorized |
| `network` + `netuid` | replaying an SN292 request against SN39 |
| `epoch` + `session` | replaying last epoch's request into this one |
| `nonce` | replay inside one epoch |
| `issued_at` + `expires_at` | unbounded validity |
| `policy_registry_release` + `_digest` + `profile_id` | authorizing work under a policy the worker is not running |

## Verification order in the worker

Cheapest and most-discriminating first, so an unauthenticated flood is
rejected before any expensive check:

1. **Schema and shape.** Strict key set, bounded lengths, canonical encodings.
2. **`worker_hotkey` is this worker.** A constant-time compare. Rejects
   misdirected traffic before any crypto.
3. **Freshness.** `issued_at <= now < expires_at`, `expires_at - issued_at <=
   MAX_REQUEST_LIFETIME` (proposed: 120 s), and `issued_at` not more than a
   small skew in the future.
4. **Signer is a trusted validator.** `validator_hotkey` must be in the
   worker's configured trust set. See the open decision below.
5. **Signature verifies** over the canonical bytes.
6. **Replay state.** `(validator_hotkey, epoch, nonce)` must be unseen. This
   is the expensive, stateful check and it goes last on purpose.
7. **Binding.** `endpoint_url`, `network`, `netuid`, `profile_id`, and the
   policy release/digest must match what this worker is actually serving
   under. A mismatch is a refusal, never a warning.

Every failure is fail-closed and returns the same generic refusal to the
caller. Detail goes to the worker's log, never to the response: a caller must
not be able to use the error text to enumerate which binding it got wrong.

## Replay state, and what it costs

The worker must remember `(validator_hotkey, epoch, nonce)` for at least
`MAX_REQUEST_LIFETIME`. The cheapest sufficient structure is a bounded
per-epoch set with the previous epoch retained during the overlap window, and
both dropped on epoch advance. Memory is bounded by
`validators x requests_per_epoch`.

This is the part that grows the measured image, and it is the reason #60 says
"do this when a second validator is actually on the roadmap". A restart
clears the set, so a restart inside one freshness window re-opens replay for
that window. Persisting it to the encrypted volume closes that at the cost of
a write per request. **This is an unmade decision, not an oversight.**

## Open decisions, stated as decisions

1. **Trust set distribution.** A static list in worker config is simplest and
   makes rotation a config push to every miner. Reading validator permits
   from the chain removes the push but adds a chain dependency inside the
   measured image, which the current design deliberately avoids everywhere
   else (`enroll.py:98-103` substitutes a rotated file for exactly this
   reason). **Recommendation: static list first**, matching the existing
   posture, with the chain lookup as a later, separate change.
2. **Replay durability across restart.** In-memory (cheap, re-opens a
   120-second window on restart) versus persisted (closes it, costs a write
   per request inside the TD). **Recommendation: in-memory first, with the
   window documented**, because a restart already forces re-attestation.
3. **Whether `/v1/capabilities` moves too.** It is currently bearer-gated
   alongside dispatch. It carries no work and no secret, so it could become
   credential-free like `/v1/evidence`. **Recommendation: keep it gated**;
   widening a surface while replacing its auth mixes two changes.

## Migration

The bearer bridge is **not** removed by this change. Both paths run in
parallel:

1. Worker accepts either a valid bearer **or** a valid signed request.
   Compatibility tests prove a v1-only validator and a v2-only validator both
   work against the same worker build.
2. Validators move to signed requests. Miner configs gain the validator
   trust set. No secret is exchanged.
3. Only after every enrolled worker reports a build that verifies signatures,
   and after a full epoch with zero bearer-path dispatches observed, does the
   bearer path get removed — in a separate change, with its own measurement
   rollover, because removing it changes the measured image.

Rollback at any point before step 3 is a validator-side config flip back to
bearer. After step 3 it is a worker image rollback, which is a measurement
rollover and therefore an owner transaction.

## Explicitly not in scope

- **This is not enrollment identity.** Enrollment proves which operator owns
  a hotkey; this proves which validator authorized one unit of work. They
  share no key material, no artifact, and no code path. Combining them would
  make a work-request compromise into an admission compromise.
- **This does not change what is admitted.** Measurement, TCB, channel
  binding, and uniqueness are untouched.
- **This grants no weight.** A verified work request authorizes work; only a
  verified receipt from completed work earns anything.

## Acceptance, from #60

- [ ] Validator signs each work request with its hotkey
- [ ] Miner verifies against the validator's on-chain address and checks the permit
- [ ] Replay protection specified and tested
- [ ] Worker TCB growth measured and documented
- [ ] Migration path that does not break enrolled miners mid-flight

The first and third are specified above. The second depends on open decision
1. The fourth cannot be answered from a design document: it needs a build of
the worker with the replay set included, measured against the current image.
