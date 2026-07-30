# SN39 Admission Policy

One signed artifact decides who may **ask to be tested** on SN39, and in which
of two modes:

- **`selected`** — the owner approves an operator coldkey once. That operator
  then enrolls its registered hotkeys and machines without any further owner
  action.
- **`all_registered`** — any hotkey currently registered on SN39 may ask,
  subject to caps and rate limits, with no owner action at all.

The artifact replaces the standalone coldkey allowlist
(`docs/ENROLLMENT_ALLOWLIST.md`). The two cannot be configured together: a
service answering to two approval artifacts has no single answer to "who is
approved right now".

## What enrollment is, and is not

Enrollment is permission to be tested. It is **never** proof, admission, a
score, a reward, or an earning guarantee.

```
REGISTERED -> ENROLLED_PENDING -> ATTESTED -> ADMITTED -> FIRST_VERIFIED_RECEIPT -> EARNING
```

This artifact governs exactly one arrow: `REGISTERED -> ENROLLED_PENDING`. A
successful enrollment writes a `PENDING` directory row and nothing else. The
response says `"status": "pending"` for that reason.

Everything after that arrow is unchanged and identical in both modes: the
validator-issued fresh challenge, HTTPS/SPKI channel binding, external Intel
TDX quote verification, exact approved measurement, current collateral and
TCB, workload binding, lifecycle checks, and the duplicate-platform and
anti-replay rules. **Open mode widens who may ask. It never widens what is
accepted.** A miner listed in `coldkeys` that never passes attestation stays
at zero exactly like a miner that was never listed.

## Artifact format

```json
{
  "schema": "cathedral_admission_policy_v1",
  "mode": "selected",
  "coldkeys": ["<approved operator coldkey ss58>"],
  "network": "finney",
  "netuid": 39,
  "required_profile_ids": ["cpu-tdx-sn39-v2"],
  "max_enrolled_endpoints_per_coldkey": 2,
  "max_admitted_workers_total": 16,
  "config_version": 1,
  "issued_at": "2026-07-30T00:00:00Z",
  "expires_at": "2026-08-30T00:00:00Z",
  "signing_key_id": "cathedral-admission-sn39-1",
  "signature": {"algorithm": "ed25519", "value_base64": "..."}
}
```

Rules, all fail-closed on violation:

- strict top-level key set; unknown or missing fields reject the artifact;
- Ed25519 over the canonical JSON of the document without `signature`,
  exactly like the policy registry and the allowlist;
- `config_version` is a bounded positive integer and must never decrease. A
  running registry refuses a version lower than one it has already accepted;
- **`network` and `netuid` are checked against the service's own
  configuration.** A policy signed for SN292 or for testnet cannot gate a
  mainnet SN39 service even when the same operator key signed it;
- `required_profile_ids` is a bounded, non-empty list of profile ids from the
  signed policy registry. A miner may only request a profile on this list;
- both caps are bounded integers in `1..100000`;
- `issued_at` must precede `expires_at`, must not sit more than five minutes
  in the future, and must be younger than
  `--admission-policy-max-age-seconds` (default 86400). Staleness is repaired
  by reissuing at a higher `config_version`, never by widening the ceiling;
- the verification time must fall inside `[issued_at, expires_at)`.

### The two mode invariants worth stating twice

- In `selected` mode an **empty** `coldkeys` list is valid and deliberate: it
  pauses approval by rejecting every enrollment. It never fails open.
- In `all_registered` mode a **populated** `coldkeys` list is refused
  outright. An operator reading a policy with entries in it would reasonably
  believe those entries were gating something. In open mode they are not, so
  the artifact is rejected rather than silently ignored.

## Coldkey resolution

Ownership is resolved from the registration snapshot
(`--registered-hotkeys-file`, extended `{"hotkeys": {hotkey: coldkey}}`
format), never from the request. The v2 request carries a `coldkey` field
that is inside the signature but is only ever **compared** against the
resolved value; a mismatch is rejected as `coldkey_mismatch`. Signing it is
what makes a disagreement attributable rather than ambiguous.

A hotkeys-only snapshot still gates registration but cannot prove ownership,
so coldkey resolution fails closed until the rotation cron emits the extended
format.

Ownership is re-checked on **every** request, so a hotkey that moves under a
different coldkey on-chain stops being able to re-enroll. It does not
retroactively remove an existing row; use `cathedral enroll reconcile` for
that.

## v2 enrollment request

```json
{
  "hotkey": "...", "coldkey": "...",
  "network": "finney", "netuid": 39,
  "endpoint_url": "https://<public IP literal>:8443",
  "requested_profile_id": "cpu-tdx-sn39-v2",
  "nonce": "<32-128 hex>",
  "timestamp": "<ISO-8601 UTC>",
  "expires_at": "<ISO-8601 UTC>",
  "signature_b64": "<sr25519 over the canonical document>"
}
```

The signed document adds `"schema": "cathedral_enroll_request_v2"` and
excludes `signature_b64`. Every field the registry acts on is inside the
signature, so a request cannot be replayed against a different subnet,
endpoint, or profile than the one the hotkey agreed to.

`expires_at` must follow `timestamp`, must be in the future, and must not
extend the request beyond the server's own signature TTL: a miner cannot mint
a request that outlives the replay window the registry is willing to police.

**There is no downgrade path.** Once a policy is configured, a v1 request
cannot enroll — the v1 and v2 signed byte strings cannot collide.

## Caps

| Cap | Enforced where | Meaning |
|---|---|---|
| `max_enrolled_endpoints_per_coldkey` | inside the enrollment write transaction | distinct endpoints one operator may have queued for testing |
| `max_admitted_workers_total` | inside the enrollment write transaction | **necessary precondition** on the total worker population |

Both are evaluated in the same `BEGIN IMMEDIATE` transaction as the write, so
two concurrent enrollments cannot both observe capacity and then both take
it. A retry that re-enrolls the same hotkey at the same endpoint consumes no
additional capacity.

Retired rows are excluded from every count: retirement is the operator's
deliberate act of freeing capacity. **Revoked rows still consume capacity**,
so losing a worker to a revocation never hands its owner a fresh slot to
retry from.

One further rule applies only under a policy: an endpoint already enrolled by
a different live worker is refused (`endpoint_claimed`). This is the
pre-attestation proxy for one physical machine; true platform uniqueness
remains the chip-id gate at admission.

> `max_admitted_workers_total` is enforced at enrollment as a necessary
> condition, because enrolled is always greater than or equal to admitted.
> The authoritative admitted-count gate belongs at admission, alongside the
> per-epoch probe budget. Until that lands, do not read this cap as a proof
> that the admitted population is bounded — read it as a bound on the pending
> directory.

## Running it

```bash
python -m cathedral.enroll \
  --db /var/lib/cathedral/enroll.sqlite \
  --production-mode \
  --network finney --netuid 39 \
  --registered-hotkeys-file /var/lib/cathedral/registered-hotkeys.json \
  --admission-policy /etc/cathedral/admission-policy-sn39.json \
  --admission-policy-keys /etc/cathedral/admission-policy-keys.json \
  --admission-policy-keys-digest sha256:<digest of the key file> \
  --admission-policy-digest sha256:<digest of the policy artifact>
```

Production requires both digests. The key digest pins the root of trust, not
the document; the `config_version` guard is in-process and resets on restart,
so a superseded but still validly signed policy could otherwise be replayed
to re-open a mode or restore a revoked coldkey. **Pinning the artifact digest
is what makes revocation durable.** Rotating a pinned policy is deliberately
a restart with the new digest.

## Rejection reasons

Every rejection logs `hotkey`, resolved `coldkey`, and a stable `reason`.
Tokens, signatures, and wallet material are never logged.

| Reason | Status | Meaning |
|---|---|---|
| `policy_unavailable` | 403 | missing, malformed, expired, stale, misbound, rolled-back, or digest-mismatched policy |
| `network_mismatch` | 403 | request signed for a different network or netuid |
| `profile_not_offered` | 403 | requested profile is not in `required_profile_ids` |
| `coldkey_unresolvable` | 403 | snapshot cannot prove ownership |
| `coldkey_mismatch` | 403 | submitted coldkey does not own this hotkey |
| `coldkey_not_selected` | 403 | selected mode, coldkey not approved |
| `endpoint_claimed` | 403 | endpoint already enrolled by another live worker |
| `coldkey_endpoint_cap` | 403 | operator at its endpoint cap |
| `total_worker_cap` | 403 | subnet at its worker cap |
| `not_registered` | 403 | hotkey not registered on the subnet |
| `hotkey_rate_limited` / `ip_rate_limited` | 429 | rate limits, unchanged |

## Migration and rollback

1. Publish the policy artifact and its key file; record both digests.
2. Move miners to v2 requests **before** enabling the policy. A v1 client
   cannot enroll against a policy-gated service.
3. Start with `mode: selected` and the current approved coldkeys, so the
   change is authentication shape only, not population.
4. Open mode is a separate, later, deliberate `config_version` bump.

Rollback is a restart with `--enroll-allowlist` and the previous artifact.
The legacy path is untouched by this change and still works exactly as
`docs/ENROLLMENT_ALLOWLIST.md` describes.
