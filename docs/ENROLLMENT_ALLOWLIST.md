# Enrollment Coldkey Allowlist

Only miners whose owning coldkey has been explicitly approved may enroll on
SN39. The enrollment registry (`cathedral/enroll.py`) enforces this with two
artifacts:

1. an **extended registration snapshot** that maps each registered hotkey to
   its owning coldkey, rotated by the same cron that already rotates the
   hotkey snapshot; and
2. a **signed coldkey allowlist**, a versioned artifact listing every
   approved coldkey, verified with the same Ed25519 machinery the policy
   registry uses (`cathedral/coldkey_allowlist.py`).

The gate keys on the coldkey rather than the hotkey because the coldkey is
the durable owner identity: hotkeys rotate and one operator may run several.

## Extended registration snapshot

`JsonHotkeyRegistrationProvider` accepts the existing hotkeys-only formats
(JSON array, `{"hotkeys": [...]}`, newline-delimited) plus the extended form:

```json
{"hotkeys": {"<hotkey ss58>": "<coldkey ss58>", "...": "..."}}
```

Hotkeys-only snapshots keep working for the registration gate, but they carry
no ownership data, so coldkey resolution fails closed until the rotation cron
emits the extended format. The same mtime-based `max_age_seconds` staleness
bound applies to every format.

## Allowlist artifact format

```json
{
  "schema": "cathedral_coldkey_allowlist_v1",
  "release": 1,
  "generated_at": "2026-07-25T00:00:00Z",
  "valid_from": "2026-07-25T00:00:00Z",
  "valid_until": "2026-08-25T00:00:00Z",
  "signing_key_id": "cathedral-enroll-allowlist-1",
  "coldkeys": ["<approved coldkey ss58>", "..."],
  "signature": {"algorithm": "ed25519", "value_base64": "..."}
}
```

Rules, all fail-closed on violation:

- strict top-level key set; unknown or missing fields reject the artifact;
- `release` is a bounded positive integer and must never decrease across
  rotations (the running registry rejects a lower release than one it has
  already accepted);
- the Ed25519 signature covers the canonical JSON of the document without
  `signature`, exactly like the policy registry;
- `generated_at` must fall before `valid_until`, must not sit more than five
  minutes in the future, and must be younger than the configured
  `--enroll-allowlist-max-age-seconds` (default 86400);
- the verification time must fall inside `[valid_from, valid_until)`;
- `coldkeys` is a bounded list (at most 4096) of unique ss58-like strings.
  An empty list is valid and rejects every enrollment (approval paused),
  never fails open.

## Signing

Produce a signed artifact with the same key-handling discipline as the policy
registry. From a machine holding the 32-byte Ed25519 seed:

```python
import json
from cathedral.coldkey_allowlist import sign_allowlist

unsigned = {
    "schema": "cathedral_coldkey_allowlist_v1",
    "release": 2,
    "generated_at": "2026-07-25T00:00:00Z",
    "valid_from": "2026-07-25T00:00:00Z",
    "valid_until": "2026-08-25T00:00:00Z",
    "signing_key_id": "cathedral-enroll-allowlist-1",
    "coldkeys": ["5..."],
}
document = sign_allowlist(unsigned, seed_bytes)
print(json.dumps(document, sort_keys=True, separators=(",", ":")))
```

The trusted-key file given to the registry is a JSON object of
`{"<signing_key_id>": "<base64 32-byte public key>"}`, the same shape as the
policy registry key file.

## Digest pinning

Two pins, mirroring the policy registry:

- `--enroll-allowlist-keys-digest sha256:<hex>` pins the trusted-key file
  (the root of trust). Mandatory in production mode.
- `--enroll-allowlist-digest sha256:<hex>` pins the artifact itself. Also
  mandatory in production mode, and this is what makes revocation durable.

Both pins are required in production because they do different jobs. The key
digest fixes the root of trust, but it is unchanged across releases and so
cannot distinguish release 5 from the superseded release 4. Release
monotonicity is held in process memory and resets on restart, so without the
artifact pin anyone able to place a file at the allowlist path could replay a
still-validly-signed earlier release across a restart and re-admit a coldkey
that was revoked. Rotating the allowlist therefore means restarting the
registry with the new digest, which is the intended cost of a revocation.

The artifact digest is `sha256:` over the canonical JSON of the full signed
document; `cathedral enroll reconcile` prints it as `allowlist_digest`.

## Rotation

Rotate the allowlist by writing a new signed document in place with a higher
`release` and a fresh `generated_at`. The registry re-reads and re-verifies
the file on every enrollment request, so no restart is needed unless the
artifact digest is pinned. A stuck rotation is caught by the staleness
ceiling within one `--enroll-allowlist-max-age-seconds` interval, after which
all enrollment fails closed.

## Fail-closed matrix

In production mode (`--production-mode`), enrollment is rejected with 403
when any of the following holds:

| Condition | Result |
|---|---|
| No allowlist configured | 403, `allowlist_missing` |
| Allowlist file missing or unreadable | 403, `allowlist_unavailable` |
| Allowlist malformed, wrong schema, or oversized | 403, `allowlist_unavailable` |
| Allowlist signature invalid or key untrusted | 403, `allowlist_unavailable` |
| Allowlist stale or outside its validity window | 403, `allowlist_unavailable` |
| Allowlist release lower than one already accepted | 403, `allowlist_unavailable` |
| Pinned artifact digest mismatch | 403, `allowlist_unavailable` |
| Coldkey unresolvable (hotkeys-only or absent mapping) | 403, `coldkey_unresolvable` |
| Coldkey resolved but not on the allowlist | 403, `coldkey_not_allowlisted` |

Outside production mode, configuring an allowlist activates the same gate.
With no allowlist configured, non-production registries keep the current
open behavior so tests and SN292 development flows are not broken.

Every rejection is logged by the registry app with the hotkey, the resolved
coldkey (or `unresolvable`), and the reason. Logs never carry tokens,
signatures, or endpoints.

Operational note: workers re-enroll after an IP rotation, so an allowlist or
resolution outage locks an already-approved miner out of re-enrollment until
the artifact is healthy again. Existing enrollment rows are untouched by the
gate; only new POSTs are affected.

## Gate ordering

Inside `POST /v1/enroll`: per-IP rate limit, payload validation, and sr25519
signature verification run first (the signature authenticates the caller
before anything else is decided). The cheap local gates follow: subnet
registration, coldkey resolution, allowlist membership. Only a request that
passes all of them records the durable per-hotkey attempt and reaches the
store, so a rejected request never burns attempt budget or creates any
durable row.

## Testnet scope

The allowlist gates any registry instance run with `--production-mode`,
which is the mainnet SN39 posture. The SN292 testnet integration lane runs
without production mode and without an allowlist, keeping self-service
enrollment for development. A testnet operator may still configure
`--enroll-allowlist` to exercise the gate end to end; the behavior is then
identical to production.

## Reconciling pre-existing enrollments

The gate blocks new enrollments only. Rows enrolled before the gate existed
survive and must be reconciled explicitly (never automatically at service
start):

```bash
cathedral enroll reconcile \
  --registry-db cathedral-enroll.sqlite \
  --allowlist enroll-allowlist.json \
  --allowlist-keys enroll-allowlist-keys.json \
  --allowlist-keys-digest sha256:<hex> \
  --registered-hotkeys-file registered-hotkeys.json
```

This lists every enrollment whose coldkey is unresolvable or absent from the
allowlist, without changing anything. Add `--remove` to retire the flagged
rows and clear their attestation verdicts. Removal is terminal lifecycle
retirement rather than physical row deletion: the worker lifecycle ledger is
append-only and its rows reference the enrollment, so the audit trail
survives while the worker leaves the refresh set, the epoch target list, and
the public verified count.

The command aborts, touching nothing, when the allowlist fails verification
or when the registration snapshot is stale, malformed, or hotkeys-only:
those states must never be interpreted as "nobody is approved".
