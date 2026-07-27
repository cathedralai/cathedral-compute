# Signed policy registry

Cathedral policy registries are public, immutable Ed25519-signed artifacts.
They identify software measurements and hardware-security profiles accepted for
new admissions during a defined UTC window. A listed measurement means that a
software configuration is approved; it does not mean that customer work was
correct or successful.

The current runtime consumer is deliberately CPU-first: it constructs strict
Intel TDX admission policy from eligible `cpu_tdx` profiles. The versioned
schema can preserve CPU SNP, runtime-measurement, and GPU profile material for
future consumers, but those fields do not yet make those lanes admission-
eligible. A registry with no usable CPU TDX profile is rejected before the
validator advances its durable release checkpoint.

## Verification contract

The schema identifier is `cathedral_policy_registry_v1`. The signed bytes are
the registry object with the top-level `signature` member removed, serialized
as UTF-8 JSON with keys sorted, ASCII escaping enabled, and separators `,` and
`:` with no extra whitespace. Duplicate keys, floating-point numbers, unknown
critical fields, noncanonical UTC timestamps, and unknown schema versions are
rejected before use. Encoded size, profile count, policy-list size, and metadata
depth/complexity are bounded before the document becomes runtime policy.

The signature object is:

```json
{"algorithm":"ed25519","value_base64":"<64-byte signature>"}
```

The `signing_key_id` selects one locally pinned 32-byte Ed25519 public key.
Keys are configuration, not registry content: a registry cannot introduce the
key that authorizes itself. Rotation uses a bounded overlap in which operators
pin the new key before a release signed by it is accepted, then remove the old
key after all validators have crossed the announced checkpoint.

Receipt-verification keys are different: their public keys are signed registry
content under `receipt_signing_keys`, while their authority still derives from
the locally pinned registry-signing root. Each receipt key fixes its ID,
Ed25519 public key, `assurance_receipt` purpose, active window, lifecycle state,
transition time, and optional replacement. Receipt key material is immutable
across releases and published keys cannot be removed. Active keys may sign;
retired keys verify only receipts predating retirement; revoked keys verify no
receipts. See [`RECEIPTS.md`](RECEIPTS.md) for rotation and compromise behavior.

Run the customer-safe verifier:

```bash
cathedral policy-registry verify \
  --registry examples/policy-registry/registry-v1.json \
  --trusted-keys examples/policy-registry/trusted-keys.json \
  --historical-at 2026-07-17T12:00:00Z
```

`--historical-at` is inspection-only and never updates admission state. Omit it
for current admission-policy checks, which enforce freshness and current time.

## Registry and profile lifecycle

Every registry has a positive monotonically increasing `release`,
`generated_at`, `valid_from`, and exclusive `valid_until`. Admission requires
the signature, the current validity window, and a configurable maximum age.
A signed but stale release is not current admission policy.

Profiles are never deleted after publication. Their states are:

| State | Admission meaning |
|---|---|
| `active` | Accepted inside the profile and registry validity windows. |
| `retiring` | Accepted only until the explicit `retire_at` boundary. |
| `retired` | Preserved for audit; not accepted for new admission. |
| `revoked` | Immediately excluded from new admission. |

Allowed transitions are `active → retiring → retired`, with revocation allowed
from active or retiring. Retired and revoked profiles cannot be reactivated.
Overlapping active and retiring CPU profiles must use identical minimum TCB,
TCB-status, advisory, and firmware controls; overlap cannot silently weaken the
security floor.

## Rollback and bootstrap

Validators persist the last accepted release, digest, and profile states in a
separate SQLite state file. A lower release, same-release different digest, a
removed historical profile, or an invalid state transition fails closed.

A fresh production state store is not an empty trust decision. Operators must
configure either an exact signed checkpoint or a positive minimum release. The
minimum must move forward with operational rollouts so restoration of an old
backup or loss of the state file cannot reopen an obsolete signed release.
The local high-water mark cannot prove that a distributor has not withheld a
newer release; bounded document age and an operator-managed minimum release are
the fail-closed controls until an authenticated release-discovery channel is
introduced.

The runtime exposes both bootstrap forms: use
`--policy-registry-min-release`, or supply the exact pair
`--policy-registry-pinned-release` and `--policy-registry-pinned-digest`.
Production also requires `--policy-registry-keys-digest sha256:...`, configured
independently of the public key file. The daemon reloads and verifies the
registry on every probe pass, immediately before each probe verdict commit,
and at every runtime admission boundary. Expiry,
maximum-age exhaustion, key-file drift, or a release change during an active
epoch fails closed before verdict or ledger commit.

## Epoch and historical verification

One verified registry snapshot is converted to an immutable `Policy` before an
epoch begins. The epoch report records the exact registry release and SHA-256
digest; a mutable file cannot change policy midway through the epoch.

Historical receipt verification may load an older signed registry only when
the receipt time falls inside that registry's validity window. That historical
check does not update the admission high-water mark and never makes the old
release current again.

### Evidence export across a registry succession

`runtime export-evidence` reconciles a frozen epoch against the release that
epoch pinned, not against whatever is live now, so a reissue between two epoch
cycles otherwise leaves the last frozen epoch permanently unreconcilable.
Because `republish-install` archives the outgoing signed registry under
`release-<release>-<sha256>.json` before installing its successor, give the
exporter the same history directory:

```bash
cathedral runtime export-evidence \
  --policy-registry /etc/cathedral/policy-registry-sn39.json \
  --policy-registry-history-dir /var/lib/cathedral-confidential-sn39/policy-history \
  ...
```

The live file is used whenever its digest already equals the signed report's
pinned `policy_digest`; only a mismatch reads the history directory. Only a
file whose content hashes to the pinned digest is accepted, so the archive
name is a lookup hint and never evidence. A pinned digest carried by neither
the live file nor an archived release still fails closed with the same error.
When an archived release is used, the export prints
`{"policy_registry": "archived", "release": N, "digest": "sha256:..."}` ahead
of its run summary.

## Freshness republication and window rollover

Production admission keeps a hard 24-hour maximum registry age. Do not widen
that ceiling. Reissue the same policy at a higher release before the ceiling:

```bash
python scripts/cathedral_measurement_approval.py republish-install \
  --registry /etc/cathedral/policy-registry-sn39.json \
  --signing-key-file /etc/cathedral/policy-signing-sn39.key \
  --state /var/lib/cathedral-confidential-sn39/policy-state.sqlite \
  --operator cathedral-sn39-systemd \
  --reason "scheduled bounded 24-hour freshness reissue" \
  --approval-log /var/lib/cathedral-confidential-sn39/policy-republication.jsonl \
  --history-dir /var/lib/cathedral-confidential-sn39/policy-history \
  --lock-file /var/lib/cathedral-confidential-sn39/policy-writer.lock
```

`republish-install` takes a nonblocking local lock, proves the exact successor
against a temporary copy of the rollback state, archives the outgoing signed
registry, and atomically installs the verified next release. It never writes
the anti-rollback state; the ordinary runtime accepts the new release. The
example systemd service and timer under `examples/systemd/` run every 12 hours
with a bounded randomized delay. Lock contention is a failed run, not a silent
success; the example service retries failures after five minutes. Create the
history directory as root-owned mode `0700` before enabling the timer. Run the
service once manually and prove the next runtime epoch records the new release
before relying on the timer.
The audit log is a write-ahead journal: `registry_reissue_prepared` and
`policy_registry_install_prepared` precede the filesystem commit, while
`policy_registry_install_committed` follows it. After an interrupted run,
compare the live signed-registry digest with those records; never roll back an
already installed higher release.

Fresh republication cannot extend immutable registry, profile, or receipt-key
validity windows. Before those windows expire, prepare an explicit bounded
rollover:

```bash
python scripts/cathedral_measurement_approval.py rollover \
  --registry /etc/cathedral/policy-registry-sn39.json \
  --signing-key-file /etc/cathedral/policy-signing-sn39.key \
  --state /var/lib/cathedral-confidential-sn39/policy-state.sqlite \
  --source-profile-id cpu-tdx-sn39-v1 \
  --new-profile-id cpu-tdx-sn39-v2 \
  --new-receipt-key-id cathedral-receipt-sn39-YYYYMMDD \
  --valid-until 2026-10-22T00:00:00Z \
  --operator "<operator>" \
  --reason "<reviewed reason>" \
  --approval-log /var/lib/cathedral-confidential-sn39/policy-rollovers.jsonl \
  --out /root/policy-registry-sn39.next.json \
  --receipt-signing-key-out /root/receipt-signing-sn39.next.key
```

The requested window must be 7–180 days from issuance. The command clones the
currently eligible CPU-TDX profile's measurements and security controls under
a new ID, adds a new Ed25519 receipt public key, retains all historical
profiles and keys, verifies the signed successor, and leaves live files
untouched. Review the diff and install the new registry, private receipt seed,
and runtime key ID as one bounded operator transaction.

Every supported writer of the live registry must use the same
`--lock-file`. Direct `cp`, `mv`, or editor writes to the live path are
unsupported because they can race the timer. Stage the newly generated receipt
seed under its final unique mode-0600 path first, then install the reviewed
registry through the shared lock:

```bash
python scripts/cathedral_measurement_approval.py install-candidate \
  --registry /etc/cathedral/policy-registry-sn39.json \
  --candidate /root/policy-registry-sn39.next.json \
  --signing-key-file /etc/cathedral/policy-signing-sn39.key \
  --state /var/lib/cathedral-confidential-sn39/policy-state.sqlite \
  --expected-current-digest sha256:<reviewed-current-digest> \
  --expected-candidate-digest sha256:<digest-printed-by-rollover> \
  --operator "<operator>" \
  --reason "<reviewed installation reason>" \
  --approval-log /var/lib/cathedral-confidential-sn39/policy-rollovers.jsonl \
  --history-dir /var/lib/cathedral-confidential-sn39/policy-history \
  --lock-file /var/lib/cathedral-confidential-sn39/policy-writer.lock
```

Only after the runtime has accepted that registry should the receipt issuer be
switched to the already staged new key ID/path; the old key remains valid
during the overlap. Never publish, log, or copy the private seed into a command
line.

The committed sample contains placeholders only. Its deterministic test key is
intentionally reproducible and must never be configured as a production trust
root. It contains no production measurement, endpoint, platform identifier, or
production signing material.
