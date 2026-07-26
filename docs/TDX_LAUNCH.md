# Cathedral TDX Launch Path

This is the current Phase 1 launch path. The original handoff was SNP-first,
but launch supply is already an Intel TDX confidential VM, so Cathedral proves
real CPU attestation with TDX first and ports the same interface to SNP after
launch.

## Live Box

The current launch worker is a cloud Intel TDX confidential VM (a 4-vCPU
TDX-capable instance running the Cathedral publisher). Deployment identifiers
(VM name, project, zone, addresses) are intentionally kept out of this public
doc.

Treat it as live infrastructure. Initial probes should only request attestation
evidence and inspect read-only capability state. Do not restart services, change
config, or stop the VM as part of attestation development.

## Reproducing an approved miner image

This is the instance definition the currently approved miner runs. Everything
in it is public and pinned, so anyone can launch the same shape. Read the
limits below before you spend money: this recipe reproduces the *configuration*,
which is necessary for an approved measurement, and it does not by itself
guarantee one.

```bash
gcloud compute instances create cathedral-miner \
  --project "$PROJECT_ID" \
  --zone "$ZONE" \
  --machine-type c3-standard-4 \
  --image projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20260717 \
  --confidential-compute-type TDX \
  --maintenance-policy TERMINATE \
  --shielded-vtpm \
  --shielded-integrity-monitoring \
  --no-shielded-secure-boot
```

| Setting | Value | Why it is fixed |
|---|---|---|
| Image | `ubuntu-2404-noble-amd64-v20260717` | Public, pinned image reference. A different image boots a different guest and measures differently. |
| Machine type | `c3-standard-4` | The TDX-capable shape the approved worker runs. The worker's fixed two-slot evidence and four-slot work pools are sized for 4 vCPU. |
| Confidential type | `TDX` | Intel TDX is the only provider class the subnet currently admits. |
| vTPM | enabled | Matches the approved instance. |
| Secure Boot | disabled | Matches the approved instance. Enabling it changes the boot chain. |
| Integrity monitoring | enabled | Matches the approved instance. |
| Maintenance policy | `TERMINATE` | Confidential VMs cannot live migrate. |

Then install the worker and check the machine before going any further:

```bash
sudo apt-get update
sudo apt-get install -y git python3-venv

git clone https://github.com/cathedralai/cathedralconfidential.git
cd cathedralconfidential

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

sudo "$PWD/.venv/bin/cathedral" worker self-check
```

### What you control and what the host controls

The Cathedral measurement is one SHA-256 over the TD identity fields:
`TD_ATTRIBUTES`, `XFAM`, `MRTD`, `MRCONFIGID`, `MROWNER`, `MROWNERCONFIG`, and
all four RTMRs. Those fields have two different owners.

- **Guest side, yours.** The RTMRs accumulate what actually booted. Pinning the
  image, leaving Secure Boot off, and not replacing the kernel keeps this half
  stable. A kernel upgrade from `apt`, an edited kernel command line, or an
  added boot disk can move it.
- **Host side, the cloud provider's.** `MRTD` is the initial TD measurement,
  produced by the host's TDX virtual firmware. The image reference does not pin
  it. Google updates that firmware on its own schedule, and a VM that is fully
  stopped and started can come back on a different version.

This split is the most likely reason the active profile approves three
measurements rather than one: the same pinned guest configuration, observed
across more than one host firmware version.

### What this recipe does not promise

- **Not byte-reproducible.** Two operators running the identical command on
  different days, or in different zones, can produce different measurements,
  because the host half is not theirs to pin. Cathedral has not demonstrated
  byte-for-byte reproducibility and this document does not claim it.
- **Not an admission guarantee.** The recipe gets you a configuration that has
  produced approved measurements. Whether *your* boot produced one is a
  question only your own quote can answer, which is what `worker self-check`
  is for. Run it before you register a hotkey or pay for anything further.
- **Not stable across upgrades.** Running `apt-get upgrade` into a new kernel
  after acceptance can move you off the approved list silently. Pin the kernel,
  and re-run `worker self-check` after any change to the guest or any full stop
  and start of the VM.

## Verifier Subprocess Controls

The validator-side subprocess verifier is governed by five environment variables:

| Variable | Default | Description |
|---|---|---|
| `CATHEDRAL_TDX_VERIFY_CMD` | *(required)* | Verifier that receives the quote file path and, in production, the independently computed 128-character lowercase-hex expected REPORTDATA value, then prints one JSON claims object. Production requires exactly one absolute static x86-64 Linux ELF executable and no configured arguments. |
| `CATHEDRAL_TDX_VERIFY_ARTIFACTS` | *(production required)* | JSON list containing exactly the same production executable path. |
| `CATHEDRAL_TDX_VERIFY_DIGEST` | *(production required)* | Exact `sha256:...` digest of the fixed execution contract, path, and executable contents. |
| `CATHEDRAL_TDX_VERIFY_TIMEOUT` | `30` | Seconds before the entire process group is killed. Values outside 1–60 use the safe default. |
| `CATHEDRAL_TDX_VERIFY_MAX_OUTPUT` | `1048576` (1 MiB) | Combined stdout/stderr cap. Values outside 1–4194304 use the safe default. |

All modes require both `intel_verified` and `report_data_match` to be the exact
JSON boolean `true`. Missing fields, JSON strings (`"true"`), integers (`1`),
`null`, or `false` all reject.

The subprocess itself is rejected (returns no claims) if:
- it exceeds `CATHEDRAL_TDX_VERIFY_TIMEOUT` seconds
- it exits with a nonzero code
- its stdout or stderr exceeds `CATHEDRAL_TDX_VERIFY_MAX_OUTPUT` bytes
- its stdout is not valid JSON
- its stdout contains duplicate object keys or non-finite JSON constants
- its stdout is valid JSON but not an object

Production accepts one statically linked x86-64 ELF executable, with no
interpreter, dynamic loader, fixed arguments, plugins, or Python import path.
The executable and every path ancestor must be root-owned and not writable by
group or other users; symlinks are rejected.
The validator rechecks the digest at startup and before every quote. The child
runs with `/` as its working directory, a fixed minimal environment, closed
inherited descriptors, no stdin, and a new process session. Timeout, output
overflow, a descendant retaining a pipe, or normal parent completion kills and
reaps any remaining process-group members.

## Interface

The miner-side self-check is:

```bash
cathedral worker self-check
cathedral worker self-check --json
cathedral worker self-check --policy-registry registry.json --trusted-keys keys.json
cathedral worker self-check --allowlist-file approved.txt
cathedral worker self-check --approved-measurement tdx-measurement-sha256:<64-hex>
cathedral worker self-check --quote-file /path/to/quote.bin
cathedral worker self-check --verifier /path/to/cathedral-tdx-verifier
```

It collects one quote through the same `collect_tdx` path `worker serve` uses
for `/v1/evidence`, derives the measurement with
`cathedral.verify.tdx_quote.parse_tdx_quote` (the derivation this document's
claims contract is pinned to), and classifies it against a supplied approved
list. It needs no Cathedral credential and runs before enrollment.

**There is no built-in approved list.** The signed policy registry is the only
measurement authority and it changes independently of any release, so a
constant compiled into the tool would eventually be confidently wrong. Run with
`--policy-registry` for the authoritative answer, or with a list the operator
gave you. With no list at all the command still reports the measurement and
says the approval question was not asked, which is the honest outcome.

TCB status is not in the quote. It is decided by Intel collateral, so the check
reports it only when `--verifier` names a binary that evaluated it, and says
`not checked locally` otherwise rather than guessing. A miner does not need
that binary and does not need any Cathedral deployment path to mine; it is
optional tooling, built from source as described later in this document. When a
verifier does run, its `measurement` claim is compared against the local
derivation and any disagreement is reported as a hard failure instead of a
verdict, and its TCB status is discarded unless `intel_verified` and
`report_data_match` are both exactly `true`.

Exit codes, for unattended provisioning:

| Code | Meaning |
|---|---|
| 0 | Measurement is on the supplied approved list |
| 2 | The command itself failed (bad arguments, unreadable file) |
| 3 | Measurement is not approved |
| 4 | TCB is not current |
| 5 | No TDX, or the quote could not be collected |
| 6 | The verifier produced no usable claims |
| 7 | The verifier and this build disagree about the measurement |
| 8 | No approved list was supplied, so nothing was classified |

### What the derivation guarantee covers

The self-check and the production verifier are two implementations of one
measurement definition, in different languages. Two things are pinned by tests:

- they agree on a shared field-value vector (`tests/test_self_check.py` and the
  Go `TestMeasurementMatchesPythonContractVector`); and
- they agree on one real production quote, go-tdx-guest's
  `tdx_prod_quote_SPR_E4.dat`, deriving the identical measurement and TCB SVN
  from the same raw bytes. This is what covers field offsets rather than only
  field values, because the synthetic vector shares the Python parser's layout
  assumptions.

**Not proven:** neither test is a demonstration on live TDX hardware. Nothing
here establishes that a quote collected from any particular machine will
verify, or that its measurement will be approved. That is the question the
command exists to ask.

The miner-side collector is:

```python
from cathedral.attest import collect_tdx
evidence = collect_tdx(
    nonce,
    hotkey,
    channel_binding=worker_channel_binding,
    report_data_version=2,
)
```

It writes Cathedral's 64-byte `report_data_v2(nonce, hotkey, channel_binding)`
value to Linux configfs-tsm and reads the raw quote from `outblob`. The worker
must be configured with the digest of a channel key generated and held inside
the attested environment. It must not attest an arbitrary digest supplied by a
requesting client.

The launch provider returns a fixed-size configfs `outblob` with zero-filled
transport bytes after Intel quote v4's declared signed-data boundary. The
collector removes only an all-zero suffix of at most 4 KiB before transmitting
evidence. Nonzero, oversized, malformed, and non-v4 suffixes remain untouched
and the production verifier rejects them. This keeps one canonical wire
representation without teaching the validator to ignore attacker-controlled
unsigned data.

The validator-side verifier is:

```python
from cathedral.verify import verify
attested = verify(evidence, nonce, policy)
```

Production invokes the fixed executable as
`cathedral-tdx-verifier /absolute/path/to/quote <expected-report-data-hex>`.
The parent computes the expected 64-byte nonce, hotkey, and channel-binding
value; the executable independently compares it to the signed quote body and
emits `report_data_match=true` only after an exact constant-time match. The
parent then compares the returned REPORTDATA a second time before admission.

Cathedral does not hand-roll Intel quote crypto. Set `CATHEDRAL_TDX_VERIFY_CMD`
to a DCAP verifier that validates the quote and prints JSON claims. The strict
contract is:

```json
{
  "report_data": "<hex or base64>",
  "measurement": "<MRTD or policy measurement>",
  "tcb_svn": "<32 lowercase hex characters>",
  "tcb_status": "UpToDate",
  "advisory_ids": [],
  "debug_enabled": false,
  "collateral_current": true,
  "stable_platform_id": "tdx-platform-sha256:<64 lowercase hex characters>",
  "platform_id": "tdx-platform-sha256:<same 64 lowercase hex characters>",
  "platform_identity_kind": "stable",
  "platform_identity_verified": true,
  "claims_bound_to_quote": true,
  "tdx_pck_cert_id": "tdx-pck-cert-sha256:<64 lowercase hex characters>",
  "tdx_attestation_key_id": "tdx-ak-sha256:<64 lowercase hex characters>",
  "intel_verified": true,
  "report_data_match": true
}
```

In strict mode Cathedral enforces:

- `REPORTDATA == report_data_v2(nonce, hotkey, channel_binding)` in production
- `measurement in policy.allowed_measurements`
- a recognized, explicitly allowed DCAP TCB status
- an exact advisory allowlist; every non-`UpToDate` exception must name at
  least one advisory
- `Revoked` is never configurable as an allowed state
- debug is disabled and collateral is current
- the status and package-stable identity claims are bound to the same verified
  quote evaluation
- the stable identity is canonical and differs from the rotating PCK and
  attestation-key audit fingerprints

Raw `tee_tcb_svn` remains in the audit verdict but is not numerically ordered
for strict admission. Unknown future status strings and absent, malformed, or
contradictory typed claims fail closed.

## Production channel binding

Production endpoints use HTTPS. The evidence request is credential-free and
names the TLS SPKI digest observed by the validator. The worker accepts that
request only when the digest equals its configured in-guest key, then binds it
into the fresh quote. After quote verification, the validator reopens the TLS
connection, checks the same SPKI before writing any request bytes, and only then
sends work and its bearer credential.

Configure the loopback worker behind the in-guest TLS endpoint with the public
digest (the digest is not a secret):

```bash
cathedral worker serve \
  --hotkey "$MINER_HOTKEY" \
  --channel-binding-type tls_spki_sha256 \
  --channel-binding-digest "$TLS_SPKI_SHA256"
```

The TLS private key must terminate inside the measured environment. A public
certificate by itself does not prove confidential execution. Plain HTTP is
limited to the explicit development loopback flag and cannot satisfy the
production channel claim.

## Customer CPU job routing

The first rentable CPU workload is bounded, satisfiable CNF-SAT. Submit it to
the exact ledger database consumed by `runtime run-epoch`:

```bash
cathedral work submit \
  --ledger-db /var/lib/cathedral/runtime.sqlite \
  --customer-id public-account-123 \
  --idempotency-key customer-request-123 \
  --n-vars 3 \
  --clauses '[[1,-2,3],[-1,2]]' \
  --seed 7

cathedral work status \
  --ledger-db /var/lib/cathedral/runtime.sqlite

cathedral work status \
  --ledger-db /var/lib/cathedral/runtime.sqlite \
  --job-id job-<32-lowercase-hex-characters>
```

The CPU runtime prefers queued customer work and uses canonical audit work only
when the durable queue is empty. Claim and challenge issuance share one SQLite
transaction. Completion and result persistence share another. A worker,
epoch, challenge, attempt, and opaque lease token must all match; expired or
aborted work cannot commit late. Transport failures, invalid certificates, and
negative results receive a bounded retry with a new challenge; no worker can
terminally fail a customer job before the ledger's attempt cap.

The runtime negotiates customer-SAT support over the authenticated, attested
worker channel before claiming. A default-off or mixed-fleet worker receives
canonical audit work and consumes no customer attempt. Customer-selected clause
count never controls emissions: every verified customer job receives the same
20 validator-derived work units as canonical audit work.

Customer SAT is disabled on workers by default. Enable it only on a bearer-
authenticated, channel-bound production worker:

```bash
cathedral worker serve \
  --hotkey "$MINER_HOTKEY" \
  --channel-binding-type tls_spki_sha256 \
  --channel-binding-digest "$TLS_SPKI_SHA256" \
  --allow-customer-sat
```

Noncanonical customer solves run in a separate killed-on-timeout process. On
Linux that child also has CPU, address-space, file-size, and descriptor limits.
Payload, response, variable, clause, and literal counts are bounded before
durable admission and again at both network ends.

The launch verifier accepts only satisfiable results carrying a complete
assignment witness, which it checks in linear time. An UNSAT claim is rejected
without re-solving attacker-controlled input on the validator. Proof-carrying
UNSAT jobs remain disabled until the result format and verifier support a
bounded, machine-checkable proof.

Durable admission is transactionally capped at 1,024 active jobs globally and
64 per public customer identifier, with a 256 MiB ledger payload/result budget.
Idempotency keys are scoped to the customer identifier. Operators can reclaim
terminal history after their audit/retention window; active jobs are never
pruned:

```bash
cathedral work prune \
  --ledger-db /var/lib/cathedral/runtime.sqlite \
  --resolved-before 2026-06-01T00:00:00Z \
  --limit 1000 \
  --confirm
```

Pruning frees SQLite pages for reuse. Run a separately scheduled `VACUUM` only
during an operator-approved maintenance window if the filesystem itself must
shrink.

This is a verified SAT rental path, not yet a general shell, VM, container, or
arbitrary-code rental API. The signed immutable workload format and bounded
external provider-adapter contract now exist, but general CPU rental still
requires the real CVM host agent, attestation-bound customer access, teardown,
billing, and external rental-lifecycle integration to pass live acceptance.

A development-only compatibility or strict policy file can look like:

```json
{
  "allowed_measurements": ["tdx-measurement-sha256:<approved digest>"],
  "tdx_strict": true,
  "tdx_allowed_tcb_statuses": ["UpToDate"],
  "tdx_allowed_advisories": []
}
```

Add a non-current status and its advisory only as a narrow, reviewed exception.
For example, allowing `SWHardeningNeeded` does not admit an unlisted advisory.
`Revoked` and unknown statuses cannot be configured.

Production never accepts this unsigned file path. Production admission and
probing require a current Ed25519-signed policy registry, an independently
configured SHA-256 digest of its trusted-key file, a rollback-resistant state
database, and either an exact release/digest
checkpoint or a positive minimum release. The selected `cpu_tdx` profile is
converted to strict policy; compatibility mode cannot start a production
runtime.

Use the adapter in `scripts/tdx_verify_json.py` with an `attestor-verify`
DCAP binary during development:

```bash
export CATHEDRAL_TDX_ATTESTOR_VERIFY_BIN=/tmp/attestor-verify
export CATHEDRAL_TDX_VERIFY_CMD='python scripts/tdx_verify_json.py'
```

The Python adapter is development-only. For production, build one static
x86-64 Linux verifier that implements the stdin-free quote-path plus expected-
REPORTDATA/JSON interface and performs both Intel-chain and Cathedral claim
extraction. Install it under a root-owned non-writable path:

```bash
export CATHEDRAL_TDX_VERIFY_CMD=/opt/cathedral/bin/cathedral-tdx-verifier
export CATHEDRAL_TDX_VERIFY_ARTIFACTS='["/opt/cathedral/bin/cathedral-tdx-verifier"]'

export CATHEDRAL_TDX_VERIFY_DIGEST="$(
  python scripts/tdx_verifier_digest.py \
    --command "$CATHEDRAL_TDX_VERIFY_CMD" \
    --artifact /opt/cathedral/bin/cathedral-tdx-verifier \
  | python -c 'import json,sys; print(json.load(sys.stdin)["digest"])'
)"
```

Digest generation deliberately fails for scripts, interpreters, dynamically
linked executables, malformed ELF files, or unsafe path permissions. Recompute
and review the digest for every verifier upgrade.

The repository now includes the production verifier source under
`cmd/cathedral-tdx-verifier`. It pins the reviewed `go-tdx-guest` revision,
accepts only quote v4 for the launch measurement contract, and fails closed
unless all of the following hold:

- the quote signature and Intel PCK chain verify to the embedded Intel root
- current Intel PCS TDX/QE collateral verifies and is unexpired
- PCK and Intel root revocation lists verify and the chain is not revoked
- the TDX platform, TDX module, and QE status all resolve to `UpToDate` and
  carry no advisory IDs
- quote shape and bounds are valid, debug is disabled, and migration is disabled
- collateral fetches use bounded HTTPS requests to the two required Intel hosts

The TDX TCB Info and TDX QE Identity requests force Intel's `update=standard`
channel, Intel's default production posture. The `early` channel applies TCB
recovery requirements before cloud fleets can deploy the matching microcode and
would reject every currently available host; `standard` gives fleets Intel's
documented deployment window while still failing platforms that miss it.
The channel is normalized on every request so callers cannot select a different
one. Version-pinned `tcbEvaluationDataNumber` requests are rejected, including
after redirects.
Redirects may use only an allowlisted Intel host, must preserve the collateral
endpoint and all resource-selecting query values, and have the `standard`/no-
version-pin rules reapplied before the redirected request is sent.
[Intel PCS API documentation](https://api.portal.trustedservices.intel.com/content/documentation.html)

The binary extracts PPID only from the verified PCK certificate. [Intel's PCK
profile](https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.4.pdf)
defines PPID as a processor-package or platform-instance identifier that does
not depend on TCB. Cathedral domain-separates and hashes its canonical
lowercase form before emitting `stable_platform_id`; raw PPID is never written
to JSON or logs. The rotating PCK certificate and attestation key remain
separate audit fingerprints and are never used as the stable anti-Sybil
identity.

Build and test the static Linux x86-64 artifact:

```bash
cd cmd/cathedral-tdx-verifier
export GOTOOLCHAIN=go1.25.12
test "$(go env GOVERSION)" = go1.25.12
go mod verify
go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -buildvcs=false -ldflags='-s -w' \
  -o cathedral-tdx-verifier .
file cathedral-tdx-verifier
readelf -l cathedral-tdx-verifier
```

The module, documented build, and CI require exactly Go 1.25.12 so a verifier
cannot be released from an older standard library with known reachable TLS,
X.509, or HTTP advisories. CI uses `GOTOOLCHAIN=local`, checks the exact compiler
version, and fails if the artifact contains either an ELF interpreter or
dynamic segment. `go mod verify` also rejects changed module-cache contents
before tests or release builds run.
Quote v5 remains rejected until Cathedral versions its measurement contract to
include the additional v5 identity fields.

The development adapter fails closed unless `attestor-verify` returns both
`intel_verified=true` and `report_data_match=true`. It parses the debug bit,
measurement, raw SVN, PCK fingerprint, and attestation-key fingerprint from the
same verified quote bytes. If the external verifier also returns a bounded
package-stable identity with `platform_identity_verified=true` and
`claims_bound_to_quote=true`, the adapter domain-separates and hashes that value
before emitting it; raw platform identifiers are never printed.

Compatibility mode exists only for controlled migration. It preserves the
legacy scalar-TCB and certificate-specific identity behavior and marks every
successful verdict with `policy_mode="compatibility"`; the verifier also emits
a warning. Strict verdicts carry `policy_mode="strict"`. Production receipts
must retain this mode so downstream auditors can distinguish the two. Do not
describe compatibility-mode evidence as package-stable or current under the
strict TDX policy. Compatibility mode also rejects empty, control-containing,
or excessively long identity strings; this fail-closed input bound is stricter
than the original launch adapter.

## Hardware Test

Run quote collection + verification on the TDX CVM with the verifier adapter:

```bash
sudo env \
  PYTHONPATH="$PWD" \
  CATHEDRAL_RUN_TDX_HW=1 \
  CATHEDRAL_TDX_VERIFY_CMD='python scripts/tdx_verify_json.py' \
  CATHEDRAL_TDX_ATTESTOR_VERIFY_BIN=/tmp/attestor-verify \
  CATHEDRAL_TDX_ALLOWED_MEASUREMENT='<tdx-measurement-sha256:...>' \
  python -m pytest tests/test_attest_tdx_hw.py -q
```

Run the full launch lane path on the TDX CVM:

```bash
sudo env \
  PYTHONPATH="$PWD" \
  CATHEDRAL_RUN_TDX_HW=1 \
  CATHEDRAL_TDX_VERIFY_CMD='python scripts/tdx_verify_json.py' \
  CATHEDRAL_TDX_ATTESTOR_VERIFY_BIN=/tmp/attestor-verify \
  CATHEDRAL_TDX_ALLOWED_MEASUREMENT='<tdx-measurement-sha256:...>' \
  python -m pytest tests/test_tdx_sat_e2e_hw.py -q
```

The compatibility test above uses one in-process miner and predates the full
production topology. The final CPU acceptance canary requires two different
disposable TDX platforms: one dedicated canary and one enrolled worker. Each
must expose a public-IP HTTPS endpoint whose private key terminates inside its
guest and whose SPKI digest is configured on the loopback worker. After those
endpoints are ready, run the production parent path from a separate Linux
validator host:

```bash
sudo env \
  CATHEDRAL_TDX_VERIFY_CMD=/opt/cathedral/bin/cathedral-tdx-verifier \
  CATHEDRAL_TDX_VERIFY_ARTIFACTS='["/opt/cathedral/bin/cathedral-tdx-verifier"]' \
  CATHEDRAL_TDX_VERIFY_DIGEST='sha256:<reviewed execution-contract digest>' \
  CATHEDRAL_CANARY_BEARER_TOKEN='<ephemeral canary token>' \
  CATHEDRAL_WORKER_BEARER_TOKEN='<ephemeral worker token>' \
  python scripts/tdx_cpu_launch_canary.py \
    --canary-hotkey cathedral-cpu-canary \
    --canary-endpoint https://<canary-public-ip>:8443 \
    --canary-certificate canary-cert.pem \
    --worker-hotkey cathedral-cpu-worker \
    --worker-endpoint https://<worker-public-ip>:8443 \
    --worker-certificate worker-cert.pem \
    --measurement tdx-measurement-sha256:<approved digest> \
    --source-epoch 1 \
    --score-network finney \
    --score-netuid 39 \
    --evidence-dir /var/tmp/cathedral-cpu-launch-evidence
```

The runner creates fresh ephemeral Ed25519 policy and receipt keys, pins the
trusted-key digest, advances a durable policy high-water mark, submits one
bounded noncanonical customer SAT job, verifies two fresh TDX quotes and their
live TLS keys, freezes the epoch, reopens the SQLite ledger, and verifies the
exact stored receipt offline. The frozen report binds its intended network and
subnet UID, and the publisher refuses to sign or send it when that audience
does not exactly match its independent configuration. Each certificate argument must contain exactly
one certificate. The runner gives each endpoint a separate trust context and
requires the live peer SPKI to equal that endpoint's designated certificate
SPKI; a different leaf signed by the supplied certificate is rejected. It
retains only the public registry, trusted public key, receipt, epoch report,
and result summary. Private signing keys and bearer credentials are not
retained. Copy those public evidence files off the validator before deleting
every disposable VM, disk, certificate private key, and temporary firewall
rule. This script is an isolated acceptance canary, not a service deployment
or a substitute for normal key management.

Compatibility-only defaults:

```bash
export CATHEDRAL_TDX_MIN_TCB=0
export CATHEDRAL_TDX_TSM_REPORT_ROOT=/sys/kernel/config/tsm/report
```

### Audience-binding upgrade preflight

Before deploying the audience-enforcing publisher, stop new epoch starts and
inspect `runtime status`. A completed report produced by an older build may not
contain `network` and `netuid`. Its frozen bytes must never be rewritten, and
the new publisher intentionally refuses to sign or send it.

Deploy only when there is no blocking completed epoch or the frozen report
already carries the exact configured audience. If a legacy unbound report is
still blocking the ledger, record the decision and abandon it explicitly:

```bash
python -m cathedral.cli runtime abandon-complete \
  --ledger-db <ledger.sqlite> \
  --epoch-id <legacy-epoch-id> \
  --reason 'pre-audience report cannot be safely published'
```

Abandonment is audited, one-way, and nonpayable. After it succeeds, start a new
epoch with explicit `--score-network` and `--score-netuid`; do not attempt to
migrate the old report by editing its stored JSON or digest.

Run the negative control on a plain Linux CPU host. This should fail before
quote collection because the host does not expose the TDX configfs-tsm report
root:

```bash
CATHEDRAL_RUN_TDX_NEGATIVE=1 \
python -m pytest tests/test_attest_tdx_negative.py -q
```

## Dedicated Compute Stream Launch Gate

After the hardware gates, test the compute publisher and the thin validator
together. Production chain submission is live on mainnet SN39; testnet SN292
remains the non-paying dry-run integration lane. The gate below is written
against the production metagraph and applies identically to SN292 except that
testnet chain submission stays disabled.
Launch acceptance requires all of the following:

1. A real TDX miner enrolls with its registered hotkey and passes fresh-nonce,
   measurement, TCB, and platform policy.
2. Cathedral dispatches useful work plus an unpredictable audit task,
   independently verifies both, and derives all credit itself.
3. The publisher freezes and signs a complete epoch stream. Missing, failed,
   stale, and revoked miners are present with explicit zero scores.
4. Every signed hotkey maps to exactly one current metagraph UID. Missing and
   duplicate mappings fail closed before submission.
5. The thin validator consumes the compute vector as its sole score input,
   conserves it through Bittensor u16 quantization, and submits it on chain.
6. A subsequent zero report removes the miner's prior weight, and all
   validators consuming the same signed epoch submit the same mapped vector.

`scripts/cross_repo_launch_verify.py` still encodes the retired mixed-vector
contract and is not launch evidence for this mechanism. Production acceptance
uses the sole-input `confidential_primary_v1` policy merged in
`cathedralai/cathedral` PR #378 plus the monitored SN39 chain submission.

## Definition Of Done

- Hardware-free suite stays green.
- Production runtime and prober reject unsigned policy, compatibility policy,
  an unpinned verifier, changed artifact bytes, unsafe path ownership, and
  verifier descendants that outlive their parent.
- Strict policy rejects every missing or malformed typed claim and every
  unapproved status/advisory combination.
- Repeated quotes across PCK rotation retain one package-stable identity while
  preserving the rotating PCK and attestation-key fingerprints for audit.
- `tests/test_attest_tdx_hw.py` passes on the live TDX CVM.
- `tests/test_tdx_sat_e2e_hw.py` passes on the live TDX CVM.
- `tests/test_attest_tdx_negative.py` fails closed on a non-TDX CPU host.
- A validator epoch can admit a real TDX-attested miner and still produce
  conserved weights.
- The publisher signs a complete Cathedral compute stream and the existing
  validator consumes it as its sole score input.
- Two validators map the same signed stream identically, including zero
  revocation after a miner disappears or fails work.
- SNP remains a second CPU platform port, not a launch blocker.

Compatibility-mode live evidence recorded July 8, 2026:

- Hardware-free local suite passed; hardware-gated cases were skipped in that
  environment.
- Live TDX CVM with the `attestor-verify` adapter:
  parsed `tdx-measurement-sha256:24da9c7003a1199293951b8e9acbf5ae0bf94b209b6958c1c3651892df5e02ce`,
  `tdx-pck-cert-sha256:cac3ee7282e1c79c9d3bcfcad2125dce41d7ef773cf61655693b51e968baa5a2`,
  and `tee_tcb_svn=0d010800000000000000000000000000`;
  both the TDX quote round trip and SAT lane end-to-end hardware tests passed.
- Live verifier smoke returned an 8000-byte quote with
  `intel_verified=true`, `report_data_match=true`, 64-byte `report_data`, and
  four Intel collateral URLs.
- Non-TDX field negative control on a disposable non-TDX Linux host:
  `/sys/module/tdx_guest`, `/dev/tdx_guest`, and
  `/sys/kernel/config/tsm/report` were absent;
  the enabled non-TDX negative-control test module passed.

This historical run predates the strict typed-claim contract. It remains valid
evidence for quote collection, signature verification, nonce binding, and the
SAT lane, but it is not evidence that strict platform-identity or TCB-status
policy passed. A fresh strict-mode canary is required before making that claim.

Strict static-verifier canary recorded July 18, 2026:

- The exact static Linux artifact with SHA-256
  `3f0baff0e6186dfb1c83de1a680a920ef16a4e07dab1a59ce501c5b394f4abdc`
  verified a fresh quote v4 and exact independently generated 64-byte
  REPORTDATA value.
- Configfs returned an 8,000-byte `outblob`: 4,935 canonical quote bytes plus
  3,065 zero transport bytes. Bounded collector canonicalization removed only
  that zero suffix before verification.
- The platform, TDX module, and quoting enclave all resolved to `UpToDate`
  with no advisories; collateral was current, debug was disabled, the stable
  platform identity was quote-bound, and the measurement was
  `tdx-measurement-sha256:8db0293f338f288e5c7ce8f984b88b10feb09d9ba3878acc7d5654dee210f7ee`.
- Another host pool correctly failed closed as `OutOfDate` and was not
  admitted. Placement must therefore route work only after strict per-host
  admission rather than assuming a whole provider region is current.
- The labelled disposable 4-vCPU canary VM and its boot disk were deleted
  immediately after the test. Only ephemeral quote collection was performed
  on the protected publisher, and its temporary files were removed afterward;
  no protected publisher configuration, service, or lifecycle state was
  changed, restarted, or stopped.

This proved the strict static quote-verification gate on real hardware. At that
stage, the signed-registry parent path, durable receipt, and full routed SAT
lane still remained separate acceptance evidence.

Full production CPU-path canary recorded July 18, 2026:

- A separate Linux validator admitted two different public-IP HTTPS TDX
  endpoints: one dedicated canary and one enrolled CPU worker. Both endpoints
  terminated their distinct TLS private keys inside their guests and bound the
  live TLS SPKI into fresh report-data-v2 quotes.
- Both stable platform identities were distinct. Both Intel platform/module/QE
  evaluations were `UpToDate` with no advisories, current collateral, and debug
  disabled. Their exact approved measurements were
  `tdx-measurement-sha256:46f864c1197eab17cbeceab124268b6e871fd68660c5199c3e049e6a09ba98d7`
  and
  `tdx-measurement-sha256:49bf7370c6953f057111015c83819332aaa8ce58bc4dbc57607d6633e1efa793`.
- The parent consumed a fresh Ed25519-signed registry, pinned the independent
  trusted-key digest, and advanced its durable release high-water mark before
  admission. The exact static verifier artifact remained
  `3f0baff0e6186dfb1c83de1a680a920ef16a4e07dab1a59ce501c5b394f4abdc`.
- One bounded customer SAT job routed only to the capability-negotiated worker,
  succeeded in one attempt, persisted its normalized result atomically, and
  produced a complete epoch with worker score `1.0`.
- The reopened ledger returned exact receipt
  `receipt-sha256:6cb79422c68762369a914539bbcabd1c621887156874fa845b52f51337d3d7f3`.
  Its byte digest was
  `sha256:1f29521aacb5d74ed1ba655ff50925fcb15947aa8515a2b1add0d47e5996f9ed`;
  independent offline verification against the retained public registry and
  trusted key passed.
- The run exposed and fixed one cross-contract bug before acceptance: strict
  TDX's exact 128-bit SVN had been copied into a legacy SQLite-bounded scalar
  receipt field. Strict mode now retains the exact SVN string and records the
  unused scalar as `0`, consistent with the existing rule that raw TDX SVN is
  never numerically ordered.
- Post-run independent review found that the acceptance runner treated the two
  supplied certificates as shared trust anchors. Before merge, the runner was
  hardened to a separate trust context and exact SPKI pin for each endpoint;
  regression coverage rejects a different valid leaf signed by a supplied CA.
  The retained live evidence proves quote binding to the observed TLS keys; the
  exact per-endpoint pin is code-and-test evidence until the next live canary.
- A host from a different pool failed strict Intel verification and was never
  admitted. It was deleted before replacement. Four labelled disposable VMs
  were used in total (three concurrently at most); every VM, boot disk, TLS
  private key, bearer credential, and temporary firewall rule was confirmed
  removed after the public evidence bundle was copied off the validator. The
  final billed amount was not yet available when this record was written.

This proves the signed-registry parent verdict, strict dual-host admission,
live TLS channel binding, customer CPU routing, atomic durable result, complete
epoch, signed receipt, offline receipt verification, and teardown. It does not
by itself prove the downstream subnet publisher or on-chain weight submission.
