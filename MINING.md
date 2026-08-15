# Provide Intel TDX compute to Cathedral

This guide is for operators who want an Intel TDX worker considered for
Cathedral SN39.

> **Current status: operator-assisted live testing.**
>
> Mainnet SN39 has historical chain-acceptance evidence, but onboarding is not
> self-service and positive weight is not guaranteed. Testnet SN292 is
> non-paying. Apply before registering or provisioning a new paid machine so a
> maintainer can confirm current capacity and the supported release.

## What a miner actually runs

Read this section for the shape of the thing. Do not register a hotkey or buy a
machine from it: the approval gate below decides whether any of it can earn, and
step 3 is the first point at which registering is the right move.

A compute miner earns on the TDX lane by doing attested confidential compute. It
runs a worker **inside an Intel TDX confidential VM**, serves a fresh attestation
quote bound to the validator's channel, and then does lane work. The validator
verifies the quote and only then sends work. No SSH, and no trust in the host.

This lane is hardware-gated. Production evidence must come from a real Intel TDX
confidential VM, and the worker's TLS key must terminate *inside* the measured
guest. A plain server cannot produce a valid channel claim.

```bash
git clone https://github.com/cathedralai/cathedral-compute.git
cd cathedral-compute
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

That installs the `cathedral` operator CLI. Inside the TDX VM, terminate TLS in
the measured guest and serve the worker bound to that channel:

```bash
export MINER_HOTKEY=<your-hotkey-ss58>
export TLS_SPKI_SHA256=<sha256 of your in-guest TLS SPKI>   # public, not a secret

cathedral worker serve \
  --hotkey "$MINER_HOTKEY" \
  --channel-binding-type tls_spki_sha256 \
  --channel-binding-digest "$TLS_SPKI_SHA256"
```

The validator requests attestation over TLS, verifies the quote binds your
channel, then sends work and its bearer credential. Credit is proportional to
verified work.

See [docs/TDX_LAUNCH.md](docs/TDX_LAUNCH.md) for the full verifier contract and
the five `CATHEDRAL_TDX_VERIFY_*` variables, and
[docs/GPU_ATTESTATION.md](docs/GPU_ATTESTATION.md) for the GPU-composite path.

### Develop without TDX hardware

The `MockMiner` in `cathedral/neuron/miner.py` serves mock evidence, meaning the
real REPORT_DATA binding and policy check without vendor crypto, and does real
SAT work. It exercises the serve, verify, and score path on any machine. It
cannot earn, because the validator runs the real vendor-crypto verifier in
production, but it is the way to build and test a worker locally.

Prerequisites: Python 3.11 or 3.12, and for production an Intel TDX confidential
VM plus an SN39 hotkey registered **after** acceptance.

## Your measurement must be approved first

This is the gate that stops most first attempts. Nothing else you do correctly
works around it.

Cathedral admits a worker only if its TDX measurement is already listed in the
signed policy registry. The verifier compares the measurement in your quote
against the active profile's approved list and rejects anything that is not on
it. A cryptographically valid TDX quote with an unknown measurement is still
rejected.

The active profile is `cpu-tdx-sn39-v2`. It requires TCB status `UpToDate` and
lists three approved measurements. Its window closes on 2026-10-22, after
which a rollover publishes a successor profile under a new id.

No reproducible image is published yet, so you cannot build a matching
measurement yourself. A VM that boots to any other measurement returns
`admit=N` every epoch, whatever else is configured correctly. Raise this in
your beta request. The operator reviews the measurement and, if it is
accepted, adds it in a signed policy release. Settle it before you pay for a
machine.

## What a provider contributes

A Cathedral provider runs a measured worker inside an Intel TDX confidential
VM. Cathedral:

1. derives a fresh challenge from finalized chain state;
2. requests vendor-backed TDX evidence bound to that challenge, the public
   hotkey, and the worker's protected channel;
3. verifies the quote, TCB, measurement, policy, and identity rules;
4. dispatches bounded audit or customer work;
5. verifies the returned witness and derives credit itself; and
6. publishes a signed complete score report, including zeros.

Attestation only makes a worker eligible for work. A worker earns nothing from
registration, availability, hardware ownership, a valid quote, or
self-reported volume alone.

## Current limits

- Intel TDX CPU is the only active provider hardware class.
- AMD SEV-SNP and NVIDIA confidential-GPU scoring are not enabled.
- Enrollment and secret exchange are operator-assisted.
- A supported mainnet worker must use the reviewed HTTPS and channel-binding
  design. The development plain-HTTP flag is not a production path.
- Cathedral may have no available beta slot or no positive work in an epoch.
- A past positive score does not guarantee future weight or emissions.

## 1. Request a beta slot

Open the public
[miner beta request](https://github.com/cathedralai/cathedral-compute/issues/new?template=miner-beta.yml).
You may apply before you have a machine. Include only:

- your public SS58 hotkey address;
- preferred network;
- current or intended Intel TDX hardware class;
- provider and broad region; and
- an optional public contact handle.

Never include a seed, private key, bearer token, TLS private key, cloud account
identifier, instance identifier, IP address, SSH credential, or cloud
credential in the issue.

A maintainer will privately confirm:

- whether a slot is available;
- whether to use SN39 or the non-paying SN292 integration lane;
- the supported release and expected digests;
- the validator source addresses and firewall rules;
- the HTTPS/channel-binding profile; and
- the private enrollment channel.

Do not buy a machine or pay a registration fee solely because this guide
exists.

## 2. Check the machine without exposing it

You need:

- an Intel TDX confidential VM with Linux `configfs-tsm`;
- a current Linux distribution and Python 3.11 or newer;
- a public Bittensor hotkey address you control;
- the ability to terminate TLS inside the measured VM; and
- a stable public endpoint that can be restricted to the approved validator.

Install the repository into an isolated environment:

```bash
git clone https://github.com/cathedralai/cathedral-compute.git
cd cathedral-compute

python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

For any mainnet deployment, replace the moving branch with the immutable tag
and digest supplied during acceptance.

Run the read-only capability probe:

```bash
sudo "$PWD/.venv/bin/cathedral" census
sudo test -d /sys/kernel/config/tsm/report && echo 'configfs-tsm: ready'
```

Required result:

```text
Intel TDX   : yes
=> CC-CAPABLE
configfs-tsm: ready
```

Do not continue if Intel TDX reports `no`. “Confidential VM” is not a
vendor-independent hardware type; a machine may use a different TEE that the
current subnet does not admit.

## 3. Register only after acceptance

Registration is a separate Bittensor transaction and may cost funds. Use the
same hotkey address that the accepted worker will serve.

```bash
# Mainnet live testing. Only after explicit acceptance.
btcli subnet register \
  --network finney \
  --netuid 39 \
  --wallet-name <wallet-name> \
  --hotkey <hotkey-name>

# Non-paying integration lane.
btcli subnet register \
  --network test \
  --netuid 292 \
  --wallet-name <wallet-name> \
  --hotkey <hotkey-name>
```

Check your installed `btcli` version and current command help before signing.
Record the public SS58 address:

```bash
export HOTKEY_ADDRESS='<ss58-hotkey-address>'
```

Registration does not prove reachability, admission, verified work, positive
weight, or earnings.

## 4. Where the worker credential comes from

**Enrollment mints it. You do not create one.** A successful `POST /v1/enroll`
returns `worker_token` in its response body, and the validator already holds
the same value, so nothing is exchanged out of band and no operator transcribes
a secret.

That changes the order of the remaining steps. Enrollment is step 7 and the
protected worker in step 6 refuses to start without the credential, so on a
minted deployment **do step 7 before step 6**. The steps below are numbered in
the order they were written, not the order you run them:

```
2 check the machine -> 3 register -> 5 prove evidence locally
  -> 7 enrol, save the returned worker_token -> 6 start the protected worker
```

Store what enrollment returned with mode `0600`:

```bash
install -d -m 700 "$HOME/.config/cathedral"
umask 077
# paste the worker_token value from the enrollment response
cat > "$HOME/.config/cathedral/worker-token"
chmod 600 "$HOME/.config/cathedral/worker-token"
export CATHEDRAL_WORKER_BEARER_TOKEN="$(tr -d '\n' < "$HOME/.config/cathedral/worker-token")"
```

The token is minted once and is preserved across re-enrollment, deliberately:
the validator is already holding it, and minting a new one on every endpoint
change would break a running worker that has not been reconfigured. If you lose
the value, enrol again at the same endpoint and the response returns the same
one.

**There is no self-service rotation.** If the token is exposed, you cannot
replace it by re-enrolling, because re-enrollment returns the same value. Ask
the operator: they can override or revoke a single worker through the
validator's own token file, which takes precedence over the minted value. A
signed rotation protocol is tracked separately.

### If your deployment predates minted tokens

Some deployments still expect the miner to generate the credential and send it
to the operator out of band. That path is self-contained, and the directory and
mode steps matter as much as the random value:

```bash
install -d -m 700 "$HOME/.config/cathedral"
umask 077
openssl rand -hex 32 > "$HOME/.config/cathedral/worker-token"
chmod 600 "$HOME/.config/cathedral/worker-token"
export CATHEDRAL_WORKER_BEARER_TOKEN="$(tr -d '\n' < "$HOME/.config/cathedral/worker-token")"
```

Either way, keep the value out of command arguments, shell history,
screenshots, public issues, and ordinary logs. A validator does not need any
wallet private key.

## 5. Prove local TDX evidence first

For a same-machine smoke test, bind only to loopback:

```bash
sudo "$PWD/.venv/bin/cathedral" worker serve \
  --hotkey "$HOTKEY_ADDRESS" \
  --host 127.0.0.1 \
  --port 8081 \
  --development-no-auth
```

`--development-no-auth` is required for this test. Without it the worker
refuses to start unless a channel binding is configured, and a plain loopback
smoke test has no TLS identity to bind to. Use the flag only here, never on a
worker anything else can reach.

In a second shell:

```bash
export HOTKEY_ADDRESS='<ss58-hotkey-address>'
NONCE="$(openssl rand -hex 32)"

curl -fsS http://127.0.0.1:8081/v1/evidence \
  -H 'Content-Type: application/json' \
  --data "{\"nonce_hex\":\"$NONCE\",\"assigned_hotkey\":\"$HOTKEY_ADDRESS\"}" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin); print("kind:", r["kind"]); print("quote bytes:", len(bytes.fromhex(r["quote_hex"]))); print("hotkey:", r["assigned_hotkey"])'
```

That request carries no credential because `/v1/evidence` never checks one.
This is deliberate: a validator holds no token for a worker it has not
attested yet. The token you created in step 4 gates the work endpoints only,
and the validator sends it after it has verified the attested channel.
Evidence collection is unauthenticated at every stage, including in
production.

The worker bounds that public path itself. Evidence requests draw on a
separate two-slot pool, so unauthenticated traffic cannot occupy the four
slots reserved for work. A full pool returns `503 busy` immediately instead of
queueing. Request bodies are capped at 64 KiB, and the request and its
response each get their own 10-second deadline, so a caller that stalls cannot
hold a slot. These bounds are fixed in the worker and are sized for the 4 vCPU
guest it ships in.

A nonempty local quote proves collection, not vendor verification, policy
acceptance, or eligibility.

Stop the loopback process after the test.

## 6. Deploy the protected worker channel

The production boundary is documented in
[the Intel TDX launch path](docs/TDX_LAUNCH.md#production-channel-binding).
In summary:

- the worker is reachable only behind TLS terminated inside the measured VM;
- Cathedral never sees a plaintext work request;
- Cathedral pins the TLS SPKI digest;
- the fresh quote binds that digest with the challenge and public hotkey;
- the validator verifies the quote, reconnects, and rechecks the same SPKI
  before sending a bearer credential or work; and
- the firewall admits only the approved validator addresses.

Two shapes are supported. Both keep the TLS private key inside the measured
VM.

Run the worker on loopback behind an in-guest HTTPS terminator and hand it the
terminator's public digest:

```bash
cathedral worker serve \
  --hotkey "$HOTKEY_ADDRESS" \
  --channel-binding-type tls_spki_sha256 \
  --channel-binding-digest "$TLS_SPKI_SHA256"
```

Or terminate TLS in the worker itself. It derives the same digest from the
certificate, so no separate binding flag is needed, and it may bind a public
address:

```bash
cathedral worker serve \
  --hotkey "$HOTKEY_ADDRESS" \
  --host 0.0.0.0 \
  --port 8443 \
  --tls-certificate /etc/cathedral/worker.crt \
  --tls-private-key /etc/cathedral/worker.key
```

The private key must be a regular owner-only file. The worker refuses to start
if it is a symlink or readable by group or other. Both commands read the
bearer token from `CATHEDRAL_WORKER_BEARER_TOKEN`.

The TLS private key must terminate inside the measured environment. A
certificate on an external load balancer does not establish this claim.

Do not use `--development-allow-non-loopback` for a mainnet worker. That flag
serves authenticated work over plain HTTP and cannot satisfy the production
channel claim.

Run the accepted command under a restricted supervisor such as systemd. Do not
leave a long-lived worker attached to an ordinary SSH session.

## 7. Complete private enrollment

Through the agreed private channel, provide only the accepted enrollment
fields:

```text
network:  mainnet SN39 or testnet SN292
hotkey:   <registered public SS58 address>
endpoint: https://<accepted worker endpoint>
token:    <unique worker bearer token>
```

If the token appears in a screenshot, shared shell history, public message or
unprotected log, tell the operator. On a minted deployment you cannot rotate it
yourself: re-enrolling returns the same value, and only the operator can
override or revoke it from the validator side. Treat that as an incident to
report, not a step you can perform.

The validator operator then checks:

1. the hotkey maps exactly once on the selected subnet;
2. the endpoint and TLS identity match the accepted enrollment;
3. fresh TDX evidence verifies under current policy;
4. the physical platform is not simultaneously claimed by another hotkey;
5. bounded work completes and its witness verifies; and
6. the complete score report contains the correct explicit outcome.

Production enrollment is additionally gated by one signed artifact that the
registry resolves your hotkey's owning coldkey against, failing closed
whenever the artifact or the resolution is unavailable. Two artifacts exist
and an operator runs exactly one of them:

- **Signed admission policy** (`docs/ADMISSION_POLICY.md`), the current
  design. It carries the mode (`selected`, approved coldkeys only, or
  `all_registered`, any registered SN39 hotkey), the network and netuid it
  speaks for, the profile ids you may request, and the enrollment caps.
- **Signed coldkey allowlist** (`docs/ENROLLMENT_ALLOWLIST.md`), the earlier
  form. Still supported and unchanged.

Which one is running changes what you send. Against an admission policy the
enrollment request is v2: it additionally carries your coldkey, the network
and netuid, the profile you are requesting, and an expiry, all inside the
signature, and it answers `{"status": "pending"}` rather than
`{"status": "enrolled"}` — because enrollment is permission to be tested,
not admission. A v1 request cannot enroll against a policy-gated registry.
Ask the operator which artifact is in force before building your client.

## 8. Know what success means

Every gate must be current:

| Gate | Required result |
|---|---|
| Registration | Public hotkey maps exactly once |
| Channel | HTTPS identity and quote binding match |
| Attestation | Fresh TDX evidence verifies and its measurement is on the approved list |
| Work | Validator-dispatched work completes and verifies |
| Report | Candidate appears in the complete signed report |
| Validator | Signature, freshness, policy, provenance, and UID mapping pass |
| Chain | An authorized mainnet validator actually includes the resulting weight |

Possible outcomes are:

- `PASS`: this epoch's required evidence and work passed;
- `FAIL`: a required check contradicted the claim; or
- `NOT_PROVEN`: required evidence was unavailable or incomplete.

Only a current positive SN39 weight can affect emissions. SN292 never pays.
Neither a provider nor Cathedral can promise a future token amount.

## Troubleshooting

| Symptom | Meaning and next check |
|---|---|
| `Intel TDX : no` | Wrong VM type, guest kernel, or `configfs-tsm` support |
| Report root missing | `/sys/kernel/config/tsm/report` is unavailable |
| Local evidence is empty | Check TDX availability and report-directory permission |
| Endpoint unreachable | Check in-guest TLS service and the approved firewall allowlist |
| Channel mismatch | TLS terminates in the wrong place or the SPKI digest changed |
| `401` on work | Worker and validator bearer credentials differ. Never applies to `/v1/evidence`, which is unauthenticated |
| `503 busy` | The two-slot evidence pool or the four-slot work pool is full. Requests are rejected, not queued |
| `assigned_hotkey mismatch` | Worker was started with a different public address |
| `admit=N` | Most often a measurement that is not on the approved list. Otherwise quote crypto, TCB status, binding, identity, or the policy window |
| `score=0` | No verified work, stale evidence, failed work, or explicit revocation |
| `NOT_PROVEN` | A required artifact or independent verification input is absent |

## What remains before self-service

- production HTTPS packaging that a third-party provider can install safely;
- signed self-service enrollment and policy discovery;
- an immutable supported validator/provider release with public pins;
- independent external reproduction; and
- continued positive-to-zero revocation testing on the final release.

The current evidence boundary is maintained in [BUILD_STATUS.md](BUILD_STATUS.md).
Historical results in that file do not override a newer live vector.
