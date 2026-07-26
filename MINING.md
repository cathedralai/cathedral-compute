# Provide Intel TDX compute to Cathedral

This guide is for operators who want an Intel TDX worker considered for
Cathedral SN39.

> **Current status: operator-assisted live testing.**
>
> Mainnet SN39 has historical chain-acceptance evidence, but onboarding is not
> self-service and positive weight is not guaranteed. Testnet SN292 is
> non-paying. Apply before registering or provisioning a new paid machine so a
> maintainer can confirm current capacity and the supported release.

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
- Enrollment is operator-assisted. A gated self-service endpoint exists but
  is not announced or open; contact the operator for a beta slot.
- A supported mainnet worker must use the reviewed HTTPS and channel-binding
  design. The development plain-HTTP flag is not a production path.
- Cathedral may have no available beta slot or no positive work in an epoch.
- A past positive score does not guarantee future weight or emissions.

## 1. Request a beta slot

Open the public
[miner beta request](https://github.com/cathedralai/cathedralconfidential/issues/new?template=miner-beta.yml).
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
git clone https://github.com/cathedralai/cathedralconfidential.git
cd cathedralconfidential

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

## 4. Create worker credentials

Use a unique random credential for each worker. Store it with mode `0600`:

```bash
install -d -m 700 "$HOME/.config/cathedral"
umask 077
openssl rand -hex 32 > "$HOME/.config/cathedral/worker-token"
export CATHEDRAL_WORKER_BEARER_TOKEN="$(tr -d '\n' < "$HOME/.config/cathedral/worker-token")"
```

Keep the value out of command arguments, shell history, screenshots, public
issues, and ordinary logs. A validator does not need any wallet private key.

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

## 7. Submit your enrollment

Enrollment is a signed request from your own machine. Your coldkey must
already be on the approved allowlist (`docs/ENROLLMENT_ALLOWLIST.md`); ask for
that in the beta request from step 1, before you get here.

Run the submit command on the host that holds your wallet:

```bash
cathedral enroll submit \
  --registry-url https://api.cathedral.computer \
  --endpoint-url "https://<public-ip>:8443" \
  --wallet-name <wallet-name> \
  --hotkey-name <hotkey-name> \
  --network finney \
  --netuid 39
```

The command reads your hotkey from the local wallet directory, signs the
enrollment, and posts it. Nothing secret leaves the machine and nothing
secret is accepted on the command line: there is no seed, mnemonic, or
private-key flag, so a seed cannot end up in `ps` output, your shell history,
or a log. What is sent is your public hotkey, the endpoint, a nonce, a
timestamp, and the signature.

`--endpoint-url` must be an HTTPS origin naming a public IP literal with an
explicit port, and nothing else: no hostname, no path, no query, no fragment.
Hostnames are rejected because the address could change between the moment you
enroll and the moment the validator connects.

### What you are signing

The signature covers this exact document, serialized as compact JSON with
sorted keys and no whitespace:

<!-- enroll-preimage-example -->
```json
{
  "domain": "cathedral-enroll-v1",
  "endpoint_url": "https://34.61.154.15:8443",
  "hotkey": "5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK",
  "netuid": 39,
  "network": "finney",
  "nonce": "9f2c41b8e7a05d3641f8b2ce90a7d5138c6e4b02af9317d5e64c8b0a72d1f3e6",
  "timestamp": "2026-07-26T21:00:00Z"
}
```

The `domain`, `network`, and `netuid` fields are inside the signature, not
just beside it. That is what stops a signature you produced for testnet SN292,
or for some other protocol, from being replayed as an SN39 enrollment. A test
in this repository rebuilds the document above from the registry's own code on
every run, so this example cannot drift from what the server verifies.

### Status contract

The endpoint answers with one of these. Nothing else is a valid outcome.

| HTTP | `status` or `error` | What it means | What to do |
|---|---|---|---|
| 200 | `enrolled_pending_secret` | The signature, registration, and coldkey approval all passed. Your endpoint is recorded. | Nothing yet. See below. |
| 400 | validation message | The request was malformed: bad field, bad endpoint shape, replayed nonce, expired timestamp, oversized body | Fix the named field and resubmit with a fresh nonce |
| 403 | `enrollment signature did not verify` | The signature does not match the document above | Check your wallet, network, and netuid, then resubmit |
| 403 | `enrollment is for a different network or netuid` | You submitted an SN292 or wrong-subnet enrollment | Resubmit with the right audience |
| 403 | `hotkey not registered on subnet` | Your hotkey is not in the current registration snapshot | Confirm your registration, then retry in a few minutes |
| 403 | `coldkey is not approved for enrollment` | Your owning coldkey is not on the allowlist | Ask in your beta request; this is an operator decision |
| 403 | `enrollment allowlist unavailable` / `hotkey coldkey could not be resolved` | An operator-side artifact is stale or unavailable. Never your fault | Retry later; report if it persists |
| 429 | rate limit exceeded | Too many attempts from your address or hotkey | Back off; the hotkey window is one hour |
| 503 | `registry busy, retry shortly` | The registry was mid write when your request landed | Retry after the `Retry-After` seconds |

**`enrolled_pending_secret` does not mean you are being scored.** It is
deliberately not called `enrolled`. Worker bearer-token provisioning is still
operator-assisted, and until the operator has provisioned yours, the validator
cannot dispatch work to you. The response says `"scored": false` for that
reason.

After a 200, provide the worker bearer token through the agreed private
channel:

```text
hotkey:   <registered public SS58 address>
token:    <unique worker bearer token>
```

Rotate the token immediately if it appears in a screenshot, shared shell
history, public message, or unprotected log. Never send a seed, a private key,
or a TLS private key through any channel.

Watch `GET /v1/attested` for your hotkey to appear with a verified status.
That, not the enrollment response, is the signal that attestation succeeded.

The validator operator then checks:

1. the hotkey maps exactly once on the selected subnet;
2. the endpoint and TLS identity match the accepted enrollment;
3. fresh TDX evidence verifies under current policy;
4. the physical platform is not simultaneously claimed by another hotkey;
5. bounded work completes and its witness verifies; and
6. the complete score report contains the correct explicit outcome.

Production enrollment is gated by a signed allowlist of approved coldkeys: the
registry resolves your hotkey's owning coldkey and rejects the enrollment
unless that coldkey has been approved, failing closed whenever the allowlist
or the resolution is unavailable. See `docs/ENROLLMENT_ALLOWLIST.md` for the
artifact format and operator workflow.

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
