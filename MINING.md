# Provide Intel TDX compute to Cathedral

This guide is for operators who want an Intel TDX worker considered for
Cathedral SN39.

> **Current status: operator-assisted live testing.**
>
> Mainnet SN39 has historical chain-acceptance evidence, but onboarding is not
> self-service and positive weight is not guaranteed. Testnet SN292 is
> non-paying. Apply before registering or provisioning a new paid machine so a
> maintainer can confirm current capacity and the supported release.

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
# Mainnet live testing — only after explicit acceptance.
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
sudo --preserve-env=CATHEDRAL_WORKER_BEARER_TOKEN \
  "$PWD/.venv/bin/cathedral" worker serve \
  --hotkey "$HOTKEY_ADDRESS" \
  --host 127.0.0.1 \
  --port 8081
```

In a second shell:

```bash
export HOTKEY_ADDRESS='<ss58-hotkey-address>'
NONCE="$(openssl rand -hex 32)"

curl -fsS http://127.0.0.1:8081/v1/evidence \
  -H 'Content-Type: application/json' \
  --data "{\"nonce_hex\":\"$NONCE\",\"assigned_hotkey\":\"$HOTKEY_ADDRESS\"}" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin); print("kind:", r["kind"]); print("quote bytes:", len(bytes.fromhex(r["quote_hex"]))); print("hotkey:", r["assigned_hotkey"])'
```

Evidence collection is credential-free and bounded. Work endpoints are
authenticated only after the channel has been verified. A nonempty local quote
proves collection, not vendor verification, policy acceptance, or eligibility.

Stop the loopback process after the test.

## 6. Deploy the protected worker channel

The production boundary is documented in
[the Intel TDX launch path](docs/TDX_LAUNCH.md#production-channel-binding).
In summary:

- the worker remains on loopback;
- TLS terminates inside the measured VM;
- Cathedral pins the TLS SPKI digest;
- the fresh quote binds that digest with the challenge and public hotkey;
- the validator verifies the quote, reconnects, and rechecks the same SPKI
  before sending a bearer credential or work; and
- the firewall admits only the approved validator addresses.

The worker receives the public digest:

```bash
cathedral worker serve \
  --hotkey "$HOTKEY_ADDRESS" \
  --channel-binding-type tls_spki_sha256 \
  --channel-binding-digest "$TLS_SPKI_SHA256"
```

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

Rotate the token immediately if it appears in a screenshot, shared shell
history, public message, or unprotected log.

The validator operator then checks:

1. the hotkey maps exactly once on the selected subnet;
2. the endpoint and TLS identity match the accepted enrollment;
3. fresh TDX evidence verifies under current policy;
4. the physical platform is not simultaneously claimed by another hotkey;
5. bounded work completes and its witness verifies; and
6. the complete score report contains the correct explicit outcome.

Production enrollment is additionally gated by a signed allowlist of
approved coldkeys: the registry resolves your hotkey's owning coldkey and
rejects the enrollment unless that coldkey has been approved, failing closed
whenever the allowlist or the resolution is unavailable. See
`docs/ENROLLMENT_ALLOWLIST.md` for the artifact format and operator
workflow.

## 8. Know what success means

Every gate must be current:

| Gate | Required result |
|---|---|
| Registration | Public hotkey maps exactly once |
| Channel | HTTPS identity and quote binding match |
| Attestation | Fresh TDX evidence passes vendor and Cathedral policy |
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
| `401` on work | Worker and validator bearer credentials differ |
| `assigned_hotkey mismatch` | Worker was started with a different public address |
| `admit=N` | Quote crypto, TCB, measurement, binding, identity, or policy failed |
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
