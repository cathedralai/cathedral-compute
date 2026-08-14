# What is actually running on polaris-tdx-7e93d5de

Written 2026-08-14 by reading the live machine, not from memory or docs. Every
claim here was checked with `systemctl`, `ss`, `journalctl`, or a direct query.

One GCP instance, `polaris-tdx-7e93d5de`, zone `us-central1-b`, project
`polaris-tdx-attest`. It runs the entire SN39 subnet. There is no second copy.

## Why it is hard to read

The machine grew by accretion. Eight services, **five separate Python
virtualenvs**, spread across `/opt` and three different home directories, none
of which declares what it is:

| Service runs from | Path |
|---|---|
| enrollment | `/opt/cathedral-sn39/venvs/enroll-path-b` |
| publisher, port 8080 app | `/home/polaris/cathedral/.venv` |
| canary worker | `/home/polaris/cathedral-cc/.venv` |
| canary worker (TLS) | `/home/polaris/cathedral-sn39/.venv` |
| scorers | `/home/polaris/cathedral-scorer/.venv` |

Five environments means five different versions of the code can be live at once,
and nothing tells you which is which. That is the root of the confusion, and it
is also why the stale-publisher problem in #102 went unnoticed for two weeks.

## The eight services

| Service | Port | What it does |
|---|---|---|
| `nginx` | 80, 443 | The public front door for `api.cathedral.computer` and `read.cathedral.computer`. Everything public goes through it. |
| `cathedral-enroll-sn39` | 8090, loopback only | Miners ask to join here. Reachable publicly only as `POST /v1/enroll` through nginx. |
| `cathedral-confidential-epoch-sn39` | none | The heart. Every 30 minutes it challenges each miner, checks their hardware attestation, gives them work, scores the result, and writes the epoch. |
| `cathedral-publisher` | 8000, loopback | Serves the signed evidence third parties verify. |
| `cathedral-scorer-sn39` | 8012, loopback, TLS | Turns epoch results into the score report. |
| `cathedral-scorer-canary` | 8010, loopback | Same, for the canary. |
| `cathedral-confidential-canary` | 8081 | A known-good fake miner used as a control. If it fails, the epoch is refused rather than published wrong. |
| `cathedral-confidential-canary-tls` | 8444 | The same control over TLS. |

Plus PostgreSQL on 5432 (loopback) and an app on 8080 reachable only from
Cloudflare.

## The databases

Three SQLite files under `/var/lib/cathedral-confidential-sn39/`:

- `registry.sqlite` — who is enrolled, their attestation state and lifecycle
- `ledger.sqlite` — every epoch, score, receipt and customer job (285 MB)
- `policy-state.sqlite` — anti-rollback state for the signed policy registry

Live counts as of writing: **2 workers** (1 attested, 1 pending), **0 customer
jobs** of any status.

## Who is allowed to mine, today

Enrollment is gated by a signed coldkey allowlist at
`/etc/cathedral/enroll-allowlist-sn39.r3.json`:

- release 3, issued 2026-08-09, valid until 2026-09-08
- **exactly three approved coldkeys**
- pinned by digest in the systemd unit, so editing the file without updating the
  unit stops the service rather than silently widening access

A miner whose coldkey is not one of those three is refused, no matter what else
is true about them.

Separately, `registered-hotkeys.json` holds the on-chain registration snapshot:
256 hotkeys with their coldkeys, refreshed 2026-08-14 20:07 UTC. A miner must
appear there *and* have an approved coldkey.

### The open-mode option does not exist on this machine

`docs/ADMISSION_POLICY.md` describes a newer signed artifact with an
`all_registered` mode that lets any registered SN39 hotkey ask to be tested with
no per-coldkey approval. The deployed enrollment build does not have it:
`--admission-policy` is not among its options. It supports only the older
`--enroll-allowlist`. Open mode requires the redeploy tracked in #102.

## Adding a miner to the allowlist

You need their **coldkey**, not their hotkey.

1. Confirm their hotkey is in `registered-hotkeys.json` and maps to that coldkey.
   If it is not, they are not registered on SN39 and nothing else matters.
2. Add the coldkey to the `coldkeys` array, set `release` to 4, and refresh
   `generated_at` / `valid_from` / `valid_until`.
3. Re-sign with the ed25519 key at
   `/etc/cathedral/enroll-allowlist-signing-sn39.key`. The signature covers the
   canonical JSON of the document without the `signature` field.
4. Recompute the file's sha256 and update `--enroll-allowlist-digest` in
   `cathedral-enroll-sn39.service`.
5. `systemctl daemon-reload && systemctl restart cathedral-enroll-sn39`.
6. Verify: the service must come up, and a test enrollment must return 200.

Step 4 is the one that bites. The digest is pinned deliberately so that editing
the allowlist alone cannot widen access. Skip it and the service refuses to
start.

## What the logs say about miners trying to join

The enrollment endpoint works. A test POST on 2026-08-14 20:14 UTC reached the
service and was answered.

Between 2026-08-09 18:07 UTC and that test, the service received **no requests at
all**. Not a rejection, not an error, nothing.

The last real activity was one hotkey,
`5GKTAkJTEa7tGwmPSJQHF6njTV9dRcSTjB7cwYoruQKsPjc6`, which was rejected **237
times** with `signature_invalid` across four hours on 2026-08-09 before
succeeding at 18:07:40.

Two conclusions follow. Anyone who says they tried to enrol since 9 August did
not reach this endpoint. And for the one miner who did reach it, the wall was not
permission, it was producing a valid signature: 237 failures before one success
is a broken onboarding path, not a user error.

## Firewall

The instance is reachable on 443 only from Cloudflare ranges, on 8011 from one
fixed address, and on 8444/8443 from one fixed address. That part is tight.

The project also carries `chutes-k3s-internal`, `chutes-nodeports`
(`0.0.0.0/0` on `tcp:30000-32767`) and `default-allow-rdp` (`0.0.0.0/0` on
3389). These are project-wide rules left from other work. Whether they apply to
this instance depends on their target tags, which is worth checking, because a
world-open port range on the machine that runs the whole subnet is not something
to leave uncertain.

## The single point of failure

Everything above is one instance. The validator, the enrollment service, the
publisher, the scorers, the canary, and all three databases. If it is lost, the
subnet stops and the evidence chain stops with it.
