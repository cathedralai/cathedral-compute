# Approved-Coldkey Allowlist Rollout (SN39 mainnet)

Operator runbook for turning on the enrollment coldkey gate described in
docs/ENROLLMENT_ALLOWLIST.md. Every command below is exact and ordered.
Each step states its rollback. Nothing here runs automatically.

Producer host, verified 2026-07-26:

```bash
gcloud compute ssh polaris-tdx-7e93d5de \
  --project polaris-tdx-attest --zone us-central1-b --tunnel-through-iap
```

Paths used throughout:

| Variable | Value |
|---|---|
| `VENV` | `/opt/cathedral-sn39/venvs/9540de4409bfda74dd9827cb7c969ad4e2243543` |
| `TOOL` | `/usr/local/sbin/cathedral-enroll-allowlist` |
| `SEED` | `/etc/cathedral/enroll-allowlist-signing-sn39.key` (mode 0600, root) |
| `KEYS` | `/etc/cathedral/enroll-allowlist-keys-sn39.json` (mode 0644, root) |
| `ART` | `/etc/cathedral/enroll-allowlist-sn39.json` (mode 0644, root) |
| `SNAP` | `/var/lib/cathedral-confidential-sn39/registered-hotkeys.json` |
| `DB` | `/var/lib/cathedral-confidential-sn39/registry.sqlite` |

The coldkey that must be in release 1 is
`5FEMxbMJTwhj1FVJN8ULjdZRXnVTw5WDK8VLRs39k7if9K1S`, owner of hotkey
`5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK` (SN39 uid 163, confirmed
against the live metagraph). Leaving it out locks the operator's own miner out
of re-enrollment and makes `enroll reconcile --remove` retire it.

## What is deployed today

Read-only survey of the producer host, 2026-07-26:

- **No enrollment registry service runs anywhere.** No systemd unit references
  `enroll`, no process runs `cathedral.enroll`, nothing listens on an
  enrollment port, and no nginx location proxies `/v1/enroll`. Listeners are
  nginx (80, 443, 8011), the canary workers (8081, 8444), sshd, and a
  loopback postgres.
- **The one enrollment row was written by hand.** `enrollments` holds exactly
  `5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK` at
  `https://34.61.154.15:8443`, inserted through `RegistryStore.enroll` as root
  on 2026-07-26T02:10:25Z. `hotkey_enroll_attempts` is empty, consistent with
  a row that never came through the HTTP endpoint. This matches MINING.md
  (private enrollment channel) and the README row "Self-service miner
  enrollment: Not deployed".
- **No registration snapshot exists.** There is no
  `registered-hotkeys.json` on the box. The only snapshot-shaped artifact is
  the per-block candidate snapshot the epoch loop writes to
  `/var/lib/cathedral-confidential-sn39/candidate-snapshots/`, which is
  hotkeys-only by design and lives under a per-block filename. It cannot
  serve as `--registered-hotkeys-file` and cannot resolve coldkeys.
- The producer venv already carries the gate: `cathedral/coldkey_allowlist.py`
  is installed, `python -m cathedral.enroll --help` lists every
  `--enroll-allowlist*` flag, and `cathedral enroll reconcile` exists.

Consequence: **there is no running service to add flags to.** Enrollment today
is closed by absence, not by policy. Pick a path before starting.

| | Path A: keep the private channel | Path B: self-service enrollment goes live |
|---|---|---|
| What the allowlist does | Governance record plus the drift check that `enroll reconcile` runs against the hand-maintained registry | The enforcing gate on every `POST /v1/enroll` |
| Steps | 1 to 6 | 1 to 7 |
| New attack surface | none | a public write endpoint |
| Note | manual `RegistryStore.enroll` bypasses the gate entirely, so the allowlist is only as good as the discipline of running step 6 | the gate is authoritative from the first start |

Path A is the smaller move and is consistent with what MINING.md promises
miners today. Path B is a launch decision, not an ops change.

## Parameter choices

Sign with a 30-day window and run the registry with a matching staleness
ceiling:

- `--valid-days 30` on the artifact.
- `--enroll-allowlist-max-age-seconds 2592000` (30 days) on the registry, not
  the 86400 default.

Why not the default: with the artifact digest pinned (mandatory in production
mode), every re-sign changes the digest and therefore requires a restart. A
24-hour staleness ceiling would force a re-sign plus restart every single day,
and one missed day fails every enrollment closed. Thirty days makes the
validity window and the staleness ceiling expire together, so there is exactly
one rotation event to diarize.

## Step 1: install the operator tool

```bash
gcloud compute scp scripts/cathedral_enroll_allowlist.py \
  polaris-tdx-7e93d5de:/tmp/cathedral-enroll-allowlist \
  --project polaris-tdx-attest --zone us-central1-b --tunnel-through-iap

sudo install -m 0700 -o root -g root \
  /tmp/cathedral-enroll-allowlist /usr/local/sbin/cathedral-enroll-allowlist
rm -f /tmp/cathedral-enroll-allowlist
```

Run it with the pinned producer interpreter so it imports the same
`cathedral` package the registry runs:

```bash
VENV=/opt/cathedral-sn39/venvs/9540de4409bfda74dd9827cb7c969ad4e2243543
sudo "$VENV/bin/python" /usr/local/sbin/cathedral-enroll-allowlist --help
```

**Rollback:** `sudo rm /usr/local/sbin/cathedral-enroll-allowlist`. Nothing
depends on it until step 2.

## Step 2: mint the trusted key pair

```bash
sudo "$VENV/bin/python" /usr/local/sbin/cathedral-enroll-allowlist keygen \
  --signing-key-id cathedral-enroll-allowlist-1 \
  --signing-key-out /etc/cathedral/enroll-allowlist-signing-sn39.key \
  --keys-out /etc/cathedral/enroll-allowlist-keys-sn39.json
```

Prints `signing_key_id`, `public_key_base64`, and `allowlist_keys_digest`.
Record the digest; it is the first of the two mandatory pins. The private seed
is written mode 0600 root-owned and is never printed. It must never enter the
repo, a ticket, a chat, or an agent transcript.

The tool refuses to overwrite either file, so a second run fails loudly rather
than silently rotating the root of trust.

**Rollback:** `sudo rm /etc/cathedral/enroll-allowlist-signing-sn39.key
/etc/cathedral/enroll-allowlist-keys-sn39.json`, then redo step 2. Safe only
before the key digest is pinned into a running service; after that, replacing
the key file is a root-of-trust rotation and needs a restart with the new
digest.

## Step 3: sign release 1

```bash
sudo "$VENV/bin/python" /usr/local/sbin/cathedral-enroll-allowlist sign \
  --signing-key-file /etc/cathedral/enroll-allowlist-signing-sn39.key \
  --signing-key-id cathedral-enroll-allowlist-1 \
  --release 1 \
  --coldkey 5FEMxbMJTwhj1FVJN8ULjdZRXnVTw5WDK8VLRs39k7if9K1S \
  --valid-days 30 \
  --max-age-seconds 2592000 \
  --out /etc/cathedral/enroll-allowlist-sn39.json
```

Prints `allowlist_release`, `allowlist_digest`, `coldkeys`, `valid_from`,
`valid_until`. The tool verifies the artifact through
`cathedral.coldkey_allowlist.verify_allowlist` before writing it, so a file
that exists is a file the registry will accept.

`--coldkey` is repeatable and the list is absolute: every approved coldkey
must appear in every release, not just the newly added one.

**Rollback:** `sudo rm /etc/cathedral/enroll-allowlist-sn39.json` and re-run.
Nothing reads the artifact until step 6.

## Step 4: record both pins

```bash
sudo sha256sum /etc/cathedral/enroll-allowlist-keys-sn39.json \
               /etc/cathedral/enroll-allowlist-sn39.json
```

Prefix each hex digest with `sha256:`. The key digest pins the root of trust;
the artifact digest is what makes revocation durable, because release
monotonicity alone lives in process memory and resets on restart.

Confirm the pair verifies together, and that the operator coldkey survived:

```bash
sudo "$VENV/bin/python" /usr/local/sbin/cathedral-enroll-allowlist verify \
  --allowlist /etc/cathedral/enroll-allowlist-sn39.json \
  --allowlist-keys /etc/cathedral/enroll-allowlist-keys-sn39.json \
  --allowlist-keys-digest sha256:<KEYS_DIGEST> \
  --expect-digest sha256:<ARTIFACT_DIGEST> \
  --expect-coldkey 5FEMxbMJTwhj1FVJN8ULjdZRXnVTw5WDK8VLRs39k7if9K1S \
  --max-age-seconds 2592000
```

A non-zero exit here means the pins or the coldkey list are wrong. Fix before
going further. Re-verify after any file copy: the digest covers exact bytes,
so reformatting the JSON invalidates the pin.

**Rollback:** none needed, this step is read-only.

## Step 5: build the extended registration snapshot

The gate resolves ownership only from the extended
`{"hotkeys": {hotkey: coldkey}}` format. Hotkeys-only snapshots fail closed
with `coldkey_unresolvable`, which rejects every enrollment including the
operator's own.

```bash
sudo "$VENV/bin/python" /usr/local/sbin/cathedral-enroll-allowlist snapshot \
  --network finney --netuid 39 \
  --output /var/lib/cathedral-confidential-sn39/registered-hotkeys.json \
  --require-hotkey 5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK
```

Prints block, hotkey count, and distinct coldkey count (256 and 199 at block
8708117). `--require-hotkey` aborts before replacing the file if the live
miner is missing from the metagraph, so a bad capture cannot deregister it.
The write is atomic, so a reader never sees a partial document.

The snapshot is bounded by its own mtime. `--registration-max-age-seconds`
defaults to 3600, so under Path B it must be rotated more often than hourly or
enrollment fails closed. Install a timer:

`/etc/systemd/system/cathedral-sn39-registration-snapshot.service`

```ini
[Unit]
Description=Cathedral SN39 extended registration snapshot (hotkey to coldkey)

[Service]
Type=oneshot
ExecStart=/opt/cathedral-sn39/venvs/9540de4409bfda74dd9827cb7c969ad4e2243543/bin/python \
  /usr/local/sbin/cathedral-enroll-allowlist snapshot \
  --network finney --netuid 39 \
  --output /var/lib/cathedral-confidential-sn39/registered-hotkeys.json
```

`/etc/systemd/system/cathedral-sn39-registration-snapshot.timer`

```ini
[Unit]
Description=Rotate the SN39 registration snapshot every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
AccuracySec=1min

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cathedral-sn39-registration-snapshot.timer
systemctl list-timers cathedral-sn39-registration-snapshot.timer
```

Do not add `--require-hotkey` to the timer unit: a permanently failing
rotation is worse than a snapshot that correctly reflects a deregistration.
Keep the check on the manual runs.

**Rollback:** `sudo systemctl disable --now
cathedral-sn39-registration-snapshot.timer` and
`sudo rm /var/lib/cathedral-confidential-sn39/registered-hotkeys.json`.
Under Path A the file is only read by step 6, so removing it is harmless.
Under Path B, removing it makes every enrollment fail closed.

## Step 6: reconcile the existing registry (read-only first)

The gate never touches existing rows. Reconcile is the only thing that does,
and it must run before the gate is enabled so that no row is left in a state
the gate would have refused.

```bash
sudo "$VENV/bin/cathedral" enroll reconcile \
  --registry-db /var/lib/cathedral-confidential-sn39/registry.sqlite \
  --allowlist /etc/cathedral/enroll-allowlist-sn39.json \
  --allowlist-keys /etc/cathedral/enroll-allowlist-keys-sn39.json \
  --allowlist-keys-digest sha256:<KEYS_DIGEST> \
  --allowlist-max-age-seconds 2592000 \
  --registered-hotkeys-file /var/lib/cathedral-confidential-sn39/registered-hotkeys.json
```

Expected today, with release 1 as specified above:

```json
{"allowlist_digest":"sha256:...","allowlist_release":1,"checked":1,"flagged":[],"removed":[]}
```

`"flagged": []` is the go signal. Anything else means release 1 or the
snapshot is wrong. Two failure shapes to recognize:

- a flagged entry with `"status": "not_allowlisted"` for
  `5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK` means the operator
  coldkey is missing from release 1. Go back to step 3.
- `{"error": "registration snapshot carries no coldkey mapping; ..."}` means
  the snapshot is a hotkeys-only file. Go back to step 5. The command aborts
  and changes nothing, by design: an unresolvable snapshot must never be read
  as "nobody is approved".

Only when the flagged list is exactly what should be retired, re-run with
`--remove`:

```bash
sudo "$VENV/bin/cathedral" enroll reconcile ... --remove
```

**Do not run `--remove` while the only flagged row is the operator's own
miner.** That row is currently `attested`/`VERIFIED`; retiring it clears the
attestation verdict, drops the worker from the refresh set, the epoch target
list, and the public verified count, which takes the lane to zero verified
workers.

**Rollback:** removal is terminal lifecycle retirement, not row deletion, and
the lifecycle ledger is append-only. Recovery is re-enrollment of the hotkey
(private channel today, `POST /v1/enroll` under Path B) followed by a fresh
attestation on the next epoch. Back up the DB first if in any doubt:
`sudo cp -a /var/lib/cathedral-confidential-sn39/registry.sqlite{,.pre-reconcile-$(date -u +%Y%m%dT%H%M%SZ).bak}`.

## Step 7 (Path B only): turn the gate on

There is no existing invocation to amend. Enabling the gate means creating the
service, with the flags present from its first start.

`/etc/systemd/system/cathedral-enroll-sn39.service`

```ini
[Unit]
Description=Cathedral SN39 miner enrollment registry (approved-coldkey gated)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/opt/cathedral-sn39/venvs/9540de4409bfda74dd9827cb7c969ad4e2243543/bin/python \
  -m cathedral.enroll \
  --db /var/lib/cathedral-confidential-sn39/registry.sqlite \
  --host 127.0.0.1 --port 8090 \
  --trusted-proxy \
  --production-mode \
  --registered-hotkeys-file /var/lib/cathedral-confidential-sn39/registered-hotkeys.json \
  --registration-max-age-seconds 3600 \
  --enroll-allowlist /etc/cathedral/enroll-allowlist-sn39.json \
  --enroll-allowlist-keys /etc/cathedral/enroll-allowlist-keys-sn39.json \
  --enroll-allowlist-keys-digest sha256:<KEYS_DIGEST> \
  --enroll-allowlist-digest sha256:<ARTIFACT_DIGEST> \
  --enroll-allowlist-max-age-seconds 2592000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`--production-mode` refuses to start without `--registered-hotkeys-file`,
`--enroll-allowlist`, `--enroll-allowlist-keys-digest`, and
`--enroll-allowlist-digest`, so a half-configured gate cannot come up.
`--trusted-proxy` is required only because nginx terminates TLS: without it
every request appears to come from 127.0.0.1 and the per-IP rate limit
collapses to a single bucket. It is correct only behind a proxy that
overwrites `X-Forwarded-For`.

Expose it on the existing `api.cathedral.computer` server block
(`/etc/nginx/sites-available/cathedral-validator-canonical`), which already
uses exact-match locations:

```nginx
location = /v1/enroll {
    proxy_pass http://127.0.0.1:8090/v1/enroll;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header Host $host;
}
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cathedral-enroll-sn39.service
sudo systemctl status cathedral-enroll-sn39.service --no-pager
sudo nginx -t && sudo systemctl reload nginx
curl -sS -o /dev/null -w '%{http_code}\n' -X POST https://api.cathedral.computer/v1/enroll -d '{}'
```

A malformed body must come back 400, never 200 and never a 5xx.

**Rollback:**

```bash
sudo systemctl disable --now cathedral-enroll-sn39.service
# and remove the nginx location, then
sudo nginx -t && sudo systemctl reload nginx
```

Stopping the service returns the subnet to today's posture (private channel
only) and touches no enrollment row. Never "roll back" by dropping
`--production-mode` or the allowlist flags: that also drops the registration
gate and the IP-literal endpoint check, which is a larger regression than the
one being undone.

## Rotation and revocation

The registry re-reads and re-verifies the artifact on every request, but the
pinned artifact digest means any new release needs a restart. That restart is
the intended cost of a revocation.

```bash
# 1. sign the next release to a staging path, listing every coldkey that stays
sudo "$VENV/bin/python" /usr/local/sbin/cathedral-enroll-allowlist sign \
  --signing-key-file /etc/cathedral/enroll-allowlist-signing-sn39.key \
  --signing-key-id cathedral-enroll-allowlist-1 \
  --release 2 \
  --coldkey 5FEMxbMJTwhj1FVJN8ULjdZRXnVTw5WDK8VLRs39k7if9K1S \
  --valid-days 30 --max-age-seconds 2592000 \
  --out /root/enroll-allowlist-sn39.release2.json

# 2. keep the current artifact, then install the new one
sudo cp -a /etc/cathedral/enroll-allowlist-sn39.json \
  /etc/cathedral/enroll-allowlist-sn39.json.release1.bak
sudo install -m 0644 -o root -g root \
  /root/enroll-allowlist-sn39.release2.json /etc/cathedral/enroll-allowlist-sn39.json

# 3. re-verify in place and take the new pin
sudo "$VENV/bin/python" /usr/local/sbin/cathedral-enroll-allowlist verify \
  --allowlist /etc/cathedral/enroll-allowlist-sn39.json \
  --allowlist-keys /etc/cathedral/enroll-allowlist-keys-sn39.json \
  --allowlist-keys-digest sha256:<KEYS_DIGEST> \
  --expect-coldkey 5FEMxbMJTwhj1FVJN8ULjdZRXnVTw5WDK8VLRs39k7if9K1S \
  --max-age-seconds 2592000

# 4. Path B only: update --enroll-allowlist-digest in the unit and restart
sudo systemctl daemon-reload && sudo systemctl restart cathedral-enroll-sn39.service

# 5. retire any enrollment the new release no longer approves
sudo "$VENV/bin/cathedral" enroll reconcile ... --remove
```

Release numbers must never decrease. A revoked coldkey stays revoked only
while the pin points at the newer release, which is why step 4 is not
optional under Path B.

**Rollback:** restore
`/etc/cathedral/enroll-allowlist-sn39.json.release1.bak` over the artifact and
restart with the old digest. Note the running process keeps the highest
release it has accepted, so an in-process downgrade fails closed until the
restart.

## Triage

Every rejection is logged by the registry with hotkey, resolved coldkey, and
reason. All are 403.

| Reason in the log | Cause | Fix |
|---|---|---|
| `allowlist_missing` | production mode with no `--enroll-allowlist` | add the flag; the parser blocks this at start |
| `allowlist_unavailable` | file missing, malformed, badly signed, stale, outside its window, release rollback, or digest mismatch | run the `verify` command from step 4; check `stale_at` |
| `coldkey_unresolvable` | snapshot is hotkeys-only, stale, or has no row for the hotkey | check the snapshot timer, re-run step 5 |
| `coldkey_not_allowlisted` | resolved coldkey is genuinely not approved | expected for a stranger; for a known miner, sign the next release |
| `not_registered` | hotkey absent from the snapshot | miner deregistered, or the snapshot is stale |

The snapshot is the component most likely to cause an outage: it has the
tightest freshness bound (one hour) and the most moving parts (chain access).

## What must be done by Fred personally

1. **Choose Path A or Path B.** Path B publishes a write endpoint and flips
   the README "Self-service miner enrollment: Not deployed" row and the
   MINING.md private-channel language. That is a launch decision.
2. **Own the signing seed (step 2).** Whoever holds it can mint an allowlist
   that admits or excludes any coldkey. Run `keygen` yourself in an
   interactive root shell. Do not let an unattended agent session hold it, do
   not copy it off the host, and never commit it. The alternative posture,
   generating it on a laptop and copying only the public key file up, is also
   fine and strictly safer; it just means every rotation needs the laptop.
3. **Approve the coldkey list for every release.** Which coldkeys are approved
   is a business decision that no tool should infer.
4. **Run `reconcile --remove` (step 6).** It is destructive lifecycle
   retirement of a currently attested miner. Read the read-only output first,
   take the DB backup, then run it by hand.
5. **Approve the nginx exposure and rate-limit posture (step 7, Path B),**
   including `--trusted-proxy` and whether `POST /v1/enroll` belongs on the
   same hostname as the validator read API.
6. **Diarize the 30-day rotation.** When the artifact goes stale every
   enrollment fails closed, including the operator's own miner after an IP
   rotation. Re-sign around day 21.
7. **Decide the SQLite concurrency posture before Path B.** The enrollment
   service and the epoch loop would write the same `registry.sqlite`, which is
   in rollback-journal mode (not WAL) with the default 5-second busy timeout.
   Enrollment POSTs landing inside an epoch write window can fail with
   "database is locked"; the miner retries, but this should be measured on a
   staging copy, and switching the DB to WAL is a deliberate change with a
   backup, not a side effect of this rollout.

## Verification of this runbook

`tests/test_enroll_allowlist_script.py` proves the tool's artifacts round-trip
through the same verifier the registry uses, that the pinned digest rejects a
resigned release, and that the snapshot is the format from which the gate
resolves coldkeys. `tests/test_enroll_allowlist.py` covers the gate itself.
The step 6 sequence was rehearsed off-host against a registry holding exactly
the production enrollment: the correct release 1 yields `"flagged": []`, a
release without the operator coldkey flags that miner `not_allowlisted`, and a
hotkeys-only snapshot aborts without changing anything.
