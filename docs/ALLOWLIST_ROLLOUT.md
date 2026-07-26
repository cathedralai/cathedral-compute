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
| Steps | 1 to 6 | 1 to 8 |
| New attack surface | none | a public write endpoint |
| Note | manual `RegistryStore.enroll` bypasses the gate entirely, so the allowlist is only as good as the discipline of running step 6 | the gate is authoritative from the first start |

Path A is the smaller move. Path B is a launch decision, not an ops change:
it publishes a write endpoint and changes what MINING.md promises miners.

Under Path B the whole request path must hold from the first start, not
eventually. Steps 7 and 8 exist because it does not: the deployed venv has no
`substrateinterface`, so the enrollment signature verifier was silently
absent and every request would have returned 403; and the registry database
is shared with the epoch loop in rollback-journal mode, so enrollment writes
would have collided with it. Both are fixed before the listener opens.

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
attestation on the next epoch. Back up the database first:

```bash
sudo "$VENV/bin/cathedral" enroll backup \
  --registry-db /var/lib/cathedral-confidential-sn39/registry.sqlite \
  --out /var/backups/cathedral/registry.pre-reconcile-$(date -u +%Y%m%dT%H%M%SZ).sqlite
```

Never `cp` this file. The epoch loop writes it every five minutes, so a plain
copy can capture pages from a transaction that was still open, with the
rollback journal left behind at the source. The result is a file that looks
like a backup and is unrecoverable exactly when it is needed. `enroll backup`
uses SQLite's online backup API, which holds a read lock and copies only
committed pages, then runs an integrity check on the copy and refuses to
overwrite an existing destination.

## Step 7 (Path B only): settle the SQLite concurrency posture

The enrollment service and the epoch loop write the same `registry.sqlite`.
In the default rollback-journal mode those two writers serialize on a single
file lock, so an enrollment POST landing inside an epoch write window waits
and then fails. WAL lets a reader and a writer overlap, which turns most of
those collisions into nothing at all. Do this before the service exists, not
after miners are pointing at it.

The migration takes a brief exclusive lock, so stop the epoch loop for it.
Nothing else is touched: the validator, the scorer, and the canaries keep
running.

```bash
sudo systemctl stop cathedral-confidential-epoch-sn39.service

sudo install -d -m 0700 -o root -g root /var/backups/cathedral
sudo "$VENV/bin/cathedral" enroll journal-mode \
  --registry-db /var/lib/cathedral-confidential-sn39/registry.sqlite \
  --mode wal \
  --backup-to /var/backups/cathedral/registry.pre-wal-$(date -u +%Y%m%dT%H%M%SZ).sqlite

sudo systemctl start cathedral-confidential-epoch-sn39.service
```

`journal-mode` refuses to run without `--backup-to` and takes the online
backup before it touches anything. It prints `journal_mode_before` and
`journal_mode_after`; both must appear and `after` must be `wal`.

Then wait for one epoch (the interval is 300 seconds) and confirm the loop is
writing again and still producing attested evidence before going further.

```bash
sudo systemctl status cathedral-confidential-epoch-sn39.service --no-pager
sudo journalctl -u cathedral-confidential-epoch-sn39.service --since '-10min' --no-pager | tail -20
```

**Rollback:** stop the epoch loop, run the same command with `--mode delete`,
start the loop. If the database itself is in doubt, stop the loop and restore
the backup file over `registry.sqlite`.

The service additionally sets an explicit `busy_timeout` of 4000 ms
(`--sqlite-busy-timeout-ms`), comfortably under the proxy's 10 s
`proxy_read_timeout`. A request that cannot get the lock inside it returns
`503` with `Retry-After`, which is a bounded, honest answer; it never hangs
and never leaves a partial write.

This bound is passed on the enrollment service's command line and nowhere
else, on purpose. `RegistryStore` is shared with the epoch/evidence path
(`cathedral/runtime.py`, `prober.py`, `key_release.py`), and its default lock
wait stays at the 5000 ms those callers have always had. Only the process
that sits behind a reverse proxy needs a shorter one.

## Step 8 (Path B only): create the confined service

There is no existing invocation to amend. Enabling the gate means creating the
service, with every flag present from its first start.

### Choosing the confinement shape

SQLite must create `-wal` and `-shm` siblings next to the database, so any
identity that writes `registry.sqlite` also needs to create files in
`/var/lib/cathedral-confidential-sn39`. That directory is `0700 root:root` and
holds the ledger, the retained evidence, and the policy history.

A dedicated `cathedral-enroll` user would therefore need either an ACL on that
directory (this host has no `setfacl`, and `acl` is not installed) or group
permissions on the directory itself, which would newly expose `ledger.sqlite`
and the rest of the directory to that group. Re-permissioning a live database
the epoch loop writes every five minutes, to narrow access to one file, is a
worse trade than it looks.

So the confinement is done in systemd instead. The service runs as root but
with **an empty capability bounding set**, which means it loses
`CAP_DAC_OVERRIDE` and gets no privileged file access at all; it reaches
`registry.sqlite` only because root owns it. Everything else in the directory
is explicitly withdrawn: the ledger and policy state are read-only, and the
evidence, snapshot, and policy-history subtrees plus the allowlist signing
seed are made invisible. The result is narrower than the group approach and
changes nothing on disk.

`/etc/systemd/system/cathedral-enroll-sn39.service`

```ini
[Unit]
Description=Cathedral SN39 miner enrollment registry (approved-coldkey gated)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/cathedral-sn39/venvs/enroll-path-b/bin/python \
  -m cathedral.enroll \
  --db /var/lib/cathedral-confidential-sn39/registry.sqlite \
  --host 127.0.0.1 --port 8090 \
  --trusted-proxy \
  --production-mode \
  --network finney --netuid 39 \
  --registered-hotkeys-file /var/lib/cathedral-confidential-sn39/registered-hotkeys.json \
  --registration-max-age-seconds 3600 \
  --enroll-allowlist /etc/cathedral/enroll-allowlist-sn39.r1.json \
  --enroll-allowlist-keys /etc/cathedral/enroll-allowlist-keys-sn39.json \
  --enroll-allowlist-keys-digest sha256:<KEYS_DIGEST> \
  --enroll-allowlist-digest sha256:<ARTIFACT_DIGEST> \
  --enroll-allowlist-max-age-seconds 2592000 \
  --sqlite-busy-timeout-ms 4000
Restart=on-failure
RestartSec=5
UMask=0077

# Confinement. The service needs one database, three read-only artifacts, and
# one loopback socket. Nothing else, and no outbound network at all.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
LockPersonality=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
RemoveIPC=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/var/lib/cathedral-confidential-sn39
ReadOnlyPaths=/etc/cathedral /opt/cathedral-sn39 \
  /var/lib/cathedral-confidential-sn39/ledger.sqlite \
  /var/lib/cathedral-confidential-sn39/policy-state.sqlite
InaccessiblePaths=/etc/cathedral/enroll-allowlist-signing-sn39.key \
  /var/lib/cathedral-confidential-sn39/retained-evidence \
  /var/lib/cathedral-confidential-sn39/candidate-snapshots \
  /var/lib/cathedral-confidential-sn39/policy-history
IPAddressDeny=any
IPAddressAllow=localhost
MemoryMax=256M
TasksMax=32
LimitNOFILE=256

[Install]
WantedBy=multi-user.target
```

`CapabilityBoundingSet=` is empty on purpose: it is what makes "runs as root"
mean "owns these files" rather than "can open anything".

`IPAddressDeny=any` with `IPAddressAllow=localhost` is the other one that
matters: the enrollment service never needs to reach anything, so even full
compromise of the process cannot originate a connection off the host.

`InaccessiblePaths=` includes the allowlist signing seed. The service verifies
signatures; it never makes them, so it must not be able to read the key that
does.

The `ExecStart` interpreter is a **separate venv**
(`/opt/cathedral-sn39/venvs/enroll-path-b`). The commit-pinned venv the epoch
loop runs from is not modified: a new service must not change the code an
already-attesting production loop imports.

`--production-mode` refuses to start without `--registered-hotkeys-file`,
`--enroll-allowlist`, `--enroll-allowlist-keys-digest`, and
`--enroll-allowlist-digest`, so a half-configured gate cannot come up. The
process also refuses to start if no sr25519 verifier is importable: without
that preflight the deployed venv, which has `bittensor_wallet` but no
`substrateinterface`, would have answered every single enrollment with a 403
whose message reads like the miner's mistake.

`--host 127.0.0.1` is enforced: the process refuses a non-loopback bind unless
explicitly overridden, so exposure is always the proxy's decision.
`--trusted-proxy` is correct only because nginx overwrites `X-Forwarded-For`
with the peer address below. Without the flag every request would appear to
come from 127.0.0.1 and the per-IP limit would collapse to one bucket; with
it, but without the overwrite, any caller could pick their own bucket. The
service additionally discards any forwarded value that is not exactly one IP
literal.

Expose it on the existing `api.cathedral.computer` server block
(`/etc/nginx/sites-available/cathedral-validator-canonical`), which already
uses exact-match locations. Add the two zones at http scope first
(`/etc/nginx/conf.d/cathedral-enroll-limits.conf`):

```nginx
limit_req_zone $binary_remote_addr zone=cathedral_enroll_req:10m rate=6r/m;
limit_conn_zone $binary_remote_addr zone=cathedral_enroll_conn:10m;
```

Then the route itself:

```nginx
location = /v1/enroll {
    limit_except POST { deny all; }
    limit_req zone=cathedral_enroll_req burst=3 nodelay;
    limit_conn cathedral_enroll_conn 4;
    limit_req_status 429;
    limit_conn_status 429;

    client_max_body_size 16k;
    client_body_timeout 5s;
    client_body_buffer_size 16k;

    proxy_pass http://127.0.0.1:8090/v1/enroll;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header Host $host;
    proxy_connect_timeout 2s;
    proxy_send_timeout 5s;
    proxy_read_timeout 10s;
    proxy_request_buffering on;

    add_header Cache-Control "no-store" always;
    add_header X-Content-Type-Options "nosniff" always;
}
```

`proxy_set_header X-Forwarded-For $remote_addr` *overwrites*; it does not
append. A client that sends its own `X-Forwarded-For` never has it forwarded.
`proxy_request_buffering on` with a 16k body cap means a slow or oversized
body is absorbed and rejected by nginx, never by the single-process registry.
The body cap matches the registry's own `MAX_BODY`.

### The CDN in front of the origin

`api.cathedral.computer` resolves to Cloudflare, not to the origin. Two
consequences, both of which must be handled or the exposure hardening above is
partly decorative:

**`$remote_addr` is a CDN egress address, not the miner.** Without correction,
the nginx rate-limit key and the `X-Forwarded-For` handed to the registry both
identify Cloudflare. Install `/etc/nginx/conf.d/cathedral-realip.conf`:

```nginx
set_real_ip_from 173.245.48.0/20;   # every range from
set_real_ip_from 103.21.244.0/22;   # https://www.cloudflare.com/ips-v4
# ... and https://www.cloudflare.com/ips-v6
real_ip_header CF-Connecting-IP;
real_ip_recursive off;
```

`set_real_ip_from` is restricted to Cloudflare's published ranges, so a client
that reaches the origin address directly cannot spoof `CF-Connecting-IP`.
Re-fetch the ranges when Cloudflare publishes new ones; a missing range only
costs accuracy in the rate-limit key, never correctness of a gate.

Verify it by sending a request with a bogus `X-Forwarded-For` and confirming
the access log shows the real client address and never the claimed one:

```bash
sudo grep -c '10.9.9.9' /var/log/nginx/cathedral-validator-canonical.access.log   # must be 0
```

**The CDN rejects `Python-urllib/*` outright with its own 403.** That is why
`cathedral enroll submit` sends an explicit `User-Agent`. A miner writing
their own client with bare `urllib` will get an opaque CDN 403 that has
nothing to do with their enrollment; tell them to set a User-Agent.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cathedral-enroll-sn39.service
sudo systemctl status cathedral-enroll-sn39.service --no-pager
sudo nginx -t && sudo systemctl reload nginx
curl -sS -o /dev/null -w '%{http_code}\n' -X POST https://api.cathedral.computer/v1/enroll -d '{}'
```

A malformed body must come back 400, never 200 and never a 5xx. Confirm the
verifier line is in the journal before trusting the service at all:

```bash
sudo journalctl -u cathedral-enroll-sn39.service --no-pager | grep 'sr25519 verifier ready'
```

**Rollback:**

```bash
sudo systemctl disable --now cathedral-enroll-sn39.service
# and remove the nginx location and the conf.d zones, then
sudo nginx -t && sudo systemctl reload nginx
```

Stopping the service returns the subnet to today's posture (private channel
only) and touches no enrollment row. Never "roll back" by dropping
`--production-mode` or the allowlist flags: that also drops the registration
gate, the strict snapshot verification, and the IP-literal endpoint check,
which is a larger regression than the one being undone.

Nothing on disk was re-permissioned, so there is nothing else to undo. To
remove the service entirely:

```bash
sudo rm /etc/systemd/system/cathedral-enroll-sn39.service
sudo systemctl daemon-reload
sudo rm -r /opt/cathedral-sn39/venvs/enroll-path-b
```

## Rotation and revocation

The registry re-reads and re-verifies the artifact on every request, but the
pinned artifact digest means any new release needs a restart. That restart is
the intended cost of a revocation.

**Each release gets its own versioned path.** The unit names
`enroll-allowlist-sn39.r1.json`, the next release is written to
`enroll-allowlist-sn39.r2.json`, and the unit is edited to point at the new
path and the new digest in the same change as the restart. Never overwrite the
artifact the running process is pinned to: the process is pinned to the old
digest, so from the instant the file changes until the restart lands, every
enrollment fails closed with `allowlist_unavailable`, including the operator's
own miner. With a versioned path there is no such window, because the old file
is still there and still matches its pin right up to the restart.

```bash
# 1. sign the next release to its own versioned path, listing every coldkey
#    that stays approved. The tool refuses to overwrite, so a path collision
#    fails loudly instead of replacing a live artifact.
sudo "$VENV/bin/python" /usr/local/sbin/cathedral-enroll-allowlist sign \
  --signing-key-file /etc/cathedral/enroll-allowlist-signing-sn39.key \
  --signing-key-id cathedral-enroll-allowlist-1 \
  --release 2 \
  --coldkey 5FEMxbMJTwhj1FVJN8ULjdZRXnVTw5WDK8VLRs39k7if9K1S \
  --valid-days 30 --max-age-seconds 2592000 \
  --out /etc/cathedral/enroll-allowlist-sn39.r2.json

# 2. verify the new file where it will live, and take its digest. The running
#    service is still serving from r1 and is completely unaffected.
sudo sha256sum /etc/cathedral/enroll-allowlist-sn39.r2.json
sudo "$VENV/bin/python" /usr/local/sbin/cathedral-enroll-allowlist verify \
  --allowlist /etc/cathedral/enroll-allowlist-sn39.r2.json \
  --allowlist-keys /etc/cathedral/enroll-allowlist-keys-sn39.json \
  --allowlist-keys-digest sha256:<KEYS_DIGEST> \
  --expect-digest sha256:<R2_DIGEST> \
  --expect-coldkey 5FEMxbMJTwhj1FVJN8ULjdZRXnVTw5WDK8VLRs39k7if9K1S \
  --max-age-seconds 2592000

# 3. grant the service read access to the new file
sudo setfacl -m u:cathedral-enroll:r-- /etc/cathedral/enroll-allowlist-sn39.r2.json

# 4. edit BOTH --enroll-allowlist and --enroll-allowlist-digest in the unit,
#    in one edit, then reload and restart. This is the only moment the
#    approved set changes.
sudo systemctl daemon-reload && sudo systemctl restart cathedral-enroll-sn39.service
sudo journalctl -u cathedral-enroll-sn39.service --since '-1min' --no-pager | tail

# 5. retire any enrollment the new release no longer approves
sudo "$VENV/bin/cathedral" enroll reconcile ... --remove
```

Release numbers must never decrease. A revoked coldkey stays revoked only
while the pin points at the newer release, which is why step 4 is not
optional under Path B.

**Rollback:** point the unit's `--enroll-allowlist` and
`--enroll-allowlist-digest` back at `enroll-allowlist-sn39.r1.json` and its
digest, then `daemon-reload` and restart. The r1 file was never touched, so
there is nothing to restore. Note the running process keeps the highest
release it has accepted, so an in-process downgrade fails closed until that
restart; the restart is what clears it.

Keep the superseded artifact on disk until the next rotation. It is the
rollback.

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
5. **Approve the nginx exposure and rate-limit posture (step 8, Path B),**
   including `--trusted-proxy` and whether `POST /v1/enroll` belongs on the
   same hostname as the validator read API.
6. **Diarize the 30-day rotation.** When the artifact goes stale every
   enrollment fails closed, including the operator's own miner after an IP
   rotation. Re-sign around day 21.
7. **Approve the brief epoch-loop stop in step 7.** The WAL migration takes an
   exclusive lock, so the loop is stopped for it. One epoch may be skipped.
   Nothing else stops, no scoring changes, and the loop must be confirmed
   producing a fresh attested epoch before step 8 proceeds.

## Verification of this runbook

`tests/test_enroll_allowlist_script.py` proves the tool's artifacts round-trip
through the same verifier the registry uses, that the pinned digest rejects a
resigned release, and that the snapshot is the format from which the gate
resolves coldkeys. `tests/test_enroll_allowlist.py` covers the gate itself.
`tests/test_enroll_public_endpoint.py` covers the Path B request path: the
verifier fallback and the refuse-to-start preflight, endpoint validation,
signed domain separation, the online backup and WAL migration, a real
two-process lock-contention test that proves the bounded 503, strict snapshot
verification, the bounded limiter and unspoofable forwarded address, the
`enrolled_pending_secret` response, and the wallet-local submit CLI. It also
asserts the two P2 fixes in this document: that no step copies a live SQLite
file, and that rotation never replaces the pinned artifact in place.

The step 6 sequence was rehearsed off-host against a registry holding exactly
the production enrollment: the correct release 1 yields `"flagged": []`, a
release without the operator coldkey flags that miner `not_allowlisted`, and a
hotkeys-only snapshot aborts without changing anything.
