# Privileged path trust

A root process that sources an environment file, imports an interpreter, or
runs a script from a directory an unprivileged user can write is not running
the operator's code. It is running whatever that user last put there, as
root, at the next timer firing.

## The finding this exists for

A root epoch wrapper sourced `/home/polaris/cathedral/.env.sh`, a file owned
by and writable by the unprivileged `polaris` user at mode 0600.

**Mode 0600 is not a mitigation.** It denies group and other; it grants the
owner. When the owner is the untrusted party, 0600 is exactly as dangerous as
0666 and considerably more reassuring to read.

The same shape shipped in this repository:
`examples/systemd/cathedral-sn39-policy-republisher.service` ran `User=root`
with `ExecStart=/home/polaris/cathedral-sn39/.venv/bin/python`. `ProtectHome=`
`read-only` does not help — it stops the *service* writing `/home`, not the
owner of `/home` writing it first.

## The rule

The unit of trust is the whole chain, not the file:

- the target **and every ancestor directory up to `/`** must be owned by a
  trusted uid;
- no component may be writable by group or other;
- no component may be a symlink.

Ancestors matter because a root-owned file inside a user-writable directory
can be replaced wholesale by renaming it. Checking only the leaf answers the
wrong question.

Symlinks are refused rather than followed, because a symlink is one more
thing whose meaning can change between the check and the use.

## Checking

```bash
python3 -m cathedral.privileged_paths /etc/cathedral/epoch.env.sh || exit 1
set -a; . /etc/cathedral/epoch.env.sh; set +a
```

Exit status 0 means every component passed. Any failure prints each reason
and exits 1. Defaults trust root alone; a service that legitimately runs
under a dedicated system account passes that uid explicitly:

```bash
python3 -m cathedral.privileged_paths --trusted-uid 0 --trusted-uid 991 /etc/cathedral/epoch.env.sh
```

From Python:

```python
from cathedral.privileged_paths import require_trusted_path

require_trusted_path("/etc/cathedral/epoch.env.sh")  # raises UntrustedPath
```

`inspect_path` returns every violation instead of raising, so one run tells an
operator everything to fix rather than one thing at a time.

## What it does not do

**It only walks the target and its ancestors.** A sibling directory that the
same process will later read is not covered. The important case is a
virtualenv: `.venv/lib/python3.x/site-packages` is not an ancestor of
`.venv/bin/python`, so checking the interpreter says nothing about the
packages it imports — and site-packages is both where every `cathedral.*`
module actually loads from and the directory `pip install` most often leaves
owned by the deploying user. Name it explicitly, as the example unit does.

**The check runs on the interpreter it is checking.** If the chain is already
loosened and exploited, the attacker's interpreter runs before the check can
refuse. The preflight catches loosening, not an exploit already in place; the
real mitigation is that the deployment root is root-owned in the first place.

It cannot close a time-of-check/time-of-use window that spans two processes:
a shell that checks a path and then sources it has a gap no external checker
can remove. What it is decisive about is the thing that actually matters
here: a path that is **structurally** writable by an unprivileged user is
refused every time, not only when someone happens to have modified it.

For a real TOCTOU-free read inside one process, use the existing
`_secure_read_bytes` helper in `scripts/cathedral_measurement_approval.py`,
which re-checks the descriptor after opening it.

## Fixing a host that already has this shape

1. Move the deployment root off `/home` to a root-owned path (`/opt/...`).
   Reinstall the virtualenv there rather than copying it, so no interpreter
   retains a home-directory `sys.prefix`.
2. Move the environment file to `/etc/cathedral/`, `chown root:root`,
   `chmod 0600`.
3. Add the preflight to the unit as `ExecStartPre`, not to a runbook. A check
   an operator has to remember to run is a check that is not run.
4. Re-run the preflight against every path the privileged unit touches,
   including the interpreter itself.

These are host operations. They are deliberately out of scope for the change
that introduced this document, which ships the checker, its tests, and the
corrected example unit only.
