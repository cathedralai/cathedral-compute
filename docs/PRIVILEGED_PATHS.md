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
- no component may have an extended ACL;
- regular-file and import-tree checks refuse symlinks;
- executable symlinks are accepted only through `--resolve-symlinks`, which
  checks every link object, every ancestor, and the eventual regular file.

Ancestors matter because a root-owned file inside a user-writable directory
can be replaced wholesale by renaming it. Checking only the leaf answers the
wrong question.

The tree check is bounded to 100,000 entries and 64 levels. It uses
descriptor-relative `stat`, never follows a descendant symlink, refuses
special files, and stops descending as soon as a directory fails. This checks
the imported package files themselves. Checking only a `site-packages`
directory misses an owner-writable `site-packages/cathedral/*.py` below it.
The tree check does not interpret `.pth` contents. Python site initialization
does, and a trusted `.pth` file can redirect imports or execute a line from an
unchecked, user-writable tree. The republisher therefore runs with `-S`; a
stdlib-only bootstrap adds the checked venv tree directly and loads Cathedral
by exact checked package path.

On Linux, access and default POSIX ACL xattrs are refused. On Darwin, native
ACL entries are refused. If ACL status cannot be inspected, the check fails
closed. The supported policy is deliberately simple: trusted ownership and
mode bits, with no extended ACL. `--allow-group-write` is an explicit escape
hatch only for a group whose every member is trusted.

## Install the checker trust anchor

A checker imported from the venv or source tree it is checking is not a
security boundary. A writable package could replace the checker before Python
imports it. Install this file once as a root-owned standalone program, then
run it with isolated OS Python and no site initialization:

```bash
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -o root -g root -m 0755 \
  cathedral/privileged_paths.py \
  /usr/local/libexec/cathedral-privileged-paths.py
```

`/usr/bin/python3`, its standard library, and the installed checker are the
bootstrap trust anchor. Their full ancestor chains must stay root-owned and
non-writable by group or other. The example unit audits their current paths,
but no program can establish its own integrity after an attacker has already
replaced the program that is running. OS package integrity and root-only
installation establish this first trust step.

## Checking

```bash
/usr/bin/python3 -I -S /usr/local/libexec/cathedral-privileged-paths.py \
  /etc/cathedral/epoch.env.sh || exit 1
set -a; . /etc/cathedral/epoch.env.sh; set +a
```

Exit status 0 means every component passed. Any failure prints each reason
and exits 1. Defaults trust root alone; a service that legitimately runs
under a dedicated system account passes that uid explicitly:

```bash
/usr/bin/python3 -I -S /usr/local/libexec/cathedral-privileged-paths.py \
  --trusted-uid 0 --trusted-uid 991 /etc/cathedral/epoch.env.sh
```

A standard POSIX venv creates interpreter symlinks. Verify the complete link
chain rather than rejecting the layout or following it blindly:

```bash
/usr/bin/python3 -I -S /usr/local/libexec/cathedral-privileged-paths.py \
  --resolve-symlinks /opt/cathedral-sn39/.venv/bin/python
```

Check every file below the two import roots used by the republisher:

```bash
/usr/bin/python3 -I -S /usr/local/libexec/cathedral-privileged-paths.py \
  --tree \
  /opt/cathedral-sn39/cathedral \
  /opt/cathedral-sn39/.venv/lib/python3.11/site-packages
```

For a file that the program securely creates on first use, check the existing
leaf when present or its complete parent chain when absent:

```bash
/usr/bin/python3 -I -S /usr/local/libexec/cathedral-privileged-paths.py \
  --creatable-file \
  /var/lib/cathedral-confidential-sn39/policy-republication.jsonl \
  /var/lib/cathedral-confidential-sn39/policy-writer.lock
```

The actual service runs Python with `-I -S`. `-I` ignores Python environment
and user-site inputs. `-S` prevents `site` from processing `.pth` redirects or
`sitecustomize`. The stdlib-only `cathedral_isolated_republisher.py` bootstrap
then adds the checked venv `site-packages` tree without `site.addsitedir` and
loads Cathedral from its exact checked package path.

From Python:

```python
from cathedral.privileged_paths import require_trusted_path

require_trusted_path("/etc/cathedral/epoch.env.sh")  # raises UntrustedPath
```

`inspect_path` returns every violation instead of raising, so one run tells an
operator everything to fix rather than one thing at a time.

## What it does not do

The checker does not infer imports. The unit must name every import root and
every separately read configuration or program file. The shipped example
does so for the policy republisher: resolved OS and venv interpreters,
`pyvenv.cfg`, the isolated bootstrap, the entry script, the Cathedral source
tree, all venv site-packages, the registry, signing key, anti-rollback state,
approval log, history directory, and lock file. The approval log and lock may
not exist before the first run. `--creatable-file` checks their complete parent
chain when absent and their full leaf checks when present; the program then
opens each with `O_NOFOLLOW|O_CREAT` and validates the resulting inode. If the
program starts using another import root or configuration file, the unit must
add it. Any other privileged Python service that leaves site initialization
enabled must separately audit every `.pth` redirect and executable line.

The standalone checker avoids importing from the inspected trees. It does not
replace the OS trust anchor, package integrity, or root-only installation.
Executing a checker after the checker or OS Python has already been replaced
does not recover trust.

It cannot close a time-of-check/time-of-use window that spans two processes:
a shell that checks a path and then sources it has a gap no external checker
can remove. Once every checked ancestor, file, tree entry, and ACL passes, an
unprivileged user has no structural write path during that gap. A root change
remains inside the trusted administrative boundary.

For a real TOCTOU-free read inside one process, use the existing
`_secure_read_bytes` helper in `scripts/cathedral_measurement_approval.py`,
which re-checks the descriptor after opening it.

## Fixing a host that already has this shape

1. Move the deployment root off `/home` to a root-owned path (`/opt/...`).
   Reinstall the virtualenv there rather than copying it, so no interpreter
   retains a home-directory `sys.prefix`.
2. Move the environment file to `/etc/cathedral/`, `chown root:root`,
   `chmod 0600`.
3. Install the standalone checker as the root-owned trust anchor above.
4. Add the preflight to the unit as `ExecStartPre`, not to a runbook. A check
   an operator has to remember to run is a check that is not run.
5. Check resolved interpreters, exact files, and complete import trees. Do not
   substitute a parent-directory check for imported descendants. Keep the
   service on the checked `-I -S` bootstrap so `.pth` redirects never activate.

These are host operations. They are deliberately out of scope for the change
that introduced this document, which ships the checker, isolated bootstrap,
tests, and corrected example unit only.
