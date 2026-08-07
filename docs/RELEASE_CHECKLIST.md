# Cutting a supported release

The launch gate is not "the code is good". It is **an outsider reproducing the
claim without asking us for anything**. Today nobody can, and the reason is
narrow: there is no tagged release and no published pins, so
`docs/PROVENANCE.md`'s one-command reproduction cannot be assembled. That is
`docs/LAUNCH_CANDIDATE.md` items 4 and 5, and it is publication work, not code.

## The rule that shapes everything here

> Every pin (key digests, verifier implementation digest, source revision)
> comes from the release notes, never from anything the evidence surface
> serves.

A trust root taken from the service under audit proves nothing. So the pins
cannot be scraped from `api.cathedral.computer`, and a release that ships with a
pin missing is worse than no release: `provenance verify --production` requires
all of them, and an operator who finds one absent is tempted to go and take it
from the API, which silently destroys the property.

## Why none of the pins can be produced from a clone

| Pin | Why it is host-specific |
|---|---|
| `--registry-keys-digest` | sha256 over the exact **published** bundle bytes |
| `--report-keys-digest` | same |
| `--index-keys-digest` | same |
| `--verifier-digest` | the preimage commits to the production **install path and argv**, not only the binary, so it is only correct computed against the real installation |
| `--source-revision` | the commit the release is cut from |

This is why the release cannot be finished from a laptop, and why the
placeholders in `docs/PROVENANCE.md` have survived: they need someone on the
host.

## Steps

**1. Freeze the revision.** Pick the commit. Everything below pins to it.

```bash
git rev-parse HEAD
```

**2. Publish the key bundles.** The three bundles must be downloadable at a
stable URL that is not the evidence surface (release assets are the obvious
choice). Publish the bytes, not a rendering of them: the digest commits to
exactly what a downloader receives.

**3. Emit the pins, on the production host.**

```bash
python3 scripts/release_pins.py \
  --registry-keys /path/to/published/registry-keys.json \
  --report-keys   /path/to/published/report-keys.json \
  --index-keys    /path/to/published/index-keys.json \
  --verifier      /absolute/installed/path/cathedral-tdx-verifier \
  --source-revision "$(git rev-parse HEAD)"
```

It fails closed on a missing, empty, oversized or non-JSON bundle rather than
printing a blank pin.

**4. Tag and write the notes.** Paste the emitted table verbatim. The notes must
carry every row; if one is missing, stop and fix it rather than shipping.

**5. Fill in `docs/PROVENANCE.md`.** Replace the `sha256:...` and
`<pinned commit>` placeholders with the published values.

**6. Prove it.** On a clean Linux host with no Cathedral access, run the
`docs/PROVENANCE.md` command using only the release notes. **This run is the
launch gate.** A `FULL` result means the narrow claim ("SN39 mainnet: validated
Intel TDX CPU compute, independently reproducible") is finally true. Anything
else means it is not, whatever this repository's docs say.

Record the result. If it is `NOT_PROVEN`, the remediation string names what is
missing; that is the next task, not a reason to soften the claim.

## Note on the verifier digest

It changes if the binary is reinstalled at a different path, because the path is
part of the preimage. A release whose verifier digest was computed against a
staging path will fail against production for a reason that reads like
tampering. Compute it against the deployed installation.

## What this checklist does not cover

Deployment questions that are not release mechanics: whether existing live
manifests need re-emitting after the `validated_supply_v2` standardization
(#102), and seeding plus reconciling the coldkey allowlist (#56). Both are
operator calls.
