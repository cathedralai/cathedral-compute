#!/usr/bin/env python3
"""Emit every pin a supported release must publish, in paste-ready form.

`docs/PROVENANCE.md` requires an external validator to take the key digests,
the verifier implementation digest and the source revision from the RELEASE
NOTES, never from the evidence surface being verified. Copying a trust root
from the service under audit proves nothing, so that rule is what makes the
one-command reproduction meaningful.

Every pin below is therefore host-specific and cannot be produced from a clone:

* the three key-bundle digests are sha256 over the exact published bytes;
* the verifier implementation digest commits to the production install PATHS
  and argv as well as the binary, so it is only correct when computed against
  the real installation;
* the source revision is the commit the release is cut from.

Run this on the production host, check the output against what is deployed, and
paste the block into the release notes.

    python3 scripts/release_pins.py \\
      --registry-keys /etc/cathedral/pins/registry-keys.json \\
      --report-keys   /etc/cathedral/pins/report-keys.json \\
      --index-keys    /etc/cathedral/pins/index-keys.json \\
      --verifier      /usr/local/bin/cathedral-tdx-verifier \\
      --source-revision "$(git -C /path/to/checkout rev-parse HEAD)"

Fails closed: a missing, unreadable, empty or non-JSON key bundle is an error,
never a blank pin. A release notes block with a blank pin is worse than none,
because `provenance verify --production` requires all of them and an operator
who finds one missing is invited to go and take it from the API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.verify import tdx_verifier_implementation_digest

MAX_BUNDLE_BYTES = 1 << 20


def _bundle_digest(label: str, path: str) -> str:
    """sha256 over the exact published bytes, with the file sanity-checked.

    The digest is over bytes, not over parsed JSON: the pin must commit to what
    a downloader actually receives. Parsing is only a guard against publishing
    a digest of a truncated or wrong file.
    """
    candidate = Path(path)
    try:
        raw = candidate.read_bytes()
    except OSError as exc:
        raise SystemExit(f"{label}: cannot read {path!r}: {exc}") from exc
    if not raw:
        raise SystemExit(f"{label}: {path!r} is empty; refusing to publish a digest of nothing")
    if len(raw) > MAX_BUNDLE_BYTES:
        raise SystemExit(f"{label}: {path!r} is implausibly large for a key bundle")
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise SystemExit(f"{label}: {path!r} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise SystemExit(f"{label}: {path!r} is not a non-empty JSON object of key ids")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--registry-keys", required=True, help="published registry key bundle")
    parser.add_argument("--report-keys", required=True, help="published report key bundle")
    parser.add_argument("--index-keys", required=True, help="published evidence-index key bundle")
    parser.add_argument(
        "--verifier",
        required=True,
        help="absolute path of the INSTALLED production TDX verifier (the digest "
        "commits to this path, not only to the bytes)",
    )
    parser.add_argument(
        "--source-revision",
        required=True,
        help="commit the release is cut from (git rev-parse HEAD)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    registry = _bundle_digest("registry-keys", args.registry_keys)
    report = _bundle_digest("report-keys", args.report_keys)
    index = _bundle_digest("index-keys", args.index_keys)

    verifier_path = args.verifier
    if not verifier_path.startswith("/"):
        raise SystemExit("--verifier must be the absolute installed path")
    command = tuple(shlex.split(verifier_path))
    verifier = tdx_verifier_implementation_digest(command, (verifier_path,))

    revision = args.source_revision.strip()
    if not revision:
        raise SystemExit("--source-revision is empty")

    print("<!-- paste into the release notes; every value below is a required pin -->")
    print()
    print("| Pin | Value |")
    print("|---|---|")
    print(f"| `--registry-keys-digest` | `{registry}` |")
    print(f"| `--report-keys-digest` | `{report}` |")
    print(f"| `--index-keys-digest` | `{index}` |")
    print(f"| `--verifier-digest` | `{verifier}` |")
    print(f"| `--source-revision` | `{revision}` |")
    print()
    print("Verifier digest computed against the installed path "
          f"`{verifier_path}`; it changes if the binary is reinstalled elsewhere.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
