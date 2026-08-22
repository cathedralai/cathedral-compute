#!/usr/bin/env python3
"""Fail if the public evidence publisher has drifted from what this repo ships.

cathedral-compute #141: source tests cannot see a live publisher that is
stale, ahead of the last sealed release, or on an unmerged revision. This
reads the public evidence surface (no secrets, no chain) and compares the
latest manifest to:

* the mechanism defaults in this checkout
* optional sealed release pins (``--release``)
* optional git ancestry against ``origin/main``

A main-only check is not enough. Production running an unsealed tip of main
must fail when ``--release`` is supplied and disagrees. Production eleven
days behind main must fail the ancestry / freshness checks.

Scheduled CI must pass ``--require-release`` and ``--require-signed-index``.
Those gates fail closed when the pin files are absent. Pull-request CI
compares mechanism ancestry against ``--git-ref origin/main`` so an
unmerged checkout cannot fail a healthy public tip.

    python3 scripts/detect_publisher_drift.py \\
      --evidence-url https://api.cathedral.computer/v1/evidence \\
      --git-dir . \\
      --git-ref origin/main \\
      --release pins/publisher-release.json \\
      --index-keys pins/evidence-index-keys.json \\
      --require-release \\
      --require-signed-index

Exit 0 only when every requested comparison agrees. Exit 1 on drift.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.evidence import EvidenceError, digest_bytes, verify_index
from cathedral.provenance import MECHANISM_REVISIONS

DEFAULT_EVIDENCE_URL = "https://api.cathedral.computer/v1/evidence"
DEFAULT_MECHANISM_ID = "validated_supply_v2"
DEFAULT_NETWORK = "finney"
DEFAULT_NETUID = 39
MAX_INDEX_BYTES = 1 << 20
MAX_MANIFEST_BYTES = 1 << 20
FETCH_DEADLINE_SECONDS = 30.0
CLOCK_SKEW = timedelta(seconds=120)
USER_AGENT = (
    "CathedralPublisherDrift/1.0 "
    "(+https://github.com/cathedralai/cathedral-sandbox)"
)
DIGEST_RE = re.compile(r"sha256:([0-9a-f]{64})$")
Fetcher = Callable[[str], bytes]


class DriftError(SystemExit):
    """Publisher drift, with the compared values in the message."""


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise DriftError("evidence fetch exceeded the whole-fetch deadline")
    return left


def _fetch(url: str, *, limit: int, deadline: float | None = None) -> bytes:
    if deadline is None:
        deadline = time.monotonic() + FETCH_DEADLINE_SECONDS
    timeout = min(30.0, _remaining(deadline))
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": USER_AGENT},
    )
    chunks: list[bytes] = []
    received = 0
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            while True:
                _remaining(deadline)
                chunk = response.read(65536)
                if not chunk:
                    break
                received += len(chunk)
                if received > limit:
                    raise DriftError(f"evidence fetch exceeded {limit} bytes: {url}")
                chunks.append(chunk)
    except DriftError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DriftError(f"evidence fetch failed: {url}: {exc}") from exc
    return b"".join(chunks)


def _load_json(label: str, raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise DriftError(f"{label} is not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise DriftError(f"{label} is not a JSON object")
    return parsed


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise DriftError(f"{label} is not a 64-character sha256 digest: {value!r}")
    return value


def _load_index_keys(path: Path) -> dict[str, bytes]:
    raw = _load_json("index keys", path.read_bytes())
    keys: dict[str, bytes] = {}
    try:
        for key_id, encoded in raw.items():
            if not isinstance(key_id, str) or not key_id or not isinstance(encoded, str):
                raise ValueError
            key = base64.b64decode(encoded, validate=True)
            if len(key) != 32:
                raise ValueError
            keys[key_id] = key
    except (ValueError, TypeError) as exc:
        raise DriftError("index keys must be 32-byte base64 values") from exc
    if not keys:
        raise DriftError("index key file cannot be empty")
    return keys


def load_latest_manifest(
    evidence_url: str,
    *,
    fetch: Fetcher | None = None,
    index_keys: dict[str, bytes] | None = None,
    network: str = DEFAULT_NETWORK,
    netuid: int = DEFAULT_NETUID,
    require_signed_index: bool = False,
    now: datetime | None = None,
) -> tuple[str, dict[str, Any]]:
    """Return (manifest digest, manifest document) for the public tip."""
    getter = fetch or (lambda url: _fetch(url, limit=MAX_MANIFEST_BYTES))
    base = evidence_url.rstrip("/")
    index_raw = getter(f"{base}/index.json")
    if require_signed_index and not index_keys:
        raise DriftError("signed index check requires --index-keys")
    if index_keys:
        try:
            verified = verify_index(
                index_raw,
                index_keys,
                expected_network=network,
                expected_netuid=netuid,
                now=now,
            )
        except EvidenceError as exc:
            raise DriftError(f"evidence index failed verification: {exc}") from exc
        digest = _require_digest(verified["latest"]["manifest"], "latest manifest digest")
    else:
        index = _load_json("index.json", index_raw)
        latest = index.get("latest")
        if not isinstance(latest, dict):
            raise DriftError("index.json has no latest object")
        digest = _require_digest(latest.get("manifest"), "manifest pointer")
    hex_digest = digest.removeprefix("sha256:")
    manifest_raw = getter(f"{base}/blobs/sha256/{hex_digest}")
    if digest_bytes(manifest_raw) != digest:
        raise DriftError(f"latest manifest bytes do not hash to {digest}")
    return digest, _load_json("latest manifest", manifest_raw)


def _parse_generated_at(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise DriftError("manifest generated_at is missing")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError as exc:
        raise DriftError(f"manifest generated_at is not UTC time: {value!r}") from exc


def _git(git_dir: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(git_dir), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or exc
        raise DriftError(f"git {' '.join(args)} failed: {detail}") from exc
    return completed.stdout.strip()


def _is_ancestor(git_dir: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(git_dir), "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise DriftError(f"git merge-base --is-ancestor failed: {result.stderr}")


def compare_manifest(
    digest: str,
    manifest: dict[str, Any],
    *,
    git_dir: Path | None,
    release: dict[str, Any] | None,
    max_age: timedelta,
    now: datetime | None = None,
    git_ref: str = "HEAD",
) -> None:
    mismatches: list[str] = []
    mechanism = manifest.get("reward_mechanism")
    if not isinstance(mechanism, dict):
        raise DriftError(f"{digest}: manifest has no reward_mechanism")
    mechanism_id = mechanism.get("id")
    mechanism_revision = mechanism.get("revision")
    expected_revision = MECHANISM_REVISIONS.get(DEFAULT_MECHANISM_ID)
    if mechanism_id != DEFAULT_MECHANISM_ID or mechanism_revision != expected_revision:
        mismatches.append(
            f"reward_mechanism {mechanism_id!r} revision {mechanism_revision!r} "
            f"!= checkout default {DEFAULT_MECHANISM_ID!r} revision {expected_revision!r}"
        )

    source_revision = manifest.get("source_revision")
    verifier = manifest.get("verifier") if isinstance(manifest.get("verifier"), dict) else {}
    verifier_digest = verifier.get("digest") if isinstance(verifier, dict) else None

    if release is not None:
        sealed_mechanism = release.get("reward_mechanism")
        if not isinstance(sealed_mechanism, dict):
            raise DriftError("release file has no reward_mechanism")
        if (
            mechanism_id != sealed_mechanism.get("id")
            or mechanism_revision != sealed_mechanism.get("revision")
        ):
            mismatches.append(
                f"reward_mechanism {mechanism_id!r} revision {mechanism_revision!r} "
                f"!= sealed release {sealed_mechanism.get('id')!r} revision "
                f"{sealed_mechanism.get('revision')!r}"
            )
        if source_revision != release.get("source_revision"):
            mismatches.append(
                f"source_revision {source_revision!r} != sealed release "
                f"{release.get('source_revision')!r}"
            )
        if verifier_digest != release.get("verifier_digest"):
            mismatches.append(
                f"verifier_digest {verifier_digest!r} != sealed release "
                f"{release.get('verifier_digest')!r}"
            )

    generated_at = _parse_generated_at(manifest.get("generated_at"))
    clock = now or datetime.now(UTC)
    if generated_at > clock + CLOCK_SKEW:
        mismatches.append(
            f"generated_at {generated_at.isoformat()} is ahead of current UTC "
            f"beyond {CLOCK_SKEW.total_seconds():.0f}s skew"
        )
    if generated_at < clock - max_age:
        mismatches.append(
            f"generated_at {generated_at.isoformat()} is older than {max_age}"
        )

    if git_dir is not None:
        if not isinstance(source_revision, str) or not source_revision:
            raise DriftError(f"{digest}: manifest source_revision is missing")
        main_revision = _git(git_dir, "rev-parse", "origin/main")
        if not _is_ancestor(git_dir, source_revision, main_revision):
            mismatches.append(
                f"source_revision {source_revision} is not an ancestor of "
                f"origin/main {main_revision}"
            )
        newest_touch = _git(
            git_dir,
            "log",
            "-1",
            "--format=%H",
            git_ref,
            "--",
            "cathedral/provenance.py",
            "cathedral/evidence.py",
            "cathedral/cli.py",
        )
        if newest_touch and not _is_ancestor(git_dir, newest_touch, source_revision):
            mismatches.append(
                f"source_revision {source_revision} is older than the newest "
                f"commit on {git_ref} touching mechanism files ({newest_touch})"
            )

    if mismatches:
        raise DriftError(
            f"publisher drift against {digest}: " + "; ".join(mismatches)
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-url", default=DEFAULT_EVIDENCE_URL)
    parser.add_argument("--git-dir", type=Path)
    parser.add_argument(
        "--git-ref",
        default="HEAD",
        help="revision used to find the newest mechanism-file commit "
        "(pull requests should pass origin/main)",
    )
    parser.add_argument(
        "--release",
        type=Path,
        help="sealed release.json; live pins must match it exactly",
    )
    parser.add_argument(
        "--require-release",
        action="store_true",
        help="fail when --release is omitted (scheduled CI)",
    )
    parser.add_argument(
        "--index-keys",
        type=Path,
        help="trusted evidence-index public keys (key_id -> base64)",
    )
    parser.add_argument(
        "--require-signed-index",
        action="store_true",
        help="fail unless the public index verifies under --index-keys",
    )
    parser.add_argument("--network", default=DEFAULT_NETWORK)
    parser.add_argument("--netuid", type=int, default=DEFAULT_NETUID)
    parser.add_argument(
        "--max-age-minutes",
        type=int,
        default=180,
        help="generated_at freshness window (default 180 minutes)",
    )
    return parser


def main(argv: list[str] | None = None, *, fetch: Fetcher | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.require_release and args.release is None:
        raise DriftError("scheduled drift check requires --release")
    if args.require_signed_index and args.index_keys is None:
        raise DriftError("signed index check requires --index-keys")
    release = None
    if args.release is not None:
        if not args.release.is_file():
            raise DriftError(f"release pin file is missing: {args.release}")
        release = _load_json("release.json", args.release.read_bytes())
    index_keys = None
    if args.index_keys is not None:
        if not args.index_keys.is_file():
            raise DriftError(f"index key file is missing: {args.index_keys}")
        index_keys = _load_index_keys(args.index_keys)
    digest, manifest = load_latest_manifest(
        args.evidence_url,
        fetch=fetch,
        index_keys=index_keys,
        network=args.network,
        netuid=int(args.netuid),
        require_signed_index=bool(args.require_signed_index),
    )
    compare_manifest(
        digest,
        manifest,
        git_dir=args.git_dir,
        release=release,
        max_age=timedelta(minutes=int(args.max_age_minutes)),
        git_ref=str(args.git_ref),
    )
    print(
        json.dumps(
            {
                "result": "ok",
                "manifest": digest,
                "source_revision": manifest.get("source_revision"),
                "reward_mechanism": manifest.get("reward_mechanism"),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
