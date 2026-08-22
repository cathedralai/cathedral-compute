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

    python3 scripts/detect_publisher_drift.py \\
      --evidence-url https://api.cathedral.computer/v1/evidence \\
      --git-dir . \\
      --release pins/release.json

Exit 0 only when every requested comparison agrees. Exit 1 on drift.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.provenance import MECHANISM_REVISIONS

DEFAULT_EVIDENCE_URL = "https://api.cathedral.computer/v1/evidence"
DEFAULT_MECHANISM_ID = "validated_supply_v2"
MAX_INDEX_BYTES = 1 << 20
MAX_MANIFEST_BYTES = 1 << 20
Fetcher = Callable[[str], bytes]


class DriftError(SystemExit):
    """Publisher drift, with the compared values in the message."""


def _fetch(url: str, *, limit: int) -> bytes:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(limit + 1)
    except urllib.error.URLError as exc:
        raise DriftError(f"evidence fetch failed: {url}: {exc}") from exc
    if len(body) > limit:
        raise DriftError(f"evidence fetch exceeded {limit} bytes: {url}")
    return body


def _load_json(label: str, raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise DriftError(f"{label} is not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise DriftError(f"{label} is not a JSON object")
    return parsed


def _digest_path(digest: str) -> str:
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise DriftError(f"manifest pointer is not a sha256 digest: {digest!r}")
    return digest


def load_latest_manifest(
    evidence_url: str, *, fetch: Fetcher | None = None
) -> tuple[str, dict[str, Any]]:
    """Return (manifest digest, manifest document) for the public tip."""
    getter = fetch or (lambda url: _fetch(url, limit=MAX_MANIFEST_BYTES))
    base = evidence_url.rstrip("/")
    index = _load_json("index.json", getter(f"{base}/index.json"))
    latest = index.get("latest")
    if not isinstance(latest, dict):
        raise DriftError("index.json has no latest object")
    digest = _digest_path(str(latest.get("manifest")))
    hex_digest = digest.removeprefix("sha256:")
    manifest = _load_json(
        "latest manifest",
        getter(f"{base}/blobs/sha256/{hex_digest}"),
    )
    return digest, manifest


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
            "--",
            "cathedral/provenance.py",
            "cathedral/evidence.py",
            "cathedral/cli.py",
        )
        if newest_touch and not _is_ancestor(git_dir, newest_touch, source_revision):
            mismatches.append(
                f"source_revision {source_revision} is older than the newest "
                f"commit touching mechanism files ({newest_touch})"
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
        "--release",
        type=Path,
        help="sealed release.json; live pins must match it exactly",
    )
    parser.add_argument(
        "--max-age-minutes",
        type=int,
        default=180,
        help="generated_at freshness window (default 180 minutes)",
    )
    return parser


def main(argv: list[str] | None = None, *, fetch: Fetcher | None = None) -> int:
    args = build_parser().parse_args(argv)
    release = None
    if args.release is not None:
        release = _load_json("release.json", args.release.read_bytes())
    digest, manifest = load_latest_manifest(args.evidence_url, fetch=fetch)
    compare_manifest(
        digest,
        manifest,
        git_dir=args.git_dir,
        release=release,
        max_age=timedelta(minutes=int(args.max_age_minutes)),
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
