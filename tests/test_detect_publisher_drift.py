"""Publisher drift detector (cathedral-compute #141)."""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "cathedral_detect_publisher_drift",
    Path(__file__).resolve().parents[1] / "scripts" / "detect_publisher_drift.py",
)
drift = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(drift)

DEFAULT_MECHANISM_ID = drift.DEFAULT_MECHANISM_ID
DriftError = drift.DriftError
compare_manifest = drift.compare_manifest
load_latest_manifest = drift.load_latest_manifest
main = drift.main

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
DIGEST = "sha256:" + "ab" * 32


def _manifest(**over: object) -> dict:
    document: dict = {
        "generated_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reward_mechanism": {"id": DEFAULT_MECHANISM_ID, "revision": 1},
        "source_revision": "d0e303b" + "0" * 33,
        "verifier": {"digest": "sha256:" + "6" * 64},
    }
    document.update(over)
    return document


def test_compare_manifest_accepts_a_current_v2_tip() -> None:
    compare_manifest(
        DIGEST,
        _manifest(),
        git_dir=None,
        release=None,
        max_age=timedelta(minutes=180),
        now=NOW,
    )


def test_compare_manifest_fails_a_stale_mechanism() -> None:
    with pytest.raises(DriftError, match="reward_mechanism"):
        compare_manifest(
            DIGEST,
            _manifest(reward_mechanism={"id": "validated_supply_v1", "revision": 1}),
            git_dir=None,
            release=None,
            max_age=timedelta(minutes=180),
            now=NOW,
        )


def test_compare_manifest_fails_when_live_is_ahead_of_the_sealed_release() -> None:
    """A main-only check would pass here. The sealed release is the gate."""
    live = _manifest(source_revision="aaaaaaaa" + "0" * 32)
    release = {
        "source_revision": "bbbbbbbb" + "0" * 32,
        "verifier_digest": live["verifier"]["digest"],
        "reward_mechanism": live["reward_mechanism"],
    }
    with pytest.raises(DriftError, match="sealed release"):
        compare_manifest(
            DIGEST,
            live,
            git_dir=None,
            release=release,
            max_age=timedelta(minutes=180),
            now=NOW,
        )


def test_compare_manifest_fails_a_stale_generated_at() -> None:
    old = (NOW - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(DriftError, match="generated_at"):
        compare_manifest(
            DIGEST,
            _manifest(generated_at=old),
            git_dir=None,
            release=None,
            max_age=timedelta(minutes=180),
            now=NOW,
        )


def test_load_latest_manifest_reads_the_public_index_shape() -> None:
    files = {
        "https://evidence.test/index.json": json.dumps(
            {"latest": {"manifest": DIGEST}}
        ).encode(),
        f"https://evidence.test/blobs/sha256/{DIGEST.removeprefix('sha256:')}": json.dumps(
            _manifest()
        ).encode(),
    }

    digest, manifest = load_latest_manifest(
        "https://evidence.test",
        fetch=lambda url: files[url],
    )
    assert digest == DIGEST
    assert manifest["reward_mechanism"]["id"] == DEFAULT_MECHANISM_ID


def test_main_prints_ok_for_a_matching_surface(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = _manifest()
    release_path = tmp_path / "release.json"
    release_path.write_text(
        json.dumps(
            {
                "source_revision": manifest["source_revision"],
                "verifier_digest": manifest["verifier"]["digest"],
                "reward_mechanism": manifest["reward_mechanism"],
            }
        )
    )
    files = {
        "https://evidence.test/index.json": json.dumps(
            {"latest": {"manifest": DIGEST}}
        ).encode(),
        f"https://evidence.test/blobs/sha256/{DIGEST.removeprefix('sha256:')}": json.dumps(
            manifest
        ).encode(),
    }
    assert (
        main(
            [
                "--evidence-url",
                "https://evidence.test",
                "--release",
                str(release_path),
                "--max-age-minutes",
                "180",
            ],
            fetch=lambda url: files[url],
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["result"] == "ok"
