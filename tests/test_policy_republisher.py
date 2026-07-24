"""Locked, atomic policy-freshness republication tests."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest

from cathedral.policy_registry import PolicyRegistryState, verify_registry
from tests.test_registry_reissue import REGISTRY_BYTES, REGISTRY_SEED, TRUSTED

_SPEC = importlib.util.spec_from_file_location(
    "cathedral_measurement_approval_republisher",
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "cathedral_measurement_approval.py",
)
approval_tool = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(approval_tool)


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    registry = tmp_path / "policy-registry.json"
    registry.write_bytes(REGISTRY_BYTES)
    registry.chmod(0o644)
    signing_key = tmp_path / "policy-signing.key"
    signing_key.write_text(base64.b64encode(REGISTRY_SEED).decode("ascii"))
    signing_key.chmod(0o600)
    state = tmp_path / "policy-state.sqlite"
    PolicyRegistryState(state, minimum_release=1).accept(
        verify_registry(REGISTRY_BYTES, TRUSTED)
    )
    history = tmp_path / "history"
    history.mkdir(mode=0o700)
    return registry, signing_key, state, history


def _argv(
    tmp_path: Path,
    registry: Path,
    signing_key: Path,
    state: Path,
    history: Path,
) -> list[str]:
    return [
        "republish-install",
        "--registry",
        str(registry),
        "--signing-key-file",
        str(signing_key),
        "--state",
        str(state),
        "--operator",
        "test-systemd",
        "--reason",
        "scheduled bounded freshness reissue",
        "--approval-log",
        str(tmp_path / "republish.jsonl"),
        "--history-dir",
        str(history),
        "--lock-file",
        str(tmp_path / "republish.lock"),
    ]


def test_republisher_archives_and_atomically_installs_next_release(tmp_path: Path):
    registry, signing_key, state, history = _inputs(tmp_path)
    state_before = state.read_bytes()
    assert approval_tool.main(
        _argv(tmp_path, registry, signing_key, state, history)
    ) == 0

    installed_bytes = registry.read_bytes()
    installed = json.loads(installed_bytes)
    snapshot = verify_registry(installed_bytes, TRUSTED)
    assert installed["release"] == json.loads(REGISTRY_BYTES)["release"] + 1
    assert snapshot.release == installed["release"]
    assert os.stat(registry).st_mode & 0o777 == 0o644
    assert state.read_bytes() == state_before

    old_digest = hashlib.sha256(REGISTRY_BYTES).hexdigest()
    archive = history / f"release-{1:020d}-{old_digest}.json"
    assert archive.read_bytes() == REGISTRY_BYTES
    assert os.stat(archive).st_mode & 0o777 == 0o644
    audit = [
        json.loads(line)
        for line in (tmp_path / "republish.jsonl").read_text().splitlines()
    ]
    assert [row["action"] for row in audit] == [
        "registry_reissue_prepared",
        "policy_registry_install_prepared",
        "policy_registry_install_committed",
    ]
    assert audit[-1]["new_release"] == installed["release"]


def test_republisher_can_advance_again_before_runtime_accepts(tmp_path: Path):
    registry, signing_key, state, history = _inputs(tmp_path)
    argv = _argv(tmp_path, registry, signing_key, state, history)
    assert approval_tool.main(argv) == 0
    release_two = registry.read_bytes()
    assert approval_tool.main(argv) == 0
    installed = json.loads(registry.read_bytes())
    assert installed["release"] == 3
    digest_two = hashlib.sha256(release_two).hexdigest()
    assert (
        history / f"release-{2:020d}-{digest_two}.json"
    ).read_bytes() == release_two
    assert len((tmp_path / "republish.jsonl").read_text().splitlines()) == 6


def test_republisher_lock_contention_is_clean_noop(tmp_path: Path):
    registry, signing_key, state, history = _inputs(tmp_path)
    lock = tmp_path / "republish.lock"
    descriptor = approval_tool._open_lock(lock)
    try:
        assert descriptor >= 0
        with pytest.raises(SystemExit, match="shared lock"):
            approval_tool.main(
                _argv(tmp_path, registry, signing_key, state, history)
            )
        assert registry.read_bytes() == REGISTRY_BYTES
        assert list(history.iterdir()) == []
        assert not (tmp_path / "republish.jsonl").exists()
    finally:
        os.close(descriptor)


def test_republisher_rejects_symlink_registry(tmp_path: Path):
    registry, signing_key, state, history = _inputs(tmp_path)
    real = tmp_path / "real-registry.json"
    registry.rename(real)
    registry.symlink_to(real)
    with pytest.raises(SystemExit, match="non-symlink"):
        approval_tool.main(
            _argv(tmp_path, registry, signing_key, state, history)
        )
    assert real.read_bytes() == REGISTRY_BYTES
    assert list(history.iterdir()) == []


def test_republisher_rejects_conflicting_history_artifact(tmp_path: Path):
    registry, signing_key, state, history = _inputs(tmp_path)
    old_digest = hashlib.sha256(REGISTRY_BYTES).hexdigest()
    archive = history / f"release-{1:020d}-{old_digest}.json"
    archive.write_text("different")
    archive.chmod(0o644)
    with pytest.raises(SystemExit, match="different content"):
        approval_tool.main(
            _argv(tmp_path, registry, signing_key, state, history)
        )
    assert registry.read_bytes() == REGISTRY_BYTES
    audit = [
        json.loads(line)
        for line in (tmp_path / "republish.jsonl").read_text().splitlines()
    ]
    assert [row["action"] for row in audit] == ["registry_reissue_prepared"]


def test_republisher_archive_failure_is_prepared_not_committed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    registry, signing_key, state, history = _inputs(tmp_path)
    original = approval_tool._secure_write_new

    def fail_archive(path: Path, data: bytes) -> None:
        if path.parent == history:
            raise OSError("archive unavailable")
        original(path, data)

    monkeypatch.setattr(approval_tool, "_secure_write_new", fail_archive)
    with pytest.raises(OSError, match="archive unavailable"):
        approval_tool.main(
            _argv(tmp_path, registry, signing_key, state, history)
        )
    assert registry.read_bytes() == REGISTRY_BYTES
    actions = [
        json.loads(line)["action"]
        for line in (tmp_path / "republish.jsonl").read_text().splitlines()
    ]
    assert actions == [
        "registry_reissue_prepared",
        "policy_registry_install_prepared",
    ]


def test_republisher_replace_failure_is_never_committed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    registry, signing_key, state, history = _inputs(tmp_path)
    original = approval_tool.os.replace

    def fail_live_replace(source: str | Path, target: str | Path) -> None:
        if Path(target) == registry:
            raise OSError("replace unavailable")
        original(source, target)

    monkeypatch.setattr(approval_tool.os, "replace", fail_live_replace)
    with pytest.raises(OSError, match="replace unavailable"):
        approval_tool.main(
            _argv(tmp_path, registry, signing_key, state, history)
        )
    assert registry.read_bytes() == REGISTRY_BYTES
    actions = [
        json.loads(line)["action"]
        for line in (tmp_path / "republish.jsonl").read_text().splitlines()
    ]
    assert actions == [
        "registry_reissue_prepared",
        "policy_registry_install_prepared",
    ]


def _prepared_candidate(
    tmp_path: Path,
    registry: Path,
    signing_key: Path,
    state: Path,
) -> Path:
    candidate = tmp_path / "reviewed-candidate.json"
    assert approval_tool.main(
        [
            "renew",
            "--registry",
            str(registry),
            "--signing-key-file",
            str(signing_key),
            "--state",
            str(state),
            "--operator",
            "reviewer",
            "--reason",
            "prepare exact reviewed successor",
            "--approval-log",
            str(tmp_path / "candidate-preparation.jsonl"),
            "--out",
            str(candidate),
        ]
    ) == 0
    return candidate


def _install_argv(
    tmp_path: Path,
    registry: Path,
    candidate: Path,
    signing_key: Path,
    state: Path,
    history: Path,
) -> list[str]:
    return [
        "install-candidate",
        "--registry",
        str(registry),
        "--candidate",
        str(candidate),
        "--signing-key-file",
        str(signing_key),
        "--state",
        str(state),
        "--expected-current-digest",
        "sha256:" + hashlib.sha256(registry.read_bytes()).hexdigest(),
        "--expected-candidate-digest",
        "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest(),
        "--operator",
        "reviewed-installer",
        "--reason",
        "install exact reviewed successor through shared lock",
        "--approval-log",
        str(tmp_path / "candidate-install.jsonl"),
        "--history-dir",
        str(history),
        "--lock-file",
        str(tmp_path / "republish.lock"),
    ]


def test_reviewed_candidate_installer_uses_same_lock_and_exact_digests(
    tmp_path: Path,
):
    registry, signing_key, state, history = _inputs(tmp_path)
    candidate = _prepared_candidate(tmp_path, registry, signing_key, state)
    candidate_bytes = candidate.read_bytes()
    argv = _install_argv(
        tmp_path, registry, candidate, signing_key, state, history
    )
    assert approval_tool.main(argv) == 0
    assert registry.read_bytes() == candidate_bytes
    assert candidate.exists()
    actions = [
        json.loads(line)["action"]
        for line in (tmp_path / "candidate-install.jsonl").read_text().splitlines()
    ]
    assert actions == [
        "policy_registry_install_prepared",
        "policy_registry_install_committed",
    ]


def test_reviewed_candidate_installer_cannot_race_republisher_lock(
    tmp_path: Path,
):
    registry, signing_key, state, history = _inputs(tmp_path)
    candidate = _prepared_candidate(tmp_path, registry, signing_key, state)
    argv = _install_argv(
        tmp_path, registry, candidate, signing_key, state, history
    )
    descriptor = approval_tool._open_lock(tmp_path / "republish.lock")
    try:
        with pytest.raises(SystemExit, match="shared lock"):
            approval_tool.main(argv)
    finally:
        os.close(descriptor)
    assert registry.read_bytes() == REGISTRY_BYTES
    assert not (tmp_path / "candidate-install.jsonl").exists()


def test_reviewed_candidate_installer_rejects_digest_mismatch(tmp_path: Path):
    registry, signing_key, state, history = _inputs(tmp_path)
    candidate = _prepared_candidate(tmp_path, registry, signing_key, state)
    argv = _install_argv(
        tmp_path, registry, candidate, signing_key, state, history
    )
    argv[argv.index("--expected-candidate-digest") + 1] = "sha256:" + "0" * 64
    with pytest.raises(SystemExit, match="reviewed digest"):
        approval_tool.main(argv)
    assert registry.read_bytes() == REGISTRY_BYTES
    assert not (tmp_path / "candidate-install.jsonl").exists()
