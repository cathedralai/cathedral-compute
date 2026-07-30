"""Measurement approval must name and verify its target profile.

A registry keeps every prior profile after a rollover, so the profile a
measurement lands in can never be inferred from list position: after
``rollover`` appends ``cpu-tdx-sn39-v2``, ``profiles[0]`` is still the legacy
``v1`` profile. These tests prove that an approval aimed at v2 mutates only
v2, that the v1 profile is byte-identical afterwards, and that every way of
naming the wrong profile fails before any live capture or write happens.
"""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

import pytest

from cathedral.policy_registry import canonical_json, sign_registry, verify_registry
from tests.test_registry_reissue import (
    REGISTRY_BYTES,
    REGISTRY_SEED,
    TRUSTED,
    _public_b64,
)

_SPEC = importlib.util.spec_from_file_location(
    "cathedral_measurement_approval_profile_target",
    Path(__file__).resolve().parents[1] / "scripts" / "cathedral_measurement_approval.py",
)
approval_tool = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(approval_tool)

V1 = "cpu-tdx-sample-v1"
V2 = "cpu-tdx-sn39-v2"
NEW_MEASUREMENT = "tdx-measurement-sha256:" + "ab" * 32
RECEIPT_SEED_V2 = bytes(range(96, 128))


def _rolled_over_registry_bytes() -> bytes:
    """The fixture registry after a v2 rollover: v1 retained, v2 appended.

    Built the way ``cmd_rollover`` builds it — the successor is appended, so
    ``profiles[0]`` remains the legacy profile.
    """
    document = json.loads(REGISTRY_BYTES)
    document.pop("signature", None)
    document["release"] = int(document["release"]) + 1
    source = document["profiles"][0]
    successor = json.loads(json.dumps(source, sort_keys=True))
    successor["id"] = V2
    successor["measurements"] = ["tdx-measurement-sha256:sample-v2"]
    successor["metadata"] = {"rollover_from": V1}
    document["profiles"].append(successor)
    document["receipt_signing_keys"].append(
        {
            **json.loads(json.dumps(document["receipt_signing_keys"][0], sort_keys=True)),
            "id": "receipt-test-2",
            "public_key_base64": _public_b64(RECEIPT_SEED_V2),
            "metadata": {"rollover_from_profile": V1},
        }
    )
    return canonical_json(sign_registry(document, REGISTRY_SEED))


ROLLED_OVER_BYTES = _rolled_over_registry_bytes()


def _profile(document: dict, profile_id: str) -> dict:
    return next(row for row in document["profiles"] if row["id"] == profile_id)


def _write_inputs(tmp_path: Path, registry_bytes: bytes = ROLLED_OVER_BYTES):
    registry_path = tmp_path / "registry.json"
    registry_path.write_bytes(registry_bytes)
    signing_key = tmp_path / "policy-signing.key"
    signing_key.write_text(base64.b64encode(REGISTRY_SEED).decode("ascii"))
    signing_key.chmod(0o600)
    return registry_path, signing_key


def _approve_argv(
    tmp_path: Path,
    registry_path: Path,
    signing_key: Path,
    *,
    profile_id: str,
    out: str = "registry.next.json",
) -> list[str]:
    return [
        "approve",
        "--registry",
        str(registry_path),
        "--profile-id",
        profile_id,
        "--signing-key-file",
        str(signing_key),
        "--endpoint",
        "https://8.8.8.8:8443",
        "--cacert",
        str(tmp_path / "ca.pem"),
        "--hotkey",
        "5F4YxgafukzLRSB3fMt6q87V65KdjYc6DJEnugKLE2LqV93n",
        "--verifier",
        str(tmp_path / "verifier"),
        "--operator",
        "test operator",
        "--reason",
        "regression coverage",
        "--approval-log",
        str(tmp_path / "approvals.jsonl"),
        "--out",
        str(tmp_path / out),
    ]


@pytest.fixture
def stub_capture(monkeypatch):
    """Stand in for the live probe; records whether it was reached at all."""
    calls: list[tuple] = []

    def _capture(endpoint, cacert, hotkey, verifier):
        calls.append((endpoint, cacert, hotkey, verifier))
        return {
            "measurement": NEW_MEASUREMENT,
            "tcb_status": "UpToDate",
            "chip_id": "chip-abcdef0123456789",
        }

    monkeypatch.setattr(approval_tool, "_capture", _capture)
    return calls


# ---------------------------------------------------------------------------
# The regression this file exists for
# ---------------------------------------------------------------------------

def test_v2_approval_does_not_mutate_v1(tmp_path: Path, stub_capture):
    registry_path, signing_key = _write_inputs(tmp_path)
    before = json.loads(ROLLED_OVER_BYTES)

    assert (
        approval_tool.main(
            _approve_argv(tmp_path, registry_path, signing_key, profile_id=V2)
        )
        == 0
    )

    emitted = json.loads((tmp_path / "registry.next.json").read_bytes())
    # v1 is byte-identical, including its measurement list.
    assert _profile(emitted, V1) == _profile(before, V1)
    assert NEW_MEASUREMENT not in _profile(emitted, V1)["measurements"]
    # v2 gained exactly the approved measurement and nothing else.
    assert NEW_MEASUREMENT in _profile(emitted, V2)["measurements"]
    assert set(_profile(emitted, V2)["measurements"]) == set(
        _profile(before, V2)["measurements"]
    ) | {NEW_MEASUREMENT}
    assert emitted["release"] == before["release"] + 1


def test_the_emitted_release_still_verifies_and_records_its_target(
    tmp_path: Path, stub_capture
):
    registry_path, signing_key = _write_inputs(tmp_path)
    approval_tool.main(
        _approve_argv(tmp_path, registry_path, signing_key, profile_id=V2)
    )

    encoded = (tmp_path / "registry.next.json").read_bytes()
    snapshot = verify_registry(encoded, TRUSTED)
    assert snapshot.release == json.loads(ROLLED_OVER_BYTES)["release"] + 1

    approval = json.loads(encoded)["metadata"]["measurement_approvals"][-1]
    assert approval["profile_id"] == V2
    assert approval["measurement"] == NEW_MEASUREMENT

    logged = json.loads((tmp_path / "approvals.jsonl").read_text().splitlines()[-1])
    assert logged["profile_id"] == V2
    assert logged["action"] == "measurement_approved"


def test_approving_v1_leaves_v2_untouched(tmp_path: Path, stub_capture):
    registry_path, signing_key = _write_inputs(tmp_path)
    before = json.loads(ROLLED_OVER_BYTES)

    approval_tool.main(
        _approve_argv(tmp_path, registry_path, signing_key, profile_id=V1)
    )

    emitted = json.loads((tmp_path / "registry.next.json").read_bytes())
    assert _profile(emitted, V2) == _profile(before, V2)
    assert NEW_MEASUREMENT in _profile(emitted, V1)["measurements"]


# ---------------------------------------------------------------------------
# Naming the wrong profile fails closed, before the live capture
# ---------------------------------------------------------------------------

def test_unknown_profile_id_is_refused_before_any_capture(tmp_path: Path, stub_capture):
    registry_path, signing_key = _write_inputs(tmp_path)
    with pytest.raises(SystemExit, match="not in the registry"):
        approval_tool.main(
            _approve_argv(
                tmp_path, registry_path, signing_key, profile_id="cpu-tdx-sn39-v9"
            )
        )
    assert stub_capture == []  # no live probe was spent
    assert not (tmp_path / "registry.next.json").exists()
    assert not (tmp_path / "approvals.jsonl").exists()


def test_retired_profile_cannot_be_approved_into(tmp_path: Path, stub_capture):
    document = json.loads(ROLLED_OVER_BYTES)
    document.pop("signature", None)
    _profile(document, V1)["status"] = "retired"
    registry_path, signing_key = _write_inputs(
        tmp_path, canonical_json(sign_registry(document, REGISTRY_SEED))
    )

    with pytest.raises(SystemExit, match="not active"):
        approval_tool.main(
            _approve_argv(tmp_path, registry_path, signing_key, profile_id=V1)
        )
    assert stub_capture == []


def test_non_cpu_tdx_profile_is_refused(tmp_path: Path, stub_capture):
    document = json.loads(ROLLED_OVER_BYTES)
    document.pop("signature", None)
    _profile(document, V2)["kind"] = "gpu_cc"
    registry_path, signing_key = _write_inputs(
        tmp_path, canonical_json(sign_registry(document, REGISTRY_SEED))
    )

    with pytest.raises(SystemExit, match="not a CPU-TDX profile"):
        approval_tool.main(
            _approve_argv(tmp_path, registry_path, signing_key, profile_id=V2)
        )
    assert stub_capture == []


def test_duplicate_profile_ids_are_refused(tmp_path: Path, stub_capture):
    document = json.loads(ROLLED_OVER_BYTES)
    document.pop("signature", None)
    document["profiles"].append(json.loads(json.dumps(_profile(document, V2))))
    registry_path, signing_key = _write_inputs(
        tmp_path, canonical_json(sign_registry(document, REGISTRY_SEED))
    )

    with pytest.raises(SystemExit, match="more than once"):
        approval_tool.main(
            _approve_argv(tmp_path, registry_path, signing_key, profile_id=V2)
        )
    assert stub_capture == []


def test_measurement_already_present_names_the_profile(tmp_path: Path, stub_capture):
    document = json.loads(ROLLED_OVER_BYTES)
    document.pop("signature", None)
    _profile(document, V2)["measurements"] = sorted(
        set(_profile(document, V2)["measurements"]) | {NEW_MEASUREMENT}
    )
    registry_path, signing_key = _write_inputs(
        tmp_path, canonical_json(sign_registry(document, REGISTRY_SEED))
    )

    with pytest.raises(SystemExit, match=f"already present in profile '{V2}'"):
        approval_tool.main(
            _approve_argv(tmp_path, registry_path, signing_key, profile_id=V2)
        )
    # The duplicate is only detectable after the capture, so the probe runs;
    # what must not happen is a write.
    assert not (tmp_path / "registry.next.json").exists()


def test_profile_id_must_be_a_bounded_identifier(tmp_path: Path, stub_capture):
    registry_path, signing_key = _write_inputs(tmp_path)
    with pytest.raises(SystemExit, match="profile id must be"):
        approval_tool.main(
            _approve_argv(
                tmp_path, registry_path, signing_key, profile_id="../../etc/passwd"
            )
        )
    assert stub_capture == []


# ---------------------------------------------------------------------------
# The independent blast-radius guard
# ---------------------------------------------------------------------------

def test_blast_radius_guard_catches_a_mutation_that_widened(monkeypatch, tmp_path: Path):
    """If the mutation path ever touches a second profile, the tool refuses."""
    registry_path, signing_key = _write_inputs(tmp_path)

    def _sloppy_bump(registry, measurement, operator, reason, *, profile_id):
        document = {
            k: v for k, v in registry.items() if k not in ("signature", "signature_base64")
        }
        document["release"] = int(document["release"]) + 1
        for row in document["profiles"]:  # the bug this guard exists to catch
            row["measurements"] = sorted(set(row["measurements"]) | {measurement})
        return document

    monkeypatch.setattr(approval_tool, "_bump_release", _sloppy_bump)
    monkeypatch.setattr(
        approval_tool,
        "_capture",
        lambda *a: {
            "measurement": NEW_MEASUREMENT,
            "tcb_status": "UpToDate",
            "chip_id": "chip-abcdef0123456789",
        },
    )

    with pytest.raises(SystemExit, match="profiles it was not asked to change"):
        approval_tool.main(
            _approve_argv(tmp_path, registry_path, signing_key, profile_id=V2)
        )
    assert not (tmp_path / "registry.next.json").exists()


def test_blast_radius_guard_catches_an_added_or_removed_profile(monkeypatch, tmp_path: Path):
    registry_path, signing_key = _write_inputs(tmp_path)

    original = approval_tool._bump_release

    def _smuggles(registry, measurement, operator, reason, *, profile_id):
        document = original(registry, measurement, operator, reason, profile_id=profile_id)
        smuggled = json.loads(json.dumps(_profile(document, profile_id)))
        smuggled["id"] = "cpu-tdx-smuggled-v1"
        document["profiles"].append(smuggled)
        return document

    monkeypatch.setattr(approval_tool, "_bump_release", _smuggles)
    monkeypatch.setattr(
        approval_tool,
        "_capture",
        lambda *a: {
            "measurement": NEW_MEASUREMENT,
            "tcb_status": "UpToDate",
            "chip_id": "chip-abcdef0123456789",
        },
    )

    with pytest.raises(SystemExit, match="must not add or remove a profile"):
        approval_tool.main(
            _approve_argv(tmp_path, registry_path, signing_key, profile_id=V2)
        )
    assert not (tmp_path / "registry.next.json").exists()


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------

def test_show_lists_every_profile_not_just_the_first(tmp_path: Path, capsys):
    registry_path, _ = _write_inputs(tmp_path)
    assert approval_tool.main(["show", "--registry", str(registry_path)]) == 0
    out = capsys.readouterr().out
    assert f"profile {V1}" in out
    assert f"profile {V2}" in out
    assert "tdx-measurement-sha256:sample-v2" in out


def test_show_reports_an_approval_target(tmp_path: Path, stub_capture, capsys):
    registry_path, signing_key = _write_inputs(tmp_path)
    approval_tool.main(
        _approve_argv(tmp_path, registry_path, signing_key, profile_id=V2)
    )
    capsys.readouterr()

    assert approval_tool.main(
        ["show", "--registry", str(tmp_path / "registry.next.json")]
    ) == 0
    out = capsys.readouterr().out
    assert f"profile {V2} by test operator" in out
