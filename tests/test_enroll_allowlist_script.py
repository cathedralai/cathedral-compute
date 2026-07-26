"""The allowlist operator tool produces artifacts the registry accepts.

The gate is fail-closed on every artifact defect, so an unusable artifact is
indistinguishable from a revoked coldkey at the registry: it locks the
operator's own miner out. These tests prove the tool's output round-trips
through the exact verification path the enrollment registry and
``cathedral enroll reconcile`` run (cathedral/coldkey_allowlist.py), and that
its snapshot is the extended format from which the gate can resolve coldkeys.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from cathedral.coldkey_allowlist import (
    SignedColdkeyAllowlistProvider,
    load_allowlist_keys,
    verify_allowlist,
)
from cathedral.enroll import JsonHotkeyRegistrationProvider

_SPEC = importlib.util.spec_from_file_location(
    "cathedral_enroll_allowlist_tool",
    Path(__file__).resolve().parents[1] / "scripts" / "cathedral_enroll_allowlist.py",
)
allowlist_tool = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(allowlist_tool)

# The production coldkey/hotkey pair the first release must never lock out.
OPERATOR_COLDKEY = "5FEMxbMJTwhj1FVJN8ULjdZRXnVTw5WDK8VLRs39k7if9K1S"
OPERATOR_HOTKEY = "5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK"
OTHER_COLDKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
KEY_ID = "cathedral-enroll-allowlist-1"


def _printed(capsys) -> dict[str, str]:
    out = capsys.readouterr().out.splitlines()
    return dict(line.split(" ", 1) for line in out if " " in line)


def _keygen(tmp_path: Path, capsys) -> tuple[Path, Path, str]:
    seed_path = tmp_path / "enroll-allowlist-signing.key"
    keys_path = tmp_path / "enroll-allowlist-keys.json"
    assert (
        allowlist_tool.main(
            [
                "keygen",
                "--signing-key-id",
                KEY_ID,
                "--signing-key-out",
                str(seed_path),
                "--keys-out",
                str(keys_path),
            ]
        )
        == 0
    )
    fields = _printed(capsys)
    return seed_path, keys_path, fields["allowlist_keys_digest"]


def _sign(tmp_path: Path, capsys, seed_path: Path, *extra: str, name: str = "allowlist.json"):
    out = tmp_path / name
    assert (
        allowlist_tool.main(
            [
                "sign",
                "--signing-key-file",
                str(seed_path),
                "--signing-key-id",
                KEY_ID,
                "--release",
                "1",
                "--coldkey",
                OPERATOR_COLDKEY,
                "--out",
                str(out),
                *extra,
            ]
        )
        == 0
    )
    return out, _printed(capsys)


def test_signed_release_round_trips_through_the_registry_verifier(tmp_path, capsys):
    seed_path, keys_path, keys_digest = _keygen(tmp_path, capsys)
    artifact, fields = _sign(tmp_path, capsys, seed_path)

    # Exactly what the registry does at startup and on every request.
    trusted = load_allowlist_keys(str(keys_path), production_mode=True, pinned_digest=keys_digest)
    snapshot = verify_allowlist(artifact.read_bytes(), trusted)

    assert snapshot.release == 1
    assert snapshot.signing_key_id == KEY_ID
    assert snapshot.coldkeys == frozenset({OPERATOR_COLDKEY})
    # The printed digest is what the operator pins; a mismatch would mean the
    # registry rejects the artifact it was just handed.
    assert snapshot.digest == fields["allowlist_digest"]
    assert fields["allowlist_release"] == "1"
    assert artifact.stat().st_mode & 0o077 == 0o044
    assert seed_path.stat().st_mode & 0o077 == 0

    provider = SignedColdkeyAllowlistProvider(
        str(artifact), trusted, pinned_digest=fields["allowlist_digest"]
    )
    assert provider.is_allowed(OPERATOR_COLDKEY) is True
    assert provider.is_allowed(OTHER_COLDKEY) is False


def test_signed_document_carries_the_documented_shape(tmp_path, capsys):
    seed_path, _keys_path, _digest = _keygen(tmp_path, capsys)
    artifact, _fields = _sign(tmp_path, capsys, seed_path, "--valid-days", "30")

    document = json.loads(artifact.read_text())
    assert set(document) == {
        "schema",
        "release",
        "generated_at",
        "valid_from",
        "valid_until",
        "signing_key_id",
        "coldkeys",
        "signature",
    }
    assert document["schema"] == "cathedral_coldkey_allowlist_v1"
    assert document["signature"]["algorithm"] == "ed25519"
    assert document["valid_from"] < document["valid_until"]


def test_pinned_digest_rejects_a_resigned_release(tmp_path, capsys):
    """Rotation invalidates the artifact pin, which is what makes revocation
    durable: the operator must restart with the new digest."""
    seed_path, keys_path, keys_digest = _keygen(tmp_path, capsys)
    first, first_fields = _sign(tmp_path, capsys, seed_path)
    trusted = load_allowlist_keys(str(keys_path), pinned_digest=keys_digest)

    rotated = tmp_path / "allowlist-2.json"
    assert (
        allowlist_tool.main(
            [
                "sign",
                "--signing-key-file",
                str(seed_path),
                "--signing-key-id",
                KEY_ID,
                "--release",
                "2",
                "--coldkey",
                OPERATOR_COLDKEY,
                "--coldkey",
                OTHER_COLDKEY,
                "--out",
                str(rotated),
            ]
        )
        == 0
    )
    rotated_digest = _printed(capsys)["allowlist_digest"]
    assert rotated_digest != first_fields["allowlist_digest"]

    stale_pin = SignedColdkeyAllowlistProvider(
        str(rotated), trusted, pinned_digest=first_fields["allowlist_digest"]
    )
    assert stale_pin.is_allowed(OPERATOR_COLDKEY) is None  # fails closed
    assert first.exists()

    fresh_pin = SignedColdkeyAllowlistProvider(str(rotated), trusted, pinned_digest=rotated_digest)
    assert fresh_pin.is_allowed(OTHER_COLDKEY) is True


def test_verify_enforces_the_pin_and_the_operator_coldkey(tmp_path, capsys):
    seed_path, keys_path, keys_digest = _keygen(tmp_path, capsys)
    artifact, fields = _sign(tmp_path, capsys, seed_path)
    common = [
        "verify",
        "--allowlist",
        str(artifact),
        "--allowlist-keys",
        str(keys_path),
        "--allowlist-keys-digest",
        keys_digest,
    ]

    assert (
        allowlist_tool.main(
            [*common, "--expect-digest", fields["allowlist_digest"], "--expect-coldkey",
             OPERATOR_COLDKEY]
        )
        == 0
    )
    with pytest.raises(SystemExit, match="does not match the pin"):
        allowlist_tool.main([*common, "--expect-digest", "sha256:" + "0" * 64])
    with pytest.raises(SystemExit, match="absent from the allowlist"):
        allowlist_tool.main([*common, "--expect-coldkey", OTHER_COLDKEY])


def test_sign_refuses_an_accidental_empty_allowlist(tmp_path, capsys):
    seed_path, _keys_path, _digest = _keygen(tmp_path, capsys)
    with pytest.raises(SystemExit, match="--allow-empty"):
        allowlist_tool.main(
            [
                "sign",
                "--signing-key-file",
                str(seed_path),
                "--signing-key-id",
                KEY_ID,
                "--release",
                "1",
                "--out",
                str(tmp_path / "empty.json"),
            ]
        )
    assert not (tmp_path / "empty.json").exists()


def test_sign_refuses_a_group_readable_seed(tmp_path, capsys):
    seed_path, _keys_path, _digest = _keygen(tmp_path, capsys)
    seed_path.chmod(0o640)
    with pytest.raises(SystemExit, match="group/world accessible"):
        _sign(tmp_path, capsys, seed_path)


def test_snapshot_is_the_extended_format_the_gate_resolves(tmp_path, monkeypatch, capsys):
    output = tmp_path / "registered-hotkeys.json"
    pairs = [(OPERATOR_HOTKEY, OPERATOR_COLDKEY), (OTHER_COLDKEY, OTHER_COLDKEY)]
    monkeypatch.setattr(allowlist_tool, "_capture_metagraph", lambda network, netuid: (42, pairs))

    assert (
        allowlist_tool.main(
            [
                "snapshot",
                "--network",
                "finney",
                "--netuid",
                "39",
                "--output",
                str(output),
                "--require-hotkey",
                OPERATOR_HOTKEY,
            ]
        )
        == 0
    )

    provider = JsonHotkeyRegistrationProvider(str(output), max_age_seconds=3600)
    assert provider.is_registered(OPERATOR_HOTKEY) is True
    assert provider.resolve_coldkey(OPERATOR_HOTKEY) == OPERATOR_COLDKEY
    assert provider.resolve_coldkey("5" + "z" * 47) is None
    assert json.loads(output.read_text())["block"] == 42


def test_snapshot_aborts_when_a_required_hotkey_is_missing(tmp_path, monkeypatch):
    output = tmp_path / "registered-hotkeys.json"
    output.write_text(json.dumps({"hotkeys": {OPERATOR_HOTKEY: OPERATOR_COLDKEY}}))
    before = output.read_bytes()
    monkeypatch.setattr(
        allowlist_tool,
        "_capture_metagraph",
        lambda network, netuid: (43, [(OTHER_COLDKEY, OTHER_COLDKEY)]),
    )
    with pytest.raises(SystemExit, match="required hotkeys absent"):
        allowlist_tool.main(
            [
                "snapshot",
                "--network",
                "finney",
                "--netuid",
                "39",
                "--output",
                str(output),
                "--require-hotkey",
                OPERATOR_HOTKEY,
            ]
        )
    # The previous good snapshot must survive a failed rotation.
    assert output.read_bytes() == before
