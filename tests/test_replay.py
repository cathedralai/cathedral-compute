"""Raw-evidence replay through a real subprocess verifier fixture.

The fake verifier is an actual executable invoked by the canonical bounded
subprocess path with the production argv contract; its claims derive from
the quote bytes, so every strict parent-process gate is exercised for real.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from cathedral.common import Evidence, EvidenceKind, evidence_report_data
from cathedral.replay import (
    ReplayError,
    parse_envelope,
    replay_evidence,
)
from cathedral.runtime import _evidence_digest, _retained_evidence_envelope
from cathedral.verify import tdx_implementation_digest_from_bytes
from tests.test_evidence import NOW, SNAPSHOT

MEASUREMENT = "tdx-measurement-sha256:sample-v1"
DECLARED = ("/opt/cathedral/bin/cathedral-tdx-verifier-test",)
POLICY = SNAPSHOT.to_policy(at=NOW)

VERIFIER_SCRIPT = b"""#!/usr/bin/env python3
import json, sys
quote = json.load(open(sys.argv[1]))
claims = dict(quote["claims"])
claims["report_data"] = quote["report_data_hex"]
claims["report_data_match"] = sys.argv[2] == quote["report_data_hex"]
print(json.dumps(claims))
"""


def _full_claims(**overrides):
    claims = {
        "intel_verified": True,
        "measurement": MEASUREMENT,
        "tcb_status": "UpToDate",
        "advisory_ids": [],
        "debug_enabled": False,
        "collateral_current": True,
        "platform_identity_kind": "stable",
        "platform_identity_verified": True,
        "claims_bound_to_quote": True,
        "stable_platform_id": "tdx-platform-sha256:" + "c" * 64,
        "platform_id": "tdx-platform-sha256:" + "c" * 64,
        "tdx_pck_cert_id": "tdx-pck-cert-sha256:" + "d" * 64,
        "tdx_attestation_key_id": "tdx-ak-sha256:" + "e" * 64,
        "tcb_svn": "01" * 16,
    }
    claims.update(overrides)
    return claims


def _evidence_and_envelope(claims: dict, *, wrong_nonce: bool = False):
    nonce = b"\x21" * 32
    seed = Evidence(
        kind=EvidenceKind.TDX,
        quote=b"placeholder",
        nonce=nonce,
        miner_hotkey="tdx-miner",
    )
    expected = evidence_report_data(seed, nonce)
    embedded = expected if not wrong_nonce else b"\x00" * 64
    quote = json.dumps(
        {"claims": claims, "report_data_hex": embedded.hex()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    evidence = Evidence(
        kind=EvidenceKind.TDX,
        quote=quote,
        nonce=nonce,
        miner_hotkey="tdx-miner",
    )
    digest = _evidence_digest(evidence)
    envelope = _retained_evidence_envelope((evidence,), digest)
    return envelope, digest


def _replay(tmp_path: Path, claims: dict, *, wrong_nonce: bool = False, **overrides):
    """Drive the full replay pipeline with authentication stubbed: these
    cases prove the CANONICAL execution gates; authentication has its own
    ELF-shape adversarial matrix below (test_verifier_authentication_*)."""
    envelope, evidence_digest = _evidence_and_envelope(claims, wrong_nonce=wrong_nonce)
    import hashlib

    envelope_digest = "sha256:" + hashlib.sha256(envelope).hexdigest()
    blob_digest = "sha256:" + hashlib.sha256(VERIFIER_SCRIPT).hexdigest()
    implementation = "sha256:" + "0" * 64  # authentication is stubbed here
    component = json.loads(envelope)["components"][0]
    quote_digest = (
        "sha256:" + hashlib.sha256(base64.b64decode(component["quote_base64"])).hexdigest()
    )
    challenge_digest = (
        "sha256:" + hashlib.sha256(base64.b64decode(component["nonce_base64"])).hexdigest()
    )
    arguments = {
        "expected_envelope_digest": envelope_digest,
        "expected_evidence_digest": evidence_digest,
        "expected_hotkey": "tdx-miner",
        "expected_measurement": MEASUREMENT,
        "expected_quote_digest": quote_digest,
        "expected_challenge_digest": challenge_digest,
        "verifier_binary": VERIFIER_SCRIPT,
        "verifier_blob_digest": blob_digest,
        "verifier_command": DECLARED,
        "verifier_artifacts": DECLARED,
        "verifier_implementation_digest": implementation,
        "policy": POLICY,
    }
    arguments.update(overrides)
    from unittest import mock

    with mock.patch("cathedral.replay.authenticate_verifier_bytes"):
        return replay_evidence(envelope, **arguments)


def test_full_claims_replay_passes(tmp_path: Path):
    verdict = _replay(tmp_path, _full_claims())
    assert verdict.measurement == MEASUREMENT
    assert verdict.hotkey == "tdx-miner"
    assert verdict.tcb_status == "UpToDate"


@pytest.mark.parametrize(
    "override",
    [
        {"intel_verified": False},
        {"measurement": "tdx-measurement-sha256:unknown"},
        {"tcb_status": "OutOfDate"},
        {"debug_enabled": True},
        {"collateral_current": False},
        {"claims_bound_to_quote": False},
        {"platform_identity_verified": False},
        {"platform_identity_kind": "ephemeral"},
        {"stable_platform_id": None},
        {"tdx_pck_cert_id": None},
        {"tdx_attestation_key_id": None},
        {"tcb_svn": "zz"},
        {"advisory_ids": ["INTEL-SA-0001"]},
    ],
)
def test_each_strict_claim_gate_fails_closed(tmp_path: Path, override):
    claims = _full_claims(**{k: v for k, v in override.items() if v is not None})
    for key, value in override.items():
        if value is None:
            claims.pop(key, None)
    with pytest.raises(ReplayError, match="canonical strict verification rejected"):
        _replay(tmp_path, claims)


def test_report_data_binding_mismatch_fails(tmp_path: Path):
    with pytest.raises(ReplayError, match="canonical strict verification rejected"):
        _replay(tmp_path, _full_claims(), wrong_nonce=True)


def test_measurement_must_match_the_receipt(tmp_path: Path):
    with pytest.raises(ReplayError, match="does not match the receipt measurement"):
        _replay(
            tmp_path,
            _full_claims(),
            expected_measurement="tdx-measurement-sha256:other",
        )


def test_wrong_hotkey_and_tampered_envelope_fail(tmp_path: Path):
    with pytest.raises(ReplayError, match="receipt subject"):
        _replay(tmp_path, _full_claims(), expected_hotkey="somebody-else")

    envelope, evidence_digest = _evidence_and_envelope(_full_claims())
    import hashlib

    good_digest = "sha256:" + hashlib.sha256(envelope).hexdigest()
    tampered = envelope.replace(b"tdx-miner", b"tdx-thief", 1)
    with pytest.raises(ReplayError, match="do not match the published manifest"):
        parse_envelope(
            tampered,
            expected_envelope_digest=good_digest,
            expected_evidence_digest=evidence_digest,
        )


def test_verifier_binary_pins_are_both_enforced():
    import hashlib

    from cathedral.replay import authenticate_verifier_bytes

    elf = _static_elf()
    implementation = tdx_implementation_digest_from_bytes(DECLARED, DECLARED, {DECLARED[0]: elf})
    with pytest.raises(ReplayError, match="pinned content digest"):
        authenticate_verifier_bytes(
            elf + b"\x00trojan",
            expected_blob_digest="sha256:" + hashlib.sha256(elf).hexdigest(),
            declared_command=DECLARED,
            declared_artifacts=DECLARED,
            expected_implementation_digest=implementation,
        )
    with pytest.raises(ReplayError, match="implementation digest"):
        authenticate_verifier_bytes(
            elf,
            expected_blob_digest="sha256:" + hashlib.sha256(elf).hexdigest(),
            declared_command=("/usr/local/bin/other",),
            declared_artifacts=("/usr/local/bin/other",),
            expected_implementation_digest=implementation,
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc.__setitem__("extra", 1),  # unknown envelope key
        lambda doc: doc["components"][0].__setitem__("composite_jwt", "a.b.c"),
        lambda doc: doc["components"][0].pop("nonce_base64"),
        lambda doc: doc["components"][0].__setitem__("cert_chain_base64", [123]),
        lambda doc: doc["components"][0].__setitem__("cert_chain_base64", ["QQ=="] * 9),
    ],
)
def test_envelope_parser_rejects_malformed_documents(mutate):
    import hashlib

    envelope, evidence_digest = _evidence_and_envelope(_full_claims())
    document = json.loads(envelope)
    mutate(document)
    rebuilt = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ReplayError):
        parse_envelope(
            rebuilt,
            expected_envelope_digest="sha256:" + hashlib.sha256(rebuilt).hexdigest(),
            expected_evidence_digest=evidence_digest,
        )


def test_envelope_parser_rejects_noncanonical_and_duplicate_keys():
    import hashlib

    envelope, evidence_digest = _evidence_and_envelope(_full_claims())
    pretty = json.dumps(json.loads(envelope), indent=2).encode()
    with pytest.raises(ReplayError, match="canonical"):
        parse_envelope(
            pretty,
            expected_envelope_digest="sha256:" + hashlib.sha256(pretty).hexdigest(),
            expected_evidence_digest=evidence_digest,
        )
    duplicated = envelope.replace(b'"schema":', b'"schema":"x","schema":', 1)
    with pytest.raises(ReplayError, match="strict JSON|duplicate"):
        parse_envelope(
            duplicated,
            expected_envelope_digest="sha256:" + hashlib.sha256(duplicated).hexdigest(),
            expected_evidence_digest=evidence_digest,
        )


# ---------------------------------------------------------------------------
# Verifier-bytes authentication: canonical config + static-ELF enforcement
# ---------------------------------------------------------------------------


def _static_elf(*, machine=62, elf_type=2, ptypes=(1,)) -> bytes:
    """Craft a minimal structurally valid static x86-64 ELF64 image."""
    import struct

    count = len(ptypes)
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4:7] = b"\x02\x01\x01"
    struct.pack_into("<HH", header, 16, elf_type, machine)
    struct.pack_into("<Q", header, 32, 64)  # program header offset
    struct.pack_into("<HH", header, 54, 56, count)  # entry size, count
    body = bytearray()
    for ptype in ptypes:
        entry = bytearray(56)
        struct.pack_into("<I", entry, 0, ptype)
        body += entry
    return bytes(header) + bytes(body)


def test_verifier_authentication_accepts_a_static_elf():
    import hashlib

    from cathedral.replay import authenticate_verifier_bytes

    elf = _static_elf()
    implementation = tdx_implementation_digest_from_bytes(DECLARED, DECLARED, {DECLARED[0]: elf})
    authenticate_verifier_bytes(
        elf,
        expected_blob_digest="sha256:" + hashlib.sha256(elf).hexdigest(),
        declared_command=DECLARED,
        declared_artifacts=DECLARED,
        expected_implementation_digest=implementation,
    )


@pytest.mark.parametrize(
    "binary",
    [
        b"#!/usr/bin/env python3\nprint()",  # script
        b"",  # empty
        _static_elf(machine=183),  # aarch64, wrong arch
        _static_elf(elf_type=3),  # ET_DYN
        _static_elf(ptypes=(1, 3)),  # PT_INTERP
        _static_elf(ptypes=(2,)),  # PT_DYNAMIC
    ],
)
def test_verifier_authentication_rejects_non_static_elves(binary):

    with pytest.raises(ValueError, match="static x86-64|invalid|empty"):
        tdx_implementation_digest_from_bytes(DECLARED, DECLARED, {DECLARED[0]: binary})


@pytest.mark.parametrize(
    "command",
    [
        ("relative/path",),
        ("/abs/with\nnewline",),
        ("/abs/with\x00nul",),
        ("/abs/secret-token-tool",),
        ("/a", "/b"),
    ],
)
def test_verifier_authentication_rejects_bad_configurations(command):

    with pytest.raises(ValueError):
        tdx_implementation_digest_from_bytes(
            tuple(command), tuple(command), {p: _static_elf() for p in command}
        )


def test_full_chain_refuses_a_script_verifier_without_stubs(tmp_path: Path):
    """The unbypassed pipeline must refuse to bless the script fixture."""
    envelope, evidence_digest = _evidence_and_envelope(_full_claims())
    import hashlib

    component = json.loads(envelope)["components"][0]
    quote_digest = (
        "sha256:" + hashlib.sha256(base64.b64decode(component["quote_base64"])).hexdigest()
    )
    challenge_digest = (
        "sha256:" + hashlib.sha256(base64.b64decode(component["nonce_base64"])).hexdigest()
    )
    with pytest.raises(ReplayError, match="static x86-64|implementation"):
        replay_evidence(
            envelope,
            expected_envelope_digest="sha256:" + hashlib.sha256(envelope).hexdigest(),
            expected_evidence_digest=evidence_digest,
            expected_hotkey="tdx-miner",
            expected_measurement=MEASUREMENT,
            expected_quote_digest=quote_digest,
            expected_challenge_digest=challenge_digest,
            verifier_binary=VERIFIER_SCRIPT,
            verifier_blob_digest="sha256:" + hashlib.sha256(VERIFIER_SCRIPT).hexdigest(),
            verifier_command=DECLARED,
            verifier_artifacts=DECLARED,
            verifier_implementation_digest="sha256:" + "0" * 64,
            policy=POLICY,
        )


def test_receipt_quote_digest_cross_binding_rejects_swapped_envelope(tmp_path: Path):
    """Counterexample 1: a receipt whose signed hardware claim hashes quote A
    must never replay against a different (internally valid) envelope B."""
    with pytest.raises(ReplayError, match="signed hardware"):
        _replay(
            tmp_path,
            _full_claims(),
            expected_quote_digest="sha256:" + "b" * 64,  # receipt bound to A
        )


def test_zero_positive_miners_never_full(tmp_path: Path):
    """Counterexample 2: an epoch with no positive miners has nothing raw to
    authenticate; assurance must stay receipts_only."""
    from cathedral.provenance import (
        ASSURANCE_RECEIPTS_ONLY,
        ProvenanceResult,
        replay_positive_miners,
    )
    from tests.test_evidence import SNAPSHOT

    result = ProvenanceResult(
        report_id="sha256:" + "1" * 64,
        previous_report_id=None,
        signing_key_id="score-test-1",
        policy_release=1,
        policy_digest=SNAPSHOT.digest,
        verifier_digest="sha256:" + "d" * 64,
        mechanism_id="validated_supply_v2",
        source_epoch=11,
        generated_at="2026-07-24T00:00:00.000000Z",
        valid_until="2026-07-24T01:00:00.000000Z",
        candidate_snapshot={
            "digest": "sha256:" + "5" * 64,
            "block": 100,
            "block_hash": "ab" * 32,
            "hotkeys": ["zero-hotkey"],
        },
        miners=[],
        recomputed_hotkey_weights={},
    )
    from unittest import mock

    # The pinned verifier bytes are still authenticated on a zero-replay
    # epoch (stubbed here; the real authentication matrix lives below).
    with mock.patch("cathedral.replay.authenticate_verifier_bytes"):
        upgraded = replay_positive_miners(
            result,
            registry=SNAPSHOT,
            envelopes_by_hotkey={},
            attestation_bindings={},
            verifier_binary=_static_elf(),
            verifier_blob_digest="sha256:" + "2" * 64,
            verifier_command=DECLARED,
            verifier_artifacts=DECLARED,
            candidate_outcomes={"zero-hotkey": "rejected"},
            independent_candidates={"zero-hotkey"},
            independent_block_hash="0x" + "ab" * 32,
        )
    assert upgraded.assurance_level == ASSURANCE_RECEIPTS_ONLY
    assert upgraded.not_proven_reasons


def test_stale_envelope_nonce_rejected_by_committed_challenge(tmp_path: Path):
    """Counterexample C: an envelope whose nonce does not reproduce the
    epoch's committed challenge randomness must never replay."""
    with pytest.raises(ReplayError, match="committed challenge"):
        _replay(
            tmp_path,
            _full_claims(),
            expected_challenge_digest="sha256:" + "9" * 64,  # other epoch
        )


# ---------------------------------------------------------------------------
# Sub-second replay budget (Codex finding 9)
# ---------------------------------------------------------------------------


def test_sub_second_replay_budget_is_preserved_to_the_subprocess(monkeypatch):
    """A 0.4s remaining command budget must reach the subprocess as 0.4s.
    The old int() floor plus max(1, ...) re-inflated any sub-second
    remainder to a full second, extending the caller's absolute deadline."""
    from cathedral import verify as verify_module

    captured: dict = {}

    def spy(cmd, max_output, timeout, **kwargs):
        captured["timeout"] = timeout
        return "{}", "", 0

    monkeypatch.setattr(verify_module, "_read_bounded_subprocess", spy)
    verify_module._run_tdx_verifier(
        b"quote-bytes",
        production_mode=True,
        expected_report_data=bytes(64),
        pinned_command=["/opt/cathedral/bin/verifier"],
        pinned_timeout=0.4,
    )
    assert captured["timeout"] == pytest.approx(0.4)
    assert captured["timeout"] < 1.0  # the exact prior inflation


def test_exhausted_replay_budget_refuses_without_launching(monkeypatch):
    """Zero, negative, or non-finite remaining budget rejects IMMEDIATELY:
    the verifier subprocess is never spawned on an exhausted deadline."""
    from cathedral import verify as verify_module

    def never(cmd, max_output, timeout, **kwargs):
        raise AssertionError("subprocess must never launch with no budget")

    monkeypatch.setattr(verify_module, "_read_bounded_subprocess", never)
    for exhausted in (0.0, -1.0, float("nan"), float("-inf"), float("inf"), True):
        claims = verify_module._run_tdx_verifier(
            b"quote-bytes",
            production_mode=True,
            expected_report_data=bytes(64),
            pinned_command=["/opt/cathedral/bin/verifier"],
            pinned_timeout=exhausted,
        )
        assert claims == {}


def test_sub_second_timeout_kills_a_slow_verifier_promptly(tmp_path, monkeypatch):
    """End-to-end wall clock: with 0.3s of budget a 5s verifier dies at
    ~0.3s. Under the old rounding it survived a full second."""
    import time

    from cathedral import verify as verify_module

    slow = tmp_path / "slow-verifier"
    slow.write_text("#!/bin/sh\nsleep 5\n")
    slow.chmod(0o700)

    started = time.monotonic()
    claims = verify_module._run_tdx_verifier(
        b"quote-bytes",
        production_mode=True,
        expected_report_data=bytes(64),
        pinned_command=[str(slow)],
        pinned_timeout=0.3,
    )
    elapsed = time.monotonic() - started
    assert claims == {}
    assert elapsed < 0.9, elapsed
