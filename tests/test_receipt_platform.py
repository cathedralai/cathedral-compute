"""The optional `platform` top-level extension point of receipt v2.

Cross-repo contract: cathedral-distill's compute receipts extend
`cathedral_assurance_receipt_v2` with exactly one top-level `platform` block
naming the confidential CPU TEE. This repo's parser previously did
`frozenset(document) != _TOP_KEYS -> reject`, so neither lane could ever admit
the other's receipts. These tests pin the reconciliation:

  * receipts WITHOUT `platform` are byte-for-byte unchanged and still verify,
    v1 and v2 alike (the golden fixtures are the proof);
  * `platform` is version-2 only: v1 plus `platform` fails;
  * with `platform` the block is accepted only as exactly
    `{"class": "confidential_cpu", "cpu_tee": "intel_tdx"}`. No arbitrary
    nested data, no composite GPU evidence, no plain SEV, and no SEV-SNP,
    because this repo validates an Intel TDX measurement and TCB body only;
  * `platform` is the ONLY tolerated extension; any other unknown top-level
    key still fails closed;
  * `platform` is covered by receipt_id and the signature, so mutating it
    without recomputing the id fails, and recomputing the id without
    resigning fails.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cathedral.common import Tier
from cathedral.policy_registry import canonical_json
from cathedral.receipt import ReceiptError, verify_receipt

from tests.test_receipt import _issued_receipt, _reidentify, _resign, _snapshot

CPU_PLATFORM = {"class": "confidential_cpu", "cpu_tee": "intel_tdx"}
V1_FIXTURE = Path("tests/fixtures/assurance-receipt-v1.json")
V2_FIXTURE = Path("tests/fixtures/assurance-receipt-v2.json")


def _extended(platform: object) -> tuple[object, bytes]:
    """A genuine issued receipt with `platform` added and re-signed."""
    snapshot, _policy, _claims, receipt = _issued_receipt()
    document = json.loads(receipt.receipt_bytes)
    document["platform"] = platform
    return snapshot, _resign(document)


# --- minimum test 1: the existing fixtures stay valid, byte for byte -------- #


def test_platform_less_v2_fixture_remains_valid_and_unchanged():
    snapshot, _policy, _claims, receipt = _issued_receipt()
    verified = verify_receipt(receipt.receipt_bytes, snapshot)
    assert "platform" not in verified.document
    # The golden fixture pins the exact pre-extension bytes: making `platform`
    # optional changed nothing for a receipt that does not carry it.
    assert V2_FIXTURE.read_bytes().rstrip(b"\n") == receipt.receipt_bytes
    assert verify_receipt(V2_FIXTURE.read_bytes().rstrip(b"\n"), snapshot).receipt_id == (
        receipt.receipt_id
    )


def test_platform_less_v1_fixture_remains_valid():
    verified = verify_receipt(V1_FIXTURE.read_bytes().rstrip(b"\n"), _snapshot())
    assert verified.document["schema"] == "cathedral_assurance_receipt_v1"
    assert "platform" not in verified.document


# --- minimum test 2: v1 plus platform fails -------------------------------- #


def test_platform_on_the_legacy_v1_schema_is_rejected():
    document = json.loads(V1_FIXTURE.read_bytes().rstrip(b"\n"))
    document["platform"] = dict(CPU_PLATFORM)
    with pytest.raises(ReceiptError, match="requires schema version 2"):
        verify_receipt(_resign(document), _snapshot())


# --- minimum test 3: a real issued v2 with the exact CPU-TDX platform ------ #


def test_exact_cpu_tdx_platform_block_verifies_and_round_trips():
    snapshot, receipt_bytes = _extended(dict(CPU_PLATFORM))
    verified = verify_receipt(receipt_bytes, snapshot)
    assert verified.document["platform"] == CPU_PLATFORM
    assert verified.receipt_bytes == receipt_bytes
    assert verified.receipt_digest == "sha256:" + hashlib.sha256(receipt_bytes).hexdigest()


# --- minimum test 6: unknown top-level and nested keys, TEE/class conflicts - #


def test_platform_plus_any_other_unknown_top_level_key_is_rejected():
    snapshot, _policy, _claims, receipt = _issued_receipt()
    document = json.loads(receipt.receipt_bytes)
    document["platform"] = dict(CPU_PLATFORM)
    document["evaluation"] = {"schema": "cathedral_distill_evaluation_v1"}
    with pytest.raises(ReceiptError, match="missing, unknown, or unsupported"):
        verify_receipt(_resign(document), snapshot)


def test_unknown_top_level_key_without_platform_is_still_rejected():
    snapshot, _policy, _claims, receipt = _issued_receipt()
    document = json.loads(receipt.receipt_bytes)
    document["extension"] = {}
    with pytest.raises(ReceiptError, match="missing, unknown, or unsupported"):
        verify_receipt(_resign(document), snapshot)


@pytest.mark.parametrize(
    ("platform", "match"),
    [
        ("confidential_cpu", "must be an object"),
        ([], "must be an object"),
        (17, "must be an object"),
        (None, "must be an object"),
        ({}, "platform keys are invalid"),
        ({"class": "gpu_only", "cpu_tee": "intel_tdx"}, "class is unsupported"),
        # A composite confidential-GPU block asserts GPU evidence this repo
        # does not verify inside a receipt: refused, not silently accepted.
        (
            {
                "class": "confidential_gpu",
                "cpu_tee": "intel_tdx",
                "gpu": {
                    "cc_mode": "on",
                    "vbios_measurement": "sha256:" + "1" * 64,
                    "attestation_report_digest": "sha256:" + "2" * 64,
                    "bound_measurement": "tdx-measurement-sha256:sample-v1",
                },
            },
            "platform keys are invalid",
        ),
        ({"class": "confidential_gpu", "cpu_tee": "intel_tdx"}, "class is unsupported"),
        # Unknown nested key, missing nested key, and nested arbitrary data.
        (
            {"class": "confidential_cpu", "cpu_tee": "intel_tdx", "extra": 1},
            "platform keys are invalid",
        ),
        ({"class": "confidential_cpu"}, "platform keys are invalid"),
        ({"cpu_tee": "intel_tdx"}, "platform keys are invalid"),
        (
            {"class": "confidential_cpu", "cpu_tee": "intel_tdx", "gpu": {}},
            "platform keys are invalid",
        ),
    ],
)
def test_malformed_platform_blocks_fail_closed(platform, match):
    snapshot, receipt_bytes = _extended(platform)
    with pytest.raises(ReceiptError, match=match):
        verify_receipt(receipt_bytes, snapshot)


@pytest.mark.parametrize("bad_class", [[], {}, 1, True, None, "", "CONFIDENTIAL_CPU"])
def test_a_non_string_platform_class_fails_as_a_typed_receipt_error(bad_class):
    # Regression: `class` was membership-tested before its type, so an
    # unhashable value raised TypeError out of the verifier instead of a
    # ReceiptError. Platform validation runs before receipt-id and signature
    # verification, so this is unsigned attacker-controlled input: it must
    # never escape the typed error boundary.
    snapshot, receipt_bytes = _extended({"class": bad_class, "cpu_tee": "intel_tdx"})
    with pytest.raises(ReceiptError, match="class is unsupported"):
        verify_receipt(receipt_bytes, snapshot)


@pytest.mark.parametrize("bad_tee", [[], {}, 1, True, None])
def test_a_non_string_platform_cpu_tee_fails_as_a_typed_receipt_error(bad_tee):
    snapshot, receipt_bytes = _extended(
        {"class": "confidential_cpu", "cpu_tee": bad_tee}
    )
    with pytest.raises(ReceiptError, match="not in the attestable set"):
        verify_receipt(receipt_bytes, snapshot)


def test_no_platform_shape_escapes_the_typed_error_boundary():
    # Sweep the whole malformed cross-product and assert the ONLY exception
    # type that can reach a caller is ReceiptError.
    values = [[], {}, 1, True, None, "", "x", 1.5, [{"a": 1}], {"a": ["b"]}]
    snapshot = _snapshot()
    for key in ("class", "cpu_tee"):
        for value in values:
            block = dict(CPU_PLATFORM)
            block[key] = value
            _snapshot_value, receipt_bytes = _extended(block)
            with pytest.raises(ReceiptError):
                verify_receipt(receipt_bytes, snapshot)


# --- D5: plain SEV and anything outside the attestable set are rejected ----- #


@pytest.mark.parametrize(
    "cpu_tee",
    ["amd_sev", "", None, "AMD_SEV_SNP", "sgx", "intel_tdx2", "intel_sgx", 1, True, {}],
)
def test_cpu_tee_outside_the_attestable_set_is_rejected(cpu_tee):
    # The live G4 GCP profile emits plain "amd_sev": no attestation interface
    # at all. It must never be admitted, and nothing outside the attestable
    # set is recognized either.
    snapshot, receipt_bytes = _extended(
        {"class": "confidential_cpu", "cpu_tee": cpu_tee}
    )
    with pytest.raises(ReceiptError, match="not in the attestable set"):
        verify_receipt(receipt_bytes, snapshot)


def test_sev_snp_is_attestable_but_still_refused_without_a_sev_body_grammar():
    # "amd_sev_snp" is attestable in the cross-repo contract, but this repo's
    # measurement and TCB grammar is Intel TDX only, so the label would not
    # describe the body that was validated. Fail closed instead of weakening
    # the TDX requirements to let it through.
    snapshot, receipt_bytes = _extended(
        {"class": "confidential_cpu", "cpu_tee": "amd_sev_snp"}
    )
    with pytest.raises(ReceiptError, match="evidence grammar"):
        verify_receipt(receipt_bytes, snapshot)


# --- minimum test 7: mutation without re-ID, re-ID without resigning ------- #


def test_platform_mutation_without_recomputing_the_receipt_id_fails():
    snapshot, receipt_bytes = _extended(dict(CPU_PLATFORM))
    document = json.loads(receipt_bytes)
    document["platform"]["cpu_tee"] = "amd_sev"
    # Fails closed on the value itself; the stale id and signature below are
    # pinned separately with a platform block that is valid on its face, so
    # the identity binding is proved independently of validation order.
    with pytest.raises(ReceiptError, match="not in the attestable set"):
        verify_receipt(canonical_json(document), snapshot)
    _reidentify(document)
    with pytest.raises(ReceiptError, match="not in the attestable set"):
        verify_receipt(canonical_json(document), snapshot)


def test_a_valid_platform_block_with_a_stale_receipt_id_fails():
    # receipt_id is computed over the canonical body including `platform`, so
    # the platform-less receipt's id cannot identify the extended body.
    snapshot, _policy, _claims, receipt = _issued_receipt()
    plain = json.loads(receipt.receipt_bytes)
    document = json.loads(_extended(dict(CPU_PLATFORM))[1])
    document["receipt_id"] = plain["receipt_id"]
    with pytest.raises(ReceiptError, match="does not match its canonical body"):
        verify_receipt(canonical_json(document), snapshot)


def test_a_valid_platform_block_with_a_stale_signature_fails():
    # The signature covers every field except itself, `platform` included: a
    # correctly recomputed id over the extended body plus the platform-less
    # signature is exactly "re-ID without resigning" and must fail.
    snapshot, _policy, _claims, receipt = _issued_receipt()
    plain = json.loads(receipt.receipt_bytes)
    document = json.loads(_extended(dict(CPU_PLATFORM))[1])
    document["signature"] = plain["signature"]
    with pytest.raises(ReceiptError, match="signature verification failed"):
        verify_receipt(canonical_json(document), snapshot)


def test_platform_cannot_be_stripped_after_signing():
    snapshot, receipt_bytes = _extended(dict(CPU_PLATFORM))
    document = json.loads(receipt_bytes)
    del document["platform"]  # keep the original receipt_id and signature
    with pytest.raises(ReceiptError, match="does not match its canonical body"):
        verify_receipt(canonical_json(document), snapshot)


def test_platform_stripped_with_a_recomputed_id_but_no_resign_fails():
    snapshot, receipt_bytes = _extended(dict(CPU_PLATFORM))
    document = json.loads(receipt_bytes)
    del document["platform"]
    _reidentify(document)
    with pytest.raises(ReceiptError, match="signature verification failed"):
        verify_receipt(canonical_json(document), snapshot)


def test_platform_cannot_be_injected_after_signing():
    snapshot, _policy, _claims, receipt = _issued_receipt()
    document = json.loads(receipt.receipt_bytes)
    document["platform"] = dict(CPU_PLATFORM)  # no re-sign
    with pytest.raises(ReceiptError, match="does not match its canonical body"):
        verify_receipt(canonical_json(document), snapshot)


def test_platform_injected_with_a_recomputed_id_but_no_resign_fails():
    snapshot, _policy, _claims, receipt = _issued_receipt()
    document = json.loads(receipt.receipt_bytes)
    document["platform"] = dict(CPU_PLATFORM)
    _reidentify(document)
    with pytest.raises(ReceiptError, match="signature verification failed"):
        verify_receipt(canonical_json(document), snapshot)


# --- the public issuance path emits the extension when asked --------------- #


def test_the_issuer_emits_nothing_unless_a_caller_asks():
    # `platform` defaults to None, so every existing caller's bytes are
    # unchanged and the runtime keeps emitting the legacy shape. Deployed
    # verifiers of earlier releases reject any receipt carrying the key, so
    # WHEN to start supplying it stays a separate deployment decision.
    _snapshot_value, _policy, _claims, receipt = _issued_receipt()
    assert "platform" not in receipt.document
    assert "platform" not in json.loads(receipt.receipt_bytes)
    assert V2_FIXTURE.read_bytes().rstrip(b"\n") == receipt.receipt_bytes


def test_the_issuer_emits_a_verifiable_platform_block_when_asked():
    # The real issuance path, not a test-assembled document: ReceiptIssuer
    # signs the block, and the receipt it returns verifies unmodified.
    snapshot, _policy, _claims, receipt = _issued_receipt(platform=dict(CPU_PLATFORM))
    assert receipt.document["platform"] == CPU_PLATFORM
    verified = verify_receipt(receipt.receipt_bytes, snapshot)
    assert verified.document["platform"] == CPU_PLATFORM
    assert verified.receipt_id == receipt.receipt_id
    assert verified.receipt_digest == receipt.receipt_digest


def test_the_issued_block_is_inside_the_receipt_id_and_the_signature():
    # Issued with and without the block, everything else identical: the id and
    # the signature must both differ, which is what makes the block
    # unstrippable and uninjectable after signing.
    _snapshot_value, _policy, _claims, plain = _issued_receipt()
    _snapshot_value2, _policy2, _claims2, extended = _issued_receipt(
        platform=dict(CPU_PLATFORM)
    )
    assert extended.receipt_id != plain.receipt_id
    assert (
        json.loads(extended.receipt_bytes)["signature"]["value_base64"]
        != json.loads(plain.receipt_bytes)["signature"]["value_base64"]
    )


@pytest.mark.parametrize(
    "platform",
    [
        {"class": "confidential_cpu", "cpu_tee": "amd_sev"},
        {"class": "confidential_cpu", "cpu_tee": "amd_sev_snp"},
        {"class": "confidential_gpu", "cpu_tee": "intel_tdx"},
        {"class": "confidential_cpu", "cpu_tee": "intel_tdx", "extra": 1},
        {"class": [], "cpu_tee": "intel_tdx"},
        {"class": "confidential_cpu"},
        {},
    ],
)
def test_the_issuer_refuses_every_block_the_verifier_would_refuse(platform):
    # Issuance and verification share one validator, so the issuer cannot emit
    # a receipt its own verifier would reject. This is also why the malformed
    # cases elsewhere in this module are assembled and re-signed by hand: they
    # are shapes the issuer will not produce.
    with pytest.raises(ReceiptError):
        _issued_receipt(platform=platform)


def test_the_issuer_refuses_a_tdx_label_on_non_tdx_attested_hardware():
    # The receipt carries no hardware tier, so a verifier cannot check the
    # label against the evidence. Bind it at issuance instead: an SEV-SNP or
    # GPU attestation may never be labeled intel_tdx.
    for tier in (Tier.CC_CPU_SNP, Tier.CC_GPU):
        with pytest.raises(ReceiptError, match="does not match the attested hardware"):
            _issued_receipt(platform=dict(CPU_PLATFORM), tier=tier)


def test_a_platform_less_issuance_is_unaffected_by_a_non_tdx_tier():
    # The tier cross-check exists only to guard the label. Without a platform
    # block there is no label, so nothing new is enforced and the legacy path
    # is untouched.
    _snapshot_value, _policy, _claims, receipt = _issued_receipt(tier=Tier.CC_CPU_SNP)
    assert "platform" not in receipt.document
