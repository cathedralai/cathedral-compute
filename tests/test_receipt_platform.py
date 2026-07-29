"""The optional `platform` top-level extension point of receipt v2.

Cross-repo contract: cathedral-distill's compute receipts extend
`cathedral_assurance_receipt_v2` with exactly one top-level `platform` block
(class + cpu_tee, plus a bound GPU block for a composite). This repo's parser
previously did `frozenset(document) != _TOP_KEYS -> reject`, so the two lanes
could never admit each other's receipts. These tests pin the reconciliation:

  * receipts WITHOUT `platform` are byte-for-byte unchanged and still verify;
  * receipts WITH `platform` validate the block strictly (recognized class,
    cpu_tee from the attestable set, exact keys, GPU guest binding);
  * `platform` is the ONLY tolerated extension; any other unknown top-level
    key still fails closed;
  * `platform` is covered by receipt_id and the signature, so it can be
    neither stripped from nor injected into a signed receipt;
  * plain "amd_sev" (no attestation interface) is never accepted, and the
    TDX/SEV-SNP requirements are not weakened: this verifier's evidence
    grammar is Intel TDX, so an `amd_sev_snp` label fails closed until an
    SEV-SNP body grammar is added deliberately.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cathedral.policy_registry import canonical_json
from cathedral.receipt import ReceiptError, verify_receipt

from tests.test_receipt import _issued_receipt, _resign, _snapshot

CPU_PLATFORM = {"class": "confidential_cpu", "cpu_tee": "intel_tdx"}


def _extended(platform: object) -> tuple[object, bytes]:
    """A genuine issued receipt with `platform` injected and re-signed."""
    snapshot, _policy, _claims, receipt = _issued_receipt()
    document = json.loads(receipt.receipt_bytes)
    document["platform"] = platform
    return snapshot, _resign(document)


def test_receipt_without_platform_is_byte_for_byte_unchanged_and_verifies():
    snapshot, _policy, _claims, receipt = _issued_receipt()
    verified = verify_receipt(receipt.receipt_bytes, snapshot)
    assert "platform" not in verified.document
    # The golden fixture pins the exact pre-extension bytes: adding the
    # optional key changed nothing for receipts that do not carry it.
    assert (
        Path("tests/fixtures/assurance-receipt-v2.json").read_bytes().rstrip(b"\n")
        == receipt.receipt_bytes
    )


def test_valid_cpu_platform_block_verifies_and_round_trips():
    snapshot, receipt_bytes = _extended(dict(CPU_PLATFORM))
    verified = verify_receipt(receipt_bytes, snapshot)
    assert verified.document["platform"] == CPU_PLATFORM
    assert verified.receipt_bytes == receipt_bytes


def test_valid_gpu_platform_block_bound_to_the_receipt_measurement_verifies():
    snapshot, _policy, _claims, receipt = _issued_receipt()
    document = json.loads(receipt.receipt_bytes)
    document["platform"] = {
        "class": "confidential_gpu",
        "cpu_tee": "intel_tdx",
        "gpu": {
            "cc_mode": "on",
            "vbios_measurement": "sha256:" + "1" * 64,
            "attestation_report_digest": "sha256:" + "2" * 64,
            "bound_measurement": document["measurement"],
        },
    }
    verified = verify_receipt(_resign(document), snapshot)
    assert verified.document["platform"]["class"] == "confidential_gpu"


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


def test_platform_cannot_be_stripped_after_signing():
    snapshot, receipt_bytes = _extended(dict(CPU_PLATFORM))
    document = json.loads(receipt_bytes)
    del document["platform"]  # keep the original receipt_id and signature
    with pytest.raises(ReceiptError, match="does not match its canonical body"):
        verify_receipt(canonical_json(document), snapshot)


def test_platform_cannot_be_injected_after_signing():
    snapshot, _policy, _claims, receipt = _issued_receipt()
    document = json.loads(receipt.receipt_bytes)
    document["platform"] = dict(CPU_PLATFORM)  # no re-sign
    with pytest.raises(ReceiptError, match="does not match its canonical body"):
        verify_receipt(canonical_json(document), snapshot)


def test_platform_on_the_legacy_v1_schema_is_rejected():
    receipt_bytes = Path("tests/fixtures/assurance-receipt-v1.json").read_bytes().rstrip(b"\n")
    document = json.loads(receipt_bytes)
    document["platform"] = dict(CPU_PLATFORM)
    with pytest.raises(ReceiptError, match="requires schema version 2"):
        verify_receipt(_resign(document), _snapshot())


@pytest.mark.parametrize(
    ("platform", "match"),
    [
        ("confidential_cpu", "must be an object"),
        ({}, "class is unknown"),
        ({"class": "gpu_only", "cpu_tee": "intel_tdx"}, "class is unknown"),
        (
            {"class": "confidential_cpu", "cpu_tee": "intel_tdx", "extra": 1},
            "confidential_cpu platform keys are invalid",
        ),
        ({"class": "confidential_cpu"}, "confidential_cpu platform keys are invalid"),
        (
            {
                "class": "confidential_cpu",
                "cpu_tee": "intel_tdx",
                "gpu": {"cc_mode": "on"},
            },
            "confidential_cpu platform keys are invalid",
        ),
        (
            {"class": "confidential_gpu", "cpu_tee": "intel_tdx"},
            "confidential_gpu platform keys are invalid",
        ),
    ],
)
def test_malformed_platform_blocks_fail_closed(platform, match):
    snapshot, receipt_bytes = _extended(platform)
    with pytest.raises(ReceiptError, match=match):
        verify_receipt(receipt_bytes, snapshot)


@pytest.mark.parametrize(
    "cpu_tee",
    ["amd_sev", "", None, "AMD_SEV_SNP", "sgx", "intel_tdx2"],
)
def test_cpu_tee_outside_the_attestable_set_is_rejected(cpu_tee):
    # The live G4 GCP profile emits plain "amd_sev" (no attestation interface).
    # It must never be accepted; only the attestable set is recognized at all.
    snapshot, receipt_bytes = _extended(
        {"class": "confidential_cpu", "cpu_tee": cpu_tee}
    )
    with pytest.raises(ReceiptError, match="not in the attestable set"):
        verify_receipt(receipt_bytes, snapshot)


def test_sev_snp_label_fails_closed_until_a_sev_body_grammar_exists():
    # "amd_sev_snp" IS in the attestable set, but this verifier's measurement
    # and TCB grammar is Intel TDX only. A receipt labeled amd_sev_snp over a
    # TDX-validated body is a label/body mismatch: fail closed, exactly as
    # distill's _validate_cpu_tee_body enforces label/body consistency.
    snapshot, receipt_bytes = _extended(
        {"class": "confidential_cpu", "cpu_tee": "amd_sev_snp"}
    )
    with pytest.raises(ReceiptError, match="evidence grammar"):
        verify_receipt(receipt_bytes, snapshot)


@pytest.mark.parametrize(
    ("gpu_mutation", "match"),
    [
        (lambda gpu: gpu.update(cc_mode="off"), "confidential-compute mode"),
        (lambda gpu: gpu.update(extra="x"), "GPU evidence keys are invalid"),
        (lambda gpu: gpu.pop("bound_measurement"), "GPU evidence keys are invalid"),
        (
            lambda gpu: gpu.update(vbios_measurement="not-a-digest"),
            "vbios_measurement is invalid",
        ),
        (
            lambda gpu: gpu.update(attestation_report_digest="sha256:short"),
            "attestation_report_digest is invalid",
        ),
        (
            lambda gpu: gpu.update(bound_measurement="tdx-measurement-sha256:other"),
            "not bound to the receipt measurement",
        ),
        (lambda gpu: gpu.update(bound_measurement=""), "not bound to the receipt"),
    ],
)
def test_gpu_platform_evidence_fails_closed(gpu_mutation, match):
    snapshot, _policy, _claims, receipt = _issued_receipt()
    document = json.loads(receipt.receipt_bytes)
    gpu = {
        "cc_mode": "on",
        "vbios_measurement": "sha256:" + "1" * 64,
        "attestation_report_digest": "sha256:" + "2" * 64,
        "bound_measurement": document["measurement"],
    }
    gpu_mutation(gpu)
    document["platform"] = {
        "class": "confidential_gpu",
        "cpu_tee": "intel_tdx",
        "gpu": gpu,
    }
    with pytest.raises(ReceiptError, match=match):
        verify_receipt(_resign(document), snapshot)
