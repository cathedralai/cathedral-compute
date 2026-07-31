"""Separate Cathedral Computer customer-receipt verifier coverage."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.cli import main as cli_main
from cathedral.customer_receipt import (
    CUSTOMER_RECEIPT_POLICY_DIGEST,
    CUSTOMER_RECEIPT_POLICY_V1,
    CUSTOMER_RECEIPT_SCHEMA,
    CUSTOMER_RECEIPT_TRUSTED_KEYS_SCHEMA,
    MAX_CUSTOMER_RECEIPT_BYTES,
    CustomerReceiptError,
    canonical_customer_receipt_json,
    customer_receipt_signed_bytes,
    parse_customer_receipt_json,
    parse_customer_receipt_trusted_keys_json,
    verify_customer_receipt,
)

ISSUED_AT = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
ISSUED_TEXT = "2026-07-30T12:00:00.000000Z"
KEY_ID = "customer-receipt-test-1"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))


def _public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _trusted_keys_bytes(
    *,
    private_key: Ed25519PrivateKey = PRIVATE_KEY,
    status: str = "active",
    valid_from: str = "2026-01-01T00:00:00.000000Z",
    valid_until: str = "2027-01-01T00:00:00.000000Z",
) -> bytes:
    return json.dumps(
        {
            "schema": CUSTOMER_RECEIPT_TRUSTED_KEYS_SCHEMA,
            "keys": {
                KEY_ID: {
                    "algorithm": "ed25519",
                    "public_key_base64": base64.b64encode(
                        _public_key(private_key)
                    ).decode("ascii"),
                    "status": status,
                    "valid_from": valid_from,
                    "valid_until": valid_until,
                }
            },
        },
        indent=2,
        sort_keys=True,
    ).encode("ascii")


def _unsigned_cpu_document() -> dict[str, object]:
    return {
        "schema": CUSTOMER_RECEIPT_SCHEMA,
        "receipt_id": "6de10d88-e554-4b68-a334-377e81744ee4",
        "issued_at": ISSUED_TEXT,
        "policy_digest": CUSTOMER_RECEIPT_POLICY_DIGEST,
        "signing_key_id": KEY_ID,
        "receipt_status": "ready",
        "execution_class": "tdx_cpu",
        "profile_id": "attest.v1",
        "cpu_tee": "intel_tdx",
        "gpu_type": None,
        "gpu_count": 0,
        "execution_outcome": "succeeded",
        "nonce_sha256": "1" * 64,
        "workload_sha256": "2" * 64,
        "result_sha256": "3" * 64,
        "execution_binding_verified": True,
        "report_data_match": True,
        "intel_verified": True,
        "gpu_attestation_verified": None,
        "guest_binding_verified": None,
        "runtime_execution_verified": None,
        "teardown_required": True,
        "teardown_confirmed": True,
        "billed": True,
        "billing_status": "billed",
        "billing_outcome": "charged",
    }


def _unsigned_gpu_document() -> dict[str, object]:
    document = _unsigned_cpu_document()
    document.update(
        {
            "receipt_id": "1c352eaf-9d1d-4e41-9fc4-35667b631870",
            "execution_class": "cc_gpu",
            "profile_id": "gcp-g4-rtx-pro-6000-sev-v1",
            "cpu_tee": "amd_sev",
            "gpu_type": "nvidia_rtx_pro_6000_96gb",
            "gpu_count": 1,
            "report_data_match": None,
            "intel_verified": None,
            "gpu_attestation_verified": True,
            "guest_binding_verified": True,
            "runtime_execution_verified": True,
        }
    )
    return document


def _sign(
    document: dict[str, object],
    *,
    private_key: Ed25519PrivateKey = PRIVATE_KEY,
) -> bytes:
    signed = dict(document)
    signed["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(
            private_key.sign(customer_receipt_signed_bytes(signed))
        ).decode("ascii"),
    }
    return canonical_customer_receipt_json(signed)


@pytest.fixture
def trusted_keys():
    return parse_customer_receipt_trusted_keys_json(_trusted_keys_bytes())


@pytest.fixture
def cpu_receipt() -> bytes:
    return _sign(_unsigned_cpu_document())


@pytest.fixture
def gpu_receipt() -> bytes:
    return _sign(_unsigned_gpu_document())


def test_policy_constant_and_digest_are_stable():
    assert CUSTOMER_RECEIPT_POLICY_V1 == b"cathedral.customer-receipt.policy.v1"
    assert CUSTOMER_RECEIPT_POLICY_DIGEST == (
        "sha256:c7ff160107c32648e99773feacaaff4f5a4dae059ef237ac8992b2a6fae743eb"
    )
    assert CUSTOMER_RECEIPT_POLICY_DIGEST == (
        "sha256:" + hashlib.sha256(CUSTOMER_RECEIPT_POLICY_V1).hexdigest()
    )


def test_valid_cpu_fixture_verifies(cpu_receipt: bytes, trusted_keys):
    verified = verify_customer_receipt(cpu_receipt, trusted_keys)

    assert verified.receipt_id == "6de10d88-e554-4b68-a334-377e81744ee4"
    assert verified.issued_at == ISSUED_AT
    assert verified.document["execution_class"] == "tdx_cpu"
    assert verified.receipt_bytes == cpu_receipt


def test_valid_g4_fixture_verifies(gpu_receipt: bytes, trusted_keys):
    verified = verify_customer_receipt(gpu_receipt, trusted_keys)

    assert verified.receipt_id == "1c352eaf-9d1d-4e41-9fc4-35667b631870"
    assert verified.document["execution_class"] == "cc_gpu"
    assert verified.document["gpu_attestation_verified"] is True


def test_tampered_execution_digest_fails_signature(cpu_receipt: bytes, trusted_keys):
    tampered = parse_customer_receipt_json(cpu_receipt)
    tampered["result_sha256"] = "4" * 64

    with pytest.raises(CustomerReceiptError, match="signature is invalid") as caught:
        verify_customer_receipt(canonical_customer_receipt_json(tampered), trusted_keys)

    assert caught.value.category == "signature"


def test_wrong_public_key_fails_signature(cpu_receipt: bytes):
    wrong_keys = parse_customer_receipt_trusted_keys_json(
        _trusted_keys_bytes(private_key=OTHER_PRIVATE_KEY)
    )

    with pytest.raises(CustomerReceiptError, match="signature is invalid") as caught:
        verify_customer_receipt(cpu_receipt, wrong_keys)

    assert caught.value.category == "signature"


def test_stale_max_age_rejected(cpu_receipt: bytes, trusted_keys):
    with pytest.raises(CustomerReceiptError, match="maximum age") as caught:
        verify_customer_receipt(
            cpu_receipt,
            trusted_keys,
            max_age_seconds=3600,
            now=ISSUED_AT + timedelta(seconds=3601),
        )

    assert caught.value.category == "stale"


def test_bad_policy_digest_rejected_after_valid_signature(trusted_keys):
    document = _unsigned_cpu_document()
    document["policy_digest"] = "sha256:" + "0" * 64

    with pytest.raises(CustomerReceiptError, match="policy digest") as caught:
        verify_customer_receipt(_sign(document), trusted_keys)

    assert caught.value.category == "policy"


def test_malformed_schema_rejected_after_valid_signature(trusted_keys):
    document = _unsigned_cpu_document()
    document["schema"] = "cathedral_customer_receipt_v2"

    with pytest.raises(CustomerReceiptError, match="schema is unsupported") as caught:
        verify_customer_receipt(_sign(document), trusted_keys)

    assert caught.value.category == "schema"


def test_noncanonical_receipt_bytes_rejected(cpu_receipt: bytes, trusted_keys):
    noncanonical = json.dumps(json.loads(cpu_receipt), indent=2, sort_keys=True).encode("ascii")

    with pytest.raises(CustomerReceiptError, match="not canonical") as caught:
        verify_customer_receipt(noncanonical, trusted_keys)

    assert caught.value.category == "schema"


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema":"one","schema":"two"}',
        b'{"gpu_count":1.0}',
        b'{"gpu_count":NaN}',
    ],
)
def test_ambiguous_json_forms_fail_closed(payload: bytes):
    with pytest.raises(CustomerReceiptError) as caught:
        parse_customer_receipt_json(payload)

    assert caught.value.category == "schema"


def test_json_integer_parser_accepts_the_full_signed_64_bit_range():
    parsed = parse_customer_receipt_json(
        b'{"maximum":9223372036854775807,"minimum":-9223372036854775808}'
    )

    assert parsed == {
        "maximum": 9223372036854775807,
        "minimum": -9223372036854775808,
    }


def test_oversize_and_excessive_depth_fail_closed():
    with pytest.raises(CustomerReceiptError, match="maximum encoded size"):
        parse_customer_receipt_json(b"{" + b" " * MAX_CUSTOMER_RECEIPT_BYTES + b"}")

    nested: object = "leaf"
    for _index in range(20):
        nested = [nested]
    with pytest.raises(CustomerReceiptError, match="too complex"):
        parse_customer_receipt_json(json.dumps({"nested": nested}))


@pytest.mark.parametrize(
    ("status", "valid_from", "valid_until", "message"),
    [
        (
            "revoked",
            "2026-01-01T00:00:00.000000Z",
            "2027-01-01T00:00:00.000000Z",
            "revoked",
        ),
        (
            "active",
            "2026-07-30T12:00:00.000001Z",
            "2027-01-01T00:00:00.000000Z",
            "validity interval",
        ),
    ],
)
def test_key_status_and_issued_at_interval_fail_closed(
    cpu_receipt: bytes,
    status: str,
    valid_from: str,
    valid_until: str,
    message: str,
):
    trusted_keys = parse_customer_receipt_trusted_keys_json(
        _trusted_keys_bytes(
            status=status,
            valid_from=valid_from,
            valid_until=valid_until,
        )
    )

    with pytest.raises(CustomerReceiptError, match=message) as caught:
        verify_customer_receipt(cpu_receipt, trusted_keys)

    assert caught.value.category == "key"


@pytest.mark.parametrize(
    ("execution_class", "field"),
    [
        ("tdx_cpu", "report_data_match"),
        ("cc_gpu", "guest_binding_verified"),
    ],
)
def test_incomplete_execution_binding_rejected(
    trusted_keys,
    execution_class: str,
    field: str,
):
    document = (
        _unsigned_cpu_document()
        if execution_class == "tdx_cpu"
        else _unsigned_gpu_document()
    )
    document[field] = False

    with pytest.raises(CustomerReceiptError, match="binding is incomplete") as caught:
        verify_customer_receipt(_sign(document), trusted_keys)

    assert caught.value.category == "binding"


def test_cli_returns_machine_readable_success_and_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    cpu_receipt: bytes,
):
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(cpu_receipt)
    trusted_keys_path = tmp_path / "trusted-keys.json"
    trusted_keys_path.write_bytes(_trusted_keys_bytes())

    command = [
        "customer-receipt",
        "verify",
        "--receipt",
        str(receipt_path),
        "--trusted-keys",
        str(trusted_keys_path),
    ]
    assert cli_main(command) == 0
    success = json.loads(capsys.readouterr().out)
    assert success["valid"] is True
    assert success["verification_scope"] == "cathedral_signed_assertions"
    assert success["evidence_independently_verified"] is False

    tampered = parse_customer_receipt_json(cpu_receipt)
    tampered["result_sha256"] = "9" * 64
    receipt_path.write_bytes(canonical_customer_receipt_json(tampered))
    assert cli_main(command) == 1
    failure = json.loads(capsys.readouterr().out)
    assert failure["valid"] is False
    assert failure["category"] == "signature"
