"""Offline verification for signed Cathedral Computer customer receipts.

This contract is deliberately separate from ``cathedral.receipt``. Assurance
receipt v2 is a subnet artifact whose verifier evaluates Intel TDX policy.
Customer receipt v1 verifies Cathedral's signature, key validity, and the
completeness and consistency of signed execution and billing assertions. It
does not independently verify Intel or NVIDIA attestation evidence.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CUSTOMER_RECEIPT_SCHEMA = "cathedral_customer_receipt_v1"
CUSTOMER_RECEIPT_TRUSTED_KEYS_SCHEMA = "cathedral_customer_receipt_trusted_keys_v1"
CUSTOMER_RECEIPT_POLICY_V1 = b"cathedral.customer-receipt.policy.v1"
CUSTOMER_RECEIPT_POLICY_DIGEST = (
    "sha256:" + hashlib.sha256(CUSTOMER_RECEIPT_POLICY_V1).hexdigest()
)

MAX_CUSTOMER_RECEIPT_BYTES = 256 * 1024
MAX_CUSTOMER_RECEIPT_TRUSTED_KEYS_BYTES = 256 * 1024
MAX_CUSTOMER_RECEIPT_DEPTH = 16
MAX_CUSTOMER_RECEIPT_NODES = 1024
MAX_CUSTOMER_RECEIPT_KEYS = 128
MAX_CUSTOMER_RECEIPT_STRING_BYTES = 16 * 1024
MAX_CUSTOMER_RECEIPT_KEY_BYTES = 256
MAX_JSON_INTEGER = 2**63 - 1

_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "receipt_id",
        "issued_at",
        "policy_digest",
        "signing_key_id",
        "receipt_status",
        "execution_class",
        "profile_id",
        "cpu_tee",
        "gpu_type",
        "gpu_count",
        "execution_outcome",
        "nonce_sha256",
        "workload_sha256",
        "result_sha256",
        "execution_binding_verified",
        "report_data_match",
        "intel_verified",
        "gpu_attestation_verified",
        "guest_binding_verified",
        "runtime_execution_verified",
        "teardown_required",
        "teardown_confirmed",
        "billed",
        "billing_status",
        "billing_outcome",
        "signature",
    }
)
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
_TRUSTED_KEYS_TOP_LEVEL = frozenset({"schema", "keys"})
_TRUSTED_KEY_FIELDS = frozenset(
    {
        "algorithm",
        "public_key_base64",
        "status",
        "valid_from",
        "valid_until",
    }
)
_EXECUTION_OUTCOMES = frozenset({"succeeded", "customer_error", "customer_timeout"})
_BILLING_STATUSES = frozenset({"billed", "trusted_service", "complimentary"})
_BILLING_OUTCOMES = frozenset({"charged", "not_charged"})
_KEY_STATUSES = frozenset({"active", "retired", "revoked"})
_CPU_PROFILE = "attest.v1"
_GPU_PROFILE = "gcp-g4-rtx-pro-6000-sev-v1"


class CustomerReceiptError(ValueError):
    """Stable customer-receipt failure with a machine-readable category."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


@dataclass(frozen=True)
class CustomerReceiptVerificationKey:
    """One locally trusted Ed25519 customer-receipt verification key."""

    key_id: str
    public_key: bytes
    status: str
    valid_from: datetime
    valid_until: datetime

    def verifies_at(self, issued_at: datetime) -> bool:
        return self.status in {"active", "retired"} and (
            self.valid_from <= issued_at < self.valid_until
        )


@dataclass(frozen=True)
class VerifiedCustomerReceipt:
    """A canonical customer receipt whose signature and assertions passed."""

    receipt_id: str
    receipt_bytes: bytes
    receipt_digest: str
    issued_at: datetime
    document: Mapping[str, object]


def _duplicate_safe_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CustomerReceiptError("schema", f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _json_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise CustomerReceiptError("schema", "JSON integer is invalid") from exc
    if not -(2**63) <= parsed <= MAX_JSON_INTEGER:
        raise CustomerReceiptError("schema", "JSON integer exceeds the supported range")
    return parsed


def _validate_json_shape(value: object) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_CUSTOMER_RECEIPT_NODES or depth > MAX_CUSTOMER_RECEIPT_DEPTH:
            raise CustomerReceiptError("schema", "JSON structure is too complex")
        if isinstance(current, dict):
            for key, child in current.items():
                if (
                    not isinstance(key, str)
                    or len(key.encode("utf-8")) > MAX_CUSTOMER_RECEIPT_KEY_BYTES
                ):
                    raise CustomerReceiptError("schema", "JSON object key is invalid")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str):
            try:
                encoded = current.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise CustomerReceiptError("schema", "JSON string is invalid") from exc
            if len(encoded) > MAX_CUSTOMER_RECEIPT_STRING_BYTES:
                raise CustomerReceiptError("schema", "JSON string exceeds the size limit")
        elif current is None or isinstance(current, (bool, int)):
            continue
        else:
            raise CustomerReceiptError("schema", "JSON contains a non-canonical value")


def _parse_json(data: bytes | str, *, maximum_bytes: int, label: str) -> dict[str, object]:
    try:
        encoded = data if isinstance(data, bytes) else data.encode("utf-8")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise CustomerReceiptError("schema", f"{label} is not UTF-8 JSON") from exc
    if len(encoded) > maximum_bytes:
        raise CustomerReceiptError("schema", f"{label} exceeds the maximum encoded size")
    try:
        parsed = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_object,
            parse_float=lambda _value: (_ for _ in ()).throw(
                CustomerReceiptError("schema", "floating-point JSON is unsupported")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                CustomerReceiptError("schema", "non-finite JSON is unsupported")
            ),
            parse_int=_json_integer,
        )
    except CustomerReceiptError:
        raise
    except (
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as exc:
        raise CustomerReceiptError("schema", f"{label} is not UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise CustomerReceiptError("schema", f"{label} must be a JSON object")
    _validate_json_shape(parsed)
    return parsed


def canonical_customer_receipt_json(value: Mapping[str, object]) -> bytes:
    """Return the one canonical byte representation used by this contract."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise CustomerReceiptError("schema", "document contains a non-canonical value") from exc


def customer_receipt_signed_bytes(document: Mapping[str, object]) -> bytes:
    """Canonical signature input, covering every top-level field except signature."""

    unsigned = dict(document)
    unsigned.pop("signature", None)
    return canonical_customer_receipt_json(unsigned)


def parse_customer_receipt_json(data: bytes | str) -> dict[str, object]:
    """Parse a bounded receipt while rejecting ambiguous JSON encodings."""

    return _parse_json(
        data,
        maximum_bytes=MAX_CUSTOMER_RECEIPT_BYTES,
        label="customer receipt",
    )


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise CustomerReceiptError("schema", f"{label} must be canonical UTC time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CustomerReceiptError("schema", f"{label} must be canonical UTC time") from exc


def _canonical_base64(value: object, *, decoded_bytes: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise CustomerReceiptError("schema", f"{label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CustomerReceiptError("schema", f"{label} must be canonical base64") from exc
    if (
        len(decoded) != decoded_bytes
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        raise CustomerReceiptError("schema", f"{label} must be canonical base64")
    return decoded


def parse_customer_receipt_trusted_keys_json(
    data: bytes | str,
) -> Mapping[str, CustomerReceiptVerificationKey]:
    """Load a bounded, locally pinned customer-receipt keyring."""

    document = _parse_json(
        data,
        maximum_bytes=MAX_CUSTOMER_RECEIPT_TRUSTED_KEYS_BYTES,
        label="customer receipt trusted keys",
    )
    if (
        frozenset(document) != _TRUSTED_KEYS_TOP_LEVEL
        or document.get("schema") != CUSTOMER_RECEIPT_TRUSTED_KEYS_SCHEMA
        or not isinstance(document.get("keys"), dict)
    ):
        raise CustomerReceiptError("key", "trusted keys schema is unsupported")
    raw_keys = document["keys"]
    assert isinstance(raw_keys, dict)
    if not raw_keys or len(raw_keys) > MAX_CUSTOMER_RECEIPT_KEYS:
        raise CustomerReceiptError("key", "trusted keys count is invalid")
    keys: dict[str, CustomerReceiptVerificationKey] = {}
    for key_id, raw in raw_keys.items():
        if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
            raise CustomerReceiptError("key", "trusted key id is invalid")
        if not isinstance(raw, dict) or frozenset(raw) != _TRUSTED_KEY_FIELDS:
            raise CustomerReceiptError("key", f"trusted key {key_id!r} has invalid fields")
        if raw["algorithm"] != "ed25519":
            raise CustomerReceiptError("key", f"trusted key {key_id!r} algorithm is unsupported")
        try:
            public_key = _canonical_base64(
                raw["public_key_base64"],
                decoded_bytes=32,
                label=f"trusted key {key_id!r} public key",
            )
        except CustomerReceiptError as exc:
            raise CustomerReceiptError("key", str(exc)) from exc
        status = raw["status"]
        if not isinstance(status, str) or status not in _KEY_STATUSES:
            raise CustomerReceiptError("key", f"trusted key {key_id!r} status is invalid")
        valid_from = _timestamp(raw["valid_from"], f"trusted key {key_id!r} valid_from")
        valid_until = _timestamp(raw["valid_until"], f"trusted key {key_id!r} valid_until")
        if valid_from >= valid_until:
            raise CustomerReceiptError("key", f"trusted key {key_id!r} interval is invalid")
        keys[key_id] = CustomerReceiptVerificationKey(
            key_id=key_id,
            public_key=public_key,
            status=status,
            valid_from=valid_from,
            valid_until=valid_until,
        )
    return MappingProxyType(keys)


def _require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise CustomerReceiptError("schema", f"{label} must be boolean")
    return value


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_HEX_RE.fullmatch(value) is None:
        raise CustomerReceiptError("binding", f"{label} must be 64 lowercase SHA-256 hex")
    return value


def _validate_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise CustomerReceiptError("schema", "receipt_id must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as exc:
        raise CustomerReceiptError("schema", "receipt_id must be a canonical UUID") from exc
    if str(parsed) != value:
        raise CustomerReceiptError("schema", "receipt_id must be a canonical UUID")
    return value


def _validate_signature_shape(document: Mapping[str, object]) -> bytes:
    signature = document.get("signature")
    if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
        raise CustomerReceiptError("schema", "receipt signature object is invalid")
    if signature["algorithm"] != "ed25519":
        raise CustomerReceiptError("signature", "receipt signature algorithm is unsupported")
    try:
        return _canonical_base64(
            signature["value_base64"],
            decoded_bytes=64,
            label="receipt signature",
        )
    except CustomerReceiptError as exc:
        raise CustomerReceiptError("signature", str(exc)) from exc


def _validate_common_assertions(document: Mapping[str, object]) -> datetime:
    if document["schema"] != CUSTOMER_RECEIPT_SCHEMA:
        raise CustomerReceiptError("schema", "customer receipt schema is unsupported")
    _validate_uuid(document["receipt_id"])
    issued_at = _timestamp(document["issued_at"], "receipt issued_at")
    if document["policy_digest"] != CUSTOMER_RECEIPT_POLICY_DIGEST:
        raise CustomerReceiptError("policy", "customer receipt policy digest is unsupported")
    if document["receipt_status"] != "ready":
        raise CustomerReceiptError("status", "customer receipt status is not ready")
    execution_outcome = document["execution_outcome"]
    if not isinstance(execution_outcome, str) or execution_outcome not in _EXECUTION_OUTCOMES:
        raise CustomerReceiptError("binding", "execution outcome is unsupported")
    for name in ("nonce_sha256", "workload_sha256", "result_sha256"):
        _require_digest(document[name], name)
    if _require_bool(
        document["execution_binding_verified"],
        "execution_binding_verified",
    ) is not True:
        raise CustomerReceiptError("binding", "execution binding is not verified")
    if _require_bool(document["teardown_required"], "teardown_required") is not True:
        raise CustomerReceiptError("binding", "receipt must require teardown")
    if _require_bool(document["teardown_confirmed"], "teardown_confirmed") is not True:
        raise CustomerReceiptError("binding", "receipt teardown is not confirmed")
    _validate_billing(document)
    return issued_at


def _validate_billing(document: Mapping[str, object]) -> None:
    billed = _require_bool(document["billed"], "billed")
    billing_status = document["billing_status"]
    billing_outcome = document["billing_outcome"]
    if (
        not isinstance(billing_status, str)
        or billing_status not in _BILLING_STATUSES
        or not isinstance(billing_outcome, str)
        or billing_outcome not in _BILLING_OUTCOMES
    ):
        raise CustomerReceiptError("billing", "receipt billing assertion is unsupported")
    if billed:
        if billing_status != "billed" or billing_outcome != "charged":
            raise CustomerReceiptError("billing", "billed receipt has contradictory billing fields")
    elif (
        billing_status not in {"trusted_service", "complimentary"}
        or billing_outcome != "not_charged"
    ):
        raise CustomerReceiptError("billing", "unbilled receipt has contradictory billing fields")


def _validate_cpu_assertions(document: Mapping[str, object]) -> None:
    if (
        document["profile_id"] != _CPU_PROFILE
        or document["cpu_tee"] != "intel_tdx"
        or document["gpu_type"] is not None
        or isinstance(document["gpu_count"], bool)
        or document["gpu_count"] != 0
    ):
        raise CustomerReceiptError("binding", "TDX CPU profile assertions are inconsistent")
    if (
        document["report_data_match"] is not True
        or document["intel_verified"] is not True
        or document["gpu_attestation_verified"] is not None
        or document["guest_binding_verified"] is not None
        or document["runtime_execution_verified"] is not None
    ):
        raise CustomerReceiptError("binding", "TDX CPU execution binding is incomplete")


def _validate_gpu_assertions(document: Mapping[str, object]) -> None:
    gpu_type = document["gpu_type"]
    gpu_count = document["gpu_count"]
    if (
        document["profile_id"] != _GPU_PROFILE
        or document["cpu_tee"] != "amd_sev"
        or not isinstance(gpu_type, str)
        or not gpu_type
        or len(gpu_type.encode("utf-8")) > 128
        or isinstance(gpu_count, bool)
        or not isinstance(gpu_count, int)
        or not 1 <= gpu_count <= 16
    ):
        raise CustomerReceiptError("binding", "confidential GPU profile assertions are inconsistent")
    if (
        document["report_data_match"] is not None
        or document["intel_verified"] is not None
        or document["gpu_attestation_verified"] is not True
        or document["guest_binding_verified"] is not True
        or document["runtime_execution_verified"] is not True
    ):
        raise CustomerReceiptError("binding", "confidential GPU execution binding is incomplete")


def verify_customer_receipt(
    data: bytes | str,
    trusted_keys: Mapping[str, CustomerReceiptVerificationKey],
    *,
    max_age_seconds: int | None = None,
    now: datetime | None = None,
) -> VerifiedCustomerReceipt:
    """Verify exact customer-receipt bytes against a locally trusted keyring.

    Success proves that the named Cathedral key signed the assertions and that
    the document contains a complete, internally consistent binding for its
    execution class. It does not replay or independently evaluate TDX quotes,
    NVIDIA evidence, billing-ledger rows, or provider teardown.
    """

    document = parse_customer_receipt_json(data)
    encoded = data if isinstance(data, bytes) else data.encode("utf-8")
    if encoded != canonical_customer_receipt_json(document):
        raise CustomerReceiptError("schema", "customer receipt JSON is not canonical")
    if frozenset(document) != _TOP_LEVEL_KEYS:
        raise CustomerReceiptError(
            "schema",
            "customer receipt has missing or unknown fields",
        )
    if document["schema"] != CUSTOMER_RECEIPT_SCHEMA:
        raise CustomerReceiptError("schema", "customer receipt schema is unsupported")
    signing_key_id = document["signing_key_id"]
    if not isinstance(signing_key_id, str) or _KEY_ID_RE.fullmatch(signing_key_id) is None:
        raise CustomerReceiptError("key", "receipt signing key id is invalid")
    key = trusted_keys.get(signing_key_id)
    if key is None or not isinstance(key, CustomerReceiptVerificationKey):
        raise CustomerReceiptError("key", "receipt signing key is not trusted")
    if key.status == "revoked":
        raise CustomerReceiptError("key", "receipt signing key is revoked")
    signature = _validate_signature_shape(document)
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(
            signature,
            customer_receipt_signed_bytes(document),
        )
    except (InvalidSignature, ValueError) as exc:
        raise CustomerReceiptError("signature", "customer receipt signature is invalid") from exc

    issued_at = _validate_common_assertions(document)
    execution_class = document["execution_class"]
    if execution_class == "tdx_cpu":
        _validate_cpu_assertions(document)
    elif execution_class == "cc_gpu":
        _validate_gpu_assertions(document)
    else:
        raise CustomerReceiptError("binding", "customer receipt execution class is unsupported")
    if not key.verifies_at(issued_at):
        raise CustomerReceiptError(
            "key",
            "receipt issue time is outside the signing key validity interval",
        )

    if max_age_seconds is not None:
        if (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, int)
            or max_age_seconds <= 0
        ):
            raise CustomerReceiptError("stale", "receipt maximum age must be positive")
        evaluated_at = now or datetime.now(UTC)
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() != timedelta(0):
            raise CustomerReceiptError("stale", "receipt evaluation time must be UTC")
        if issued_at > evaluated_at:
            raise CustomerReceiptError("stale", "customer receipt is future-dated")
        if evaluated_at - issued_at > timedelta(seconds=max_age_seconds):
            raise CustomerReceiptError("stale", "customer receipt exceeds the maximum age")

    return VerifiedCustomerReceipt(
        receipt_id=str(document["receipt_id"]),
        receipt_bytes=encoded,
        receipt_digest="sha256:" + hashlib.sha256(encoded).hexdigest(),
        issued_at=issued_at,
        document=MappingProxyType(document),
    )


__all__ = [
    "CUSTOMER_RECEIPT_POLICY_DIGEST",
    "CUSTOMER_RECEIPT_POLICY_V1",
    "CUSTOMER_RECEIPT_SCHEMA",
    "CUSTOMER_RECEIPT_TRUSTED_KEYS_SCHEMA",
    "CustomerReceiptError",
    "CustomerReceiptVerificationKey",
    "VerifiedCustomerReceipt",
    "canonical_customer_receipt_json",
    "customer_receipt_signed_bytes",
    "parse_customer_receipt_json",
    "parse_customer_receipt_trusted_keys_json",
    "verify_customer_receipt",
]
