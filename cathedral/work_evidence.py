"""Versioned transport encoding for replayable Compute work artifacts.

The assurance receipt signs the item and result digests.  This module exports
the exact canonical bytes that a downstream validator needs to replay the
``sat_work_units_v1`` derivation; it makes no statement beyond those signed
digests.  Consumers must still verify the receipt signature and independently
replay the evidence before crediting work.
"""
from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from typing import Any

WORK_EVIDENCE_SCHEMA = "cathedral_compute_work_evidence_v1"
MAX_WORK_ITEM_BYTES = 60 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024

_RECEIPT_ID_RE = re.compile(r"\Areceipt-sha256:[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")


class WorkEvidenceError(ValueError):
    """A requested work-evidence transport record is unsafe to export."""


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_work_evidence(
    receipt: Mapping[str, Any], work_item_bytes: bytes, result_bytes: bytes
) -> dict[str, str]:
    """Encode artifacts that exactly match one signed Compute receipt.

    The evidence is deliberately a sidecar rather than a new unsigned receipt
    field: raw SAT artifacts can be sizeable, while the receipt retains its
    existing compact, signed format.  The receipt id plus both signed digests
    bind the sidecar unambiguously; a substituted or reordered byte string is
    rejected by the independent consumer.
    """
    if not isinstance(receipt, Mapping):
        raise WorkEvidenceError("receipt must be an object")
    receipt_id = receipt.get("receipt_id")
    work = receipt.get("work")
    if not isinstance(receipt_id, str) or _RECEIPT_ID_RE.fullmatch(receipt_id) is None:
        raise WorkEvidenceError("receipt_id is invalid")
    if not isinstance(work, Mapping):
        raise WorkEvidenceError("receipt work block is invalid")
    if not isinstance(work_item_bytes, bytes) or not isinstance(result_bytes, bytes):
        raise WorkEvidenceError("work artifacts must be bytes")
    if len(work_item_bytes) > MAX_WORK_ITEM_BYTES:
        raise WorkEvidenceError("work item exceeds the transport limit")
    if len(result_bytes) > MAX_RESULT_BYTES:
        raise WorkEvidenceError("work result exceeds the transport limit")
    manifest_digest = work.get("manifest_digest")
    result_digest = work.get("result_digest")
    if not isinstance(manifest_digest, str) or _DIGEST_RE.fullmatch(manifest_digest) is None:
        raise WorkEvidenceError("receipt manifest_digest is invalid")
    if not isinstance(result_digest, str) or _DIGEST_RE.fullmatch(result_digest) is None:
        raise WorkEvidenceError("receipt result_digest is invalid")
    if manifest_digest != _digest(work_item_bytes):
        raise WorkEvidenceError("work item does not match the receipt manifest digest")
    if result_digest != _digest(result_bytes):
        raise WorkEvidenceError("work result does not match the receipt result digest")
    return {
        "schema": WORK_EVIDENCE_SCHEMA,
        "receipt_id": receipt_id,
        "work_item_base64": base64.b64encode(work_item_bytes).decode("ascii"),
        "result_base64": base64.b64encode(result_bytes).decode("ascii"),
    }


__all__ = ["WORK_EVIDENCE_SCHEMA", "WorkEvidenceError", "build_work_evidence"]
