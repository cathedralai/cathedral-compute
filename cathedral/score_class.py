"""Signed score-class reports for validator-owned Bittensor weight assignment.

Cathedral Confidential exports bounded, receipt-backed facts.  It never sees a
validator wallet, chooses an emissions allocation, or submits weights.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.launch_limits import (
    MAX_LAUNCH_CANDIDATES,
    MAX_LAUNCH_EVIDENCE_BASE_URI_BYTES,
    MAX_LAUNCH_SCORE_REPORT_BYTES,
    is_launch_hotkey,
)
from cathedral.ledger import Ledger, LedgerError
from cathedral.receipt import ReceiptError, parse_receipt_json

REPORT_SCHEMA = "cathedral_score_class_report_v2"
REPORT_DOMAIN = b"cathedral-score-class-report-v1\x00"
REPORT_ID_DOMAIN = b"cathedral-score-class-id-v1\x00"
CANDIDATE_SNAPSHOT_SCHEMA = "cathedral_candidate_snapshot_v1"
_BLOCK_HASH_RE = re.compile(r"^(0x)?[0-9a-f]{64}$")
MAX_REPORT_BYTES = MAX_LAUNCH_SCORE_REPORT_BYTES
MAX_REPORT_ENTRIES = MAX_LAUNCH_CANDIDATES
_IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_KEY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST_RE = re.compile(r"(?:sha256|receipt-sha256):[0-9a-f]{64}")
_METRIC_DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,12})?")


class ScoreClassError(ValueError):
    """The ledger cannot produce a valid, provenance-complete score report."""


def canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ScoreClassError("score report contains a non-canonical value") from exc


def format_time(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise ScoreClassError("score report time must be UTC")
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ScoreClassError(f"invalid {label}")
    return value


def _digest(value: str | None, label: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ScoreClassError(f"invalid {label}")
    return value


def _decimal(value: object, label: str) -> Decimal:
    if isinstance(value, bool):
        raise ScoreClassError(f"invalid {label}")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ScoreClassError(f"invalid {label}") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ScoreClassError(f"invalid {label}")
    return parsed


def _decimal_text(value: Decimal) -> str:
    encoded = format(value, "f")
    if "." in encoded:
        encoded = encoded.rstrip("0").rstrip(".")
    return "0" if encoded in {"", "-0"} else encoded


def _receipt_uri(base_uri: str | None, receipt_id: str) -> str | None:
    if base_uri is None:
        return None
    if (
        not isinstance(base_uri, str)
        or not base_uri.endswith("/")
        or len(base_uri.encode("utf-8")) > MAX_LAUNCH_EVIDENCE_BASE_URI_BYTES
    ):
        raise ScoreClassError("evidence base URI must end with a slash")
    parsed = urllib.parse.urlsplit(base_uri)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ScoreClassError("evidence base URI must be credential-free HTTPS")
    return base_uri + urllib.parse.quote(receipt_id, safe=":-") + ".json"


def validate_candidate_snapshot(
    document: Mapping[str, Any], *, network: str, netuid: int
) -> dict[str, Any]:
    """Validate a ``cathedral_candidate_snapshot_v1`` and return its normalized
    binding: {digest, block, block_hash, hotkeys}.

    The digest commits to the EXACT snapshot document (canonical JSON), so the
    score report, the evidence manifest, and any later export can only ever be
    built from the one snapshot the epoch actually observed."""
    if not isinstance(document, Mapping):
        raise ScoreClassError("candidate snapshot must be a JSON object")
    if frozenset(document) != {
        "schema",
        "network",
        "netuid",
        "block",
        "block_hash",
        "hotkeys",
    }:
        raise ScoreClassError("candidate snapshot has missing or unknown fields")
    if document["schema"] != CANDIDATE_SNAPSHOT_SCHEMA:
        raise ScoreClassError("candidate snapshot schema is unsupported")
    if document["network"] != network or document["netuid"] != netuid:
        raise ScoreClassError("candidate snapshot audience does not match the report")
    block = document["block"]
    if isinstance(block, bool) or not isinstance(block, int) or block < 0:
        raise ScoreClassError("candidate snapshot block is invalid")
    block_hash = document["block_hash"]
    if (
        not isinstance(block_hash, str)
        or _BLOCK_HASH_RE.fullmatch(block_hash.strip().lower()) is None
    ):
        raise ScoreClassError("candidate snapshot block hash is invalid")
    hotkeys = document["hotkeys"]
    if not isinstance(hotkeys, list) or len(hotkeys) > MAX_REPORT_ENTRIES:
        raise ScoreClassError("candidate snapshot hotkeys are invalid")
    for hotkey in hotkeys:
        if not is_launch_hotkey(hotkey):
            raise ScoreClassError("candidate snapshot carries an invalid hotkey")
    if len(set(hotkeys)) != len(hotkeys):
        raise ScoreClassError("candidate snapshot carries duplicate hotkeys")
    return {
        "digest": "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest(),
        "block": int(block),
        "block_hash": block_hash.strip().lower().removeprefix("0x"),
        "hotkeys": sorted(hotkeys),
    }


def _report_id(document: Mapping[str, Any]) -> str:
    material = {
        key: value for key, value in document.items() if key not in {"report_id", "signature"}
    }
    return "sha256:" + hashlib.sha256(REPORT_ID_DOMAIN + canonical_json(material)).hexdigest()


def _sign_report(document: Mapping[str, Any], private_key_seed: bytes) -> bytes:
    if not isinstance(private_key_seed, bytes) or len(private_key_seed) != 32:
        raise ScoreClassError("score report private key seed must be 32 bytes")
    signed = dict(document)
    signed["report_id"] = _report_id(signed)
    body = {key: value for key, value in signed.items() if key != "signature"}
    signature = Ed25519PrivateKey.from_private_bytes(private_key_seed).sign(
        REPORT_DOMAIN + canonical_json(body)
    )
    signed["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    encoded = canonical_json(signed)
    if len(encoded) > MAX_REPORT_BYTES:
        raise ScoreClassError("score report exceeds the validator size limit")
    return encoded


def export_score_class_report(
    ledger: Ledger,
    epoch_id: int,
    *,
    network: str,
    netuid: int,
    class_id: str,
    source_id: str,
    signing_key_id: str,
    private_key_seed: bytes,
    generated_at: datetime,
    valid_until: datetime,
    valid_from_block: int,
    valid_until_block: int,
    verifier_digest: str,
    candidate_snapshot: Mapping[str, Any],
    policy_digest: str | None = None,
    previous_report_id: str | None = None,
    evidence_base_uri: str | None = None,
    require_epoch_anchor: bool = True,
) -> bytes:
    """Export one frozen epoch as a thin-subnet-compatible signed report.

    Every positive metric is derived from the exact signed assurance receipt
    persisted atomically with that miner's verified challenge.  The report
    accounts for EVERY candidate in the anchored historical snapshot —
    ledger-scored or not — with explicit zero rows, and binds the snapshot's
    digest, block, hash, and full sorted hotkey set into the signed body so
    manifest, report, and recomputation always cover the identical set.
    """

    if not isinstance(ledger, Ledger):
        raise ScoreClassError("ledger is invalid")
    if not isinstance(network, str) or not 1 <= len(network.encode("utf-8")) <= 128:
        raise ScoreClassError("invalid network")
    if isinstance(netuid, bool) or not isinstance(netuid, int) or netuid < 0:
        raise ScoreClassError("invalid netuid")
    _identifier(class_id, "class id")
    _identifier(source_id, "source id")
    existing = ledger.get_score_class_export(
        epoch_id,
        network=network,
        netuid=netuid,
        class_id=class_id,
        source_id=source_id,
    )
    if existing is not None:
        return bytes(existing["report_body"])
    if not isinstance(signing_key_id, str) or _KEY_ID_RE.fullmatch(signing_key_id) is None:
        raise ScoreClassError("invalid signing key id")
    if (
        isinstance(valid_from_block, bool)
        or isinstance(valid_until_block, bool)
        or not isinstance(valid_from_block, int)
        or not isinstance(valid_until_block, int)
        or valid_from_block < 0
        or valid_until_block <= valid_from_block
    ):
        raise ScoreClassError("invalid score report block window")
    generated_text = format_time(generated_at)
    valid_until_text = format_time(valid_until)
    if generated_at >= valid_until:
        raise ScoreClassError("score report validity window is empty")
    checked_verifier_digest = _digest(verifier_digest, "verifier digest")

    try:
        snapshot = ledger.score_class_snapshot(epoch_id)
    except LedgerError as exc:
        raise ScoreClassError(str(exc)) from exc
    if (snapshot["network"], snapshot["netuid"]) != (network, netuid):
        raise ScoreClassError("frozen epoch audience does not match score report audience")
    snapshot_binding = validate_candidate_snapshot(
        candidate_snapshot, network=network, netuid=netuid
    )
    anchor_block = snapshot["challenge_anchor_block"]
    anchor_hash = snapshot["challenge_anchor_hash"]
    if anchor_block is None:
        if require_epoch_anchor:
            raise ScoreClassError(
                "epoch has no durable challenge anchor; production reports "
                "require begin_epoch to persist the finalized-block anchor"
            )
    elif (int(anchor_block), str(anchor_hash)) != (
        snapshot_binding["block"],
        snapshot_binding["block_hash"],
    ):
        raise ScoreClassError(
            "candidate snapshot block/hash does not match the epoch's durable "
            "challenge anchor; the report must bind the snapshot the epoch's "
            "nonces were actually derived from"
        )
    if valid_from_block < snapshot_binding["block"]:
        raise ScoreClassError(
            f"valid_from_block {valid_from_block} precedes the anchored "
            f"candidate snapshot block {snapshot_binding['block']}; the "
            "report's validity window cannot start before the finalized "
            "state it was derived from"
        )
    selected_policy_digest = policy_digest or snapshot["policy_registry_digest"]
    checked_policy_digest = _digest(selected_policy_digest, "policy digest")
    prior_export = ledger.previous_score_class_export(
        snapshot["source_epoch"],
        network=network,
        netuid=netuid,
        class_id=class_id,
        source_id=source_id,
    )
    checked_previous = _digest(previous_report_id, "previous report id", optional=True)
    if prior_export is not None:
        automatic_previous = str(prior_export["report_id"])
        if checked_previous is None:
            checked_previous = automatic_previous
        elif checked_previous != automatic_previous:
            raise ScoreClassError("previous report id does not match the durable export chain")
    elif checked_previous is not None:
        raise ScoreClassError("first score-class export must not declare a previous report id")
    rows = snapshot["rows"]
    if not isinstance(rows, tuple) or len(rows) > MAX_REPORT_ENTRIES:
        raise ScoreClassError("score report has too many entries")

    # Exhaustive candidate accounting (defect 4): the report's entry set must
    # be EXACTLY the anchored snapshot's hotkey set. A ledger row outside the
    # snapshot means the epoch scored an unregistered hotkey — refuse; a
    # snapshot candidate with no ledger row gets an explicit zero entry.
    rows_by_hotkey: dict[str, Any] = {}
    for row in rows:
        hotkey = row["hotkey"]
        if not is_launch_hotkey(hotkey):
            raise ScoreClassError("invalid miner hotkey in frozen epoch")
        rows_by_hotkey[hotkey] = row
    for hotkey in sorted(set(rows_by_hotkey) - set(snapshot_binding["hotkeys"])):
        row = rows_by_hotkey.pop(hotkey)
        if _decimal(row["work_units"], "frozen work units") > 0:
            raise ScoreClassError(
                "frozen epoch carries POSITIVE work for a hotkey that is not "
                f"registered in the anchored candidate snapshot: {hotkey!r}"
            )
        # A zero-valued historical row for a since-deregistered hotkey is
        # simply omitted: it earns nothing, it is not a candidate, and the
        # report's entry set must remain EXACTLY the signed snapshot — a
        # departed miner must never permanently block future epochs.

    entries: list[dict[str, Any]] = []
    for hotkey in snapshot_binding["hotkeys"]:
        row = rows_by_hotkey.get(hotkey)
        if row is None:
            entries.append(
                {
                    "miner_hotkey": hotkey,
                    "metrics": {"verified_work_units": "0"},
                    "asserted_score": None,
                    "reason_codes": ["not_admitted"],
                    "evidence": [],
                }
            )
            continue
        frozen_units = _decimal(row["work_units"], "frozen work units")
        evidence: list[dict[str, Any]] = []
        reasons = ["no_verified_work"]
        metric_units = Decimal(0)
        if frozen_units > 0:
            if row["work_status"] != "verified" or not isinstance(row["receipt_body"], bytes):
                raise ScoreClassError(
                    f"positive work for {hotkey!r} lacks a verified assurance receipt"
                )
            receipt_body = bytes(row["receipt_body"])
            expected_digest = "sha256:" + hashlib.sha256(receipt_body).hexdigest()
            if row["receipt_digest"] != expected_digest:
                raise ScoreClassError(f"receipt digest mismatch for {hotkey!r}")
            try:
                receipt = parse_receipt_json(receipt_body)
            except ReceiptError as exc:
                raise ScoreClassError(f"stored receipt is invalid for {hotkey!r}") from exc
            work = receipt.get("work")
            if (
                canonical_json(receipt) != receipt_body
                or receipt.get("schema") != "cathedral_assurance_receipt_v2"
                or receipt.get("receipt_id") != row["receipt_id"]
                or receipt.get("epoch_id") != snapshot["epoch_id"]
                or receipt.get("source_epoch") != snapshot["source_epoch"]
                or receipt.get("subject_hotkey") != hotkey
                or not isinstance(work, dict)
                or work.get("status") != "passed"
                or work.get("challenge_id") != row["challenge_id"]
            ):
                raise ScoreClassError(f"stored receipt provenance mismatch for {hotkey!r}")
            metric_units = _decimal(work.get("work_units"), "receipt work units")
            if metric_units != frozen_units:
                raise ScoreClassError(f"receipt work units mismatch for {hotkey!r}")
            receipt_id = str(row["receipt_id"])
            evidence = [
                {
                    "kind": "cathedral_assurance_receipt_v2",
                    "id": receipt_id,
                    "digest": expected_digest,
                    "uri": _receipt_uri(evidence_base_uri, receipt_id),
                }
            ]
            reasons = ["receipt_verified", "work_verified"]
        metric_text = _decimal_text(metric_units)
        if _METRIC_DECIMAL_RE.fullmatch(metric_text) is None:
            # One out-of-range receipt must not invalidate every honest miner.
            # Preserve its exact provenance, score only that row as zero, and
            # make the exclusion explicit in the decision record.
            metric_text = "0"
            reasons = ["unsupported_work_unit_precision"]
        entries.append(
            {
                "miner_hotkey": hotkey,
                "metrics": {"verified_work_units": metric_text},
                "asserted_score": None,
                "reason_codes": reasons,
                "evidence": evidence,
            }
        )

    report = {
        "schema": REPORT_SCHEMA,
        "network": network,
        "netuid": netuid,
        "class_id": class_id,
        "source_id": source_id,
        "source_epoch": snapshot["source_epoch"],
        "generated_at": generated_text,
        "valid_until": valid_until_text,
        "valid_from_block": valid_from_block,
        "valid_until_block": valid_until_block,
        "complete": True,
        "policy_digest": checked_policy_digest,
        "verifier_digest": checked_verifier_digest,
        "previous_report_id": checked_previous,
        "candidate_snapshot": snapshot_binding,
        "entries": entries,
        "signing_key_id": signing_key_id,
    }
    encoded = _sign_report(report, private_key_seed)
    try:
        return ledger.record_score_class_export(
            epoch_id,
            source_epoch=snapshot["source_epoch"],
            network=network,
            netuid=netuid,
            class_id=class_id,
            source_id=source_id,
            report_id=_report_id(report),
            previous_report_id=checked_previous,
            report_body=encoded,
        )
    except LedgerError as exc:
        raise ScoreClassError(str(exc)) from exc
