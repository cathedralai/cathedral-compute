"""Public evidence bundles: content-addressed artifacts plus a signed index.

The launch evidence model has two tiers:

  * **Public** — everything an independent validator needs to reproduce the
    weight decision: the signed policy registry, the signed score-class
    report, every referenced assurance receipt, the pinned verifier identity,
    the versioned reward-mechanism id, and digests binding the rest of the
    chain. Artifacts are immutable and content-addressed
    (``blobs/sha256/<hex>``); the only mutable object is ``index.json``, a
    signed pointer to the newest epoch manifest.
  * **Controlled** — raw Intel TDX quotes and collateral. These are retained
    off the public surface (root-only retention store) and referenced in the
    public manifest by digest with ``"disclosure": "controlled"``. An
    authorized full validator can request the raw bytes and check them
    against the published digest; nothing about the public chain depends on
    trusting an unpublished byte.

Nothing in this module performs network I/O; callers move bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cathedral.launch_limits import (
    MAX_LAUNCH_CANDIDATES,
    MAX_LAUNCH_SCORE_REPORT_BYTES,
    MAX_LAUNCH_VERIFIED_CANDIDATES,
    is_launch_hotkey,
)
from cathedral.policy_registry import (
    MAX_REGISTRY_BYTES,
    PolicyRegistryError,
    canonical_json,
    parse_registry_json,
)

# v2 added verifier command/artifact bindings and per-attestation
# envelope_digest. v1 never shipped to any public surface; v1 documents are
# rejected with an explicit versioned error, not a generic shape failure.
# v3 adds the exhaustive candidate-set binding: every enrolled candidate for
# the epoch is accounted for as verified, rejected, or retired, so omission
# cannot inflate a remaining miner. Only verified outcomes carry replayable
# positive evidence in the launch model; any non-verified anchored candidate
# keeps epoch-level FULL assurance NOT_PROVEN.
MANIFEST_SCHEMA = "cathedral_evidence_manifest_v3"
LEGACY_MANIFEST_SCHEMA_V2 = "cathedral_evidence_manifest_v2"
LEGACY_MANIFEST_SCHEMA = "cathedral_evidence_manifest_v1"
INDEX_SCHEMA = "cathedral_evidence_index_v1"
INDEX_DOMAIN = b"cathedral-evidence-index-v1\x00"
MAX_INDEX_RECENT = 96

# ---------------------------------------------------------------------------
# Launch byte/cardinality budget (docs/BUDGET.md, "Evidence byte budget")
#
# The manifest grammar and the verifier's aggregate command budget are ONE
# coherent contract: every per-kind artifact cap below is enforced at export
# (a producer can never publish an artifact the verifier must refuse) and at
# every verify read site, and the supported receipt cardinality is DERIVED so
# that the worst-case maximal valid epoch — every artifact at its cap, FULL
# mode included (verifier binary, independent snapshot, publisher vector, one
# controlled envelope per verified candidate) — fits inside the verifier's
# 64 MiB aggregate byte budget. A manifest the grammar accepts is therefore
# always verifiable; the aggregate cap only ever stops non-compliant inputs.
# ---------------------------------------------------------------------------
MAX_INDEX_ARTIFACT_BYTES = 256 * 1024
MAX_MANIFEST_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_REGISTRY_ARTIFACT_BYTES = MAX_REGISTRY_BYTES  # 1 MiB, policy_registry pin
MAX_REPORT_ARTIFACT_BYTES = MAX_LAUNCH_SCORE_REPORT_BYTES
MAX_RECEIPT_ARTIFACT_BYTES = 64 * 1024
# SAT grammar worst case (cathedral/lanes/sat.py): 65,536 literals over
# <= 8192 clauses encodes to ~410 KiB of canonical JSON; 512 KiB bounds it.
MAX_WORK_ITEM_ARTIFACT_BYTES = 512 * 1024
MAX_WORK_RESULT_ARTIFACT_BYTES = 64 * 1024
# A real CPU-TDX envelope (quote + certificate chain, base64 JSON) is tens of
# KiB; 256 KiB is the launch disclosure contract, enforced at retention time
# so an oversized envelope can never silently invalidate a published epoch.
MAX_CONTROLLED_ENVELOPE_BYTES = 256 * 1024
MAX_SNAPSHOT_ARTIFACT_BYTES = 1024 * 1024
MAX_VECTOR_ARTIFACT_BYTES = 1024 * 1024
# Mirrors cathedral.replay.MAX_VERIFIER_BINARY_BYTES (asserted by test).
MAX_VERIFIER_ARTIFACT_BYTES = 32 * 1024 * 1024
# The verifier's ONE aggregate byte budget for a whole verify command.
VERIFY_AGGREGATE_BUDGET_BYTES = 64 * 1024 * 1024
# Fixed per-command overhead: index + manifest + registry + report +
# verifier binary + publisher vector + independent candidate snapshot.
VERIFY_FIXED_OVERHEAD_BYTES = (
    MAX_INDEX_ARTIFACT_BYTES
    + MAX_MANIFEST_ARTIFACT_BYTES
    + MAX_REGISTRY_ARTIFACT_BYTES
    + MAX_REPORT_ARTIFACT_BYTES
    + MAX_VERIFIER_ARTIFACT_BYTES
    + MAX_VECTOR_ARTIFACT_BYTES
    + MAX_SNAPSHOT_ARTIFACT_BYTES
)
# Worst-case bytes one verified candidate can add to a FULL verify: its
# receipt, its two work-proof artifacts, and its controlled envelope.
PER_VERIFIED_CANDIDATE_BYTES = (
    MAX_RECEIPT_ARTIFACT_BYTES
    + MAX_WORK_ITEM_ARTIFACT_BYTES
    + MAX_WORK_RESULT_ARTIFACT_BYTES
    + MAX_CONTROLLED_ENVELOPE_BYTES
)
# The supported candidate-set cardinality is shared with the score producer.
# Candidate rows cost manifest bytes only; the 2 MiB manifest cap covers the
# complete 4,096-hotkey SN39 metagraph contract.
MAX_MANIFEST_CANDIDATES = MAX_LAUNCH_CANDIDATES
# The aggregate byte budget derives the maximum supported VERIFIED
# cardinality. Keep the shared launch constant asserted against the derivation
# so producer/exporter/verifier drift fails at import rather than publication.
_DERIVED_MAX_MANIFEST_RECEIPTS = (
    VERIFY_AGGREGATE_BUDGET_BYTES - VERIFY_FIXED_OVERHEAD_BYTES
) // PER_VERIFIED_CANDIDATE_BYTES
if _DERIVED_MAX_MANIFEST_RECEIPTS != MAX_LAUNCH_VERIFIED_CANDIDATES:
    raise RuntimeError("launch verified-candidate limit does not match the evidence byte budget")
MAX_MANIFEST_RECEIPTS = MAX_LAUNCH_VERIFIED_CANDIDATES
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DISCLOSURES = frozenset({"public", "controlled"})

_MANIFEST_KEYS = frozenset(
    {
        "schema",
        "network",
        "netuid",
        "source_epoch",
        "epoch_id",
        "generated_at",
        "reward_mechanism",
        "source_revision",
        "policy_registry",
        "verifier",
        "score_report",
        "receipts",
        "attestations",
        "candidate_set",
        "wire_report_sha256",
    }
)
_CANDIDATE_OUTCOMES = frozenset({"verified", "rejected", "retired"})
_INDEX_KEYS = frozenset(
    {
        "schema",
        "network",
        "netuid",
        "generated_at",
        "latest",
        "recent",
        "signing_key_id",
        "signature",
    }
)


class EvidenceError(Exception):
    """The evidence store or a bundle failed an integrity check."""


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise EvidenceError(f"{label} is not a sha256 digest")
    return value


def _utc_now_text() -> str:
    dt = datetime.now(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_manifest_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError(f"{label} is not a string timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise EvidenceError(f"{label} is not a UTC timestamp") from exc


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _reject_symlink(path: Path) -> None:
    if os.path.lexists(path) and Path(path).is_symlink():
        raise EvidenceError(f"refusing to touch symlink {path.name!r}")


def _atomic_write(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    """Create-only, non-symlink, fsynced (file and parent) atomic publish."""
    _reject_symlink(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(temporary, flags, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_dir(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class EvidenceStore:
    """Append-only content-addressed public evidence directory.

    Layout::

        <root>/blobs/sha256/<hex>          immutable artifact bytes
        <root>/epochs/<source_epoch>.json  immutable manifest convenience copy
        <root>/receipts/<receipt_id>.json  immutable receipt convenience copy
        <root>/index.json                  signed mutable pointer
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    # -- blobs ------------------------------------------------------------

    def blob_path(self, digest: str) -> Path:
        checked = _require_digest(digest, "blob digest")
        return self.root / "blobs" / "sha256" / checked.split(":", 1)[1]

    def put_blob(self, data: bytes) -> str:
        digest = digest_bytes(data)
        path = self.blob_path(digest)
        _reject_symlink(path)
        if path.exists():
            existing = path.read_bytes()
            if digest_bytes(existing) != digest or existing != data:
                raise EvidenceError(f"blob collision: {digest} exists with different content")
            return digest
        _atomic_write(path, data)
        return digest

    def get_blob(self, digest: str) -> bytes:
        path = self.blob_path(digest)
        _reject_symlink(path)
        try:
            data = path.read_bytes()
        except FileNotFoundError as exc:
            raise EvidenceError(f"blob {digest} is not in the store") from exc
        if digest_bytes(data) != digest:
            raise EvidenceError(f"blob {digest} content is corrupt")
        return data

    # -- convenience immutable copies -------------------------------------

    def put_receipt_copy(self, receipt_id: str, data: bytes) -> Path:
        if not isinstance(receipt_id, str) or not re.fullmatch(
            r"receipt-sha256:[0-9a-f]{64}", receipt_id
        ):
            raise EvidenceError("receipt id has an unexpected shape")
        path = self.root / "receipts" / f"{receipt_id}.json"
        if path.exists():
            if path.read_bytes() != data:
                raise EvidenceError(f"receipt copy {receipt_id} diverges from bytes")
            return path
        _atomic_write(path, data)
        return path

    def put_epoch_copy(self, source_epoch: int, manifest_bytes: bytes) -> Path:
        path = self.root / "epochs" / f"{int(source_epoch)}.json"
        if path.exists():
            if path.read_bytes() != manifest_bytes:
                raise EvidenceError(
                    f"epoch manifest {source_epoch} already exists with other content"
                )
            return path
        _atomic_write(path, manifest_bytes)
        return path

    # -- index -------------------------------------------------------------

    def read_index(self) -> bytes | None:
        path = self.root / "index.json"
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    class _IndexTransaction:
        """One exclusive critical section covering read → decide → publish.

        ``publish`` is compare-and-publish: it re-reads the current index
        under the same lock and refuses to move ``latest`` backwards or to
        equivocate (same epoch, different manifest) unless the bytes are
        identical. Concurrent exporters therefore cannot lose history or
        roll the pointer back.
        """

        def __init__(self, store: EvidenceStore) -> None:
            self._store = store
            self._descriptor: int | None = None

        def __enter__(self) -> EvidenceStore._IndexTransaction:
            import fcntl

            self._store.root.mkdir(parents=True, exist_ok=True)
            lock_path = self._store.root / ".index.lock"
            self._descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
            fcntl.flock(self._descriptor, fcntl.LOCK_EX)
            return self

        def __exit__(self, *_exc: object) -> None:
            if self._descriptor is not None:
                os.close(self._descriptor)
                self._descriptor = None

        def read(self) -> bytes | None:
            return self._store.read_index()

        @staticmethod
        def _latest_of(index_bytes: bytes) -> tuple[int, str] | None:
            try:
                document = parse_registry_json(index_bytes)
                latest = document.get("latest")
                return (int(latest["source_epoch"]), str(latest["manifest"]))
            except Exception:  # noqa: BLE001 - unreadable current index
                return None

        def _highwater_path(self) -> Path:
            return self._store.root / ".index-highwater.json"

        def read_highwater(self) -> tuple[int, str] | None:
            """Durable latest pointer that survives a corrupt index.json."""
            path = self._highwater_path()
            try:
                document = json.loads(path.read_text())
                return (int(document["source_epoch"]), str(document["manifest"]))
            except (OSError, ValueError, KeyError, TypeError):
                return None

        def publish(self, index_bytes: bytes) -> None:
            if self._descriptor is None:
                raise EvidenceError("index publish requires an open transaction")
            new_latest = self._latest_of(index_bytes)
            if new_latest is None:
                raise EvidenceError("refusing to publish a structurally invalid index")
            highwater = self.read_highwater()
            if highwater is not None:
                if new_latest[0] < highwater[0]:
                    raise EvidenceError(
                        "refusing to publish an index older than the durable "
                        "high-water (corrupt-index recovery must not roll back)"
                    )
                if new_latest[0] == highwater[0] and new_latest[1] != highwater[1]:
                    raise EvidenceError("refusing to equivocate the durable high-water manifest")
            current = self._store.read_index()
            if current is not None and current != index_bytes:
                current_latest = self._latest_of(current)
                new_latest = self._latest_of(index_bytes)
                if current_latest is not None and new_latest is not None:
                    if new_latest[0] < current_latest[0]:
                        raise EvidenceError(
                            "refusing to publish an index whose latest epoch moves backwards"
                        )
                    if new_latest[0] == current_latest[0] and new_latest[1] != current_latest[1]:
                        raise EvidenceError("refusing to equivocate the index latest manifest")
            _atomic_write(self._store.root / "index.json", index_bytes)
            _atomic_write(
                self._highwater_path(),
                json.dumps(
                    {"source_epoch": new_latest[0], "manifest": new_latest[1]},
                    sort_keys=True,
                ).encode("utf-8"),
                mode=0o600,
            )

    def index_transaction(self) -> EvidenceStore._IndexTransaction:
        return EvidenceStore._IndexTransaction(self)

    def write_index(self, index_bytes: bytes) -> None:
        with self.index_transaction() as transaction:
            transaction.publish(index_bytes)


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def build_manifest(
    *,
    network: str,
    netuid: int,
    source_epoch: int,
    epoch_id: int,
    generated_at: str | None,
    mechanism_id: str,
    mechanism_revision: int,
    source_revision: str | None,
    registry_release: int,
    registry_digest: str,
    registry_blob: str,
    verifier_digest: str,
    verifier_binary_blob: str | None,
    verifier_command: list[str] | None = None,
    verifier_artifacts: list[str] | None = None,
    report_id: str,
    report_blob: str,
    report_signing_key_id: str,
    receipts: list[dict[str, str]],
    attestations: list[dict[str, str]],
    candidate_set: dict[str, Any],
    wire_report_sha256: str | None,
) -> bytes:
    document: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "network": network,
        "netuid": int(netuid),
        "source_epoch": int(source_epoch),
        "epoch_id": int(epoch_id),
        "generated_at": generated_at or _utc_now_text(),
        "reward_mechanism": {
            "id": mechanism_id,
            "revision": int(mechanism_revision),
        },
        "source_revision": source_revision,
        "policy_registry": {
            "release": int(registry_release),
            "digest": _require_digest(registry_digest, "registry digest"),
            "blob": _require_digest(registry_blob, "registry blob"),
        },
        "verifier": {
            "digest": _require_digest(verifier_digest, "verifier digest"),
            "binary_blob": (
                _require_digest(verifier_binary_blob, "verifier binary blob")
                if verifier_binary_blob is not None
                else None
            ),
            "command": list(verifier_command) if verifier_command else None,
            "artifacts": list(verifier_artifacts) if verifier_artifacts else None,
        },
        "score_report": {
            "report_id": report_id,
            "blob": _require_digest(report_blob, "report blob"),
            "signing_key_id": report_signing_key_id,
        },
        "receipts": receipts,
        "attestations": attestations,
        "candidate_set": candidate_set,
        "wire_report_sha256": wire_report_sha256,
    }
    validate_manifest(document)
    encoded = canonical_json(document)
    if len(encoded) > MAX_MANIFEST_ARTIFACT_BYTES:
        raise EvidenceError("evidence manifest exceeds its artifact cap")
    return encoded


def validate_manifest(document: Mapping[str, Any]) -> None:
    if frozenset(document) != _MANIFEST_KEYS:
        raise EvidenceError("evidence manifest has missing or unknown fields")
    if document["schema"] in (LEGACY_MANIFEST_SCHEMA, LEGACY_MANIFEST_SCHEMA_V2):
        raise EvidenceError(
            "evidence manifest schema v1/v2 is superseded by v3 (exhaustive "
            "candidate-set binding is required); neither was ever published"
        )
    if document["schema"] != MANIFEST_SCHEMA:
        raise EvidenceError("evidence manifest schema is unsupported")
    if not isinstance(document["network"], str) or not document["network"]:
        raise EvidenceError("evidence manifest network is invalid")
    for name in ("netuid", "source_epoch", "epoch_id"):
        value = document[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise EvidenceError(f"evidence manifest {name} is invalid")
    _parse_manifest_time(document["generated_at"], "evidence manifest generated_at")
    mechanism = document["reward_mechanism"]
    if (
        not isinstance(mechanism, Mapping)
        or set(mechanism) != {"id", "revision"}
        or not isinstance(mechanism["id"], str)
        or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", mechanism["id"])
        or isinstance(mechanism["revision"], bool)
        or not isinstance(mechanism["revision"], int)
        or mechanism["revision"] < 1
    ):
        raise EvidenceError("evidence manifest reward_mechanism is invalid")
    source_revision = document["source_revision"]
    if source_revision is not None and (
        not isinstance(source_revision, str) or not re.fullmatch(r"[0-9a-f]{7,64}", source_revision)
    ):
        raise EvidenceError("evidence manifest source_revision is invalid")
    registry = document["policy_registry"]
    if (
        not isinstance(registry, Mapping)
        or set(registry) != {"release", "digest", "blob"}
        or isinstance(registry["release"], bool)
        or not isinstance(registry["release"], int)
        or registry["release"] < 1
    ):
        raise EvidenceError("evidence manifest policy_registry is invalid")
    _require_digest(registry["digest"], "registry digest")
    _require_digest(registry["blob"], "registry blob")
    verifier = document["verifier"]
    if not isinstance(verifier, Mapping) or set(verifier) != {
        "digest",
        "binary_blob",
        "command",
        "artifacts",
    }:
        raise EvidenceError("evidence manifest verifier is invalid")
    _require_digest(verifier["digest"], "verifier digest")
    if verifier["binary_blob"] is not None:
        _require_digest(verifier["binary_blob"], "verifier binary blob")
    for name in ("command", "artifacts"):
        value = verifier[name]
        if value is not None and (
            not isinstance(value, list)
            or not value
            or len(value) > 4
            or any(
                not isinstance(item, str)
                or not item.startswith("/")
                or len(item) > 4096
                or "\x00" in item
                or "\n" in item
                for item in value
            )
        ):
            raise EvidenceError(f"evidence manifest verifier {name} is invalid")
    report = document["score_report"]
    if (
        not isinstance(report, Mapping)
        or set(report) != {"report_id", "blob", "signing_key_id"}
        or not isinstance(report["report_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", report["report_id"]) is None
        or not isinstance(report["signing_key_id"], str)
        or not report["signing_key_id"]
    ):
        raise EvidenceError("evidence manifest score_report is invalid")
    _require_digest(report["blob"], "report blob")
    receipts = document["receipts"]
    if not isinstance(receipts, list) or len(receipts) > MAX_MANIFEST_RECEIPTS:
        raise EvidenceError("evidence manifest receipts is invalid")
    seen_receipt_ids: set[str] = set()
    receipt_hotkeys: set[str] = set()
    for row in receipts:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"receipt_id", "hotkey", "blob", "work_item_blob", "result_blob"}
            or not isinstance(row["receipt_id"], str)
            or re.fullmatch(r"receipt-sha256:[0-9a-f]{64}", row["receipt_id"]) is None
            or not is_launch_hotkey(row["hotkey"])
        ):
            raise EvidenceError("evidence manifest receipt row is invalid")
        _require_digest(row["blob"], "receipt blob")
        _require_digest(row["work_item_blob"], "work item blob")
        _require_digest(row["result_blob"], "work result blob")
        if row["receipt_id"] in seen_receipt_ids or row["hotkey"] in receipt_hotkeys:
            raise EvidenceError("evidence manifest duplicates a receipt or receipt hotkey")
        seen_receipt_ids.add(row["receipt_id"])
        receipt_hotkeys.add(row["hotkey"])
    attestations = document["attestations"]
    if not isinstance(attestations, list) or len(attestations) > MAX_MANIFEST_RECEIPTS:
        raise EvidenceError("evidence manifest attestations is invalid")
    attestation_hotkeys: set[str] = set()
    for row in attestations:
        if (
            not isinstance(row, Mapping)
            or set(row)
            != {
                "hotkey",
                "verdict",
                "evidence_digest",
                "envelope_digest",
                "challenge_digest",
                "disclosure",
            }
            or not is_launch_hotkey(row["hotkey"])
            or not isinstance(row["verdict"], str)
            or row["disclosure"] not in _DISCLOSURES
        ):
            raise EvidenceError("evidence manifest attestation row is invalid")
        _require_digest(row["evidence_digest"], "attestation evidence digest")
        if row["envelope_digest"] is not None:
            _require_digest(row["envelope_digest"], "attestation envelope digest")
        if row["challenge_digest"] is not None:
            _require_digest(row["challenge_digest"], "attestation challenge digest")
        if row["hotkey"] in attestation_hotkeys:
            raise EvidenceError("evidence manifest duplicates an attestation hotkey")
        attestation_hotkeys.add(row["hotkey"])
    candidate_set = document["candidate_set"]
    if (
        not isinstance(candidate_set, Mapping)
        or set(candidate_set)
        != {"source", "network", "netuid", "block", "block_hash", "candidates"}
        or candidate_set["source"] != "sn39_metagraph"
        or candidate_set["network"] != document["network"]
        or candidate_set["netuid"] != document["netuid"]
    ):
        raise EvidenceError("evidence manifest candidate_set is invalid")
    block = candidate_set["block"]
    if isinstance(block, bool) or not isinstance(block, int) or block < 0:
        raise EvidenceError("evidence manifest candidate block is invalid")
    block_hash = candidate_set["block_hash"]
    if not isinstance(block_hash, str) or not re.fullmatch(r"(0x)?[0-9a-f]{64}", block_hash):
        raise EvidenceError("evidence manifest candidate block hash is invalid")
    candidates = candidate_set["candidates"]
    if not isinstance(candidates, list) or len(candidates) > MAX_MANIFEST_CANDIDATES:
        raise EvidenceError("evidence manifest candidates list is invalid")
    seen_candidates: set[str] = set()
    for row in candidates:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"hotkey", "outcome", "reason"}
            or not is_launch_hotkey(row["hotkey"])
            or row["outcome"] not in _CANDIDATE_OUTCOMES
            or not isinstance(row["reason"], str)
            or not 1 <= len(row["reason"]) <= 200
            or not row["reason"].isascii()
            or any(ord(character) < 0x20 or ord(character) > 0x7E for character in row["reason"])
        ):
            raise EvidenceError("evidence manifest candidate row is invalid")
        if row["hotkey"] in seen_candidates:
            raise EvidenceError("evidence manifest duplicates a candidate")
        seen_candidates.add(row["hotkey"])
    verified_hotkeys = {row["hotkey"] for row in candidates if row["outcome"] == "verified"}
    if len(verified_hotkeys) > MAX_MANIFEST_RECEIPTS:
        raise EvidenceError(
            "evidence manifest verified-candidate count exceeds the launch "
            f"receipt budget ({len(verified_hotkeys)} > {MAX_MANIFEST_RECEIPTS}); "
            "every verified candidate needs a receipt, two work artifacts, "
            "and a controlled envelope inside the verifier's aggregate byte cap"
        )
    if receipt_hotkeys != verified_hotkeys:
        raise EvidenceError(
            "evidence manifest receipts must cover exactly the verified candidate set"
        )
    if attestation_hotkeys != verified_hotkeys:
        raise EvidenceError(
            "evidence manifest attestations must cover exactly the verified candidate set"
        )
    wire = document["wire_report_sha256"]
    if wire is not None and (not isinstance(wire, str) or not re.fullmatch(r"[0-9a-f]{64}", wire)):
        raise EvidenceError("evidence manifest wire_report_sha256 is invalid")


def parse_manifest(manifest_bytes: bytes) -> dict[str, Any]:
    if (
        not isinstance(manifest_bytes, bytes)
        or not manifest_bytes
        or len(manifest_bytes) > MAX_MANIFEST_ARTIFACT_BYTES
    ):
        raise EvidenceError("evidence manifest is empty or exceeds its artifact cap")

    def _reject_manifest_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError(f"duplicate evidence manifest JSON key {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_reject_manifest_duplicates,
            parse_float=lambda _value: (_ for _ in ()).throw(
                EvidenceError("floating-point evidence manifest JSON is not canonical")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                EvidenceError("non-finite evidence manifest JSON is not canonical")
            ),
        )
    except EvidenceError:
        raise
    except (
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as exc:
        raise EvidenceError("evidence manifest is not strict UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise EvidenceError("evidence manifest must be a JSON object")
    if canonical_json(document) != manifest_bytes:
        raise EvidenceError("evidence manifest bytes are not canonical JSON")
    validate_manifest(document)
    return document


# ---------------------------------------------------------------------------
# Signed index
# ---------------------------------------------------------------------------


def build_signed_index(
    *,
    network: str,
    netuid: int,
    latest_source_epoch: int,
    latest_manifest_digest: str,
    recent: list[dict[str, Any]],
    signing_key_id: str,
    private_key_seed: bytes,
    generated_at: str | None = None,
) -> bytes:
    if not isinstance(private_key_seed, bytes) or len(private_key_seed) != 32:
        raise EvidenceError("index signing key seed must be 32 bytes")
    entries = [
        {
            "source_epoch": int(row["source_epoch"]),
            "manifest": _require_digest(row["manifest"], "recent manifest digest"),
        }
        for row in recent[:MAX_INDEX_RECENT]
    ]
    document: dict[str, Any] = {
        "schema": INDEX_SCHEMA,
        "network": network,
        "netuid": int(netuid),
        "generated_at": generated_at or _utc_now_text(),
        "latest": {
            "source_epoch": int(latest_source_epoch),
            "manifest": _require_digest(latest_manifest_digest, "latest manifest"),
        },
        "recent": entries,
        "signing_key_id": signing_key_id,
    }
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signature = Ed25519PrivateKey.from_private_bytes(private_key_seed).sign(
        INDEX_DOMAIN + canonical_json(document)
    )
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return canonical_json(document)


def verify_index(
    index_bytes: bytes,
    trusted_keys: Mapping[str, bytes],
    *,
    expected_network: str,
    expected_netuid: int,
    max_age_seconds: float | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        document = parse_registry_json(index_bytes)
    except PolicyRegistryError as exc:
        raise EvidenceError(f"evidence index is not strict JSON: {exc}") from exc
    if canonical_json(document) != index_bytes:
        raise EvidenceError("evidence index bytes are not canonical JSON")
    if frozenset(document) != _INDEX_KEYS:
        raise EvidenceError("evidence index has missing or unknown fields")
    if document["schema"] != INDEX_SCHEMA:
        raise EvidenceError("evidence index schema is unsupported")
    if document["network"] != expected_network or document["netuid"] != expected_netuid:
        raise EvidenceError("evidence index network/netuid mismatch")
    key_id = document["signing_key_id"]
    if not isinstance(key_id, str) or key_id not in trusted_keys:
        raise EvidenceError("evidence index is signed by an unknown key id")
    signature = document["signature"]
    if not isinstance(signature, Mapping) or signature.get("algorithm") != "ed25519":
        raise EvidenceError("evidence index signature is missing or not ed25519")
    value = signature.get("value_base64")
    if not isinstance(value, str):
        raise EvidenceError("evidence index signature value is missing")
    try:
        raw_signature = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise EvidenceError("evidence index signature is not valid base64") from exc
    body = {k: v for k, v in document.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(trusted_keys[key_id]).verify(
            raw_signature, INDEX_DOMAIN + canonical_json(body)
        )
    except (InvalidSignature, ValueError) as exc:
        raise EvidenceError("evidence index signature is invalid") from exc

    generated_at = _parse_manifest_time(document["generated_at"], "evidence index generated_at")
    moment = now if now is not None else datetime.now(UTC)
    if generated_at > moment:
        raise EvidenceError("evidence index generated_at is in the future")
    if max_age_seconds is not None and ((moment - generated_at).total_seconds() > max_age_seconds):
        raise EvidenceError("evidence index is stale")
    latest = document["latest"]
    if (
        not isinstance(latest, Mapping)
        or set(latest) != {"source_epoch", "manifest"}
        or isinstance(latest["source_epoch"], bool)
        or not isinstance(latest["source_epoch"], int)
    ):
        raise EvidenceError("evidence index latest pointer is invalid")
    _require_digest(latest["manifest"], "latest manifest digest")
    recent = document["recent"]
    if not isinstance(recent, list) or len(recent) > MAX_INDEX_RECENT:
        raise EvidenceError("evidence index recent list is invalid")
    seen_epochs: set[int] = {int(latest["source_epoch"])}
    seen_manifests: set[str] = {str(latest["manifest"])}
    previous_epoch = int(latest["source_epoch"])
    for row in recent:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"source_epoch", "manifest"}
            or isinstance(row["source_epoch"], bool)
            or not isinstance(row["source_epoch"], int)
            or row["source_epoch"] < 0
        ):
            raise EvidenceError("evidence index recent row is invalid")
        _require_digest(row["manifest"], "recent manifest digest")
        epoch = int(row["source_epoch"])
        if epoch in seen_epochs:
            raise EvidenceError("evidence index duplicates a source epoch")
        if row["manifest"] in seen_manifests:
            raise EvidenceError("evidence index duplicates a manifest digest")
        if epoch >= previous_epoch:
            raise EvidenceError("evidence index recent epochs must strictly decrease from latest")
        seen_epochs.add(epoch)
        seen_manifests.add(str(row["manifest"]))
        previous_epoch = epoch
    return document


# ---------------------------------------------------------------------------
# Controlled-disclosure retention
# ---------------------------------------------------------------------------


class RetentionStore:
    """Root-only retention for raw quotes/collateral (controlled disclosure).

    Raw bytes live under ``<root>/blobs/sha256/<hex>`` with 0600 permissions;
    every retention is journaled (digest + metadata, never content) in
    ``<root>/log.jsonl``. The public manifest references these by digest only.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def retain(
        self,
        data: bytes,
        *,
        kind: str,
        hotkey: str | None = None,
        source_epoch: int | None = None,
        epoch_id: int | None = None,
    ) -> str:
        if kind == "admission_evidence" and len(data) > MAX_CONTROLLED_ENVELOPE_BYTES:
            raise EvidenceError(
                "controlled envelope exceeds the launch disclosure cap "
                f"({len(data)} > {MAX_CONTROLLED_ENVELOPE_BYTES} bytes); an "
                "unfetchable envelope would silently unprove the epoch later"
            )
        digest = digest_bytes(data)
        path = self.root / "blobs" / "sha256" / digest.split(":", 1)[1]
        _reject_symlink(path)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        if path.exists():
            # Validate pre-existing blobs fully before acceptance: regular,
            # owned, private (no drifted 0644), and content-correct.
            import stat as stat_module

            metadata = os.lstat(path)
            if (
                stat_module.S_ISLNK(metadata.st_mode)
                or not stat_module.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o077
                or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
            ):
                raise EvidenceError(f"retained blob {digest} is unsafe on disk (mode/owner/type)")
            if digest_bytes(path.read_bytes()) != digest:
                raise EvidenceError(f"retained blob {digest} is corrupt on disk")
        else:
            _atomic_write(path, data, mode=0o600)
        record = {
            "ts": _utc_now_text(),
            "kind": kind,
            "digest": digest,
            "bytes": len(data),
        }
        if hotkey is not None:
            record["hotkey"] = hotkey
        if source_epoch is not None:
            record["source_epoch"] = int(source_epoch)
        if epoch_id is not None:
            record["epoch_id"] = int(epoch_id)
        log_path = self.root / "log.jsonl"
        _reject_symlink(log_path)
        import fcntl

        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(log_path, flags, 0o600)
        try:
            opened = os.fstat(descriptor)
            if opened.st_mode & 0o077:
                raise EvidenceError("retention journal must not be group/world accessible")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
                descriptor = -1
                handle.write(json.dumps(record, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor != -1:
                os.close(descriptor)
        return digest
