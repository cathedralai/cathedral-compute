"""Cathedral operator CLI (docs/DESIGN.md §7, §10).

Thin argparse front-end over the in-process control plane (cathedral.api),
the SAT lane (cathedral.lanes.sat), and the shared Policy check
(cathedral.common). ``work submit`` and ``work status`` use the runtime's
durable SQLite ledger so customer work can be atomically leased to admitted
CPU workers instead of living in a disconnected local file.

Every subcommand is a plain, importable function taking parsed args and
returning an int exit code -- callers (tests, scripts) never need to shell
out.

    python -m cathedral.cli census
    python -m cathedral.cli verify-quote --measurement M --allowed-measurement M --tcb 3 --min-tcb 1
    python -m cathedral.cli work submit --ledger-db runtime.sqlite --customer-id demo --n-vars 3 --clauses '[[1, 2, -3]]'
    python -m cathedral.cli work status --ledger-db runtime.sqlite
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import re
import ssl
import stat
import sys
from collections.abc import Mapping
from pathlib import Path

from cathedral import census as census_mod
from cathedral.admission_policy import (
    MODE_SELECTED,
    load_policy_keys,
    verify_admission_policy,
)
from cathedral.assurance import AssuranceDimension
from cathedral.attest import collect_snp, collect_tdx_gpu
from cathedral.channel import ChannelBindingError, tls_spki_binding
from cathedral.coldkey_allowlist import (
    DEFAULT_ALLOWLIST_MAX_AGE_SECONDS,
    load_allowlist_keys,
    verify_allowlist,
)
from cathedral.common import ChannelBinding, ChannelBindingType, Policy, Tier
from cathedral.customer_receipt import (
    MAX_CUSTOMER_RECEIPT_BYTES,
    MAX_CUSTOMER_RECEIPT_TRUSTED_KEYS_BYTES,
    CustomerReceiptError,
    parse_customer_receipt_trusted_keys_json,
    verify_customer_receipt,
)
from cathedral.enroll import JsonHotkeyRegistrationProvider, RegistryStore
from cathedral.evidence import (
    MAX_CONTROLLED_ENVELOPE_BYTES,
    MAX_INDEX_ARTIFACT_BYTES,
    MAX_MANIFEST_ARTIFACT_BYTES,
    MAX_MANIFEST_RECEIPTS,
    MAX_RECEIPT_ARTIFACT_BYTES,
    MAX_REGISTRY_ARTIFACT_BYTES,
    MAX_REPORT_ARTIFACT_BYTES,
    MAX_SNAPSHOT_ARTIFACT_BYTES,
    MAX_VECTOR_ARTIFACT_BYTES,
    MAX_VERIFIER_ARTIFACT_BYTES,
    MAX_WORK_ITEM_ARTIFACT_BYTES,
    MAX_WORK_RESULT_ARTIFACT_BYTES,
    VERIFY_AGGREGATE_BUDGET_BYTES,
)
from cathedral.gpu import (
    GpuIdentityRegistry,
    gpu_profile_from_registry,
    gpu_verifier_from_env,
)
from cathedral.lanes.sat import SatLane, _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem
from cathedral.ledger import Ledger
from cathedral.policy_registry import (
    MAX_REGISTRY_BYTES,
    PolicyRegistryError,
    PolicyRegistrySnapshot,
    PolicyRegistryState,
    parse_registry_json,
    verify_registry,
)
from cathedral.poster import Poster
from cathedral.receipt import (
    MAX_RECEIPT_BYTES,
    ReceiptError,
    ReceiptIssuer,
    parse_receipt_json,
    verify_receipt,
)
from cathedral.runtime import (
    MAX_BEARER_TOKEN_LENGTH,
    ConfidentialRuntime,
    EpochRun,
    MinerOutcome,
    MinerTarget,
    RuntimeConfig,
)
from cathedral.score_class import export_score_class_report
from cathedral.worker import WorkerServer

DEFAULT_PUBLISHER_BEARER_ENV = "CATHEDRAL_PUBLISHER_BEARER_TOKEN"
DEFAULT_PUBLISHER_HMAC_ENV = "CATHEDRAL_PUBLISHER_HMAC_SECRET"
DEFAULT_WORKER_BEARER_ENV = "CATHEDRAL_WORKER_BEARER_TOKEN"


# --------------------------------------------------------------------------
# pretty output helpers: human-readable operator logs for run-epoch and
# retry-publish.  JSON is still the default; --pretty opts in.
# --------------------------------------------------------------------------


def _utc_ts() -> str:
    """Current UTC timestamp in compact ISO format for operator logs."""
    return datetime.datetime.now(tz=datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _abbrev(s: str | None, prefix: int = 5, suffix: int = 4) -> str:
    """Abbreviate a long identifier (hotkey, challenge ID) for single-line display."""
    if not s:
        return "-"
    if len(s) <= prefix + suffix + 2:
        return s
    return f"{s[:prefix]}..{s[-suffix:]}"


# Patterns that identify a credential value inside an error string.
# Conservative: require an explicit keyword followed by = or : and a
# non-whitespace token.  The key name is preserved; only the value is
# replaced.  Redaction runs before truncation so no partial secret can
# survive at the length boundary.
_REDACT_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Authorization: <scheme> <opaque>, including QUOTED whole values as they
    # appear in serialized JSON / Python reprs echoed inside exceptions.
    re.compile(
        r"([\"']?Authorization[\"']?\s*[=:]\s*)"
        r"(\"[^\"]*\"|'[^']*'|(?:Bearer|Basic)\s+\S+|\S+)",
        re.IGNORECASE,
    ),
    # key=value / key: value with bare, quoted (spaces included), or
    # URL-safe values; keys may themselves be quoted.
    re.compile(
        r"([\"']?(?:bearer|basic|token|secret|hmac|password|private_key|"
        r"api[-_]?key)[\"']?\s*[=:]\s*)"
        r"(\"[^\"]*\"|'[^']*'|\S+)",
        re.IGNORECASE,
    ),
)
_REDACT_REPLACEMENT = r"\g<1>[REDACTED]"


def _sanitize_error(err: str | None, maxlen: int = 100) -> str:
    """Flatten, redact credential patterns, and truncate an error string.

    Redaction targets obvious credential assignments embedded in upstream
    error messages:

    * ``Authorization: Bearer <token>`` (HTTP header echoed verbatim)
    * ``bearer=``, ``token=``, ``secret=``, ``hmac=``, ``api_key=``,
      ``api-key=`` assignments (``=`` or ``:`` separator, case-insensitive)

    Non-secret text is preserved.  Redaction runs before truncation so a
    partial credential cannot survive at the length boundary.
    """
    if not err:
        return ""
    # 1. Flatten to a single line.
    flat = err.replace("\n", " ").replace("\r", " ").strip()
    # 2. Redact credential-shaped patterns.
    for pattern in _REDACT_PATTERNS:
        flat = pattern.sub(_REDACT_REPLACEMENT, flat)
    # 3. Truncate.
    return flat[:maxlen]


def _pretty_outcome_indicator(outcome: MinerOutcome) -> str:
    """Return a fixed-width 4-char status indicator: OK, ZERO, or FAIL."""
    if outcome.admitted and outcome.score > 0.0:
        return "OK  "
    if outcome.admitted:
        return "ZERO"
    return "FAIL"


def _format_run_pretty(run: EpochRun, *, out: object = None) -> None:
    """Write a concise ASCII epoch summary to *out* (default: sys.stdout).

    One lifecycle header, one line per worker, one summary footer::

        [TIMESTAMP] EPOCH START  source=N  ep=N
        [TIMESTAMP] OK    5Ctob..awK  ep=7/1  admit=Y  work=verified
                    wu=20.00  score=1.000  pub=NO  ch=ababab..bababa
        [TIMESTAMP] ZERO  5Zero..ero  ep=7/1  admit=Y  work=sat_failed
                    wu=0.00  score=0.000  pub=NO  ch=cdcdcd..dcdcdc
                    err=invalid SAT certificate
        [TIMESTAMP] FAIL  5Fail..ail  ep=7/1  admit=N  work=attestation_failed
                    wu=0.00  score=0.000  pub=NO  err=worker returned HTTP 401
        [TIMESTAMP] EPOCH END  ep=7/1  status=complete  published=NO
                    ok=1  zeros=1  fail=1
    """
    if out is None:
        out = sys.stdout

    pub_str = "YES" if run.published else "NO"

    print(
        f"[{_utc_ts()}] EPOCH START  source={run.source_epoch}  ep={run.epoch_id}",
        file=out,
    )

    ok_count = zero_count = fail_count = 0
    for outcome in run.outcomes:
        ind = _pretty_outcome_indicator(outcome)
        if ind == "OK  ":
            ok_count += 1
        elif ind == "ZERO":
            zero_count += 1
        else:
            fail_count += 1

        hotkey_str = _abbrev(outcome.hotkey, prefix=5, suffix=4)
        ch_str = _abbrev(outcome.challenge_id, prefix=6, suffix=6)
        admit_str = "Y" if outcome.admitted else "N"
        err_part = f"  err={_sanitize_error(outcome.error)}" if outcome.error else ""

        print(
            f"[{_utc_ts()}] {ind}  {hotkey_str:<14}"
            f"  ep={run.source_epoch}/{run.epoch_id}"
            f"  admit={admit_str}"
            f"  work={outcome.status:<22}"
            f"  wu={outcome.work_units:>8.2f}"
            f"  score={outcome.score:.3f}"
            f"  pub={pub_str}"
            f"  ch={ch_str}"
            f"{err_part}",
            file=out,
        )
        if outcome.assurance is not None:
            claim_summary = " ".join(
                f"{dimension.value[0].upper()}={outcome.assurance.claim(dimension).status.value}"
                for dimension in AssuranceDimension
            )
            print(f"            assurance {claim_summary}", file=out)

    status_flag = "  !! EPOCH FAILED" if run.status not in {"complete", "published"} else ""
    print(
        f"[{_utc_ts()}] EPOCH END"
        f"  ep={run.source_epoch}/{run.epoch_id}"
        f"  status={run.status}{status_flag}"
        f"  published={pub_str}"
        f"  workers={len(run.outcomes)}"
        f"  ok={ok_count}  zeros={zero_count}  fail={fail_count}",
        file=out,
    )


def _format_publish_pretty(epoch_id: int, ack: dict[str, object], *, out: object = None) -> None:
    """Write a concise human-readable publish acknowledgement to *out*."""
    if out is None:
        out = sys.stdout
    ack_status = ack.get("status", "?")
    print(
        f"[{_utc_ts()}] PUBLISH  epoch={epoch_id}  ok  ack={ack_status}",
        file=out,
    )


def _item_to_dict(item: SatWorkItem) -> dict:
    return {
        "n_vars": item.instance.n_vars,
        "clauses": item.instance.clauses,
        "seed": item.seed,
        "challenge_id": item.challenge_id,
    }


def _dict_to_item(d: dict) -> SatWorkItem:
    instance = SatInstance(n_vars=d["n_vars"], clauses=d["clauses"])
    # Legacy queue entries may lack challenge_id; recompute and validate.
    stored_id = d.get("challenge_id")
    computed_id = _compute_challenge_id(instance, d["seed"])
    if stored_id is not None and stored_id != computed_id:
        raise ValueError(
            f"persisted challenge_id {stored_id} does not match "
            f"recomputed {computed_id} for seed={d['seed']}"
        )
    return SatWorkItem(instance=instance, seed=d["seed"], challenge_id=computed_id)


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------


def cmd_census(args: argparse.Namespace) -> int:
    return census_mod.main()


def cmd_verify_quote(args: argparse.Namespace) -> int:
    policy = Policy(allowed_measurements=set(args.allowed_measurement), min_tcb=args.min_tcb)
    ok = args.measurement in policy.allowed_measurements and args.tcb >= policy.min_tcb
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


def cmd_work_submit(args: argparse.Namespace) -> int:
    if args.clauses is not None:
        clauses = json.loads(args.clauses)
        instance = SatInstance(n_vars=args.n_vars, clauses=clauses)
        seed = args.seed if args.seed is not None else 0
        challenge_id = _compute_challenge_id(instance, seed)
        item = SatWorkItem(instance=instance, seed=seed, challenge_id=challenge_id)
    else:
        # No explicit job given: backfill one canonical instance to submit.
        dispatched = SatLane().dispatch("cli-submit", budget=1)
        assert isinstance(dispatched, SatWorkItem)
        item = dispatched

    with Ledger(args.ledger_db) as ledger:
        job = ledger.enqueue_customer_job(
            item,
            customer_id=getattr(args, "customer_id", "operator"),
            idempotency_key=getattr(args, "idempotency_key", None),
        )
        queued = ledger.customer_job_counts()["queued"]
    print(
        f"submitted {job.job_id} (n_vars={item.instance.n_vars}, seed={item.seed}); queued={queued}"
    )
    return 0


def cmd_work_status(args: argparse.Namespace) -> int:
    with Ledger(args.ledger_db) as ledger:
        job_id = getattr(args, "job_id", None)
        if job_id is not None:
            job = ledger.customer_job(job_id)
            print(
                json.dumps(
                    {
                        "job_id": job.job_id,
                        "customer_id": job.customer_id,
                        "status": job.status,
                        "attempt_count": job.attempt_count,
                        "lease_owner": job.lease_owner,
                        "lease_epoch_id": job.lease_epoch_id,
                        "result": dict(job.result) if job.result is not None else None,
                        "last_error": (
                            _sanitize_error(job.last_error, maxlen=300)
                            if job.last_error is not None
                            else None
                        ),
                    },
                    sort_keys=True,
                )
            )
            return 0
        counts = ledger.customer_job_counts()
    print(json.dumps({"customer_jobs": dict(counts)}, sort_keys=True))
    return 0


def cmd_work_prune(args: argparse.Namespace) -> int:
    if not getattr(args, "confirm", False):
        raise ValueError("work prune requires --confirm")
    try:
        before = datetime.datetime.fromisoformat(args.resolved_before.replace("Z", "+00:00"))  # noqa: FURB162 - intentional fail-closed/UTC-text semantics
    except (AttributeError, TypeError, ValueError):
        raise ValueError("--resolved-before must be a UTC ISO-8601 timestamp") from None
    if before.tzinfo is None or before.utcoffset() != datetime.timedelta(0):
        raise ValueError("--resolved-before must be a UTC ISO-8601 timestamp")
    with Ledger(args.ledger_db) as ledger:
        removed = ledger.prune_customer_jobs(
            before,
            limit=args.limit,
            customer_id=getattr(args, "customer_id", None),
        )
    print(json.dumps({"pruned_customer_jobs": removed}, sort_keys=True))
    return 0


def _load_json(path: str, description: str) -> object:
    try:
        with Path(path).open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to load {description} file") from exc


def _load_policy(path: str) -> Policy:
    raw = _load_json(path, "measurements")
    if isinstance(raw, list):
        measurements = raw
        min_tcb = 0
        tdx_strict = False
        tdx_allowed_tcb_statuses = ["UpToDate"]
        tdx_allowed_advisories: list[str] = []
    elif isinstance(raw, dict):
        measurements = raw.get("allowed_measurements")
        min_tcb = raw.get("min_tcb", 0)
        tdx_strict = raw.get("tdx_strict", False)
        tdx_allowed_tcb_statuses = raw.get("tdx_allowed_tcb_statuses", ["UpToDate"])
        tdx_allowed_advisories = raw.get("tdx_allowed_advisories", [])
    else:
        raise ValueError("measurements file must be a JSON array or object")  # noqa: TRY004 - intentional fail-closed/UTC-text semantics
    if not isinstance(measurements, list) or any(
        not isinstance(value, str) or not value for value in measurements
    ):
        raise ValueError("allowed_measurements must be a list of nonempty strings")
    if isinstance(min_tcb, bool) or not isinstance(min_tcb, int) or min_tcb < 0:
        raise ValueError("min_tcb must be a nonnegative integer")
    if not isinstance(tdx_strict, bool):
        raise ValueError("tdx_strict must be a boolean")  # noqa: TRY004 - intentional fail-closed/UTC-text semantics
    for name, values in (
        ("tdx_allowed_tcb_statuses", tdx_allowed_tcb_statuses),
        ("tdx_allowed_advisories", tdx_allowed_advisories),
    ):
        if not isinstance(values, list) or any(
            not isinstance(value, str) or not value for value in values
        ):
            raise ValueError(f"{name} must be a list of nonempty strings")
    return Policy(
        allowed_measurements=set(measurements),
        min_tcb=min_tcb,
        tdx_strict=tdx_strict,
        tdx_allowed_tcb_statuses=set(tdx_allowed_tcb_statuses),
        tdx_allowed_advisories=set(tdx_allowed_advisories),
    )


def _read_bounded_registry_file(path: str, label: str) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_REGISTRY_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"unable to load {label}") from exc
    if len(data) > MAX_REGISTRY_BYTES:
        raise ValueError(f"{label} exceeds the maximum encoded size")
    return data


def _load_registry_keys(
    path: str,
    *,
    production_mode: bool = False,
    pinned_digest: str | None = None,
) -> dict[str, bytes]:
    encoded = _read_bounded_registry_file(path, "policy registry key file")
    if production_mode and pinned_digest is None:
        raise ValueError("production policy registry keys require a pinned digest")
    if pinned_digest is not None:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", pinned_digest) is None:
            raise ValueError("policy registry key digest is invalid")
        actual_digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
        if not hmac.compare_digest(actual_digest, pinned_digest):
            raise ValueError("policy registry key digest does not match")
    raw = parse_registry_json(encoded)
    keys: dict[str, bytes] = {}
    try:
        for key_id, encoded in raw.items():
            if not isinstance(key_id, str) or not key_id or not isinstance(encoded, str):
                raise ValueError
            key = base64.b64decode(encoded, validate=True)
            if len(key) != 32:
                raise ValueError
            keys[key_id] = key
    except (binascii.Error, ValueError):
        raise ValueError("policy registry keys must be 32-byte base64 values") from None
    if not keys:
        raise ValueError("policy registry key file cannot be empty")
    return keys


def _verified_registry_policy(
    registry_path: str,
    keys_path: str,
    *,
    state_path: str,
    minimum_release: int | None,
    max_age_seconds: int,
    production_mode: bool,
    trusted_keys_digest: str | None = None,
    pinned_release: int | None = None,
    pinned_digest: str | None = None,
) -> Policy:
    policy, _snapshot = _verified_registry_snapshot_and_policy(
        registry_path,
        keys_path,
        state_path=state_path,
        minimum_release=minimum_release,
        max_age_seconds=max_age_seconds,
        production_mode=production_mode,
        trusted_keys_digest=trusted_keys_digest,
        pinned_release=pinned_release,
        pinned_digest=pinned_digest,
    )
    return policy


def _verified_registry_snapshot_and_policy(
    registry_path: str,
    keys_path: str,
    *,
    state_path: str,
    minimum_release: int | None,
    max_age_seconds: int,
    production_mode: bool,
    trusted_keys_digest: str | None = None,
    pinned_release: int | None = None,
    pinned_digest: str | None = None,
) -> tuple[Policy, PolicyRegistrySnapshot]:
    data = _read_bounded_registry_file(registry_path, "policy registry")
    snapshot = verify_registry(
        data,
        _load_registry_keys(
            keys_path,
            production_mode=production_mode,
            pinned_digest=trusted_keys_digest,
        ),
        max_age_seconds=max_age_seconds,
    )
    # Prove the signed snapshot can produce a usable CPU admission policy
    # before advancing the durable high-water mark.
    policy = snapshot.to_policy(max_age_seconds=max_age_seconds)
    state = PolicyRegistryState(
        state_path,
        production_mode=production_mode,
        minimum_release=minimum_release,
        pinned_release=pinned_release,
        pinned_digest=pinned_digest,
    )
    state.accept(snapshot)
    return policy, snapshot


def _read_bounded_receipt_file(path: str, label: str) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_RECEIPT_BYTES + 1)
    except OSError as exc:
        raise ReceiptError("schema", f"unable to load {label}") from exc
    if len(data) > MAX_RECEIPT_BYTES:
        raise ReceiptError("schema", f"{label} exceeds the maximum encoded size")
    return data


def _read_bounded_customer_receipt_file(
    path: str,
    label: str,
    *,
    maximum_bytes: int,
    category: str,
) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(maximum_bytes + 1)
    except OSError as exc:
        raise CustomerReceiptError(category, f"unable to load {label}") from exc
    if len(data) > maximum_bytes:
        raise CustomerReceiptError(category, f"{label} exceeds the maximum encoded size")
    return data


def _load_private_seed(
    path: str,
    *,
    production_mode: bool,
    label: str,
) -> bytes:
    target = Path(path)
    try:
        before = target.lstat()
    except OSError as exc:
        raise ValueError(f"unable to load {label}") from exc
    if not stat.S_ISREG(before.st_mode) or target.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise ValueError(f"unable to load {label}") from exc
    try:
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != (
                before.st_dev,
                before.st_ino,
            ):
                raise ValueError(f"{label} must be a stable regular non-symlink file")
            if production_mode and metadata.st_mode & 0o077:
                raise ValueError(f"production {label} must not be group/world accessible")
            if production_mode and hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise ValueError(f"production {label} must be owned by the runtime user")
            raw = os.read(descriptor, 257)
        except OSError as exc:
            raise ValueError(f"unable to load {label}") from exc
    finally:
        os.close(descriptor)
    if len(raw) > 256:
        raise ValueError(f"{label} must be a 32-byte base64 seed")
    try:
        seed = base64.b64decode(raw.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be a 32-byte base64 seed") from exc
    if len(seed) != 32:
        raise ValueError(f"{label} must be a 32-byte base64 seed")
    return seed


def _load_receipt_private_seed(path: str, *, production_mode: bool) -> bytes:
    return _load_private_seed(
        path,
        production_mode=production_mode,
        label="receipt signing key",
    )


def _load_gpu_identity_key(path: str, *, production_mode: bool) -> bytes:
    return _load_private_seed(
        path,
        production_mode=production_mode,
        label="GPU identity key",
    )


def cmd_policy_registry_verify(args: argparse.Namespace) -> int:
    historical_at = None
    historical_raw = getattr(args, "historical_at", None)
    if historical_raw is not None:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", historical_raw) is None:
            raise ValueError("--historical-at must be canonical UTC time")
        try:
            historical_at = datetime.datetime.strptime(
                historical_raw, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=datetime.UTC)
        except ValueError:
            raise ValueError("--historical-at must be canonical UTC time") from None
    registry_bytes = _read_bounded_registry_file(args.registry, "policy registry")
    snapshot = verify_registry(
        registry_bytes,
        _load_registry_keys(args.trusted_keys),
        max_age_seconds=args.max_age_seconds,
        historical_at=historical_at,
    )
    print(
        json.dumps(
            {
                "release": snapshot.release,
                "digest": snapshot.digest,
                "signing_key_id": snapshot.signing_key_id,
                "profiles": [
                    {"id": profile.profile_id, "kind": profile.kind, "status": profile.status}
                    for profile in snapshot.profiles
                ],
            },
            sort_keys=True,
        )
    )
    return 0


def cmd_receipt_verify(args: argparse.Namespace) -> int:
    try:
        receipt_bytes = _read_bounded_receipt_file(args.receipt, "assurance receipt")
        preview = parse_receipt_json(receipt_bytes)
        issued_raw = preview.get("issued_at")
        if (
            not isinstance(issued_raw, str)
            or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", issued_raw) is None
        ):
            raise ReceiptError("schema", "receipt issued_at is invalid")
        try:
            issued_at = datetime.datetime.strptime(issued_raw, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=datetime.UTC
            )
        except ValueError as exc:
            raise ReceiptError("schema", "receipt issued_at is invalid") from exc
        policy_registry = verify_registry(
            _read_bounded_registry_file(args.policy_registry, "policy registry"),
            _load_registry_keys(args.trusted_keys),
            historical_at=issued_at,
        )
        key_registry = policy_registry
        if getattr(args, "key_registry", None) is not None:
            key_registry = verify_registry(
                _read_bounded_registry_file(args.key_registry, "receipt key registry"),
                _load_registry_keys(args.key_registry_trusted_keys or args.trusted_keys),
                max_age_seconds=args.key_registry_max_age_seconds,
            )
        verified = verify_receipt(
            receipt_bytes,
            policy_registry,
            key_registry=key_registry,
        )
    except ReceiptError as exc:
        print(
            json.dumps(
                {"valid": False, "category": exc.category, "error": str(exc)},
                sort_keys=True,
            )
        )
        return 1
    except (PolicyRegistryError, ValueError) as exc:
        print(
            json.dumps(
                {"valid": False, "category": "policy_registry", "error": str(exc)},
                sort_keys=True,
            )
        )
        return 1
    print(
        json.dumps(
            {
                "valid": True,
                "receipt_id": verified.receipt_id,
                "receipt_digest": verified.receipt_digest,
                "policy_registry_release": policy_registry.release,
                "key_registry_release": key_registry.release,
            },
            sort_keys=True,
        )
    )
    return 0


def cmd_customer_receipt_verify(args: argparse.Namespace) -> int:
    try:
        receipt_bytes = _read_bounded_customer_receipt_file(
            args.receipt,
            "customer receipt",
            maximum_bytes=MAX_CUSTOMER_RECEIPT_BYTES,
            category="schema",
        )
        trusted_keys = parse_customer_receipt_trusted_keys_json(
            _read_bounded_customer_receipt_file(
                args.trusted_keys,
                "customer receipt trusted keys",
                maximum_bytes=MAX_CUSTOMER_RECEIPT_TRUSTED_KEYS_BYTES,
                category="key",
            )
        )
        verified = verify_customer_receipt(
            receipt_bytes,
            trusted_keys,
            max_age_seconds=args.max_age_seconds,
        )
    except CustomerReceiptError as exc:
        print(
            json.dumps(
                {"valid": False, "category": exc.category, "error": str(exc)},
                sort_keys=True,
            )
        )
        return 1
    print(
        json.dumps(
            {
                "valid": True,
                "schema": verified.document["schema"],
                "receipt_id": verified.receipt_id,
                "receipt_digest": verified.receipt_digest,
                "issued_at": verified.document["issued_at"],
                "signing_key_id": verified.document["signing_key_id"],
                "policy_digest": verified.document["policy_digest"],
                "execution_class": verified.document["execution_class"],
                "profile_id": verified.document["profile_id"],
                "verification_scope": "cathedral_signed_assertions",
                "evidence_independently_verified": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _load_tokens(path: str | None, *, production_mode: bool = False) -> dict[str, str]:
    if path is None:
        return {}
    if production_mode and os.name == "posix":
        raw = _load_production_tokens(path)
    else:
        raw = _load_json(path, "token mapping")
    if not isinstance(raw, dict) or any(
        not isinstance(hotkey, str) or not hotkey or not _valid_bearer_token(token)
        for hotkey, token in raw.items()
    ):
        raise ValueError("token mapping must contain bounded bearer tokens")
    return dict(raw)


def _load_production_tokens(path: str) -> object:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor: int | None = os.open(path, flags)
    except OSError as exc:
        raise ValueError("unable to securely open token mapping file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("production token mapping must be a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("production token mapping permissions must be owner-only")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError("production token mapping must be owned by the current user")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = None
            try:
                return json.load(handle)
            except json.JSONDecodeError as exc:
                raise ValueError("unable to load token mapping file") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _valid_bearer_token(token: object) -> bool:
    return (
        isinstance(token, str)
        and 0 < len(token) <= MAX_BEARER_TOKEN_LENGTH
        and all(0x21 <= ord(character) <= 0x7E for character in token)
    )


def _publisher_from_args(args: argparse.Namespace) -> Poster | None:
    endpoint = getattr(args, "publisher_endpoint", None)
    if endpoint is None:
        return None
    bearer_env = args.publisher_bearer_env
    hmac_env = args.publisher_hmac_env
    bearer = os.environ.get(bearer_env)
    secret = os.environ.get(hmac_env)
    if not bearer or not secret:
        raise ValueError(f"publisher credentials must be set in {bearer_env} and {hmac_env}")
    return Poster(
        endpoint,
        bearer,
        secret,
        network=getattr(args, "score_network", None),
        netuid=getattr(args, "score_netuid", None),
    )


def _build_runtime(
    args: argparse.Namespace,
    *,
    require_policy: bool = False,
    require_report_audience: bool = False,
) -> tuple[ConfidentialRuntime, Ledger, dict[str, str]]:
    development = getattr(args, "development", False)
    gpu_profile_id = getattr(args, "gpu_profile_id", None)
    gpu_identity_db = getattr(args, "gpu_identity_db", None)
    gpu_identity_key_file = getattr(args, "gpu_identity_key_file", None)
    gpu_identity_anchor_file = getattr(args, "gpu_identity_anchor_file", None)
    gpu_values = (
        gpu_profile_id,
        gpu_identity_db,
        gpu_identity_key_file,
        gpu_identity_anchor_file,
    )
    if any(item is not None for item in gpu_values) and any(item is None for item in gpu_values):
        raise ValueError(
            "--gpu-profile-id, --gpu-identity-db, --gpu-identity-key-file, and "
            "--gpu-identity-anchor-file are required together"
        )
    config = RuntimeConfig(
        miner_timeout_seconds=getattr(args, "miner_timeout_seconds", 10.0),
        miner_attempts=getattr(args, "miner_attempts", 2),
        max_workers=getattr(args, "max_workers", 8),
        production_mode=not development,
        allow_insecure_http_for_tests=development,
        reattestation_failures_before_failed=getattr(
            args, "reattestation_failures_before_failed", 3
        ),
        reattestation_retry_base_seconds=getattr(args, "reattestation_retry_base_seconds", 5),
        reattestation_retry_maximum_seconds=getattr(
            args, "reattestation_retry_maximum_seconds", 300
        ),
        reattestation_retry_jitter_seconds=getattr(args, "reattestation_retry_jitter_seconds", 5),
        customer_job_lease_seconds=getattr(args, "customer_job_lease_seconds", 120),
        customer_job_max_attempts=getattr(args, "customer_job_max_attempts", 3),
        expected_tier=Tier.CC_GPU if gpu_profile_id is not None else Tier.CC_CPU_TDX,
        admission_enabled=require_policy,
        score_network=getattr(args, "score_network", None),
        score_netuid=getattr(args, "score_netuid", None),
        evidence_retention_dir=(
            getattr(args, "evidence_retention_dir", None)
            or os.environ.get("CATHEDRAL_EVIDENCE_RETENTION_DIR")
            or None
        ),
        challenge_anchor_block=getattr(args, "challenge_anchor_block", None),
        challenge_anchor_hash=(
            getattr(args, "challenge_anchor_hash", None)
            or os.environ.get("CATHEDRAL_CHALLENGE_ANCHOR_HASH")
            or None
        ),
    )
    if require_report_audience and config.production_mode and config.score_network is None:
        raise ValueError("production score reports require --score-network and --score-netuid")
    if (
        require_policy
        and config.production_mode
        and getattr(args, "receipt_signing_key_id", None) is None
    ):
        # Both receipt flags are optional, which is right for dev and testnet.
        # In production that is a fail-open: with no issuer, work resolution
        # records validator-derived units and returns before any receipt
        # exists, so the epoch completes and weights publish on work carrying
        # no assurance. The only existing objection lives in the score-class
        # export ("positive work ... lacks an assurance receipt"), which runs
        # AFTER payment and is a report rather than a gate.
        #
        # require_policy already means "this command admits miners and runs
        # epochs"; recovery and status commands work on frozen ledger state and
        # legitimately need no issuer. Refused here with the other argument
        # gates, before any file is read, so a misconfigured production start
        # fails on its arguments rather than part-way through setup.
        raise ValueError(
            "production admission requires an assurance receipt issuer "
            "(--receipt-signing-key-id AND --receipt-signing-key-file); "
            "without one the lane pays verified work that carries no receipt"
        )
    tokens = _load_tokens(
        getattr(args, "tokens_file", None),
        production_mode=config.production_mode,
    )
    measurements_file = getattr(args, "measurements_file", None)
    policy_registry = getattr(args, "policy_registry", None)
    policy_snapshot: PolicyRegistrySnapshot | None = None
    policy_refresher = None
    if measurements_file and policy_registry:
        raise ValueError("--measurements-file and --policy-registry are mutually exclusive")
    if policy_registry is not None:
        for name in ("policy_registry_keys", "policy_registry_state"):
            if not getattr(args, name, None):
                raise ValueError(f"--{name.replace('_', '-')} is required with --policy-registry")
        policy, policy_snapshot = _verified_registry_snapshot_and_policy(
            policy_registry,
            args.policy_registry_keys,
            state_path=args.policy_registry_state,
            minimum_release=args.policy_registry_min_release,
            max_age_seconds=args.policy_registry_max_age_seconds,
            production_mode=config.production_mode,
            trusted_keys_digest=getattr(args, "policy_registry_keys_digest", None),
            pinned_release=getattr(args, "policy_registry_pinned_release", None),
            pinned_digest=getattr(args, "policy_registry_pinned_digest", None),
        )
        if config.production_mode:

            def refresh_policy() -> Policy:
                refreshed, _snapshot = _verified_registry_snapshot_and_policy(
                    policy_registry,
                    args.policy_registry_keys,
                    state_path=args.policy_registry_state,
                    minimum_release=args.policy_registry_min_release,
                    max_age_seconds=args.policy_registry_max_age_seconds,
                    production_mode=True,
                    trusted_keys_digest=getattr(args, "policy_registry_keys_digest", None),
                    pinned_release=getattr(args, "policy_registry_pinned_release", None),
                    pinned_digest=getattr(args, "policy_registry_pinned_digest", None),
                )
                return refreshed

            policy_refresher = refresh_policy
    elif measurements_file:
        if config.production_mode:
            raise ValueError(
                "production admission requires --policy-registry; "
                "--measurements-file is development-only"
            )
        policy = _load_policy(measurements_file)
    elif require_policy:
        raise ValueError("one of --measurements-file or --policy-registry is required")
    else:
        # Recovery/status commands do not admit miners or start epochs. Their
        # runtime methods operate only on already-frozen ledger state, so they
        # intentionally need no current admission policy.
        policy = Policy()
    if require_policy and config.production_mode and not policy.production_ready_for_tdx:
        raise ValueError(
            "production admission requires strict signed CPU policy registry authority"
        )
    receipt_key_id = getattr(args, "receipt_signing_key_id", None)
    receipt_key_file = getattr(args, "receipt_signing_key_file", None)
    if (receipt_key_id is None) != (receipt_key_file is None):
        raise ValueError(
            "--receipt-signing-key-id and --receipt-signing-key-file are required together"
        )
    receipt_issuer = None
    if receipt_key_id is not None:
        if policy_snapshot is None:
            raise ValueError("receipt issuance requires --policy-registry authority")
        receipt_issuer = ReceiptIssuer(
            policy_snapshot,
            receipt_key_id,
            _load_receipt_private_seed(
                receipt_key_file,
                production_mode=config.production_mode,
            ),
        )
    gpu_profile = None
    gpu_verifier = None
    gpu_identity_registry = None
    if gpu_profile_id is not None:
        if policy_snapshot is None:
            raise ValueError("GPU runtime requires --policy-registry authority")
        if config.production_mode and gpu_identity_db == ":memory:":
            raise ValueError("production GPU identity registry must be durable")
        gpu_profile = gpu_profile_from_registry(policy_snapshot, gpu_profile_id)
        if not gpu_profile.production_ready:
            raise ValueError("GPU profile is not production ready")
        gpu_verifier = gpu_verifier_from_env(production_mode=config.production_mode)
        gpu_identity_registry = GpuIdentityRegistry(
            gpu_identity_db,
            identity_digest_key=_load_gpu_identity_key(
                gpu_identity_key_file,
                production_mode=config.production_mode,
            ),
            production_mode=config.production_mode,
            generation_anchor_path=gpu_identity_anchor_file,
        )
    candidate_snapshot_path = getattr(args, "candidate_snapshot", None)
    candidate_snapshot = None
    if candidate_snapshot_path is not None:
        candidate_snapshot = _strict_json_object(
            Path(candidate_snapshot_path).read_bytes(), "candidate snapshot"
        )
    ledger = Ledger(args.ledger_db)
    registry = RegistryStore(getattr(args, "registry_db", ":memory:"))

    def token_provider(hotkey: str) -> str | None:
        """The operator's token file first, then the token minted at enrollment.

        File first so an operator can still override or revoke one worker's
        token without touching the registry, which is the only manual control
        that remains. Registry second so a miner that enrolled after this
        landed needs no manual step at all.
        """
        return tokens.get(hotkey) or registry.worker_token(hotkey)

    runtime = ConfidentialRuntime(
        registry,
        ledger,
        policy,
        _publisher_from_args(args),
        token_provider=token_provider,
        policy_refresher=policy_refresher,
        config=config,
        receipt_issuer=receipt_issuer,
        candidate_snapshot=candidate_snapshot,
        gpu_profile=gpu_profile,
        gpu_verifier=gpu_verifier,
        gpu_identity_registry=gpu_identity_registry,
    )
    return runtime, ledger, tokens


def _target(args: argparse.Namespace, tokens: dict[str, str]) -> MinerTarget:
    return MinerTarget(args.canary_hotkey, args.canary_endpoint, tokens.get(args.canary_hotkey))


def _outcome_json(outcome: MinerOutcome) -> dict[str, object]:
    # Miner/upstream error text may echo request context (headers, URLs) that
    # embeds a credential; sanitize it here too so the default JSON path gets
    # the same redaction as --pretty, not just a narrower one applied later.
    return {
        "hotkey": outcome.hotkey,
        "endpoint_url": outcome.endpoint_url,
        "status": outcome.status,
        "verified": outcome.status == "attestation_verified" or outcome.admitted,
        "admitted": outcome.admitted,
        "challenge_id": outcome.challenge_id,
        "work_units": outcome.work_units,
        "score": outcome.score,
        "error": _sanitize_error(outcome.error, maxlen=300) if outcome.error else None,
        "error_category": outcome.error_category,
        "assurance": outcome.assurance.to_dict() if outcome.assurance else None,
        "component_audit": (
            _audit_json_value(outcome.component_audit)
            if outcome.component_audit is not None
            else None
        ),
    }


def _audit_json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _audit_json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_audit_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError("component audit contains an unsupported value")


def _run_json(run: EpochRun) -> dict[str, object]:
    return {
        "epoch_id": run.epoch_id,
        "source_epoch": run.source_epoch,
        "status": run.status,
        "published": run.published,
        "scores": dict(run.scores),
        "outcomes": [_outcome_json(outcome) for outcome in run.outcomes],
    }


def cmd_worker_serve(args: argparse.Namespace) -> int:
    tls_certificate = getattr(args, "tls_certificate", None)
    tls_private_key = getattr(args, "tls_private_key", None)
    if (tls_certificate is None) != (tls_private_key is None):
        raise ValueError("worker TLS certificate and private key must be supplied together")
    tls_enabled = tls_certificate is not None
    try:
        is_loopback = ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        is_loopback = args.host == "localhost"
    development_no_auth = bool(getattr(args, "development_no_auth", False))
    # The locality guard keys off AUTHENTICATION, not TLS.
    #
    # It used to be `not tls_enabled`, so supplying a certificate satisfied it and
    # the check was skipped. But TLS encrypts the channel; it does not authenticate
    # the caller. Combined with --development-no-auth (which separately drops the
    # bearer and the channel-binding requirement) that bound an unauthenticated
    # worker to 0.0.0.0 and served /v1/sat-work to anyone who could reach the port,
    # with no warning on stdout or stderr (#87).
    #
    # The plain-HTTP form of exactly the same mistake was already refused, which is
    # what made this asymmetry a trap rather than a policy: adding TLS -- the thing
    # an operator does to make a service MORE secure -- silently removed a control.
    if not is_loopback and not args.development_allow_non_loopback:
        if not tls_enabled:
            raise ValueError(
                "plain worker HTTP must bind loopback unless development mode is explicit")
        if development_no_auth:
            raise ValueError(
                "an unauthenticated worker must bind loopback: TLS encrypts the "
                "channel but does not authenticate the caller, so "
                "--development-no-auth on a non-loopback bind serves work to anyone "
                "who can reach the port")
    if development_no_auth:
        if not is_loopback:
            # Reachable only via the explicit development escape hatch above.
            print(
                "WARNING: serving UNAUTHENTICATED on a non-loopback address "
                f"({args.host}); every work endpoint is open to anyone who can "
                "reach this port. Development only.",
                file=sys.stderr, flush=True)
        token = None
    else:
        bearer_env = getattr(args, "bearer_token_env", DEFAULT_WORKER_BEARER_ENV)
        if not isinstance(bearer_env, str) or not bearer_env:
            raise ValueError("worker bearer environment variable name is required")
        token = os.environ.get(bearer_env)
        if not _valid_bearer_token(token):
            raise ValueError(f"worker bearer token must be set in {bearer_env}")
    binding_type = getattr(args, "channel_binding_type", None)
    binding_digest = getattr(args, "channel_binding_digest", None)
    if (binding_type is None) != (binding_digest is None):
        raise ValueError("worker channel binding type and digest must be supplied together")
    channel_binding = None
    if binding_type is not None:
        try:
            if re.fullmatch(r"[0-9a-f]{64}", binding_digest) is None:
                raise ValueError
            digest = bytes.fromhex(binding_digest)
            channel_binding = ChannelBinding(ChannelBindingType(binding_type), digest)
        except (TypeError, ValueError):
            raise ValueError("worker channel binding is invalid") from None
    tls_context = None
    if tls_enabled:
        key_path = Path(tls_private_key)
        try:
            key_stat = key_path.lstat()
        except OSError as exc:
            raise ValueError("worker TLS private key is not readable") from exc
        if (
            not stat.S_ISREG(key_stat.st_mode)
            or stat.S_ISLNK(key_stat.st_mode)
            or key_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
        ):
            raise ValueError("worker TLS private key must be a regular owner-only file")
        certificate_path = Path(tls_certificate)
        try:
            certificate_pem = certificate_path.read_text(encoding="ascii")
            match = re.search(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                certificate_pem,
                flags=re.DOTALL,
            )
            if match is None:
                raise ValueError
            certificate_der = ssl.PEM_cert_to_DER_cert(match.group(0))
            certificate_binding = tls_spki_binding(certificate_der)
        except (OSError, UnicodeError, ValueError, ChannelBindingError) as exc:
            raise ValueError("worker TLS certificate is invalid") from exc
        if channel_binding is not None and channel_binding != certificate_binding:
            raise ValueError("worker channel binding does not match TLS certificate")
        channel_binding = certificate_binding
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            tls_context.load_cert_chain(certfile=str(certificate_path), keyfile=str(key_path))
        except (OSError, ssl.SSLError) as exc:
            raise ValueError("worker TLS certificate or private key could not be loaded") from exc
    if not getattr(args, "development_no_auth", False) and channel_binding is None:
        raise ValueError("production worker requires a configured channel binding")
    allow_customer_sat = getattr(args, "allow_customer_sat", False)
    if allow_customer_sat and (token is None or channel_binding is None):
        raise ValueError("customer SAT requires bearer authentication and channel binding")
    if allow_customer_sat and getattr(args, "development_allow_non_loopback", False):
        raise ValueError("customer SAT cannot use the development non-loopback HTTP bind")
    if allow_customer_sat and getattr(args, "gpu_composite", False):
        raise ValueError("customer SAT is available only on the CPU worker path")
    # Select the CPU TEE evidence collector. Default stays TDX so existing
    # deployments are unchanged; --tee snp serves AMD SEV-SNP evidence, and
    # --gpu-composite (TDX+GPU) is TDX-only by construction.
    tee = getattr(args, "tee", "tdx")
    if getattr(args, "gpu_composite", False) and tee != "tdx":
        raise ValueError("--gpu-composite collects TDX+GPU and cannot combine with --tee snp")
    if tee == "snp":
        evidence_collector = collect_snp
    elif getattr(args, "gpu_composite", False):
        evidence_collector = collect_tdx_gpu
    else:
        evidence_collector = None
    with WorkerServer(
        args.host,
        args.port,
        configured_hotkey=args.hotkey,
        bearer_token=token,
        channel_binding=channel_binding,
        tls_context=tls_context,
        evidence_collector=evidence_collector,
        allow_noncanonical_sat=allow_customer_sat,
        allow_non_loopback_for_development=args.development_allow_non_loopback,
    ) as server:
        print(
            json.dumps(
                {
                    "host": server.host,
                    "port": server.port,
                    "hotkey": args.hotkey,
                    "tls": tls_context is not None,
                }
            )
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


def cmd_runtime_canary(args: argparse.Namespace) -> int:
    runtime, ledger, tokens = _build_runtime(args, require_policy=True)
    try:
        outcome = runtime.check_canary(_target(args, tokens))
        print(json.dumps(_outcome_json(outcome), sort_keys=True))
        return 0
    finally:
        ledger.close()


def cmd_runtime_audit_attestation(args: argparse.Namespace) -> int:
    runtime, ledger, tokens = _build_runtime(args, require_policy=True)
    try:
        outcome = runtime.audit_attestation(_target(args, tokens))
        print(json.dumps(_outcome_json(outcome), sort_keys=True))
        return 0 if outcome.status == "attestation_verified" else 1
    finally:
        runtime.close()
        ledger.close()


def cmd_runtime_run_epoch(args: argparse.Namespace) -> int:
    runtime, ledger, tokens = _build_runtime(
        args,
        require_policy=True,
        require_report_audience=True,
    )
    try:
        run = runtime.run_epoch(
            args.source_epoch,
            _target(args, tokens),
            publish=args.publish,
        )
        if getattr(args, "pretty", False):
            _format_run_pretty(run)
        else:
            print(json.dumps(_run_json(run), sort_keys=True))
        return 0
    finally:
        ledger.close()


def cmd_runtime_status(args: argparse.Namespace) -> int:
    runtime, ledger, _ = _build_runtime(args)
    try:
        print(json.dumps(dict(runtime.status()), sort_keys=True))
        return 0
    finally:
        ledger.close()


def _score_class_time(value: str, label: str) -> datetime.datetime:
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))  # noqa: FURB162 - intentional fail-closed/UTC-text semantics
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{label} must be a timezone-aware ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise ValueError(f"{label} must be UTC")
    return parsed


def _write_score_class_report(path: str, body: bytes) -> None:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(temporary, flags, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def cmd_runtime_export_score_class(args: argparse.Namespace) -> int:
    ledger = Ledger(args.ledger_db)
    try:
        epoch_id = _resolve_evidence_epoch(ledger, str(args.epoch_id))
        existing = ledger.get_score_class_export(
            epoch_id,
            network=args.score_network,
            netuid=args.score_netuid,
            class_id=args.class_id,
            source_id=args.source_id,
        )
        replayed = existing is not None
        if existing is not None:
            report = bytes(existing["report_body"])
        else:
            if not args.development and not args.evidence_base_uri:
                raise ValueError(
                    "production score-class export requires --evidence-base-uri "
                    "for validator provenance"
                )
            generated_at = (
                datetime.datetime.now(datetime.UTC)
                if args.generated_at is None
                else _score_class_time(args.generated_at, "generated_at")
            )
            snapshot_document = _strict_json_object(
                Path(args.candidate_snapshot).read_bytes(), "candidate snapshot"
            )
            report = export_score_class_report(
                ledger,
                epoch_id,
                network=args.score_network,
                netuid=args.score_netuid,
                class_id=args.class_id,
                source_id=args.source_id,
                signing_key_id=args.signing_key_id,
                private_key_seed=_load_private_seed(
                    args.signing_key_file,
                    production_mode=not args.development,
                    label="score-class signing key",
                ),
                generated_at=generated_at,
                valid_until=_score_class_time(args.valid_until, "valid_until"),
                valid_from_block=args.valid_from_block,
                valid_until_block=args.valid_until_block,
                verifier_digest=args.verifier_digest,
                candidate_snapshot=snapshot_document,
                policy_digest=args.policy_digest,
                previous_report_id=args.previous_report_id,
                evidence_base_uri=args.evidence_base_uri,
                require_epoch_anchor=not args.development,
            )
        _write_score_class_report(args.output, report)
        document = json.loads(report)
        print(
            json.dumps(
                {
                    "class_id": document["class_id"],
                    "entries": len(document["entries"]),
                    "output": str(Path(args.output).expanduser()),
                    "replayed": replayed,
                    "report_id": document["report_id"],
                    "source_epoch": document["source_epoch"],
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        ledger.close()


def _resolve_evidence_epoch(ledger: Ledger, epoch_argument: str) -> int:
    if epoch_argument == "latest-published":
        epoch_id = ledger.latest_published_epoch_id()
        if epoch_id is None:
            raise ValueError("no published epoch exists yet")
        return epoch_id
    try:
        return int(epoch_argument)
    except ValueError as exc:
        raise ValueError("epoch id must be an integer or 'latest-published'") from exc


def _resolve_pinned_policy_registry(
    live_bytes: bytes, pinned_digest: object, history_dir: str | None
) -> tuple[bytes, bool]:
    """Return the registry bytes a frozen epoch pinned, and whether they came
    from the succession archive.

    A frozen epoch pins its registry digest forever, but the live registry is
    reissued (re-signed, same policy material) on the bounded freshness
    schedule, so the pinned digest stops matching the live file permanently
    the moment a successor is installed. ``republish-install`` archives the
    outgoing bytes under their content-addressed name BEFORE installing the
    successor, so the pinned release stays resolvable with no missing-archive
    window.

    Content-hash equality with the pinned digest stays the only acceptance
    rule: the archive file name is a lookup hint, never evidence. Anything
    unresolvable returns the live bytes so the caller's existing digest check
    fails exactly as it does without a history directory.
    """
    if "sha256:" + hashlib.sha256(live_bytes).hexdigest() == pinned_digest:
        return live_bytes, False
    if history_dir is None or not isinstance(pinned_digest, str):
        return live_bytes, False
    # Constrain the pinned hex BEFORE it reaches the filesystem: a report is
    # signed input and its digest field must never shape a lookup path.
    pinned = re.fullmatch(r"sha256:([0-9a-f]{64})", pinned_digest)
    if pinned is None:
        return live_bytes, False
    pinned_hex = pinned.group(1)
    history = Path(history_dir)
    if not history.is_dir():
        raise ValueError("policy registry history path is not a directory")
    for candidate in sorted(history.glob(f"release-*-{pinned_hex}.json")):
        # The epoch loop runs unattended: opening a FIFO or device node here
        # would block it forever, a worse wedge than the one this resolves.
        if not candidate.is_file():
            continue
        try:
            with candidate.open("rb") as handle:
                archived = handle.read(MAX_REGISTRY_BYTES + 1)
        except OSError:
            continue  # an unreadable archive is a non-match, never a pass
        if len(archived) > MAX_REGISTRY_BYTES:
            continue
        if hashlib.sha256(archived).hexdigest() != pinned_hex:
            continue
        return archived, True
    return live_bytes, False


def cmd_runtime_export_evidence(args: argparse.Namespace) -> int:
    """Export one published epoch as a public content-addressed evidence bundle.

    Requires a prior ``runtime export-score-class`` for the same epoch: the
    signed report is the spine of the bundle and this command never signs a
    new one. It publishes: the registry blob, the signed report blob, every
    referenced assurance receipt, the pinned verifier identity (and its binary
    when supplied), the versioned reward-mechanism id, attestation digests
    (controlled disclosure), and a freshly signed index pointing at the new
    manifest.
    """
    from cathedral.evidence import (
        EvidenceStore,
        build_manifest,
        build_signed_index,
        digest_bytes,
        parse_manifest,
    )

    ledger = Ledger(args.ledger_db)
    try:
        # Fail BEFORE any publication side effect: a production manifest is
        # immutable, so exporting with a null/invalid source_revision would
        # brick the epoch (production verification pins --source-revision
        # and would reject it forever, and the immutable epoch copy blocks
        # a corrected retry). Development keeps its explicit relaxation.
        if not args.development and (
            not isinstance(args.source_revision, str)
            or re.fullmatch(r"[0-9a-f]{7,64}", args.source_revision) is None
        ):
            raise ValueError(
                "production evidence export requires --source-revision "
                "(7-64 lowercase hex of the pinned source commit); an "
                "immutable manifest published without it could never verify "
                "under production pins"
            )
        from cathedral.provenance import MECHANISM_REVISIONS

        pinned_pair_revision = MECHANISM_REVISIONS.get(args.mechanism)
        if pinned_pair_revision is None or int(args.mechanism_revision) != pinned_pair_revision:
            raise ValueError(
                f"mechanism pair ({args.mechanism!r}, revision="
                f"{args.mechanism_revision!r}) is not a frozen supported pair; "
                f"production exports publish exactly {sorted(MECHANISM_REVISIONS.items())}"
            )
        epoch_id = _resolve_evidence_epoch(ledger, args.epoch_id)
        epoch_row = ledger.get_epoch(epoch_id)
        if epoch_row is None or epoch_row["status"] != "published":
            raise ValueError(
                f"epoch {epoch_id} is not published/frozen; public export "
                "requires a published epoch even with an explicit --epoch-id"
            )
        export = ledger.get_score_class_export(
            epoch_id,
            network=args.score_network,
            netuid=args.score_netuid,
            class_id=args.class_id,
            source_id=args.source_id,
        )
        if export is None:
            raise ValueError(
                f"epoch {epoch_id} has no score-class export for "
                f"{args.class_id}/{args.source_id}; run 'runtime export-score-class' first"
            )
        report_bytes = bytes(export["report_body"])
        if len(report_bytes) > MAX_REPORT_ARTIFACT_BYTES:
            raise ValueError(
                "signed report exceeds the launch report artifact cap; the "
                "verifier could never fetch it"
            )
        report = json.loads(report_bytes)

        registry_bytes = _read_bounded_registry_file(args.policy_registry, "policy registry")
        registry_bytes, registry_from_archive = _resolve_pinned_policy_registry(
            registry_bytes,
            report.get("policy_digest"),
            args.policy_registry_history_dir,
        )
        registry_document = parse_registry_json(registry_bytes)
        registry_release = registry_document.get("release")
        registry_digest = "sha256:" + hashlib.sha256(registry_bytes).hexdigest()
        if report.get("policy_digest") != registry_digest:
            raise ValueError(
                "signed report policy_digest does not match the supplied registry file"
            )
        if registry_from_archive:
            # The whole bundle now publishes a superseded release; say so on
            # the same channel as the run summary so the substitution needs
            # no journal archaeology to find.
            print(
                json.dumps(
                    {
                        "policy_registry": "archived",
                        "release": int(registry_release),
                        "digest": registry_digest,
                    },
                    sort_keys=True,
                )
            )
        if report.get("verifier_digest") != args.verifier_digest:
            raise ValueError("signed report verifier_digest does not match --verifier-digest")

        snapshot = ledger.score_class_snapshot(epoch_id)
        receipts_by_id: dict[str, bytes] = {}
        for row in snapshot["rows"]:
            if row["receipt_id"] is not None and row["receipt_body"] is not None:
                receipts_by_id[str(row["receipt_id"])] = bytes(row["receipt_body"])

        store = EvidenceStore(args.evidence_dir)
        registry_blob = store.put_blob(registry_bytes)
        report_blob = store.put_blob(report_bytes)

        manifest_receipts: list[dict[str, str]] = []
        for entry in report.get("entries", []):
            for reference in entry.get("evidence", []):
                receipt_id = reference.get("id")
                body = receipts_by_id.get(receipt_id)
                if body is None:
                    raise ValueError(
                        f"report references receipt {receipt_id!r} that the ledger lacks"
                    )
                if digest_bytes(body) != reference.get("digest"):
                    raise ValueError(
                        f"ledger receipt {receipt_id!r} does not match the report digest"
                    )
                blob = store.put_blob(body)
                store.put_receipt_copy(receipt_id, body)
                receipt_document = json.loads(body)
                receipt_work = receipt_document.get("work") or {}
                artifacts = ledger.work_artifacts_for_challenge(
                    str(receipt_work.get("challenge_id"))
                )
                if artifacts is None:
                    raise ValueError(
                        f"receipt {receipt_id!r} has no persisted work "
                        "artifacts; a signer-only work assertion is never "
                        "publishable"
                    )
                work_item_body = bytes(artifacts["work_item_body"])
                result_body = bytes(artifacts["result_body"])
                if digest_bytes(work_item_body) != receipt_work.get(
                    "manifest_digest"
                ) or digest_bytes(result_body) != receipt_work.get("result_digest"):
                    raise ValueError(
                        f"persisted work artifacts for {receipt_id!r} do not "
                        "match the receipt's signed digests"
                    )
                # Byte-budget coherence: never publish an artifact the
                # verifier's per-kind fetch caps must refuse.
                if len(body) > MAX_RECEIPT_ARTIFACT_BYTES:
                    raise ValueError(
                        f"receipt {receipt_id!r} exceeds the launch receipt artifact cap"
                    )
                if len(work_item_body) > MAX_WORK_ITEM_ARTIFACT_BYTES:
                    raise ValueError(
                        f"work item for {receipt_id!r} exceeds the launch work artifact cap"
                    )
                if len(result_body) > MAX_WORK_RESULT_ARTIFACT_BYTES:
                    raise ValueError(
                        f"work result for {receipt_id!r} exceeds the launch work artifact cap"
                    )
                manifest_receipts.append(
                    {
                        "receipt_id": receipt_id,
                        "hotkey": entry["miner_hotkey"],
                        "blob": blob,
                        "work_item_blob": store.put_blob(work_item_body),
                        "result_blob": store.put_blob(result_body),
                    }
                )

        verifier_binary_blob = None
        if args.verifier_binary:
            verifier_binary_blob = store.put_blob(
                _read_bounded_local_file(
                    args.verifier_binary, MAX_VERIFIER_FETCH_BYTES, "verifier binary"
                )
            )

        def _normalized_digest(value: str) -> str:
            text = str(value)
            if re.fullmatch(r"[0-9a-f]{64}", text):
                return "sha256:" + text
            return text

        attestation_rows = ledger.attestation_rows(epoch_id)

        wire_digest = str(snapshot["report_digest"]).removeprefix("sha256:")
        # Deterministic manifest bytes: generated_at derives from the FROZEN
        # epoch generation time, so an exact retry reproduces byte-identical
        # blobs and the idempotent store paths succeed.
        frozen_generated = datetime.datetime.fromisoformat(
            str(snapshot["generated_at"]).replace("Z", "+00:00")  # noqa: FURB162 - ledger text may carry either suffix
        ).astimezone(datetime.UTC)
        manifest_generated_at = frozen_generated.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        from cathedral.score_class import validate_candidate_snapshot

        snapshot_document = _strict_json_object(
            Path(args.candidate_snapshot).read_bytes(), "candidate snapshot"
        )
        snapshot_binding = validate_candidate_snapshot(
            snapshot_document,
            network=args.score_network,
            netuid=args.score_netuid,
        )
        # The evidence bundle REUSES the exact snapshot the signed report
        # bound: digest, block, and hash must all match, and the epoch's
        # durable challenge anchor must agree. A later, unrelated snapshot
        # can never be substituted at evidence-export time.
        report_binding = report.get("candidate_snapshot")
        if not isinstance(report_binding, dict) or (
            report_binding.get("digest"),
            report_binding.get("block"),
            report_binding.get("block_hash"),
        ) != (
            snapshot_binding["digest"],
            snapshot_binding["block"],
            snapshot_binding["block_hash"],
        ):
            raise ValueError(
                "candidate snapshot does not match the one bound into the "
                "signed score report; evidence export must reuse the exact "
                "frozen snapshot"
            )
        if sorted(report_binding.get("hotkeys") or []) != snapshot_binding["hotkeys"]:
            raise ValueError(
                "candidate snapshot hotkeys do not match the signed report's bound hotkey set"
            )
        epoch_anchor = ledger.epoch_challenge_anchor(epoch_id)
        if epoch_anchor is not None and (
            int(epoch_anchor["block"]),
            str(epoch_anchor["block_hash"]),
        ) != (snapshot_binding["block"], snapshot_binding["block_hash"]):
            raise ValueError(
                "candidate snapshot block/hash does not match the epoch's durable challenge anchor"
            )
        if epoch_anchor is None and not args.development:
            raise ValueError(
                "production evidence export requires the epoch's durable "
                "challenge anchor (persisted at begin_epoch)"
            )
        registered = {str(h) for h in snapshot_document["hotkeys"]}
        # EVERY registered hotkey at the anchored snapshot is accounted for,
        # and "verified" is asserted ONLY for entries the SIGNED report backs
        # with positive verified work and a verified receipt reference — the
        # ledger's mere possession of a receipt row (failed or zero-work)
        # must never mint a manifest outcome the verifier will later reject.
        # Only hotkeys appear — never machine identity or endpoints.
        from decimal import Decimal as _Decimal

        verified_hotkeys = set()
        for entry in report.get("entries", []):
            units_text = str(entry.get("metrics", {}).get("verified_work_units", "0"))
            if entry.get("evidence") and _Decimal(units_text) > 0:
                verified_hotkeys.add(str(entry["miner_hotkey"]))
        stray_verified = verified_hotkeys - registered
        if stray_verified:
            raise ValueError(
                "signed report carries positive entries outside the anchored "
                f"snapshot: {sorted(stray_verified)}"
            )
        # Only a positive, receipt-backed candidate needs an attestation
        # binding in the public replay manifest. Including every zero-work
        # attested candidate can amplify a producer-valid 4,096-row epoch past
        # the 2 MiB manifest ceiling even though only 28 positive candidates
        # are supported by the replay byte budget.
        attestations = [
            {
                "hotkey": str(row["hotkey"]),
                "verdict": str(row["verdict"]),
                "evidence_digest": _normalized_digest(row["evidence_digest"]),
                "envelope_digest": (
                    str(row["envelope_digest"]) if row["envelope_digest"] is not None else None
                ),
                "challenge_digest": (
                    str(row["challenge_digest"]) if row["challenge_digest"] is not None else None
                ),
                "disclosure": "controlled",
            }
            for row in attestation_rows
            if row["evidence_digest"] and str(row["hotkey"]) in verified_hotkeys
        ]
        if {row["hotkey"] for row in attestations} != verified_hotkeys:
            missing = sorted(verified_hotkeys - {row["hotkey"] for row in attestations})
            raise ValueError(
                f"signed report carries positive entries without attestation bindings: {missing}"
            )
        candidate_rows = [
            {
                "hotkey": hotkey,
                "outcome": "verified" if hotkey in verified_hotkeys else "rejected",
                "reason": (
                    "receipt_verified" if hotkey in verified_hotkeys else "no_verified_work"
                ),
            }
            for hotkey in sorted(registered)
        ]
        manifest_bytes = build_manifest(
            network=args.score_network,
            netuid=args.score_netuid,
            source_epoch=int(snapshot["source_epoch"]),
            epoch_id=epoch_id,
            generated_at=manifest_generated_at,
            mechanism_id=args.mechanism,
            mechanism_revision=args.mechanism_revision,
            source_revision=args.source_revision,
            registry_release=int(registry_release),
            registry_digest=registry_digest,
            registry_blob=registry_blob,
            verifier_digest=args.verifier_digest,
            verifier_binary_blob=verifier_binary_blob,
            verifier_command=(
                [args.verifier_production_path] if args.verifier_production_path else None
            ),
            verifier_artifacts=(
                [args.verifier_production_path] if args.verifier_production_path else None
            ),
            report_id=str(report["report_id"]),
            report_blob=report_blob,
            report_signing_key_id=str(report["signing_key_id"]),
            receipts=manifest_receipts,
            attestations=attestations,
            candidate_set={
                "source": "sn39_metagraph",
                "network": args.score_network,
                "netuid": args.score_netuid,
                "block": int(snapshot_document["block"]),
                "block_hash": str(snapshot_document["block_hash"]),
                "candidates": candidate_rows,
            },
            wire_report_sha256=wire_digest,
        )
        index_seed = _load_private_seed(
            args.index_signing_key_file,
            production_mode=not args.development,
            label="evidence index signing key",
        )
        from cryptography.hazmat.primitives import serialization as _ser
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey as _EdPriv,
        )

        index_public = (
            _EdPriv.from_private_bytes(index_seed)
            .public_key()
            .public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
        )

        def _rebuild_recent_from_manifests() -> list[dict[str, object]]:
            """History source of truth: the immutable epoch manifests."""
            rebuilt: list[dict[str, object]] = []
            epochs_dir = Path(args.evidence_dir) / "epochs"
            if not epochs_dir.is_dir():
                return rebuilt
            for entry in sorted(epochs_dir.glob("*.json"), reverse=True):
                try:
                    data = entry.read_bytes()
                    manifest_doc = parse_manifest(data)
                except Exception:  # noqa: S112, BLE001 - skip corrupt copies
                    continue
                rebuilt.append(
                    {
                        "source_epoch": int(manifest_doc["source_epoch"]),
                        "manifest": digest_bytes(data),
                    }
                )
            return rebuilt

        # NEVER carry history from an unverified prior index: verify the old
        # signature first; on any failure rebuild from the immutable
        # manifests instead of re-signing attacker-controlled rows. The
        # whole read -> carry -> sign -> publish sequence holds ONE
        # exclusive index transaction — entered via the context manager so
        # EVERY pre-publication exception releases the lock descriptor and
        # flock (a leaked exclusive flock would deadlock the in-process
        # retry forever).
        if len(manifest_bytes) > MAX_MANIFEST_ARTIFACT_BYTES:
            raise ValueError(
                "built manifest exceeds the launch manifest artifact cap; the "
                "verifier could never fetch it"
            )
        with store.index_transaction() as index_txn:
            # The manifest blob and immutable epoch copy publish inside the
            # SAME critical section as the index update: a crash after the
            # copy but before the index leaves only immutable artifacts, and
            # the next export's rebuild-from-manifests recovery
            # re-references them.
            manifest_digest = store.put_blob(manifest_bytes)
            store.put_epoch_copy(int(snapshot["source_epoch"]), manifest_bytes)
            recent: list[dict[str, object]] = []
            existing_index = index_txn.read()
            if existing_index is not None:
                from cathedral.evidence import verify_index as _verify_index

                try:
                    previous = _verify_index(
                        existing_index,
                        {args.index_signing_key_id: index_public},
                        expected_network=args.score_network,
                        expected_netuid=args.score_netuid,
                        max_age_seconds=None,
                    )
                    recent.append(dict(previous["latest"]))
                    recent.extend(dict(row) for row in previous["recent"])
                except Exception:  # noqa: BLE001 - unverified history is rebuilt
                    recent = _rebuild_recent_from_manifests()
            deduped: list[dict[str, object]] = []
            seen_epochs = {int(snapshot["source_epoch"])}
            for row in recent:
                try:
                    row_epoch = int(row["source_epoch"])
                except (KeyError, TypeError, ValueError):
                    continue
                if row_epoch in seen_epochs:
                    continue
                seen_epochs.add(row_epoch)
                deduped.append({"source_epoch": row_epoch, "manifest": row.get("manifest")})
            deduped.sort(key=lambda row: int(row["source_epoch"]), reverse=True)
            index_bytes = build_signed_index(
                network=args.score_network,
                netuid=args.score_netuid,
                latest_source_epoch=int(snapshot["source_epoch"]),
                latest_manifest_digest=manifest_digest,
                recent=deduped,
                signing_key_id=args.index_signing_key_id,
                private_key_seed=index_seed,
            )
            from cathedral.evidence import verify_index as _self_check_index

            if len(index_bytes) > MAX_INDEX_ARTIFACT_BYTES:
                raise ValueError(
                    "built index exceeds the launch index artifact cap; the "
                    "verifier could never fetch it"
                )
            # The completed signed index must VERIFY (signature, shape,
            # ordering, latest consistency) before it is published - a
            # rebuild from a corrupted store can never publish a
            # self-invalid index.
            _self_check_index(
                index_bytes,
                {args.index_signing_key_id: index_public},
                expected_network=args.score_network,
                expected_netuid=args.score_netuid,
                max_age_seconds=None,
            )
            index_txn.publish(index_bytes)
        parse_manifest(manifest_bytes)  # final self-check before reporting

        print(
            json.dumps(
                {
                    "epoch_id": epoch_id,
                    "source_epoch": int(snapshot["source_epoch"]),
                    "manifest": manifest_digest,
                    "report_id": report["report_id"],
                    "receipts": len(manifest_receipts),
                    "attestations": len(attestations),
                    "evidence_dir": str(Path(args.evidence_dir).expanduser()),
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        ledger.close()


def _load_evidence_keyfile(path: str, digest: str | None, label: str) -> dict[str, bytes]:
    return _load_registry_keys(
        path,
        production_mode=digest is not None,
        pinned_digest=digest,
    )


def _verify_wire_vector(
    payload: Mapping[str, object],
    *,
    public_key_hex: str,
    expected_key_id: str,
    network: str,
    netuid: int,
) -> None:
    """Verify Cathedral's signed weight vector exactly as the thin validator
    does: ed25519 over sorted compact JSON minus ``signature``."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if payload.get("key_id") != expected_key_id:
        raise ValueError("weight vector key_id does not match the pinned key id")
    if payload.get("network") != network or payload.get("netuid") != netuid:
        raise ValueError("weight vector network/netuid mismatch")
    signature_b64 = payload.get("signature")
    if not isinstance(signature_b64, str) or not signature_b64.strip():
        raise ValueError("weight vector is missing its signature")
    body = {key: value for key, value in payload.items() if key != "signature"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex.strip())).verify(
            base64.b64decode(signature_b64, validate=True), canonical
        )
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise ValueError("weight vector signature verification failed") from exc
    expires = payload.get("expires_at")
    if not isinstance(expires, str):
        raise ValueError("weight vector has no expiry")  # noqa: TRY004 - intentional fail-closed/UTC-text semantics
    expiry = datetime.datetime.fromisoformat(expires.replace("Z", "+00:00"))  # noqa: FURB162 - intentional fail-closed/UTC-text semantics
    if expiry <= datetime.datetime.now(datetime.UTC):
        raise ValueError("weight vector is expired")


# Legacy default for miscellaneous evidence fetches; every named artifact
# class in the verify pipeline uses its per-kind cap from cathedral.evidence
# (docs/BUDGET.md "Evidence byte budget"), so the worst-case maximal valid
# epoch provably fits the aggregate command budget.
MAX_EVIDENCE_FETCH_BYTES = 4 * 1024 * 1024
MAX_VERIFIER_FETCH_BYTES = MAX_VERIFIER_ARTIFACT_BYTES
MAX_COMMAND_FETCH_BYTES = VERIFY_AGGREGATE_BUDGET_BYTES
# Coherent with the supported manifest RECEIPT cardinality: an epoch may
# carry up to MAX_MANIFEST_RECEIPTS verified candidates, each needing THREE
# content-addressed artifacts (receipt + work item + work result) plus one
# controlled envelope in FULL mode, plus the fixed per-command overhead
# (index, manifest, registry, report, verifier binary, publisher vector,
# independent snapshot) with slack. Memory and network stay bounded by the
# per-artifact size caps, the aggregate byte cap, and the deadline — this
# cap only stops count-based denial of service, and it must never make a
# valid maximal epoch unverifiable.
COMMAND_ARTIFACT_OVERHEAD = 16
MAX_COMMAND_ARTIFACTS = 4 * MAX_MANIFEST_RECEIPTS + COMMAND_ARTIFACT_OVERHEAD
DEFAULT_COMMAND_DEADLINE_SECONDS = 120.0


class _FetchBudget:
    """One command-wide budget: a single monotonic wall-clock deadline plus
    aggregate byte and artifact caps shared by EVERY remote operation (DNS,
    connect, TLS, headers, every blob read) and every budget-charged local
    evidence read."""

    def __init__(
        self,
        *,
        deadline_seconds: float = DEFAULT_COMMAND_DEADLINE_SECONDS,
        max_total_bytes: int = MAX_COMMAND_FETCH_BYTES,
        max_artifacts: int | None = None,
    ) -> None:
        import time as time_module

        self._clock = time_module.monotonic
        self.deadline = self._clock() + deadline_seconds
        self.bytes_remaining = max_total_bytes
        self.artifacts_remaining = MAX_COMMAND_ARTIFACTS if max_artifacts is None else max_artifacts

    def remaining_seconds(self) -> float:
        remaining = self.deadline - self._clock()
        if remaining <= 0:
            raise ValueError("evidence command exceeded its total deadline")
        return remaining

    def start_artifact(self) -> None:
        self.artifacts_remaining -= 1
        if self.artifacts_remaining < 0:
            raise ValueError("evidence command exceeded its artifact cap")
        self.remaining_seconds()

    def charge(self, count: int) -> None:
        self.bytes_remaining -= count
        if self.bytes_remaining < 0:
            raise ValueError("evidence command exceeded its aggregate byte cap")
        self.remaining_seconds()


def _read_bounded_local_file(path, max_bytes: int, label: str, *, budget=None) -> bytes:
    """Read a local artifact fail-closed: O_NOFOLLOW at open, post-open
    fstat regular-file verification (the opened descriptor is what gets
    read, so a swap after the check cannot redirect the read), and a
    max+1 bounded read loop that rejects oversized input outright.

    When a ``_FetchBudget`` is supplied the read is charged EXACTLY like a
    remote fetch: one artifact slot before the open, and every chunk against
    the aggregate byte cap AS IT IS READ — an oversized local file can never
    be materialized past either limit before acceptance."""
    if budget is not None:
        budget.start_artifact()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise ValueError(
            f"{label} cannot be opened safely (missing, unreadable, or a symlink)"
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} must be a regular file")
        chunks: list[bytes] = []
        received = 0
        while True:
            chunk = os.read(descriptor, min(65536, max_bytes + 1 - received))
            if not chunk:
                break
            received += len(chunk)
            if received > max_bytes:
                raise ValueError(f"{label} exceeds the bounded size limit")
            if budget is not None:
                budget.charge(len(chunk))
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


RESOLVER_SLOT_CAP = 16
_RESOLVER_SLOTS = None
_RESOLVER_SLOTS_GUARD = None


def _resolver_slots():
    """Process-global bounded resolver slot pool (defect 5).

    Every in-flight ``getaddrinfo`` — including calls whose caller already
    timed out and moved on — holds exactly one slot until the resolver
    thread actually returns, so repeated timeouts can never accumulate
    unbounded daemon threads. When every slot is held by a hung resolver,
    new callers fail PROMPTLY instead of queuing forever."""
    global _RESOLVER_SLOTS, _RESOLVER_SLOTS_GUARD
    import threading as _threading

    if _RESOLVER_SLOTS_GUARD is None:
        _RESOLVER_SLOTS_GUARD = _threading.Lock()
    with _RESOLVER_SLOTS_GUARD:
        if _RESOLVER_SLOTS is None:
            _RESOLVER_SLOTS = _threading.BoundedSemaphore(RESOLVER_SLOT_CAP)
    return _RESOLVER_SLOTS


def _getaddrinfo_bounded(host: str, port: int, timeout: float) -> list:
    """Resolve with a GENUINE prompt bound: getaddrinfo runs on a daemon
    thread from a bounded process-global slot pool and the caller waits at
    most ``timeout`` seconds — a slow resolver fails at the budget, an
    abandoned call retains its slot only until the resolver returns, and
    slot-pool exhaustion fails promptly instead of queuing."""
    import queue as _queue
    import socket as _socket
    import threading as _threading

    slots = _resolver_slots()
    if not slots.acquire(timeout=max(0.0, min(timeout, 5.0))):
        raise ValueError(
            f"DNS resolver capacity exhausted while resolving {host}: "
            f"{RESOLVER_SLOT_CAP} lookups are already in flight (slow or "
            "hung resolver); failing promptly instead of queuing"
        )
    channel: _queue.Queue = _queue.Queue(maxsize=1)

    def _resolve() -> None:
        try:
            try:
                channel.put(("ok", _socket.getaddrinfo(host, port, proto=_socket.IPPROTO_TCP)))
            except OSError as exc:
                channel.put(("err", exc))
        finally:
            # The slot is released when the RESOLVER finishes — not when the
            # caller gives up — so abandoned slow lookups stay accounted for.
            slots.release()

    try:
        worker = _threading.Thread(target=_resolve, name="cathedral-dns", daemon=True)
        worker.start()
    except BaseException:
        slots.release()  # the worker never ran; do not leak the slot
        raise
    try:
        kind, value = channel.get(timeout=max(0.0, timeout))
    except _queue.Empty:
        raise ValueError(f"DNS resolution for {host} exceeded the command deadline") from None
    if kind == "err":
        raise ValueError(f"evidence host does not resolve: {host}") from value
    return value


def _resolved_public_address(
    host: str,
    port: int,
    *,
    allow_private: bool,
    budget: _FetchBudget | None = None,
) -> tuple[str, int]:
    """Resolve once, validate the address policy, and return the EXACT peer
    the transport must use — no second unvalidated resolution."""
    import ipaddress as _ip

    timeout = budget.remaining_seconds() if budget is not None else 30.0
    infos = _getaddrinfo_bounded(host, port, timeout)
    if not infos:
        raise ValueError(f"evidence host does not resolve: {host}")
    for info in infos:
        address = _ip.ip_address(info[4][0])
        if not allow_private and (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        ):
            raise ValueError(f"evidence host resolves to a non-public address: {host}")
    return infos[0][4][0], port


def _bounded_https_fetch(
    url: str,
    *,
    max_bytes: int = MAX_EVIDENCE_FETCH_BYTES,
    allow_private: bool = False,
    timeout: float = 30.0,
    budget: _FetchBudget | None = None,
) -> bytes:
    """HTTPS-only bounded fetch pinned to the validated peer.

    The validated DNS answer IS the transport peer: the TCP connection goes
    to that exact address while TLS verifies the certificate for the
    original hostname via SNI. No redirects are possible by construction
    (any non-200 status fails), and the shared budget's deadline and caps
    gate DNS, connect, TLS, headers, and every read.
    """
    import http.client as _http
    import socket as _socket
    import ssl as _ssl
    import time as _time
    import urllib.parse as _parse

    parsed = _parse.urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError("evidence fetches must use https")
    if parsed.username or parsed.password:
        raise ValueError("evidence URLs must be credential-free")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("evidence URL has no host")
    if budget is not None:
        budget.start_artifact()
    # ONE total deadline for this fetch, drawn down by EVERY phase: the
    # per-call ceiling and the command-wide budget both bound it, and the
    # remaining time is RECOMPUTED after DNS and before every blocking
    # connect, TLS, request/header, and body-read phase — DNS time consumes
    # the same total, so a slow resolver can never re-arm a later phase.
    fetch_deadline = _time.monotonic() + timeout

    def _phase_timeout() -> float:
        remaining = fetch_deadline - _time.monotonic()
        if budget is not None:
            remaining = min(remaining, budget.remaining_seconds())
        if remaining <= 0:
            raise ValueError("evidence fetch exceeded the total deadline")
        return remaining

    peer_ip, peer_port = _resolved_public_address(
        host, parsed.port or 443, allow_private=allow_private, budget=budget
    )
    _phase_timeout()  # DNS consumed shared time; fail now if exhausted

    class _PinnedConnection(_http.HTTPSConnection):
        def connect(self) -> None:
            raw = _socket.create_connection((peer_ip, peer_port), _phase_timeout())
            try:
                # TCP consumed shared time: the TLS handshake runs under the
                # RECOMPUTED absolute remainder, never the stale pre-connect
                # timeout still armed on the raw socket.
                raw.settimeout(_phase_timeout())
                self.sock = self._context.wrap_socket(raw, server_hostname=host)
            except BaseException:
                raw.close()
                raise

    context = _ssl.create_default_context()
    connection = _PinnedConnection(host, peer_port, timeout=_phase_timeout(), context=context)
    try:
        target = parsed.path or "/"
        if parsed.query:
            raise ValueError("evidence URLs must be query-free")
        connection.connect()  # TCP + TLS, each under a freshly computed bound
        connection.sock.settimeout(_phase_timeout())  # request/header phase
        connection.request(
            "GET",
            target,
            headers={"Host": host, "User-Agent": "cathedral-provenance/1.0"},
        )
        connection.sock.settimeout(_phase_timeout())
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(
                f"evidence fetch failed with status {response.status} "
                "(redirects and errors are never followed)"
            )
        chunks: list[bytes] = []
        received = 0
        while True:
            connection.sock.settimeout(_phase_timeout())
            # read1 performs AT MOST ONE underlying receive, so the absolute
            # deadline above is re-checked between every receive; a server
            # trickling one byte per almost-timeout can re-arm a per-receive
            # inactivity timer, but never this loop's total deadline.
            chunk = response.read1(min(65536, max_bytes + 1 - received))
            if not chunk:
                break
            received += len(chunk)
            if received > max_bytes:
                raise ValueError("evidence response exceeds the bounded size limit")
            if budget is not None:
                budget.charge(len(chunk))
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        connection.close()


def _strict_json_object(data: bytes, label: str) -> dict:
    def _no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate {label} JSON key")
            result[key] = value
        return result

    document = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_no_duplicates,
        parse_constant=lambda _v: (_ for _ in ()).throw(ValueError(f"non-finite {label} JSON")),
    )
    if not isinstance(document, dict):
        raise ValueError(f"{label} is not a JSON object")  # noqa: TRY004 - intentional fail-closed/UTC-text semantics
    return document


def _read_retained_blob(blob_path: Path, digest: str) -> bytes:
    """No-follow open of a retained blob with regular/owner/0600/content
    validation before acceptance — a drifted 0644 or foreign blob refuses."""
    import stat as stat_module

    from cathedral.evidence import EvidenceError, digest_bytes

    if not os.path.lexists(blob_path):
        raise EvidenceError(f"retained envelope {digest} is unavailable")
    before = os.lstat(blob_path)
    if stat_module.S_ISLNK(before.st_mode) or not stat_module.S_ISREG(before.st_mode):
        raise EvidenceError(f"retained envelope {digest} must be a regular file")
    if before.st_mode & 0o077:
        raise EvidenceError(f"retained envelope {digest} has unsafe permissions")
    if hasattr(os, "geteuid") and before.st_uid != os.geteuid():
        raise EvidenceError(f"retained envelope {digest} has foreign ownership")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(blob_path, flags)
    try:
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise EvidenceError(f"retained envelope {digest} changed underneath")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read(4 * 1024 * 1024 + 1)
    finally:
        if descriptor != -1:
            os.close(descriptor)
    if len(data) > 4 * 1024 * 1024:
        raise EvidenceError(f"retained envelope {digest} is oversized")
    if digest_bytes(data) != digest:
        raise EvidenceError(f"retained envelope {digest} is corrupt")
    return data


def cmd_runtime_export_controlled(args: argparse.Namespace) -> int:
    """Package controlled-disclosure envelopes for an authorized validator.

    Only a completed, PUBLISHED (frozen) epoch may be disclosed, bound to its
    exact frozen report digest. All inputs are validated first, the package
    is staged in a private temp directory, and only then atomically renamed
    into place — a failure leaves nothing partial, and an exact retry of an
    already-exported epoch succeeds idempotently. Symlinked or unsafe output
    paths are rejected; nothing is ever chmod'ed or written through a
    pre-existing path.
    """
    import tempfile as tempfile_module

    from cathedral.evidence import digest_bytes

    ledger = Ledger(args.ledger_db)
    staging: str | None = None
    try:
        epoch_id = _resolve_evidence_epoch(ledger, args.epoch_id)
        epoch_row = ledger.get_epoch(epoch_id)
        if epoch_row is None or epoch_row["status"] != "published":
            raise ValueError(f"epoch {epoch_id} is not published/frozen; refusing disclosure")
        snapshot = ledger.score_class_snapshot(epoch_id)
        rows = [
            row for row in ledger.attestation_rows(epoch_id) if row["envelope_digest"] is not None
        ]
        if not rows:
            raise ValueError(f"epoch {epoch_id} has no retained envelopes to disclose")

        out_root = Path(args.out_dir)
        if os.path.lexists(out_root) and out_root.is_symlink():
            raise ValueError("controlled output path must not be a symlink")
        parent = out_root.parent
        if not parent.is_dir() or parent.is_symlink():
            raise ValueError("controlled output parent must be a real directory")
        parent_stat = os.lstat(parent)
        if hasattr(os, "geteuid") and parent_stat.st_uid != os.geteuid():
            raise ValueError("controlled output parent must be owned by the caller")
        if parent_stat.st_mode & 0o022:
            raise ValueError("controlled output parent must not be group/world writable")

        # Validate and read EVERY input before creating anything.
        retention_root = Path(args.retention_dir)
        envelopes: list[tuple[str, bytes, dict]] = []
        for row in rows:
            digest = str(row["envelope_digest"])
            blob_path = retention_root / "blobs" / "sha256" / digest.split(":", 1)[1]
            data = _read_retained_blob(blob_path, digest)
            if len(data) > MAX_CONTROLLED_ENVELOPE_BYTES:
                raise ValueError(
                    f"retained envelope {digest} exceeds the launch disclosure "
                    "cap; an authorized verifier could never fetch it"
                )
            envelopes.append(
                (
                    digest,
                    data,
                    {
                        "hotkey": str(row["hotkey"]),
                        "envelope_digest": digest,
                        "evidence_digest": str(row["evidence_digest"]),
                    },
                )
            )
        controlled_manifest = {
            "schema": "cathedral_controlled_disclosure_v1",
            "epoch_id": epoch_id,
            "source_epoch": int(snapshot["source_epoch"]),
            "report_digest": str(snapshot["report_digest"]),
            "entries": [entry for _, _, entry in envelopes],
        }
        manifest_text = json.dumps(controlled_manifest, sort_keys=True, indent=2)

        if out_root.exists():
            # Idempotent EXACT retry only when the COMPLETE package validates:
            # directory type/owner/mode, the manifest text, and every envelope
            # file present as a regular non-symlink 0600 owned file whose
            # bytes hash to the manifest digest. Anything missing or unsafe
            # fails closed — never a false "replayed" success.
            root_stat = os.lstat(out_root)
            import stat as stat_module

            if (
                stat_module.S_ISLNK(root_stat.st_mode)
                or not stat_module.S_ISDIR(root_stat.st_mode)
                or root_stat.st_mode & 0o077
                or (hasattr(os, "geteuid") and root_stat.st_uid != os.geteuid())
            ):
                raise ValueError("existing controlled output directory is unsafe; refusing")
            existing = out_root / "controlled-manifest.json"
            if not existing.is_file() or existing.read_text() != manifest_text:
                raise ValueError("controlled output path exists with different content; refusing")
            for digest, data, _entry in envelopes:
                candidate = out_root / f"{digest.split(':', 1)[1]}.json"
                file_stat = os.lstat(candidate) if os.path.lexists(candidate) else None
                if (
                    file_stat is None
                    or stat_module.S_ISLNK(file_stat.st_mode)
                    or not stat_module.S_ISREG(file_stat.st_mode)
                    or file_stat.st_mode & 0o077
                    or (hasattr(os, "geteuid") and file_stat.st_uid != os.geteuid())
                    or digest_bytes(candidate.read_bytes()) != digest
                ):
                    raise ValueError(
                        f"controlled package is incomplete or unsafe at {digest}; "
                        "refusing to report an exact replay"
                    )
            print(
                json.dumps(
                    {
                        "epoch_id": epoch_id,
                        "envelopes": len(envelopes),
                        "out": str(out_root),
                        "replayed": True,
                    },
                    sort_keys=True,
                )
            )
            return 0

        staging = tempfile_module.mkdtemp(prefix=f".controlled.{epoch_id}.", dir=parent)
        os.chmod(staging, 0o700)
        for digest, data, _entry in envelopes:
            target = Path(staging) / f"{digest.split(':', 1)[1]}.json"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(Path(staging) / "controlled-manifest.json", flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(manifest_text)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(staging, out_root)
        staging = None
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        print(
            json.dumps(
                {
                    "epoch_id": epoch_id,
                    "envelopes": len(envelopes),
                    "out": str(out_root),
                    "replayed": False,
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        if staging is not None:
            import shutil

            shutil.rmtree(staging, ignore_errors=True)
        ledger.close()


def _reserve_fences(
    fence_path: Path,
    *,
    index_epoch: int,
    index_manifest: str,
    policy_release: int,
    policy_digest: str,
    report_id: str,
    previous_report_id: str | None,
    source_epoch: int,
    historical: bool = False,
) -> None:
    """ONE atomic lock/check/reserve transaction executed BEFORE PASS.

    Any conflict - index rollback or equivocation, policy rollback or
    same-release digest change, or a report that does not chain from the
    recorded predecessor - RAISES. There is no silent keep-newer path: a
    concurrent fork writing a conflicting reservation is an error, never an
    accepted state.

    `historical` marks a run whose --source-epoch selected an epoch other
    than the index's current latest pointer: a verification of the past,
    not a frontier observation. A historical audit never lowers or
    establishes a fence, and it never writes the index fence, because this
    run did not verify the latest pointer's manifest (that check only runs
    when the frontier is selected). It still enforces equal-epoch
    equivocation and the forward chain rule unconditionally, so a stale or
    rolled-back report is still rejected and sequential catch-up through
    --source-epoch still advances the report fence forward one epoch at a
    time.
    """
    import fcntl

    fence_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = fence_path.with_suffix(".lock")
    lock_descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        current: dict = {}
        if os.path.lexists(fence_path):
            if fence_path.is_symlink() or not fence_path.is_file():
                raise ValueError("verifier state file must be a regular file")
            current = json.loads(fence_path.read_text())

        stored_epoch = current.get("index_source_epoch")
        if isinstance(stored_epoch, int):
            if index_epoch < stored_epoch:
                raise ValueError(
                    f"index rollback: epoch {index_epoch} < reserved high-water {stored_epoch}"
                )
            if index_epoch == stored_epoch and current.get("index_manifest") != index_manifest:
                raise ValueError(
                    "index equivocation: same epoch reserved with a different manifest"
                )
        stored_release = current.get("policy_release")
        if isinstance(stored_release, int):
            if not historical and policy_release < stored_release:
                raise ValueError(
                    f"policy rollback: release {policy_release} < reserved {stored_release}"
                )
            if policy_release == stored_release and current.get("policy_digest") != policy_digest:
                raise ValueError("policy equivocation: same release, different digest")
        stored_report = current.get("report_id")
        stored_source = current.get("report_source_epoch")
        if (
            isinstance(stored_source, int)
            and source_epoch > stored_source
            and stored_report is not None
            and previous_report_id != stored_report
        ):
            raise ValueError("report does not chain from the reserved predecessor")
        if isinstance(stored_source, int):
            if not historical and source_epoch < stored_source:
                raise ValueError(
                    f"report rollback: source epoch {source_epoch} < reserved {stored_source}"
                )
            if source_epoch == stored_source and stored_report != report_id:
                raise ValueError("report equivocation: same source epoch, different report")

        # A historical audit is a verification of the past: it may advance
        # or reconfirm an existing fence, but it never lowers one and never
        # establishes one from nothing, and it never writes the index
        # fence, because this run never fetched or checked the latest
        # pointer's manifest.
        if not historical:
            current["index_source_epoch"] = index_epoch
            current["index_manifest"] = index_manifest
        if not historical or (
            isinstance(stored_release, int) and policy_release >= stored_release
        ):
            current["policy_release"] = policy_release
            current["policy_digest"] = policy_digest
        if not historical or (isinstance(stored_source, int) and source_epoch >= stored_source):
            current["report_id"] = report_id
            current["report_source_epoch"] = source_epoch
        for stale in fence_path.parent.glob(fence_path.name + ".*.tmp"):
            if not stale.is_symlink():
                try:
                    stale.unlink()
                except FileNotFoundError:
                    pass
        fence_tmp = fence_path.with_name(f"{fence_path.name}.{os.getpid()}.tmp")
        descriptor = os.open(
            fence_tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(current, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(fence_tmp, fence_path)
        parent = os.open(fence_path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.close(lock_descriptor)


def cmd_provenance_verify(args: argparse.Namespace) -> int:
    """Independently verify the published evidence chain and recompute weights.

    Exit 0 only when every stage PASSes (and, when a publisher URL is given,
    the recomputation matches Cathedral's signed vector). Any failure is
    fail-closed: exit 1 with a FAIL/NOT_PROVEN event naming the broken link.
    """
    import time as time_mod

    from cathedral import provenance
    from cathedral.events import FAIL, PASS, EventLogger
    from cathedral.evidence import (
        EvidenceError,
        EvidenceStore,
        digest_bytes,
        parse_manifest,
        verify_index,
    )

    logger = EventLogger(
        mode="full_provenance",
        jsonl=sys.stdout,
        jsonl_path=args.jsonl,
        tty=sys.stderr,
    )

    command_budget = _FetchBudget(
        deadline_seconds=float(
            getattr(args, "fetch_deadline_secs", DEFAULT_COMMAND_DEADLINE_SECONDS)
        )
    )

    def fetch_url(path: str, *, max_bytes: int = MAX_EVIDENCE_FETCH_BYTES) -> bytes:
        url = args.evidence_url.rstrip("/") + path
        try:
            return _bounded_https_fetch(
                url,
                max_bytes=max_bytes,
                allow_private=bool(getattr(args, "allow_private_evidence_host", False)),
                budget=command_budget,
            )
        except ValueError as exc:
            raise EvidenceError(str(exc)) from exc

    store = EvidenceStore(args.evidence_dir) if args.evidence_dir else None

    def _read_local_artifact(path, max_bytes: int, label: str) -> bytes:
        """Local evidence reads carry the SAME bounds as remote fetches:
        O_NOFOLLOW regular-file access, the per-artifact size cap enforced
        during the read, and the command-wide artifact/byte budget charged
        before/while bytes are accepted — never after materialization."""
        try:
            return _read_bounded_local_file(path, max_bytes, label, budget=command_budget)
        except ValueError as exc:
            raise EvidenceError(str(exc)) from exc

    def load_index_bytes() -> bytes:
        if store is not None:
            return _read_local_artifact(
                store.root / "index.json", MAX_INDEX_ARTIFACT_BYTES, "evidence index"
            )
        return fetch_url("/index.json", max_bytes=MAX_INDEX_ARTIFACT_BYTES)

    def load_blob(digest: str, *, max_bytes: int = MAX_EVIDENCE_FETCH_BYTES) -> bytes:
        if store is not None:
            data = _read_local_artifact(
                store.blob_path(digest), max_bytes, f"evidence blob {digest}"
            )
            if digest_bytes(data) != digest:
                raise EvidenceError(f"blob {digest} content is corrupt")
            return data
        data = fetch_url("/blobs/sha256/" + digest.split(":", 1)[1], max_bytes=max_bytes)
        if digest_bytes(data) != digest:
            raise EvidenceError(f"fetched blob does not match digest {digest}")
        return data

    audit: dict[str, object] = {"result": "FAIL"}
    try:
        if getattr(args, "production", False):
            if getattr(args, "allow_private_evidence_host", False):
                raise ValueError(
                    "--allow-private-evidence-host is testing-only and is "
                    "refused in production (SSRF policy)"
                )
            missing = [
                flag
                for flag, value in (
                    ("--registry-keys-digest", args.registry_keys_digest),
                    ("--report-keys-digest", args.report_keys_digest),
                    ("--index-keys-digest", args.index_keys_digest),
                    ("--source-revision", getattr(args, "source_revision", None)),
                    ("--current-block", getattr(args, "current_block", None)),
                    ("--state-file", getattr(args, "state_file", None)),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    "production verification requires independent pins: " + ", ".join(missing)
                )
        started = time_mod.monotonic()
        index_keys = _load_evidence_keyfile(args.index_keys, args.index_keys_digest, "index keys")
        index_document = verify_index(
            load_index_bytes(),
            index_keys,
            expected_network=args.network,
            expected_netuid=args.netuid,
            max_age_seconds=args.index_max_age_secs,
        )
        logger.event(
            "EVIDENCE_INDEX_VERIFIED",
            stage="fetch",
            status=PASS,
            duration_ms=(time_mod.monotonic() - started) * 1000,
            detail=(
                f"latest source_epoch={index_document['latest']['source_epoch']} "
                f"key={index_document['signing_key_id']}"
            ),
            artifact=index_document["latest"]["manifest"],
        )

        if args.source_epoch is not None:
            wanted = int(args.source_epoch)
            manifest_digest = None
            for row in [index_document["latest"], *index_document["recent"]]:
                if int(row["source_epoch"]) == wanted:
                    manifest_digest = row["manifest"]
                    break
            if manifest_digest is None:
                raise EvidenceError(f"source epoch {wanted} is not present in the evidence index")
        else:
            manifest_digest = index_document["latest"]["manifest"]

        started = time_mod.monotonic()
        manifest = parse_manifest(load_blob(manifest_digest, max_bytes=MAX_MANIFEST_ARTIFACT_BYTES))
        if manifest["network"] != args.network or manifest["netuid"] != args.netuid:
            raise EvidenceError("evidence manifest network/netuid mismatch")
        if args.source_epoch is None:
            if int(manifest["source_epoch"]) != int(index_document["latest"]["source_epoch"]):
                raise EvidenceError(
                    "index latest.source_epoch does not match the manifest it points to"
                )
        elif int(manifest["source_epoch"]) != int(args.source_epoch):
            raise EvidenceError(
                "selected historical index row does not match its manifest's source epoch"
            )

        # Durable anti-rollback fences: a signed-but-older index or a
        # same-epoch different manifest must never verify.
        fence_path = Path(args.state_file).expanduser() if args.state_file else None
        fences: dict[str, object] = {}
        if fence_path is not None and fence_path.exists():
            if fence_path.is_symlink() or not fence_path.is_file():
                raise EvidenceError("verifier state file must be a regular file")
            fences = json.loads(fence_path.read_text())
            last_epoch = fences.get("index_source_epoch")
            last_manifest = fences.get("index_manifest")
            new_epoch = int(index_document["latest"]["source_epoch"])
            if isinstance(last_epoch, int):
                if new_epoch < last_epoch:
                    raise EvidenceError(
                        f"index rollback: latest epoch {new_epoch} < recorded "
                        f"high-water {last_epoch}"
                    )
                if (
                    new_epoch == last_epoch
                    and index_document["latest"]["manifest"] != last_manifest
                ):
                    raise EvidenceError("index equivocation: same epoch, different manifest")
        # Dispatch is on the exact (mechanism id, revision) PAIR: both halves
        # are pinned, and an unsupported pair fails HERE — before any
        # recomputation and before any fence reservation.
        if manifest["reward_mechanism"]["id"] != args.mechanism:
            raise EvidenceError(
                "manifest reward mechanism "
                f"{manifest['reward_mechanism']['id']!r} does not match the "
                f"pinned mechanism {args.mechanism!r}"
            )
        pinned_mechanism_revision = int(getattr(args, "mechanism_revision", 1))
        if int(manifest["reward_mechanism"]["revision"]) != pinned_mechanism_revision:
            raise EvidenceError(
                "manifest reward mechanism revision "
                f"{manifest['reward_mechanism']['revision']!r} does not match "
                f"the pinned pair ({args.mechanism!r}, "
                f"revision={pinned_mechanism_revision})"
            )
        if manifest["verifier"]["digest"] != args.verifier_digest:
            raise EvidenceError(
                "manifest verifier digest does not match the pinned verifier digest"
            )
        logger.event(
            "EVIDENCE_MANIFEST_VERIFIED",
            stage="fetch",
            status=PASS,
            duration_ms=(time_mod.monotonic() - started) * 1000,
            detail=(
                f"source_epoch={manifest['source_epoch']} "
                f"mechanism={manifest['reward_mechanism']['id']} "
                f"registry_release={manifest['policy_registry']['release']}"
            ),
            artifact=manifest_digest,
        )

        started = time_mod.monotonic()
        registry_keys = _load_evidence_keyfile(
            args.registry_keys, args.registry_keys_digest, "registry keys"
        )
        registry_bytes = load_blob(
            manifest["policy_registry"]["blob"], max_bytes=MAX_REGISTRY_ARTIFACT_BYTES
        )
        if (
            "sha256:" + hashlib.sha256(registry_bytes).hexdigest()
            != manifest["policy_registry"]["digest"]
        ):
            raise EvidenceError("registry blob does not match the manifest digest")
        report_keys = _load_evidence_keyfile(
            args.report_keys, args.report_keys_digest, "report keys"
        )
        report_bytes = load_blob(
            manifest["score_report"]["blob"], max_bytes=MAX_REPORT_ARTIFACT_BYTES
        )
        receipts_by_id = {
            row["receipt_id"]: load_blob(row["blob"], max_bytes=MAX_RECEIPT_ARTIFACT_BYTES)
            for row in manifest["receipts"]
        }
        work_artifacts_by_receipt = {
            row["receipt_id"]: (
                load_blob(row["work_item_blob"], max_bytes=MAX_WORK_ITEM_ARTIFACT_BYTES),
                load_blob(row["result_blob"], max_bytes=MAX_WORK_RESULT_ARTIFACT_BYTES),
            )
            for row in manifest["receipts"]
        }
        logger.event(
            "EVIDENCE_ARTIFACTS_FETCHED",
            stage="fetch",
            status=PASS,
            duration_ms=(time_mod.monotonic() - started) * 1000,
            detail=f"registry+report+{len(receipts_by_id)} receipts, content-addressed",
        )

        started = time_mod.monotonic()
        result = provenance.verify_and_recompute(
            report_bytes=report_bytes,
            receipts_by_id=receipts_by_id,
            registry_bytes=registry_bytes,
            trusted_registry_keys=registry_keys,
            report_signing_keys=report_keys,
            expected_network=args.network,
            expected_netuid=args.netuid,
            expected_verifier_digest=args.verifier_digest,
            mechanism_id=args.mechanism,
            mechanism_revision=pinned_mechanism_revision,
            registry_max_age_seconds=args.registry_max_age_secs,
            work_artifacts_by_receipt=work_artifacts_by_receipt,
            candidate_set=manifest["candidate_set"],
            current_block=(int(args.current_block) if args.current_block is not None else None),
        )
        if result.policy_release != manifest["policy_registry"]["release"]:
            raise EvidenceError("verified registry release differs from the manifest")
        if result.report_id != manifest["score_report"]["report_id"]:
            raise EvidenceError("verified report id differs from the manifest")
        if int(result.source_epoch) != int(manifest["source_epoch"]):
            raise EvidenceError("verified report source epoch differs from the manifest")
        pinned_revision = getattr(args, "source_revision", None)
        if pinned_revision and manifest["source_revision"] != pinned_revision:
            raise EvidenceError("manifest source revision does not match the operator's pin")

        # ---- FULL assurance: raw-evidence replay through the pinned verifier.
        controlled_dir = getattr(args, "controlled_dir", None)
        if controlled_dir:
            from cathedral import provenance as provenance_module
            from cathedral.score_class import validate_candidate_snapshot

            independent_path = getattr(args, "independent_candidate_snapshot", None)
            if not independent_path:
                raise EvidenceError(
                    "FULL assurance requires --independent-candidate-snapshot: "
                    "an independently captured historical candidate set for "
                    "the anchored block (Cathedral's own artifacts are not an "
                    "oracle)"
                )
            independent_document = _strict_json_object(
                _read_local_artifact(
                    independent_path,
                    MAX_SNAPSHOT_ARTIFACT_BYTES,
                    "independent candidate snapshot",
                ),
                "independent candidate snapshot",
            )
            independent_binding = validate_candidate_snapshot(
                independent_document,
                network=args.network,
                netuid=int(args.netuid),
            )
            if int(independent_binding["block"]) != int(manifest["candidate_set"]["block"]):
                raise EvidenceError(
                    "independent candidate snapshot was captured at block "
                    f"{independent_binding['block']}, not the anchored block "
                    f"{manifest['candidate_set']['block']}"
                )

            bindings = {row["hotkey"]: row for row in manifest["attestations"]}

            class _StreamedEnvelopes:
                """Controlled envelopes read lazily, one at a time, during
                the replay loop — never a retained multi-envelope set — with
                every read charged to the SAME command artifact/byte/deadline
                budget as public evidence fetches (symlinks, oversize, and
                budget exhaustion all fail closed at the read)."""

                def get(self, hotkey: str) -> bytes | None:
                    binding = bindings.get(hotkey)
                    envelope_digest = binding.get("envelope_digest") if binding else None
                    if not envelope_digest:
                        return None
                    envelope_path = (
                        Path(controlled_dir) / f"{str(envelope_digest).split(':', 1)[1]}.json"
                    )
                    return _read_local_artifact(
                        envelope_path,
                        MAX_CONTROLLED_ENVELOPE_BYTES,
                        f"controlled envelope for {hotkey!r}",
                    )

            verifier_info = manifest["verifier"]
            if not verifier_info["binary_blob"] or not verifier_info["command"]:
                raise EvidenceError("manifest lacks verifier binary/command bindings for full mode")
            if getattr(args, "verifier_binary", None):
                verifier_bytes = _read_local_artifact(
                    args.verifier_binary,
                    MAX_VERIFIER_FETCH_BYTES,
                    "verifier binary",
                )
            else:
                verifier_bytes = load_blob(
                    verifier_info["binary_blob"],
                    max_bytes=MAX_VERIFIER_FETCH_BYTES,
                )
            # The challenge anchor and the per-candidate outcome map come
            # from the SIGNED, ALREADY-VERIFIED chain: verify_and_recompute
            # proved the manifest candidate_set equals the report's signed
            # snapshot binding (block, hash, hotkeys), so these values are
            # exactly what the epoch's nonces were derived from. The outcome
            # map gates the epoch-level FULL claim: any active rejected
            # candidate keeps the result receipts_only (NOT PROVEN) because
            # rejections are not independently replayable.
            candidate_snapshot = manifest["candidate_set"]
            result = provenance_module.replay_positive_miners(
                result,
                candidate_outcomes={
                    str(row["hotkey"]): str(row["outcome"])
                    for row in candidate_snapshot["candidates"]
                },
                independent_candidates=independent_binding["hotkeys"],
                independent_block_hash=independent_binding["block_hash"],
                challenge_anchor={
                    "block": int(candidate_snapshot["block"]),
                    "block_hash": str(candidate_snapshot["block_hash"]),
                    "network": args.network,
                    "netuid": int(args.netuid),
                },
                registry=provenance_module.load_registry(
                    registry_bytes,
                    registry_keys,
                    max_age_seconds=args.registry_max_age_secs,
                ),
                envelopes_by_hotkey=_StreamedEnvelopes(),
                attestation_bindings=bindings,
                verifier_binary=verifier_bytes,
                verifier_blob_digest=verifier_info["binary_blob"],
                verifier_command=tuple(verifier_info["command"]),
                verifier_artifacts=tuple(verifier_info["artifacts"] or verifier_info["command"]),
                epoch_generated_at=manifest["generated_at"],
                deadline_monotonic=command_budget.deadline,
            )
            for miner in result.miners:
                if miner.raw_verified:
                    logger.event(
                        "RAW_EVIDENCE_REPLAYED",
                        stage="replay",
                        status=PASS,
                        hotkey=miner.hotkey,
                        detail=(
                            "pinned verifier re-verified the raw quote and "
                            "its nonce/worker/channel binding"
                        ),
                    )
        for miner in result.miners:
            if miner.receipt_verified:
                logger.event(
                    "RECEIPT_VERIFIED",
                    stage="verify",
                    status=PASS,
                    hotkey=miner.hotkey,
                    artifact=miner.receipt_id,
                    detail=f"work_units={miner.verified_work_units}",
                )
        logger.event(
            "CHAIN_VERIFIED_AND_RECOMPUTED",
            stage="recompute",
            status=PASS,
            duration_ms=(time_mod.monotonic() - started) * 1000,
            detail=(
                f"report={result.report_id[:23]} release={result.policy_release} "
                f"mechanism={result.mechanism_id} "
                f"positive_miners={len(result.recomputed_hotkey_weights)}"
            ),
        )

        audit = {
            "result": "PASS",
            "source_epoch": result.source_epoch,
            "report_id": result.report_id,
            "previous_report_id": result.previous_report_id,
            "policy_release": result.policy_release,
            "policy_digest": result.policy_digest,
            "verifier_digest": result.verifier_digest,
            "mechanism": result.mechanism_id,
            "mechanism_revision": result.mechanism_revision,
            "manifest": manifest_digest,
            "recomputed_hotkey_weights": result.recomputed_hotkey_weights,
        }

        if args.publisher_url:
            started = time_mod.monotonic()
            vector_bytes = _bounded_https_fetch(
                args.publisher_url.rstrip("/") + "/v1/validator/weights/next",
                max_bytes=MAX_VECTOR_ARTIFACT_BYTES,
                allow_private=bool(getattr(args, "allow_private_evidence_host", False)),
                budget=command_budget,
            )
            vector = _strict_json_object(vector_bytes, "weight vector")
            _verify_wire_vector(
                vector,
                public_key_hex=args.weight_policy_public_key_hex,
                expected_key_id=args.weight_policy_key_id,
                network=args.network,
                netuid=args.netuid,
            )
            agree, discrepancies = provenance.compare_with_vector(
                result, vector, wire_report_sha256=manifest["wire_report_sha256"]
            )
            vector_metadata = vector.get("policy_metadata")
            external_status = (
                vector_metadata.get("external_scores")
                if isinstance(vector_metadata, dict)
                else None
            ) or {}
            audit["vector_id"] = vector.get("vector_id")
            audit["vector_agrees"] = agree
            audit["vector_discrepancies"] = discrepancies
            # The SIGNED binding the agreement was checked against, for the
            # operator trail: which ingested report/epoch the publisher
            # asserts this vector was composed from.
            audit["vector_report_binding"] = {
                "manifest_wire_report_sha256": manifest["wire_report_sha256"],
                "latest_epoch": external_status.get("latest_epoch"),
                "latest_report_sha256": external_status.get("latest_report_sha256"),
                "latest_body_sha256": external_status.get("latest_body_sha256"),
            }
            if agree:
                logger.event(
                    "VECTOR_COMPARE_AGREES",
                    stage="compare",
                    status=PASS,
                    duration_ms=(time_mod.monotonic() - started) * 1000,
                    detail=(
                        f"vector={str(vector.get('vector_id'))[:8]} matches the "
                        "independent recomputation"
                    ),
                )
            else:
                audit["result"] = "FAIL"
                logger.event(
                    "VECTOR_COMPARE_MISMATCH",
                    stage="compare",
                    status=FAIL,
                    duration_ms=(time_mod.monotonic() - started) * 1000,
                    detail="; ".join(discrepancies)[:512],
                    remediation=(
                        "Do not submit from this vector. Compare the manifest "
                        "epoch against the publisher feed and escalate to the "
                        "Cathedral operators; full-provenance authority mode "
                        "submits the recomputed vector instead."
                    ),
                )

        audit["assurance"] = result.assurance_level
        if result.not_proven_reasons:
            audit["not_proven_reasons"] = list(result.not_proven_reasons)
        full = result.assurance_level == "full"
        passed = audit["result"] == "PASS"
        succeeded = passed and (full or bool(getattr(args, "allow_receipts_only", False)))
        if not passed:
            # A CONCRETE check failed (e.g. the signed vector disagreed with
            # the recomputation). The failure stays FAIL: it is never
            # reclassified as NOT_PROVEN partial assurance, and it never
            # reserves fences — fences record trusted observations, and this
            # run proved the opposite.
            logger.event(
                "PROVENANCE_RESULT",
                stage="result",
                status=FAIL,
                detail=(
                    f"assurance={result.assurance_level} "
                    f"source_epoch={audit.get('source_epoch')}: a concrete "
                    "verification step failed (see the FAIL event above)"
                ),
                remediation=(
                    "Fail closed: do not submit from this epoch. Investigate "
                    "the failing stage; nothing was recorded as verified."
                ),
            )
            if args.audit_out:
                Path(args.audit_out).expanduser().write_text(
                    json.dumps(audit, sort_keys=True, indent=2) + "\n"
                )
            return 1
        if not full:
            audit["result"] = "NOT_PROVEN"
        # The atomic reservation COMPLETES before any terminal PASS or
        # NOT_PROVEN event is emitted and before the audit record reports
        # acceptance: a conflicting concurrent reservation raises into the
        # failure path below, which emits ONLY a terminal FAIL — an
        # accepting terminal event can never precede a failed reservation.
        if fence_path is not None:
            # A historical audit is one whose selected manifest is not the
            # index's current latest pointer: nothing in this run verified
            # the latest pointer's manifest (the consistency check above
            # only runs when the frontier is selected), so this run must
            # not be treated as a frontier observation of the index.
            historical_audit = str(manifest_digest) != str(index_document["latest"]["manifest"])
            _reserve_fences(
                fence_path,
                index_epoch=int(index_document["latest"]["source_epoch"]),
                index_manifest=str(index_document["latest"]["manifest"]),
                policy_release=int(result.policy_release),
                policy_digest=str(result.policy_digest),
                report_id=str(result.report_id),
                previous_report_id=result.previous_report_id,
                historical=historical_audit,
                source_epoch=int(result.source_epoch),
            )
        if not full:
            from cathedral.events import NOT_PROVEN as _NOT_PROVEN

            reasons = "; ".join(result.not_proven_reasons)[:300]
            logger.event(
                "PROVENANCE_RESULT",
                stage="result",
                status=_NOT_PROVEN,
                detail=(
                    "receipts-only (PARTIAL) provenance: signed statements are "
                    "internally consistent, but the epoch was not fully "
                    f"replayed. source_epoch={audit.get('source_epoch')}"
                    + (f" ({reasons})" if reasons else "")
                ),
                remediation=(
                    "Obtain the controlled envelope package and rerun with "
                    "--controlled-dir for FULL assurance."
                ),
            )
        else:
            logger.event(
                "PROVENANCE_RESULT",
                stage="result",
                status=PASS,
                detail=(
                    f"assurance=full source_epoch={audit.get('source_epoch')} "
                    f"weights={audit.get('recomputed_hotkey_weights')}"
                ),
            )
        if args.audit_out:
            Path(args.audit_out).expanduser().write_text(
                json.dumps(audit, sort_keys=True, indent=2) + "\n"
            )
        return 0 if succeeded else 1
    except (EvidenceError, provenance.ProvenanceError, ValueError, OSError) as exc:
        logger.event(
            "PROVENANCE_FAILED",
            stage="result",
            status=FAIL,
            detail=str(exc)[:512],
            remediation=(
                "Fail closed: keep or fall back to the burn vector. Check the "
                "evidence endpoint, pinned keys, and digests; rerun with "
                "--jsonl for a machine-readable trail."
            ),
        )
        if args.audit_out:
            # The audit must never report acceptance for a run that raised —
            # including a fence-reservation conflict AFTER the checks passed.
            audit["result"] = "FAIL"
            audit["error"] = str(exc)[:512]
            Path(args.audit_out).expanduser().write_text(
                json.dumps(audit, sort_keys=True, indent=2) + "\n"
            )
        return 1
    finally:
        logger.close()


def cmd_runtime_retry_publish(args: argparse.Namespace) -> int:
    runtime, ledger, _ = _build_runtime(args)
    try:
        acknowledgement = runtime.publish_completed(args.epoch_id)
        if getattr(args, "pretty", False):
            _format_publish_pretty(args.epoch_id, dict(acknowledgement))
        else:
            print(json.dumps(dict(acknowledgement), sort_keys=True))
        return 0
    finally:
        ledger.close()


def cmd_runtime_abort_running(args: argparse.Namespace) -> int:
    runtime, ledger, _ = _build_runtime(args)
    try:
        epoch_id = runtime.abort_running()
        print(json.dumps({"aborted_epoch_id": epoch_id}, sort_keys=True))
        return 0
    finally:
        ledger.close()


def cmd_runtime_abandon_complete(args: argparse.Namespace) -> int:
    """Recovery command: abandon a 'complete' epoch that can never publish.

    See ``ConfidentialRuntime.abandon_completed`` / ``Ledger.abandon_completed_epoch``
    for the invariants (audited, one-way, never payable, never mutates report bytes).
    """
    runtime, ledger, _ = _build_runtime(args)
    try:
        epoch_id = runtime.abandon_completed(args.epoch_id, args.reason)
        row = ledger.get_epoch(epoch_id)
        assert row is not None
        print(
            json.dumps(
                {
                    "abandoned_epoch_id": epoch_id,
                    "reason": row["abandon_reason"],
                    "abandoned_at": row["abandoned_at"],
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        ledger.close()


def cmd_runtime_recover_gpu_identities(args: argparse.Namespace) -> int:
    """Authenticate and audit deterministic recovery of crash-left GPU claims."""

    outcome = GpuIdentityRegistry.recover_interrupted(
        args.gpu_identity_db,
        identity_digest_key=_load_gpu_identity_key(
            args.gpu_identity_key_file,
            production_mode=not args.development,
        ),
        reason=args.reason,
        production_mode=not args.development,
        generation_anchor_path=args.gpu_identity_anchor_file,
    )
    print(json.dumps(dict(outcome), sort_keys=True))
    return 0


def cmd_runtime_release_gpu_identities(args: argparse.Namespace) -> int:
    """Authenticate and audit an explicit release of one worker's GPU claims."""

    registry = GpuIdentityRegistry(
        args.gpu_identity_db,
        identity_digest_key=_load_gpu_identity_key(
            args.gpu_identity_key_file,
            production_mode=not args.development,
        ),
        production_mode=not args.development,
        generation_anchor_path=args.gpu_identity_anchor_file,
    )
    outcome = registry.release_worker(args.hotkey, reason=args.reason)
    print(json.dumps(dict(outcome), sort_keys=True))
    return 0


def cmd_runtime_initialize_gpu_identities(args: argparse.Namespace) -> int:
    """Perform the explicit one-time creation of production GPU identity state."""

    registry = GpuIdentityRegistry(
        args.gpu_identity_db,
        identity_digest_key=_load_gpu_identity_key(
            args.gpu_identity_key_file,
            production_mode=not args.development,
        ),
        production_mode=not args.development,
        generation_anchor_path=args.gpu_identity_anchor_file,
        initialize=True,
    )
    print(
        json.dumps(
            {
                "generation_anchor": str(args.gpu_identity_anchor_file),
                "identity_database": str(args.gpu_identity_db),
                "initialized": True,
                "production_ready": registry.production_ready,
            },
            sort_keys=True,
        )
    )
    return 0


def cmd_lifecycle_status(args: argparse.Namespace) -> int:
    if not Path(args.registry_db).is_file():
        raise ValueError("registry database does not exist")
    store = RegistryStore(args.registry_db)
    snapshot = store.lifecycle_snapshot(args.hotkey)
    payload = snapshot.operator_dict() if args.operator else snapshot.public_dict()
    print(json.dumps({"hotkey": args.hotkey, **payload}, sort_keys=True))
    return 0


def cmd_lifecycle_history(args: argparse.Namespace) -> int:
    if not Path(args.registry_db).is_file():
        raise ValueError("registry database does not exist")
    store = RegistryStore(args.registry_db)
    history = store.lifecycle_history(args.hotkey, operator=args.operator)
    print(
        json.dumps(
            {"hotkey": args.hotkey, "events": list(history)},
            sort_keys=True,
        )
    )
    return 0


def cmd_lifecycle_reenroll(args: argparse.Namespace) -> int:
    if not Path(args.registry_db).is_file():
        raise ValueError("registry database does not exist")
    snapshot = RegistryStore(args.registry_db).reenroll_lifecycle(args.hotkey, operator=True)
    print(json.dumps({"hotkey": args.hotkey, **snapshot.public_dict()}, sort_keys=True))
    return 0


def cmd_lifecycle_retire(args: argparse.Namespace) -> int:
    if not Path(args.registry_db).is_file():
        raise ValueError("registry database does not exist")
    snapshot = RegistryStore(args.registry_db).retire_lifecycle(
        args.hotkey,
        removed=args.removed,
    )
    print(json.dumps({"hotkey": args.hotkey, **snapshot.public_dict()}, sort_keys=True))
    return 0


def cmd_enroll_reconcile(args: argparse.Namespace) -> int:
    """List enrollments the current approval artifact no longer covers.

    With --remove, retire the flagged rows and clear their attestation
    verdicts. Never runs automatically: reconciliation of pre-existing rows
    is an explicit operator action.

    Accepts either approval artifact, because it is the only way to free
    enrollment capacity and a service running an admission policy could
    otherwise not run it at all (docs/ADMISSION_POLICY.md names this command
    as the remedy).

    Under open mode there is no approved-coldkey set, so coldkey approval is
    not a criterion. Applying one anyway would flag every row and, with
    --remove, retire the entire board. Open mode therefore reclaims exactly
    the rows whose hotkey is no longer registered on the subnet.
    """
    if not Path(args.registry_db).is_file():
        raise ValueError("registry database does not exist")
    # getattr: callers construct this namespace directly (tests, and the
    # operator wrapper), so a missing optional attribute must mean "not
    # supplied" rather than AttributeError.
    policy_path = getattr(args, "admission_policy", None)
    if bool(getattr(args, "allowlist", None)) == bool(policy_path):
        raise ValueError("pass exactly one of --allowlist or --admission-policy")
    approved: frozenset[str] | None
    artifact: dict[str, object]
    if getattr(args, "allowlist", None):
        allowlist = verify_allowlist(
            _read_bounded_registry_file(args.allowlist, "coldkey allowlist"),
            load_allowlist_keys(
                args.allowlist_keys,
                pinned_digest=args.allowlist_keys_digest,
            ),
            max_age_seconds=args.allowlist_max_age_seconds,
        )
        approved = allowlist.coldkeys
        artifact = {
            "allowlist_release": allowlist.release,
            "allowlist_digest": allowlist.digest,
        }
    else:
        policy = verify_admission_policy(
            _read_bounded_registry_file(policy_path, "admission policy"),
            load_policy_keys(
                args.admission_policy_keys,
                pinned_digest=getattr(args, "admission_policy_keys_digest", None),
            ),
            network=getattr(args, "network", "finney"),
            netuid=getattr(args, "netuid", 39),
            max_age_seconds=args.allowlist_max_age_seconds,
        )
        approved = policy.coldkeys if policy.mode == MODE_SELECTED else None
        artifact = {
            "admission_config_version": policy.config_version,
            "admission_digest": policy.digest,
            "admission_mode": policy.mode,
        }
    registration = JsonHotkeyRegistrationProvider(
        args.registered_hotkeys_file,
        max_age_seconds=args.registration_max_age_seconds,
    ).load_snapshot()
    # A broken snapshot must abort loudly: treating every enrollment as
    # unresolvable would flag (and with --remove retire) the whole board.
    if registration is None:
        raise ValueError("registration snapshot is missing, stale, empty, or malformed")
    registered_hotkeys, coldkey_map = registration
    if coldkey_map is None and approved is not None:
        raise ValueError(
            "registration snapshot carries no coldkey mapping; rotate the "
            "extended {'hotkeys': {hotkey: coldkey}} format first"
        )
    store = RegistryStore(args.registry_db)
    checked = 0
    flagged: list[dict[str, object]] = []
    for enrollment in store.enrollments():
        checked += 1
        coldkey = (coldkey_map or {}).get(enrollment.hotkey)
        if approved is None:
            # Open mode: the only reclaimable rows are workers that left the
            # subnet. Everything else is legitimately enrolled.
            if enrollment.hotkey in registered_hotkeys:
                continue
            status = "not_registered"
        elif coldkey is not None and coldkey in approved:
            continue
        else:
            status = "unresolvable" if coldkey is None else "not_allowlisted"
        lifecycle = store.lifecycle_snapshot(enrollment.hotkey)
        flagged.append(
            {
                "hotkey": enrollment.hotkey,
                "coldkey": coldkey,
                "status": status,
                "lifecycle_state": lifecycle.state.value,
            }
        )
    removed: list[str] = []
    if args.remove:
        for entry in flagged:
            store.remove_enrollment(str(entry["hotkey"]))
            removed.append(str(entry["hotkey"]))
    print(
        json.dumps(
            {
                **artifact,
                "checked": checked,
                "flagged": flagged,
                "removed": removed,
            },
            sort_keys=True,
        )
    )
    return 0


# --------------------------------------------------------------------------
# argparse wiring
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cathedral", description="Cathedral operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_census = sub.add_parser("census", help="run the local CC capability probe")
    p_census.add_argument(
        "--json",
        action="store_true",
        help="machine-readable output (passed through to cathedral.census)",
    )
    p_census.set_defaults(func=cmd_census)

    p_verify = sub.add_parser("verify-quote", help="check a mock attested quote against a policy")
    p_verify.add_argument("--measurement", required=True, help="the (mock) attested measurement")
    p_verify.add_argument("--tcb", type=int, required=True, help="the (mock) attested tcb version")
    p_verify.add_argument(
        "--allowed-measurement",
        action="append",
        required=True,
        dest="allowed_measurement",
        help="repeatable; one or more measurements the policy allows",
    )
    p_verify.add_argument("--min-tcb", type=int, default=0)
    p_verify.set_defaults(func=cmd_verify_quote)

    p_work = sub.add_parser("work", help="drive the SAT-lane work queue")
    work_sub = p_work.add_subparsers(dest="work_command", required=True)

    p_submit = work_sub.add_parser("submit", help="enqueue a customer job")
    p_submit.add_argument(
        "--n-vars", type=int, default=0, help="variable count (paired with --clauses)"
    )
    p_submit.add_argument(
        "--clauses",
        default=None,
        help="JSON list of clauses (DIMACS ints); omit to submit canonical backfill work",
    )
    p_submit.add_argument("--seed", type=int, default=None)
    p_submit.add_argument("--ledger-db", required=True)
    p_submit.add_argument("--customer-id", required=True)
    p_submit.add_argument("--idempotency-key")
    p_submit.set_defaults(func=cmd_work_submit)

    p_status = work_sub.add_parser("status", help="report queue/backfill state")
    p_status.add_argument("--ledger-db", required=True)
    p_status.add_argument("--job-id")
    p_status.set_defaults(func=cmd_work_status)

    p_prune = work_sub.add_parser("prune", help="delete bounded terminal customer-job history")
    p_prune.add_argument("--ledger-db", required=True)
    p_prune.add_argument("--resolved-before", required=True)
    p_prune.add_argument("--customer-id")
    p_prune.add_argument("--limit", type=int, default=1000)
    p_prune.add_argument("--confirm", action="store_true")
    p_prune.set_defaults(func=cmd_work_prune)

    p_worker = sub.add_parser("worker", help="run a miner worker")
    worker_sub = p_worker.add_subparsers(dest="worker_command", required=True)
    p_serve = worker_sub.add_parser("serve", help="serve one configured miner hotkey")
    p_serve.add_argument("--hotkey", required=True)
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8081)
    p_serve.add_argument("--bearer-token-env", default=DEFAULT_WORKER_BEARER_ENV)
    p_serve.add_argument(
        "--tls-certificate",
        help="PEM certificate served directly by the worker",
    )
    p_serve.add_argument(
        "--tls-private-key",
        help="owner-only PEM private key kept inside the worker guest",
    )
    p_serve.add_argument("--development-no-auth", action="store_true")
    p_serve.add_argument("--development-allow-non-loopback", action="store_true")
    p_serve.add_argument(
        "--allow-customer-sat",
        action="store_true",
        help="accept bounded customer SAT jobs; requires bearer auth and channel binding",
    )
    p_serve.add_argument(
        "--gpu-composite",
        action="store_true",
        help=(
            "collect bound TDX plus confidential-GPU evidence; requires CATHEDRAL_GPU_COLLECT_CMD"
        ),
    )
    p_serve.add_argument(
        "--tee",
        choices=["tdx", "snp"],
        default="tdx",
        help="CPU TEE evidence class the worker collects (default: tdx)",
    )
    p_serve.add_argument(
        "--channel-binding-type",
        choices=[binding.value for binding in ChannelBindingType],
    )
    p_serve.add_argument(
        "--channel-binding-digest",
        help="32-byte channel public-key digest as 64 lowercase hex characters",
    )
    p_serve.set_defaults(func=cmd_worker_serve)

    p_policy = sub.add_parser("policy-registry", help="verify signed public measurement policy")
    policy_sub = p_policy.add_subparsers(dest="policy_command", required=True)
    p_policy_verify = policy_sub.add_parser("verify", help="verify and inspect a registry")
    p_policy_verify.add_argument("--registry", required=True)
    p_policy_verify.add_argument("--trusted-keys", required=True)
    p_policy_verify.add_argument("--max-age-seconds", type=int, default=86400)
    p_policy_verify.add_argument(
        "--historical-at",
        help="verify at canonical UTC receipt time instead of current admission time",
    )
    p_policy_verify.set_defaults(func=cmd_policy_registry_verify)

    p_receipt = sub.add_parser("receipt", help="verify assurance receipts")
    receipt_sub = p_receipt.add_subparsers(dest="receipt_command", required=True)
    p_receipt_verify = receipt_sub.add_parser(
        "verify", help="offline verification of exact signed receipt bytes"
    )
    p_receipt_verify.add_argument("--receipt", required=True)
    p_receipt_verify.add_argument("--policy-registry", required=True)
    p_receipt_verify.add_argument("--trusted-keys", required=True)
    p_receipt_verify.add_argument(
        "--key-registry",
        help="newer registry used to enforce receipt-key retirement or revocation",
    )
    p_receipt_verify.add_argument("--key-registry-trusted-keys")
    p_receipt_verify.add_argument("--key-registry-max-age-seconds", type=int, default=86400)
    p_receipt_verify.set_defaults(func=cmd_receipt_verify)

    p_customer_receipt = sub.add_parser(
        "customer-receipt",
        help="verify signed Cathedral Computer customer receipts",
    )
    customer_receipt_sub = p_customer_receipt.add_subparsers(
        dest="customer_receipt_command",
        required=True,
    )
    p_customer_receipt_verify = customer_receipt_sub.add_parser(
        "verify",
        help="verify exact signed customer-receipt bytes",
    )
    p_customer_receipt_verify.add_argument("--receipt", required=True)
    p_customer_receipt_verify.add_argument("--trusted-keys", required=True)
    p_customer_receipt_verify.add_argument(
        "--max-age-seconds",
        type=int,
        help="reject a valid signed receipt older than this many seconds",
    )
    p_customer_receipt_verify.set_defaults(func=cmd_customer_receipt_verify)

    p_lifecycle = sub.add_parser("lifecycle", help="inspect worker attestation lifecycle state")
    lifecycle_sub = p_lifecycle.add_subparsers(dest="lifecycle_command", required=True)
    p_lifecycle_status = lifecycle_sub.add_parser(
        "status", help="show the current customer-safe worker state"
    )
    p_lifecycle_status.add_argument("--registry-db", required=True)
    p_lifecycle_status.add_argument("--hotkey", required=True)
    p_lifecycle_status.add_argument(
        "--operator",
        action="store_true",
        help="include internal evidence, policy, retry, and event identifiers",
    )
    p_lifecycle_status.set_defaults(func=cmd_lifecycle_status)

    p_lifecycle_history = lifecycle_sub.add_parser(
        "history", help="show append-only worker transition history"
    )
    p_lifecycle_history.add_argument("--registry-db", required=True)
    p_lifecycle_history.add_argument("--hotkey", required=True)
    p_lifecycle_history.add_argument(
        "--operator",
        action="store_true",
        help="include internal evidence, policy, retry, and error details",
    )
    p_lifecycle_history.set_defaults(func=cmd_lifecycle_history)

    p_lifecycle_reenroll = lifecycle_sub.add_parser(
        "reenroll",
        help="start a new pending generation after failed, retired, or revoked state",
    )
    p_lifecycle_reenroll.add_argument("--registry-db", required=True)
    p_lifecycle_reenroll.add_argument("--hotkey", required=True)
    p_lifecycle_reenroll.set_defaults(func=cmd_lifecycle_reenroll)

    p_lifecycle_retire = lifecycle_sub.add_parser(
        "retire", help="stop refresh and score eligibility for a worker"
    )
    p_lifecycle_retire.add_argument("--registry-db", required=True)
    p_lifecycle_retire.add_argument("--hotkey", required=True)
    p_lifecycle_retire.add_argument(
        "--removed",
        action="store_true",
        help="finish directly in retired instead of leaving the worker retiring",
    )
    p_lifecycle_retire.set_defaults(func=cmd_lifecycle_retire)

    p_enroll = sub.add_parser(
        "enroll", help="reconcile the enrollment registry against approvals"
    )
    enroll_sub = p_enroll.add_subparsers(dest="enroll_command", required=True)
    p_enroll_reconcile = enroll_sub.add_parser(
        "reconcile",
        help=(
            "list (and with --remove retire) enrollments whose coldkey is "
            "absent from the signed allowlist"
        ),
    )
    p_enroll_reconcile.add_argument("--registry-db", required=True)
    p_enroll_reconcile.add_argument(
        "--allowlist", help="signed coldkey allowlist artifact"
    )
    p_enroll_reconcile.add_argument(
        "--allowlist-keys",
        help="trusted allowlist signing keys (JSON object of id to base64 key)",
    )
    p_enroll_reconcile.add_argument(
        "--admission-policy",
        help=(
            "signed admission policy artifact, as an alternative to "
            "--allowlist. Exactly one of the two is required"
        ),
    )
    p_enroll_reconcile.add_argument(
        "--admission-policy-keys",
        help="trusted admission policy signing keys (JSON object of id to base64 key)",
    )
    p_enroll_reconcile.add_argument(
        "--admission-policy-keys-digest",
        metavar="sha256:HEX",
        help="pin the admission policy key file to this sha256 digest",
    )
    p_enroll_reconcile.add_argument(
        "--network", default="finney", help="network the policy must be bound to"
    )
    p_enroll_reconcile.add_argument(
        "--netuid", type=int, default=39, help="netuid the policy must be bound to"
    )
    p_enroll_reconcile.add_argument(
        "--allowlist-keys-digest",
        metavar="sha256:HEX",
        help=(
            "pin the key file to this sha256 digest. Required: reconcile is "
            "the only enforcement for pre-existing rows and --remove is "
            "destructive, so an unpinned key file would let a substituted key "
            "both hide rogue rows and retire honest ones."
        ),
    )
    p_enroll_reconcile.add_argument(
        "--allowlist-max-age-seconds",
        type=int,
        default=DEFAULT_ALLOWLIST_MAX_AGE_SECONDS,
        metavar="N",
    )
    p_enroll_reconcile.add_argument(
        "--registered-hotkeys-file",
        required=True,
        help="extended registration snapshot carrying hotkey-to-coldkey mappings",
    )
    p_enroll_reconcile.add_argument(
        "--registration-max-age-seconds", type=int, default=3600, metavar="N"
    )
    p_enroll_reconcile.add_argument(
        "--remove",
        action="store_true",
        help="retire flagged enrollments and clear their attestation verdicts",
    )
    p_enroll_reconcile.set_defaults(func=cmd_enroll_reconcile)

    p_runtime = sub.add_parser("runtime", help="operate confidential-compute report epochs")
    runtime_sub = p_runtime.add_subparsers(dest="runtime_command", required=True)

    def add_runtime_common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--registry-db", required=True)
        command.add_argument("--ledger-db", required=True)
        command.add_argument("--measurements-file")
        command.add_argument(
            "--challenge-anchor-block",
            type=int,
            default=None,
            help="finalized SN39 block number anchoring this epoch's derived "
            "challenge nonces (REQUIRED for production CPU scoring)",
        )
        command.add_argument(
            "--challenge-anchor-hash",
            default=None,
            help="hash of the finalized anchor block; nonces derive from the "
            "normalized height AND hash under the cathedral-tdx-challenge-v2 "
            "domain",
        )
        command.add_argument(
            "--evidence-retention-dir",
            default=None,
            help="retain verified raw admission evidence (controlled disclosure) "
            "in this root-only directory; default $CATHEDRAL_EVIDENCE_RETENTION_DIR",
        )
        command.add_argument("--policy-registry")
        command.add_argument("--policy-registry-keys")
        command.add_argument(
            "--policy-registry-keys-digest",
            help="independently configured sha256 digest of the trusted-key file",
        )
        command.add_argument("--policy-registry-state")
        command.add_argument("--policy-registry-min-release", type=int)
        command.add_argument("--policy-registry-pinned-release", type=int)
        command.add_argument("--policy-registry-pinned-digest")
        command.add_argument("--policy-registry-max-age-seconds", type=int, default=86400)
        command.add_argument("--receipt-signing-key-id")
        command.add_argument("--receipt-signing-key-file")
        command.add_argument(
            "--gpu-profile-id",
            help="active gpu_cc profile id from the verified policy registry",
        )
        command.add_argument(
            "--gpu-identity-db",
            help="durable pseudonymous GPU identity-claim database",
        )
        command.add_argument(
            "--gpu-identity-key-file",
            help="owner-only file containing a 32-byte base64 identity key",
        )
        command.add_argument(
            "--gpu-identity-anchor-file",
            help="external protected monotonic generation anchor",
        )
        command.add_argument("--tokens-file", default=None)
        command.add_argument("--miner-timeout-seconds", type=float, default=10.0)
        command.add_argument("--miner-attempts", type=int, default=2)
        command.add_argument("--max-workers", type=int, default=8)
        command.add_argument("--reattestation-failures-before-failed", type=int, default=3)
        command.add_argument("--reattestation-retry-base-seconds", type=int, default=5)
        command.add_argument("--reattestation-retry-maximum-seconds", type=int, default=300)
        command.add_argument("--reattestation-retry-jitter-seconds", type=int, default=5)
        command.add_argument("--customer-job-lease-seconds", type=int, default=120)
        command.add_argument("--customer-job-max-attempts", type=int, default=3)
        command.add_argument("--development", action="store_true")
        command.add_argument("--publisher-endpoint", default=None)
        command.add_argument("--publisher-bearer-env", default=DEFAULT_PUBLISHER_BEARER_ENV)
        command.add_argument("--publisher-hmac-env", default=DEFAULT_PUBLISHER_HMAC_ENV)
        command.add_argument(
            "--score-network",
            help="exact network audience embedded in each frozen score report",
        )
        command.add_argument(
            "--score-netuid",
            type=int,
            help="subnet UID audience embedded in each frozen score report",
        )

    def add_canary(command: argparse.ArgumentParser) -> None:
        command.add_argument("--canary-hotkey", required=True)
        command.add_argument("--canary-endpoint", required=True)

    p_canary = runtime_sub.add_parser(
        "canary", help="run fresh requested-tier attestation and SAT canary"
    )
    add_runtime_common(p_canary)
    add_canary(p_canary)
    p_canary.set_defaults(func=cmd_runtime_canary)

    p_audit = runtime_sub.add_parser(
        "audit-attestation",
        help="verify fresh evidence and channel binding without work or scoring",
    )
    add_runtime_common(p_audit)
    add_canary(p_audit)
    p_audit.set_defaults(func=cmd_runtime_audit_attestation)

    p_run = runtime_sub.add_parser("run-epoch", help="freeze one complete report")
    add_runtime_common(p_run)
    add_canary(p_run)
    p_run.add_argument("--source-epoch", type=int, required=True)
    p_run.add_argument(
        "--candidate-snapshot",
        default=None,
        help="cathedral_candidate_snapshot_v1 JSON captured at the challenge "
        "anchor block (cathedral-candidate-snapshot --network ... --netuid "
        "... --block <the same --challenge-anchor-block>); REQUIRED for "
        "production CPU scoring, and it must be the exact file later passed "
        "to export-score-class, or that export refuses a still-enrolled "
        "hotkey the chain has since deregistered",
    )
    p_run.add_argument("--publish", action="store_true")
    p_run.add_argument(
        "--pretty",
        action="store_true",
        help="human-readable epoch summary (default: JSON)",
    )
    p_run.set_defaults(func=cmd_runtime_run_epoch)

    p_runtime_status = runtime_sub.add_parser("status", help="show restart-blocking state")
    p_runtime_status.add_argument("--ledger-db", required=True)
    p_runtime_status.set_defaults(func=cmd_runtime_status)

    p_export_class = runtime_sub.add_parser(
        "export-score-class",
        help="export a frozen receipt-backed report for an independent validator",
    )
    p_export_class.add_argument("--ledger-db", required=True)
    p_export_class.add_argument(
        "--epoch-id",
        required=True,
        help="epoch id, or 'latest-published'",
    )
    p_export_class.add_argument("--score-network", required=True)
    p_export_class.add_argument("--score-netuid", type=int, required=True)
    p_export_class.add_argument("--class-id", default="confidential_compute")
    p_export_class.add_argument("--source-id", default="cathedralconfidential")
    p_export_class.add_argument("--signing-key-id", required=True)
    p_export_class.add_argument("--signing-key-file", required=True)
    p_export_class.add_argument("--generated-at")
    p_export_class.add_argument("--valid-until", required=True)
    p_export_class.add_argument("--valid-from-block", type=int, required=True)
    p_export_class.add_argument("--valid-until-block", type=int, required=True)
    p_export_class.add_argument("--verifier-digest", required=True)
    p_export_class.add_argument(
        "--candidate-snapshot",
        required=True,
        help="cathedral_candidate_snapshot_v1 JSON captured from finalized "
        "chain state; its digest, block, hash, and full sorted hotkey "
        "set are bound into the signed report and must match the "
        "epoch's durable challenge anchor",
    )
    p_export_class.add_argument("--policy-digest")
    p_export_class.add_argument("--previous-report-id")
    p_export_class.add_argument("--evidence-base-uri")
    p_export_class.add_argument("--output", required=True)
    p_export_class.add_argument(
        "--development",
        action="store_true",
        help="relax production signing-key ownership and mode checks",
    )
    p_export_class.set_defaults(func=cmd_runtime_export_score_class)

    p_export_evidence = runtime_sub.add_parser(
        "export-evidence",
        help="publish one epoch's content-addressed public evidence bundle",
    )
    p_export_evidence.add_argument("--ledger-db", required=True)
    p_export_evidence.add_argument(
        "--epoch-id",
        default="latest-published",
        help="epoch id, or 'latest-published' (default)",
    )
    p_export_evidence.add_argument("--evidence-dir", required=True)
    p_export_evidence.add_argument("--score-network", required=True)
    p_export_evidence.add_argument("--score-netuid", type=int, required=True)
    p_export_evidence.add_argument("--class-id", default="confidential_compute")
    p_export_evidence.add_argument("--source-id", default="cathedralconfidential")
    p_export_evidence.add_argument("--policy-registry", required=True)
    p_export_evidence.add_argument(
        "--policy-registry-history-dir",
        help="content-addressed archive of superseded signed registries "
        "(release-<n>-<sha256>.json, written by republish-install); read "
        "only when the live --policy-registry no longer carries the frozen "
        "epoch's pinned digest, and only a file whose content hashes to that "
        "digest is accepted",
    )
    p_export_evidence.add_argument("--verifier-digest", required=True)
    p_export_evidence.add_argument("--verifier-binary")
    p_export_evidence.add_argument(
        "--verifier-production-path",
        help="the absolute production install path of the pinned verifier "
        "(published so external validators can recompute the "
        "implementation digest from the binary blob)",
    )
    # New evidence is emitted as validated_supply_v2, which is what README.md
    # documents and what cathedral.provenance already defaults to. The default
    # here named the retired v1 id, so an operator running the documented
    # command stamped a mechanism the docs call historical, and every test had
    # to pin v2 explicitly to work around it. v1 stays registered and can still
    # be pinned by hand so already-signed historical evidence keeps verifying.
    p_export_evidence.add_argument("--mechanism", default="validated_supply_v2")
    p_export_evidence.add_argument("--mechanism-revision", type=int, default=1)
    p_export_evidence.add_argument("--source-revision")
    p_export_evidence.add_argument(
        "--candidate-snapshot",
        required=True,
        help="cathedral_candidate_snapshot_v1 JSON: the anchored SN39 "
        "metagraph (network/netuid/block/block_hash/hotkeys) the epoch "
        "loop observed; every registered hotkey is accounted for",
    )
    p_export_evidence.add_argument("--index-signing-key-id", required=True)
    p_export_evidence.add_argument("--index-signing-key-file", required=True)
    p_export_evidence.add_argument(
        "--development",
        action="store_true",
        help="relax production signing-key ownership checks",
    )
    p_export_evidence.set_defaults(func=cmd_runtime_export_evidence)

    p_retry = runtime_sub.add_parser("retry-publish", help="publish frozen report bytes")
    p_retry.add_argument("--ledger-db", required=True)
    p_retry.add_argument("--publisher-endpoint", required=True)
    p_retry.add_argument("--publisher-bearer-env", default=DEFAULT_PUBLISHER_BEARER_ENV)
    p_retry.add_argument("--publisher-hmac-env", default=DEFAULT_PUBLISHER_HMAC_ENV)
    p_retry.add_argument("--score-network", required=True)
    p_retry.add_argument("--score-netuid", type=int, required=True)
    p_retry.add_argument("--epoch-id", type=int, required=True)
    p_retry.add_argument(
        "--pretty",
        action="store_true",
        help="human-readable publish summary (default: JSON)",
    )
    p_retry.set_defaults(func=cmd_runtime_retry_publish)

    p_abort = runtime_sub.add_parser("abort-running", help="abort the running epoch")
    p_abort.add_argument("--ledger-db", required=True)
    p_abort.set_defaults(func=cmd_runtime_abort_running)

    p_abandon = runtime_sub.add_parser(
        "abandon-complete",
        help=(
            "abandon a completed-but-unpublished epoch that can never publish "
            "(e.g. its report is too old for the ingest service's first-publish window)"
        ),
    )
    p_abandon.add_argument("--ledger-db", required=True)
    p_abandon.add_argument("--epoch-id", type=int, required=True)
    p_abandon.add_argument(
        "--reason",
        required=True,
        help="nonempty operator justification; recorded in the ledger audit trail",
    )
    p_abandon.set_defaults(func=cmd_runtime_abandon_complete)

    p_gpu_recovery = runtime_sub.add_parser(
        "recover-gpu-identities",
        help="reconcile interrupted GPU claims and record an authenticated audit event",
    )
    p_gpu_recovery.add_argument("--gpu-identity-db", required=True)
    p_gpu_recovery.add_argument("--gpu-identity-key-file", required=True)
    p_gpu_recovery.add_argument("--gpu-identity-anchor-file", required=True)
    p_gpu_recovery.add_argument(
        "--reason",
        required=True,
        help="operator justification recorded in the GPU identity audit trail",
    )
    p_gpu_recovery.add_argument(
        "--development",
        action="store_true",
        help="relax production ownership checks for a local recovery exercise",
    )
    p_gpu_recovery.set_defaults(func=cmd_runtime_recover_gpu_identities)

    p_gpu_release = runtime_sub.add_parser(
        "release-gpu-identities",
        help="release one worker's committed GPU identity claims and audit it",
    )
    p_gpu_release.add_argument("--gpu-identity-db", required=True)
    p_gpu_release.add_argument("--gpu-identity-key-file", required=True)
    p_gpu_release.add_argument("--gpu-identity-anchor-file", required=True)
    p_gpu_release.add_argument("--hotkey", required=True)
    p_gpu_release.add_argument(
        "--reason",
        required=True,
        help="operator justification recorded in the GPU identity audit trail",
    )
    p_gpu_release.add_argument(
        "--development",
        action="store_true",
        help="relax production ownership checks for a local release exercise",
    )
    p_gpu_release.set_defaults(func=cmd_runtime_release_gpu_identities)

    p_gpu_initialize = runtime_sub.add_parser(
        "initialize-gpu-identities",
        help="perform one-time creation of the GPU identity database and external anchor",
    )
    p_gpu_initialize.add_argument("--gpu-identity-db", required=True)
    p_gpu_initialize.add_argument("--gpu-identity-key-file", required=True)
    p_gpu_initialize.add_argument("--gpu-identity-anchor-file", required=True)
    p_gpu_initialize.add_argument(
        "--development",
        action="store_true",
        help="relax production path separation and ownership checks for a local exercise",
    )
    p_gpu_initialize.set_defaults(func=cmd_runtime_initialize_gpu_identities)

    p_provenance = sub.add_parser(
        "provenance",
        help="independently verify published evidence and recompute weights",
    )
    provenance_sub = p_provenance.add_subparsers(dest="provenance_command", required=True)
    p_prov_verify = provenance_sub.add_parser(
        "verify",
        help="verify the full evidence chain for one epoch and recompute the vector",
    )
    source = p_prov_verify.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--evidence-url",
        help="public evidence base URL, e.g. https://api.cathedral.computer/v1/evidence",
    )
    source.add_argument("--evidence-dir", help="local evidence store directory")
    p_prov_verify.add_argument("--network", default="finney")
    p_prov_verify.add_argument("--netuid", type=int, default=39)
    p_prov_verify.add_argument(
        "--registry-keys", required=True, help="trusted policy-registry key file (key_id -> base64)"
    )
    p_prov_verify.add_argument(
        "--registry-keys-digest", help="pinned sha256:<hex> of the registry key file"
    )
    p_prov_verify.add_argument(
        "--report-keys", required=True, help="trusted score-report key file (key_id -> base64)"
    )
    p_prov_verify.add_argument("--report-keys-digest")
    p_prov_verify.add_argument(
        "--index-keys", required=True, help="trusted evidence-index key file (key_id -> base64)"
    )
    p_prov_verify.add_argument("--index-keys-digest")
    p_prov_verify.add_argument(
        "--verifier-digest", required=True, help="pinned TDX verifier implementation digest"
    )
    # Matches the export default above, so verifying freshly exported evidence
    # needs no flag. Verifying historical v1 evidence still works, but now says
    # so out loud: pass --mechanism validated_supply_v1 explicitly. The pin is
    # deliberately fail-closed on mismatch, so a wrong default is not a
    # cosmetic disagreement, it rejects the bundle.
    p_prov_verify.add_argument("--mechanism", default="validated_supply_v2")
    p_prov_verify.add_argument(
        "--mechanism-revision",
        type=int,
        default=1,
        help="pinned reward-mechanism revision; verification dispatches on "
        "the exact (id, revision) pair and refuses any other",
    )
    p_prov_verify.add_argument(
        "--source-epoch",
        type=int,
        help=(
            "verify a specific epoch (default: index latest). Auditing an "
            "epoch older than the state file's high-water is a historical "
            "audit: it passes or fails on that epoch's own evidence and "
            "does not move the fences."
        ),
    )
    p_prov_verify.add_argument("--index-max-age-secs", type=float, default=3600.0)
    p_prov_verify.add_argument(
        "--registry-max-age-secs",
        type=int,
        default=86400,
        help="reject a registry whose publication (generated_at) is older "
        "than this many seconds (default 24 hours, fail closed)",
    )
    p_prov_verify.add_argument(
        "--publisher-url", help="also fetch Cathedral's signed vector and compare"
    )
    p_prov_verify.add_argument(
        "--weight-policy-public-key-hex",
        default=os.environ.get("CATHEDRAL_WEIGHT_POLICY_PUBLIC_KEY", ""),
        help="pinned weight-vector signing key (hex) for --publisher-url comparison",
    )
    p_prov_verify.add_argument("--weight-policy-key-id", default="cathedral-weight-policy")
    p_prov_verify.add_argument("--jsonl", help="append JSONL events to this file")
    p_prov_verify.add_argument("--audit-out", help="write the audit record JSON here")
    p_prov_verify.add_argument(
        "--state-file",
        help="durable anti-rollback fences (index high-water epoch/manifest)",
    )
    p_prov_verify.add_argument(
        "--controlled-dir",
        help="controlled-disclosure envelope directory; enables FULL assurance "
        "(raw-evidence replay through the pinned verifier)",
    )
    p_prov_verify.add_argument(
        "--independent-candidate-snapshot",
        help="cathedral_candidate_snapshot_v1 JSON captured by YOUR OWN chain "
        "access at the anchored block (cathedral-candidate-snapshot --block "
        "<anchor>); REQUIRED with --controlled-dir - FULL never trusts "
        "Cathedral-produced artifacts as the candidate oracle",
    )
    p_prov_verify.add_argument(
        "--verifier-binary",
        help="local verifier binary (must match the manifest's binary blob "
        "digest); default: fetched from the evidence store",
    )
    p_prov_verify.add_argument(
        "--source-revision",
        help="independent pin of the expected source revision; the manifest "
        "must match (never self-authorized)",
    )
    p_prov_verify.add_argument(
        "--production",
        action="store_true",
        help="require every independent pin (key digests + source revision)",
    )
    p_prov_verify.add_argument(
        "--allow-receipts-only",
        action="store_true",
        help="exit 0 for a receipts-only chain; the result is still recorded "
        "and logged as NOT_PROVEN, never as full provenance",
    )
    p_prov_verify.add_argument(
        "--current-block",
        type=int,
        help="trusted current finalized SN39 block (REQUIRED in production); "
        "the report's valid_from_block..valid_until_block window is "
        "enforced against it",
    )
    p_prov_verify.add_argument(
        "--fetch-deadline-secs",
        type=float,
        default=DEFAULT_COMMAND_DEADLINE_SECONDS,
        help="one command-wide wall-clock budget covering DNS, connect, TLS, and every blob read",
    )
    p_prov_verify.add_argument(
        "--allow-private-evidence-host",
        action="store_true",
        help="testing only: permit evidence hosts resolving to private ranges",
    )
    p_prov_verify.set_defaults(func=cmd_provenance_verify)

    p_controlled = provenance_sub.add_parser(
        "export-controlled",
        help="package controlled-disclosure envelopes for an authorized validator",
    )
    p_controlled.add_argument("--ledger-db", required=True)
    p_controlled.add_argument("--epoch-id", default="latest-published")
    p_controlled.add_argument("--retention-dir", required=True)
    p_controlled.add_argument("--out-dir", required=True)
    p_controlled.set_defaults(func=cmd_runtime_export_controlled)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001 - intentional fail-closed/UTC-text semantics
        # Any exception text may echo request/response context that embeds a
        # credential (e.g. a token-mapping load error); sanitize before it
        # reaches logs, same as the outcome/run JSON and --pretty paths.
        print(json.dumps({"error": _sanitize_error(str(exc), maxlen=300)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
