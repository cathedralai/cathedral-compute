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
from cathedral.assurance import AssuranceDimension
from cathedral.attest import collect_tdx_gpu
from cathedral.channel import ChannelBindingError, tls_spki_binding
from cathedral.common import ChannelBinding, ChannelBindingType, Policy, Tier
from cathedral.enroll import RegistryStore
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
    # Authorization: Bearer <token>  (HTTP header echoed in error text)
    re.compile(r"(Authorization\s*:\s*Bearer\s+)\S+", re.IGNORECASE),
    # bearer=, token=, secret=, hmac=, api_key=, api-key=, apikey=
    re.compile(
        r"((?:bearer|token|secret|hmac|api[-_]?key)\s*[=:]\s*)\S+",
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
    print(f"submitted {job.job_id} (n_vars={item.instance.n_vars}, seed={item.seed}); queued={queued}")
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
    )
    if require_report_audience and config.production_mode and config.score_network is None:
        raise ValueError("production score reports require --score-network and --score-netuid")
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
    ledger = Ledger(args.ledger_db)
    runtime = ConfidentialRuntime(
        RegistryStore(getattr(args, "registry_db", ":memory:")),
        ledger,
        policy,
        _publisher_from_args(args),
        token_provider=tokens.get,
        policy_refresher=policy_refresher,
        config=config,
        receipt_issuer=receipt_issuer,
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
    if not is_loopback and not tls_enabled and not args.development_allow_non_loopback:
        raise ValueError("plain worker HTTP must bind loopback unless development mode is explicit")
    if getattr(args, "development_no_auth", False):
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
            tls_context.load_cert_chain(
                certfile=str(certificate_path), keyfile=str(key_path)
            )
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
    with WorkerServer(
        args.host,
        args.port,
        configured_hotkey=args.hotkey,
        bearer_token=token,
        channel_binding=channel_binding,
        tls_context=tls_context,
        evidence_collector=(collect_tdx_gpu if getattr(args, "gpu_composite", False) else None),
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
                policy_digest=args.policy_digest,
                previous_report_id=args.previous_report_id,
                evidence_base_uri=args.evidence_base_uri,
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
        epoch_id = _resolve_evidence_epoch(ledger, args.epoch_id)
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
        report = json.loads(report_bytes)

        registry_bytes = _read_bounded_registry_file(
            args.policy_registry, "policy registry"
        )
        registry_document = parse_registry_json(registry_bytes)
        registry_release = registry_document.get("release")
        registry_digest = "sha256:" + hashlib.sha256(registry_bytes).hexdigest()
        if report.get("policy_digest") != registry_digest:
            raise ValueError(
                "signed report policy_digest does not match the supplied registry file"
            )
        if report.get("verifier_digest") != args.verifier_digest:
            raise ValueError(
                "signed report verifier_digest does not match --verifier-digest"
            )

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
                manifest_receipts.append(
                    {
                        "receipt_id": receipt_id,
                        "hotkey": entry["miner_hotkey"],
                        "blob": blob,
                    }
                )

        verifier_binary_blob = None
        if args.verifier_binary:
            verifier_binary_blob = store.put_blob(Path(args.verifier_binary).read_bytes())

        def _normalized_digest(value: str) -> str:
            text = str(value)
            if re.fullmatch(r"[0-9a-f]{64}", text):
                return "sha256:" + text
            return text

        attestations = [
            {
                "hotkey": str(row["hotkey"]),
                "verdict": str(row["verdict"]),
                "evidence_digest": _normalized_digest(row["evidence_digest"]),
                "envelope_digest": (
                    str(row["envelope_digest"])
                    if row["envelope_digest"] is not None
                    else None
                ),
                "disclosure": "controlled",
            }
            for row in ledger.attestation_rows(epoch_id)
            if row["evidence_digest"]
        ]

        wire_digest = str(snapshot["report_digest"]).removeprefix("sha256:")
        candidate_rows = [
            {
                "hotkey": str(row["hotkey"]),
                "outcome": "verified" if row["receipt_id"] else "rejected",
                "reason": (
                    "receipt_verified" if row["receipt_id"] else "no_verified_work"
                ),
            }
            for row in snapshot["rows"]
        ]
        manifest_bytes = build_manifest(
            network=args.score_network,
            netuid=args.score_netuid,
            source_epoch=int(snapshot["source_epoch"]),
            epoch_id=epoch_id,
            generated_at=None,
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
                "source": "enrollment_registry",
                "finalized_block": None,
                "candidates": candidate_rows,
            },
            wire_report_sha256=wire_digest,
        )
        manifest_digest = store.put_blob(manifest_bytes)
        store.put_epoch_copy(int(snapshot["source_epoch"]), manifest_bytes)

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
        # exclusive index transaction so concurrent exporters cannot lose
        # the latest pointer or history.
        index_txn = store.index_transaction()
        index_txn.__enter__()
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
        try:
            index_txn.publish(index_bytes)
        finally:
            index_txn.__exit__(None, None, None)
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
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
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


MAX_EVIDENCE_FETCH_BYTES = 4 * 1024 * 1024
MAX_VERIFIER_FETCH_BYTES = 32 * 1024 * 1024


def _bounded_https_fetch(
    url: str,
    *,
    max_bytes: int = MAX_EVIDENCE_FETCH_BYTES,
    allow_private: bool = False,
    timeout: float = 30.0,
) -> bytes:
    """HTTPS-only bounded fetch: no redirects, no downgrade, no private hosts."""
    import ipaddress as _ip
    import socket as _socket
    import urllib.parse as _parse
    import urllib.request as _request

    parsed = _parse.urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError("evidence fetches must use https")
    if parsed.username or parsed.password:
        raise ValueError("evidence URLs must be credential-free")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("evidence URL has no host")
    if not allow_private:
        try:
            infos = _socket.getaddrinfo(host, parsed.port or 443, proto=_socket.IPPROTO_TCP)
        except OSError as exc:
            raise ValueError(f"evidence host does not resolve: {host}") from exc
        for info in infos:
            address = _ip.ip_address(info[4][0])
            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_reserved
                or address.is_multicast
                or address.is_unspecified
            ):
                raise ValueError(
                    f"evidence host resolves to a non-public address: {host}"
                )

    class _NoRedirect(_request.HTTPRedirectHandler):
        def redirect_request(self, *arguments, **keywords):
            raise ValueError("evidence fetches must not follow redirects")

    opener = _request.build_opener(_NoRedirect, _request.HTTPSHandler())
    request = _request.Request(url, headers={"User-Agent": "cathedral-provenance/1.0"})
    with opener.open(request, timeout=timeout) as response:
        return _read_bounded_deadline(response, max_bytes, timeout)


def _read_bounded_deadline(response, max_bytes: int, total_seconds: float) -> bytes:
    """Read with BOTH a size bound and a total wall-clock deadline: a slow
    drip that keeps each read under the socket timeout still cannot exceed
    the overall budget."""
    import time as _time

    deadline = _time.monotonic() + total_seconds
    chunks: list[bytes] = []
    received = 0
    while True:
        if _time.monotonic() > deadline:
            raise ValueError("evidence fetch exceeded the total deadline")
        chunk = response.read(min(65536, max_bytes + 1 - received))
        if not chunk:
            break
        received += len(chunk)
        if received > max_bytes:
            raise ValueError("evidence response exceeds the bounded size limit")
        chunks.append(chunk)
    return b"".join(chunks)


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
        parse_constant=lambda _v: (_ for _ in ()).throw(
            ValueError(f"non-finite {label} JSON")
        ),
    )
    if not isinstance(document, dict):
        raise ValueError(f"{label} is not a JSON object")  # noqa: TRY004 - intentional fail-closed/UTC-text semantics
    return document


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

    from cathedral.evidence import EvidenceError, digest_bytes

    ledger = Ledger(args.ledger_db)
    staging: str | None = None
    try:
        epoch_id = _resolve_evidence_epoch(ledger, args.epoch_id)
        epoch_row = ledger.get_epoch(epoch_id)
        if epoch_row is None or epoch_row["status"] != "published":
            raise ValueError(
                f"epoch {epoch_id} is not published/frozen; refusing disclosure"
            )
        snapshot = ledger.score_class_snapshot(epoch_id)
        rows = [
            row
            for row in ledger.attestation_rows(epoch_id)
            if row["envelope_digest"] is not None
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
            if blob_path.is_symlink() or not blob_path.is_file():
                raise EvidenceError(f"retained envelope {digest} is unavailable")
            data = blob_path.read_bytes()
            if digest_bytes(data) != digest:
                raise EvidenceError(f"retained envelope {digest} is corrupt")
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
            # Idempotent EXACT retry: identical manifest bytes => success.
            existing = out_root / "controlled-manifest.json"
            if existing.is_file() and existing.read_text() == manifest_text:
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
            raise ValueError(
                "controlled output path exists with different content; refusing"
            )

        staging = tempfile_module.mkdtemp(
            prefix=f".controlled.{epoch_id}.", dir=parent
        )
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

    def fetch_url(path: str, *, max_bytes: int = MAX_EVIDENCE_FETCH_BYTES) -> bytes:
        url = args.evidence_url.rstrip("/") + path
        try:
            return _bounded_https_fetch(
                url,
                max_bytes=max_bytes,
                allow_private=bool(getattr(args, "allow_private_evidence_host", False)),
            )
        except ValueError as exc:
            raise EvidenceError(str(exc)) from exc

    store = EvidenceStore(args.evidence_dir) if args.evidence_dir else None

    def load_index_bytes() -> bytes:
        if store is not None:
            data = store.read_index()
            if data is None:
                raise EvidenceError("evidence index is missing from the store")
            return data
        return fetch_url("/index.json")

    def load_blob(digest: str, *, max_bytes: int = MAX_EVIDENCE_FETCH_BYTES) -> bytes:
        if store is not None:
            return store.get_blob(digest)
        data = fetch_url("/blobs/sha256/" + digest.split(":", 1)[1], max_bytes=max_bytes)
        if digest_bytes(data) != digest:
            raise EvidenceError(f"fetched blob does not match digest {digest}")
        return data

    audit: dict[str, object] = {"result": "FAIL"}
    try:
        if getattr(args, "production", False):
            missing = [
                flag
                for flag, value in (
                    ("--registry-keys-digest", args.registry_keys_digest),
                    ("--report-keys-digest", args.report_keys_digest),
                    ("--index-keys-digest", args.index_keys_digest),
                    ("--source-revision", getattr(args, "source_revision", None)),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    "production verification requires independent pins: "
                    + ", ".join(missing)
                )
        started = time_mod.monotonic()
        index_keys = _load_evidence_keyfile(
            args.index_keys, args.index_keys_digest, "index keys"
        )
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
                raise EvidenceError(
                    f"source epoch {wanted} is not present in the evidence index"
                )
        else:
            manifest_digest = index_document["latest"]["manifest"]

        started = time_mod.monotonic()
        manifest = parse_manifest(load_blob(manifest_digest))
        if manifest["network"] != args.network or manifest["netuid"] != args.netuid:
            raise EvidenceError("evidence manifest network/netuid mismatch")
        if args.source_epoch is None and int(manifest["source_epoch"]) != int(
            index_document["latest"]["source_epoch"]
        ):
            raise EvidenceError(
                "index latest.source_epoch does not match the manifest it points to"
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
                if new_epoch == last_epoch and index_document["latest"][
                    "manifest"
                ] != last_manifest:
                    raise EvidenceError(
                        "index equivocation: same epoch, different manifest"
                    )
        if manifest["reward_mechanism"]["id"] != args.mechanism:
            raise EvidenceError(
                "manifest reward mechanism "
                f"{manifest['reward_mechanism']['id']!r} does not match the "
                f"pinned mechanism {args.mechanism!r}"
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
        registry_bytes = load_blob(manifest["policy_registry"]["blob"])
        if (
            "sha256:" + hashlib.sha256(registry_bytes).hexdigest()
            != manifest["policy_registry"]["digest"]
        ):
            raise EvidenceError("registry blob does not match the manifest digest")
        report_keys = _load_evidence_keyfile(
            args.report_keys, args.report_keys_digest, "report keys"
        )
        report_bytes = load_blob(manifest["score_report"]["blob"])
        receipts_by_id = {
            row["receipt_id"]: load_blob(row["blob"]) for row in manifest["receipts"]
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
            registry_max_age_seconds=args.registry_max_age_secs,
        )
        if result.policy_release != manifest["policy_registry"]["release"]:
            raise EvidenceError("verified registry release differs from the manifest")
        if result.report_id != manifest["score_report"]["report_id"]:
            raise EvidenceError("verified report id differs from the manifest")
        pinned_revision = getattr(args, "source_revision", None)
        if pinned_revision and manifest["source_revision"] != pinned_revision:
            raise EvidenceError(
                "manifest source revision does not match the operator's pin"
            )

        # ---- FULL assurance: raw-evidence replay through the pinned verifier.
        controlled_dir = getattr(args, "controlled_dir", None)
        if controlled_dir:
            from cathedral import provenance as provenance_module

            bindings = {
                row["hotkey"]: row for row in manifest["attestations"]
            }
            envelopes: dict[str, bytes] = {}
            for miner in result.miners:
                if not miner.receipt_verified:
                    continue
                binding = bindings.get(miner.hotkey)
                envelope_digest = (
                    binding.get("envelope_digest") if binding else None
                )
                if not envelope_digest:
                    raise EvidenceError(
                        f"no controlled envelope binding for {miner.hotkey!r}"
                    )
                envelope_path = (
                    Path(controlled_dir)
                    / f"{str(envelope_digest).split(':', 1)[1]}.json"
                )
                if envelope_path.is_symlink() or not envelope_path.is_file():
                    raise EvidenceError(
                        f"controlled envelope file missing for {miner.hotkey!r}"
                    )
                envelopes[miner.hotkey] = envelope_path.read_bytes()
            verifier_info = manifest["verifier"]
            if not verifier_info["binary_blob"] or not verifier_info["command"]:
                raise EvidenceError(
                    "manifest lacks verifier binary/command bindings for full mode"
                )
            if getattr(args, "verifier_binary", None):
                binary_path = Path(args.verifier_binary)
                if binary_path.stat().st_size > MAX_VERIFIER_FETCH_BYTES:
                    raise EvidenceError("verifier binary exceeds the bounded limit")
                verifier_bytes = binary_path.read_bytes()
            else:
                verifier_bytes = load_blob(
                    verifier_info["binary_blob"],
                    max_bytes=MAX_VERIFIER_FETCH_BYTES,
                )
            result = provenance_module.replay_positive_miners(
                result,
                registry=provenance_module.load_registry(
                    registry_bytes,
                    registry_keys,
                    max_age_seconds=args.registry_max_age_secs,
                ),
                envelopes_by_hotkey=envelopes,
                attestation_bindings=bindings,
                verifier_binary=verifier_bytes,
                verifier_blob_digest=verifier_info["binary_blob"],
                verifier_command=tuple(verifier_info["command"]),
                verifier_artifacts=tuple(
                    verifier_info["artifacts"] or verifier_info["command"]
                ),
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
            "manifest": manifest_digest,
            "recomputed_hotkey_weights": result.recomputed_hotkey_weights,
        }

        if args.publisher_url:
            started = time_mod.monotonic()
            vector_bytes = _bounded_https_fetch(
                args.publisher_url.rstrip("/") + "/v1/validator/weights/next",
                allow_private=bool(getattr(args, "allow_private_evidence_host", False)),
            )
            vector = _strict_json_object(vector_bytes, "weight vector")
            _verify_wire_vector(
                vector,
                public_key_hex=args.weight_policy_public_key_hex,
                expected_key_id=args.weight_policy_key_id,
                network=args.network,
                netuid=args.netuid,
            )
            agree, discrepancies = provenance.compare_with_vector(result, vector)
            audit["vector_id"] = vector.get("vector_id")
            audit["vector_agrees"] = agree
            audit["vector_discrepancies"] = discrepancies
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
        full = result.assurance_level == "full"
        succeeded = audit["result"] == "PASS" and (
            full or bool(getattr(args, "allow_receipts_only", False))
        )
        if not full:
            audit["result"] = "NOT_PROVEN"
            from cathedral.events import NOT_PROVEN as _NOT_PROVEN

            logger.event(
                "PROVENANCE_RESULT",
                stage="result",
                status=_NOT_PROVEN,
                detail=(
                    "receipts-only (PARTIAL) provenance: signed statements are "
                    "internally consistent, but no raw evidence was replayed. "
                    f"source_epoch={audit.get('source_epoch')}"
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
                status=PASS if succeeded else FAIL,
                detail=(
                    f"assurance=full source_epoch={audit.get('source_epoch')} "
                    f"weights={audit.get('recomputed_hotkey_weights')}"
                ),
            )
        if fence_path is not None and audit["result"] in ("PASS", "NOT_PROVEN"):
            fences.update(
                {
                    "index_source_epoch": int(
                        index_document["latest"]["source_epoch"]
                    ),
                    "index_manifest": index_document["latest"]["manifest"],
                }
            )
            fence_tmp = fence_path.with_suffix(".tmp")
            descriptor = os.open(
                fence_tmp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(fences, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(fence_tmp, fence_path)
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
    snapshot = RegistryStore(args.registry_db).reenroll_lifecycle(args.hotkey)
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

    p_runtime = sub.add_parser("runtime", help="operate confidential-compute report epochs")
    runtime_sub = p_runtime.add_subparsers(dest="runtime_command", required=True)

    def add_runtime_common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--registry-db", required=True)
        command.add_argument("--ledger-db", required=True)
        command.add_argument("--measurements-file")
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
    p_export_evidence.add_argument("--verifier-digest", required=True)
    p_export_evidence.add_argument("--verifier-binary")
    p_export_evidence.add_argument(
        "--verifier-production-path",
        help="the absolute production install path of the pinned verifier "
             "(published so external validators can recompute the "
             "implementation digest from the binary blob)",
    )
    p_export_evidence.add_argument("--mechanism", default="validated_supply_v1")
    p_export_evidence.add_argument("--mechanism-revision", type=int, default=1)
    p_export_evidence.add_argument("--source-revision")
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
    p_prov_verify.add_argument("--registry-keys", required=True,
                               help="trusted policy-registry key file (key_id -> base64)")
    p_prov_verify.add_argument("--registry-keys-digest",
                               help="pinned sha256:<hex> of the registry key file")
    p_prov_verify.add_argument("--report-keys", required=True,
                               help="trusted score-report key file (key_id -> base64)")
    p_prov_verify.add_argument("--report-keys-digest")
    p_prov_verify.add_argument("--index-keys", required=True,
                               help="trusted evidence-index key file (key_id -> base64)")
    p_prov_verify.add_argument("--index-keys-digest")
    p_prov_verify.add_argument("--verifier-digest", required=True,
                               help="pinned TDX verifier implementation digest")
    p_prov_verify.add_argument("--mechanism", default="validated_supply_v1")
    p_prov_verify.add_argument("--source-epoch", type=int,
                               help="verify a specific epoch (default: index latest)")
    p_prov_verify.add_argument("--index-max-age-secs", type=float, default=3600.0)
    p_prov_verify.add_argument(
        "--registry-max-age-secs", type=int, default=86400,
        help="reject a registry whose publication (generated_at) is older "
             "than this many seconds (default 24 hours, fail closed)",
    )
    p_prov_verify.add_argument("--publisher-url",
                               help="also fetch Cathedral's signed vector and compare")
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
