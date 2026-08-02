#!/usr/bin/env python3
"""Auditable measurement-approval flow for the SN39 CPU policy registry.

The launch measurement changes far more easily than "different guest firmware"
suggests, and this is the tool you run when it does.

It is NOT a bare MRTD: it is a SHA-256 over eight fields, of which `mr_td` is
one, and ALL FOUR RTMRs are folded in (see `cathedral/verify/tdx_quote.py` and
`docs/MRTD.md`). RTMR1 conventionally measures kernel and initrd, so ANY
initramfs regeneration moves it -- installing a single package is enough.
Measured on real TDX hardware, `apt full-upgrade` plus installing Docker
changed the value while `mr_td` and `rtmr0` stayed constant. Migration onto a
host with different guest firmware (TDVF) also changes it, but it is not the
common case; routine patching is.

The runtime fails closed on any measurement not in the signed policy registry,
so a provider that patches stops being admitted until this flow is run for its
new measurement. Whether routine patching SHOULD be an approvable event, and at
what cadence, is an open policy question (cathedral-compute#88) -- the mechanics
below are ready either way.

This tool is the only sanctioned way to add a new measurement: it never trusts
a measurement blindly. It

  1. captures the candidate measurement live from a named worker, through the
     pinned production verifier, proving intel_verified + report_data_match +
     an acceptable TCB status before the measurement is even eligible;
  2. records full provenance (endpoint, chip/platform id, TCB status, verifier,
     operator, UTC time, justification) into an append-only approval log;
  3. emits the next monotonic signed registry release adding exactly that one
     measurement to exactly the one profile the operator named, preserving
     every prior profile/key transition time so the registry's own
     anti-equivocation and unchanged-transition guards accept it.

Profile selection is always explicit. A registry retains every prior profile
after a rollover, so no command may infer its target from list position.

It does not deploy. The operator reviews the emitted registry and approval
record and installs it deliberately. Unknown measurements continue to fail
closed until this flow is run for them.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import ssl
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.common import evidence_report_data
from cathedral.policy_registry import parse_registry_json, sign_registry, verify_registry
from cathedral.remote import RemoteMiner

MEASUREMENT_PREFIX = "tdx-measurement-sha256:"
ACCEPTABLE_TCB = {"UpToDate"}
MAX_ROLLOVER_DAYS = 180
MIN_ROLLOVER_DAYS = 7
MAX_ROLLOVER_AUDIT_ENTRIES = 32
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MAX_REGISTRY_BYTES = 8 * 1024 * 1024


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _public_key_b64(seed: bytes) -> str:
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(public).decode()


def _secure_read_bytes(
    path: str | Path,
    *,
    label: str,
    maximum: int = MAX_REGISTRY_BYTES,
) -> bytes:
    """Read a bounded, owned, non-symlink regular file without a TOCTOU gap."""
    target = Path(path)
    before = target.lstat()
    if not stat.S_ISREG(before.st_mode) or target.is_symlink():
        raise SystemExit(f"{label} must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags)
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise SystemExit(f"{label} changed underneath the tool")
        if after.st_mode & 0o022:
            raise SystemExit(f"{label} must not be group/world writable")
        if hasattr(os, "geteuid") and after.st_uid != os.geteuid():
            raise SystemExit(f"{label} must be owned by the invoking user")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) > maximum:
        raise SystemExit(f"{label} exceeds the {maximum}-byte limit")
    return raw


def _capture(endpoint: str, cacert: str, hotkey: str, verifier: str) -> dict:
    ctx = ssl.create_default_context(cafile=cacert)
    client = RemoteMiner(endpoint, hotkey, ssl_context=ctx, timeout=20.0)
    nonce = secrets.token_bytes(32)
    evidence = client.fetch_evidence(nonce)
    expected = evidence_report_data(evidence, nonce)
    with tempfile.TemporaryDirectory(prefix="measure-") as directory:
        quote = os.path.join(directory, "quote.bin")
        fd = os.open(quote, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, evidence.quote)
        finally:
            os.close(fd)
        result = subprocess.run(
            [verifier, quote, expected.hex()],
            check=False,
            capture_output=True,
            text=True,
            timeout=90,
        )
    if result.returncode != 0:
        raise SystemExit(f"verifier rejected candidate evidence: {result.stderr.strip()[:300]}")
    claims = json.loads(result.stdout)
    if claims.get("intel_verified") is not True:
        raise SystemExit("candidate is not Intel-verified; refusing to approve")
    if claims.get("report_data_match") is not True:
        raise SystemExit("candidate report_data does not bind to the fresh nonce; refusing")
    tcb = claims.get("tcb_status")
    if tcb not in ACCEPTABLE_TCB:
        raise SystemExit(f"candidate TCB status {tcb!r} is not acceptable; refusing")
    measurement = claims.get("measurement")
    if not isinstance(measurement, str) or not measurement.startswith(MEASUREMENT_PREFIX):
        raise SystemExit(f"verifier returned an unexpected measurement value: {measurement!r}")
    chip = claims.get("stable_platform_id") or claims.get("chip_id")
    return {"measurement": measurement, "tcb_status": tcb, "chip_id": chip}


def _select_active_profile(document: dict, profile_id: str) -> dict:
    """Return the one profile *profile_id* names, verified active CPU-TDX.

    A registry may legitimately carry several profiles at once (a rollover
    appends the successor while retaining every prior profile for historical
    verification), so positional selection is never safe: after a rollover,
    ``profiles[0]`` is the legacy profile. Every mutation must name its
    target explicitly and prove the target is a currently active CPU-TDX
    profile before touching anything.
    """
    profiles = document.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        raise SystemExit("registry profiles are malformed")
    matches = [
        row for row in profiles if isinstance(row, dict) and row.get("id") == profile_id
    ]
    if not matches:
        known = ", ".join(
            sorted(str(row.get("id")) for row in profiles if isinstance(row, dict))
        )
        raise SystemExit(
            f"profile {profile_id!r} is not in the registry (profiles: {known})"
        )
    if len(matches) > 1:
        raise SystemExit(f"profile {profile_id!r} appears more than once in the registry")
    profile = matches[0]
    if profile.get("kind") != "cpu_tdx":
        raise SystemExit(f"profile {profile_id!r} is not a CPU-TDX profile")
    if profile.get("status") != "active":
        raise SystemExit(f"profile {profile_id!r} is not active")
    return profile


def _assert_only_profile_changed(before: dict, after: dict, profile_id: str) -> None:
    """Refuse to emit a release that touched any profile but *profile_id*.

    The mutation itself already targets one named profile; this is the
    independent check that the emitted document agrees, so a future edit to
    the mutation path cannot silently widen its blast radius.
    """

    def by_id(document: dict) -> dict[str, str]:
        rows = document.get("profiles")
        if not isinstance(rows, list):
            raise SystemExit("registry profiles are malformed")
        indexed: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                raise SystemExit("registry profiles are malformed")
            if row["id"] in indexed:
                raise SystemExit(f"profile {row['id']!r} appears more than once")
            indexed[row["id"]] = json.dumps(row, sort_keys=True)
        return indexed

    original = by_id(before)
    emitted = by_id(after)
    if set(original) != set(emitted):
        raise SystemExit("approval must not add or remove a profile")
    changed = {key for key in original if original[key] != emitted[key]}
    if changed != {profile_id}:
        unexpected = sorted(changed - {profile_id})
        raise SystemExit(
            "approval changed profiles it was not asked to change: "
            + (", ".join(unexpected) if unexpected else f"{profile_id!r} was not modified")
        )


def _bump_release(
    registry: dict, measurement: str, operator: str, reason: str, *, profile_id: str
) -> dict:
    doc = {k: v for k, v in registry.items() if k not in ("signature", "signature_base64")}
    # Detach from the caller's parsed registry: the dict comprehension is
    # shallow, so without this the nested profile edit below would also
    # rewrite the document the caller still holds as the "before" state.
    doc = json.loads(json.dumps(doc, sort_keys=True))
    doc["release"] = int(doc["release"]) + 1
    profile = _select_active_profile(doc, profile_id)
    if measurement in profile["measurements"]:
        raise SystemExit(
            f"measurement already present in profile {profile_id!r}; nothing to approve"
        )
    profile["measurements"] = sorted(set(profile["measurements"]) | {measurement})
    # Publication time is now (a fresh release restores the 24-hour freshness
    # clock); validity windows and every transition time stay exactly as the
    # accepted release left them, so the state store's unchanged-transition
    # and window-equivocation guards pass.
    doc["generated_at"] = _now_iso()
    meta = dict(doc.get("metadata", {}))
    approvals = list(meta.get("measurement_approvals", []))
    approvals.append({
        "measurement": measurement,
        "profile_id": profile_id,
        "operator": operator,
        "reason": reason,
        "approved_at": _now_iso(),
        "release": doc["release"],
    })
    meta["measurement_approvals"] = approvals
    doc["metadata"] = meta
    return doc


def cmd_show(args: argparse.Namespace) -> int:
    registry = parse_registry_json(
        _secure_read_bytes(args.registry, label="policy registry")
    )
    profiles = registry.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        raise SystemExit("registry profiles are malformed")
    print(f"release {registry['release']}")
    print(f"valid {registry['valid_from']} .. {registry['valid_until']}")
    for profile in profiles:
        if not isinstance(profile, dict):
            raise SystemExit("registry profiles are malformed")
        print(
            f"profile {profile.get('id')}  kind {profile.get('kind')}  "
            f"status {profile.get('status')}"
        )
        measurements = profile.get("measurements")
        for measurement in measurements if isinstance(measurements, list) else []:
            print(f"  measurement {measurement}")
    for approval in registry.get("metadata", {}).get("measurement_approvals", []):
        target = approval.get("profile_id", "(unrecorded profile)")
        print(f"  approval r{approval['release']} {approval['approved_at']} "
              f"profile {target} by {approval['operator']}: {approval['reason']}")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    registry = parse_registry_json(
        _secure_read_bytes(args.registry, label="policy registry")
    )
    profile_id = _identifier(args.profile_id, "profile id")
    # Prove the named profile exists and is an active CPU-TDX profile before
    # the capture spends a live probe against the worker.
    _select_active_profile(registry, profile_id)
    candidate = _capture(args.endpoint, args.cacert, args.hotkey, args.verifier)
    measurement = candidate["measurement"]
    print(
        f"captured candidate {measurement} (tcb {candidate['tcb_status']}, "
        f"chip {str(candidate['chip_id'])[:16]}...)",
        file=sys.stderr,
    )

    operator = _bounded_field(args.operator, "operator")
    reason = _bounded_field(args.reason, "reason")
    doc = _bump_release(registry, measurement, operator, reason, profile_id=profile_id)
    _assert_only_profile_changed(registry, doc, profile_id)
    seed = _load_signing_seed(args.signing_key_file)
    signed = sign_registry(doc, seed)
    encoded = json.dumps(signed, separators=(",", ":"), sort_keys=True).encode()

    # Verify the freshly signed registry before writing anything.
    verify_registry(encoded, {signed["signing_key_id"]: base64.b64decode(_public_key_b64(seed))})

    _secure_write_new(Path(args.out), encoded)
    digest = "sha256:" + hashlib.sha256(encoded).hexdigest()

    record = {
        "at": _now_iso(),
        "action": "measurement_approved",
        "measurement": measurement,
        "profile_id": profile_id,
        "tcb_status": candidate["tcb_status"],
        "chip_id": candidate["chip_id"],
        "endpoint": args.endpoint,
        "hotkey": args.hotkey,
        "verifier": args.verifier,
        "operator": operator,
        "reason": reason,
        "new_release": signed["release"],
        "registry_digest": digest,
    }
    try:
        _secure_append_line(Path(args.approval_log), json.dumps(record, sort_keys=True))
    except BaseException:
        try:
            Path(args.out).unlink()
        except FileNotFoundError:
            pass
        else:
            _fsync_parent(Path(args.out))
        raise

    print(f"release {signed['release']} written to {args.out}")
    print(f"registry_digest {digest}")
    print(f"approval logged to {args.approval_log}")
    return 0


def _reissue_stripped(document: dict) -> dict:
    """The material that a same-policy reissue must preserve byte-for-byte.

    Everything except: release, generated_at, signature, and the bounded
    ``metadata.reissues`` audit list.
    """
    stripped = {
        k: v
        for k, v in document.items()
        if k not in ("release", "generated_at", "signature", "signature_base64")
    }
    metadata = {k: v for k, v in dict(stripped.get("metadata", {})).items()
                if k != "reissues"}
    stripped["metadata"] = metadata
    return json.loads(json.dumps(stripped, sort_keys=True))


def _load_signing_seed(path: str) -> bytes:
    """Load the 32-byte Ed25519 seed with strict file hygiene.

    Rejects symlinks and non-regular files, group/world-accessible modes,
    foreign ownership, oversized content, and non-canonical base64. The seed
    is returned to the caller and never printed or logged.
    """
    target = Path(path)
    before = target.lstat()
    import stat as stat_mod

    if not stat_mod.S_ISREG(before.st_mode) or target.is_symlink():
        raise SystemExit("signing key must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags)
    try:
        after = os.fstat(descriptor)
        if (
            not stat_mod.S_ISREG(after.st_mode)
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise SystemExit("signing key file changed underneath the tool")
        if after.st_mode & 0o077:
            raise SystemExit("signing key must not be group/world accessible")
        if hasattr(os, "geteuid") and after.st_uid != os.geteuid():
            raise SystemExit("signing key must be owned by the invoking user")
        raw = os.read(descriptor, 129)
    finally:
        os.close(descriptor)
    if len(raw) > 128:
        raise SystemExit("signing key file is too large for a 32-byte seed")
    text = raw.decode("ascii", errors="strict").strip() if raw else ""
    try:
        seed = base64.b64decode(text, validate=True)
    except Exception:
        raise SystemExit("signing key must be canonical base64") from None
    if len(seed) != 32 or base64.b64encode(seed).decode("ascii") != text:
        raise SystemExit("signing key must be a canonical 32-byte base64 seed")
    return seed


def _bounded_field(value: str, label: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise SystemExit(f"{label} must be 1..{maximum} characters")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise SystemExit(f"{label} must not contain control characters")
    return value


def _fsync_parent(path: Path) -> None:
    parent = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _secure_write_new(path: Path, data: bytes) -> None:
    """Create-only, non-symlink, mode-0600, durably fsynced write.

    Refuses to overwrite anything (a symlink at the path also fails EEXIST).
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_parent(path)


def _secure_append_line(path: Path, line: str) -> None:
    """Append one audit line with strict hygiene on any existing log:
    regular non-symlink file, mode 0600, owned by the invoking user."""
    import stat as stat_mod

    exists = os.path.lexists(path)
    if exists:
        before = path.lstat()
        if not stat_mod.S_ISREG(before.st_mode) or path.is_symlink():
            raise SystemExit("approval log must be a regular non-symlink file")
    flags = (
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        after = os.fstat(descriptor)
        if not stat_mod.S_ISREG(after.st_mode):
            raise SystemExit("approval log must be a regular file")
        if after.st_mode & 0o077:
            raise SystemExit("approval log must not be group/world accessible")
        if hasattr(os, "geteuid") and after.st_uid != os.geteuid():
            raise SystemExit("approval log must be owned by the invoking user")
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor != -1:
            os.close(descriptor)
    _fsync_parent(path)


MAX_REISSUE_AUDIT_ENTRIES = 32


def cmd_renew(args: argparse.Namespace) -> int:
    """Reissue the current policy unchanged with a fresh publication time.

    The 24-hour freshness ceiling is a fail-closed security contract and is
    never widened. Instead, a higher signed release may republish the SAME
    policy: identical validity window, profiles, measurements, receipt keys,
    and every transition time — only the release number, the publication
    timestamp (generated_at), the signature, and one bounded audit record
    change. Verification accepts a publication after activation
    (valid_from) but never after expiry (valid_until), and still rejects
    future publication, staleness beyond 24 h, replay, rollback,
    equivocation, and tampering.

    Before writing anything this command proves, against a TEMPORARY
    anti-rollback state store — a copy of the production state when --state
    is given, else one seeded with the current registry — that the reissue
    would be accepted as a monotonic successor with a non-decreasing
    publication time. The live state file is never touched.
    """
    from cathedral.policy_registry import PolicyRegistryState

    operator = _bounded_field(args.operator, "operator")
    reason = _bounded_field(args.reason, "reason")
    current_bytes = _secure_read_bytes(args.registry, label="policy registry")
    registry = parse_registry_json(current_bytes)
    seed = _load_signing_seed(args.signing_key_file)
    trusted = {registry["signing_key_id"]: base64.b64decode(_public_key_b64(seed))}
    now = datetime.now(UTC)
    # The current registry may already be past the freshness ceiling — that
    # is exactly when a reissue is needed — so verify it historically at
    # now (signature, window containment, structure, and the wall-clock
    # future gate) without the staleness gate. A registry outside its
    # validity window cannot be reissued.
    current_snapshot = verify_registry(current_bytes, trusted, historical_at=now)

    doc = {k: v for k, v in registry.items() if k not in ("signature", "signature_base64")}
    doc["release"] = int(doc["release"]) + 1
    doc["generated_at"] = _now_iso()
    meta = dict(doc.get("metadata", {}))
    reissues = list(meta.get("reissues", []))
    reissues.append(
        {
            "reissued_at": doc["generated_at"],
            "operator": operator,
            "reason": reason,
        }
    )
    meta["reissues"] = reissues[-MAX_REISSUE_AUDIT_ENTRIES:]
    doc["metadata"] = meta

    # Deep-compare: everything except release/generated_at/signature/audit
    # record must be byte-identical to the current registry.
    if _reissue_stripped(doc) != _reissue_stripped(registry):
        raise SystemExit(
            "reissue aborted: policy material would change; a reissue must "
            "preserve every field except release, generated_at, signature, "
            "and the bounded audit record"
        )

    signed = sign_registry(doc, seed)
    encoded = json.dumps(signed, separators=(",", ":"), sort_keys=True).encode()
    # Full verification of the successor, including the 24-hour freshness
    # and future-publication gates.
    successor_snapshot = verify_registry(encoded, trusted, now=now)

    # Prove the anti-rollback state store accepts current -> successor
    # (release monotonic, transitions preserved, publication time
    # non-decreasing) before anything is written. With --state the proof
    # runs against a temporary COPY of the production state.
    import sqlite3

    with tempfile.TemporaryDirectory() as scratch:
        proof_path = Path(scratch) / "reissue-proof.sqlite"
        if getattr(args, "state", None):
            source = sqlite3.connect(f"file:{args.state}?mode=ro", uri=True)
            try:
                destination = sqlite3.connect(proof_path)
                try:
                    source.backup(destination)
                finally:
                    destination.close()
            finally:
                source.close()
        state = PolicyRegistryState(
            proof_path, minimum_release=int(registry["release"])
        )
        state.accept(current_snapshot)
        state.accept(successor_snapshot)

    _secure_write_new(Path(args.out), encoded)
    digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    record = {
        "at": _now_iso(),
        "action": "registry_reissue_prepared",
        "operator": operator,
        "reason": reason,
        "previous_release": int(registry["release"]),
        "new_release": signed["release"],
        "registry_digest": digest,
        "generated_at": signed["generated_at"],
        "valid_from": signed["valid_from"],
        "valid_until": signed["valid_until"],
    }
    try:
        _secure_append_line(Path(args.approval_log), json.dumps(record, sort_keys=True))
    except BaseException:
        # Never leave an unlogged artifact: the output we just created is
        # removed (durably) before the failure propagates.
        try:
            Path(args.out).unlink()
        except FileNotFoundError:
            pass
        else:
            _fsync_parent(Path(args.out))
        raise

    print(f"reissued release {signed['release']} written to {args.out}")
    print(f"registry_digest {digest}")
    print("policy material, windows, keys, and transitions are unchanged; "
          "the state store accepts this as a monotonic successor (no "
          "re-anchor). Install deliberately after review.")
    return 0


def _parse_rollover_until(value: str, now: datetime) -> tuple[datetime, str]:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (TypeError, ValueError) as exc:
        raise SystemExit("--valid-until must be an exact UTC timestamp") from exc
    minimum = now + timedelta(days=MIN_ROLLOVER_DAYS)
    maximum = now + timedelta(days=MAX_ROLLOVER_DAYS)
    if not minimum <= parsed <= maximum:
        raise SystemExit(
            f"--valid-until must be between {MIN_ROLLOVER_DAYS} and "
            f"{MAX_ROLLOVER_DAYS} days from now"
        )
    return parsed, parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise SystemExit(
            f"{label} must be a 1..128 character identifier containing only "
            "letters, digits, dot, underscore, colon, or hyphen"
        )
    return value


def _prove_registry_successor(
    *,
    current_snapshot: object,
    successor_snapshot: object,
    current_release: int,
    state_path: str | None,
) -> None:
    """Prove current -> successor against a temporary anti-rollback state."""
    import sqlite3

    from cathedral.policy_registry import PolicyRegistryState

    with tempfile.TemporaryDirectory(prefix="cathedral-policy-proof-") as scratch:
        proof_path = Path(scratch) / "policy-proof.sqlite"
        if state_path:
            try:
                source = sqlite3.connect(f"file:{state_path}?mode=ro", uri=True)
            except sqlite3.Error as exc:
                raise SystemExit("unable to open the policy state read-only") from exc
            try:
                destination = sqlite3.connect(proof_path)
                try:
                    source.backup(destination)
                finally:
                    destination.close()
            finally:
                source.close()
        state = PolicyRegistryState(proof_path, minimum_release=current_release)
        state.accept(current_snapshot)
        state.accept(successor_snapshot)


def _remove_created(paths: list[Path]) -> None:
    for path in reversed(paths):
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        else:
            _fsync_parent(path)


def cmd_rollover(args: argparse.Namespace) -> int:
    """Prepare a bounded profile and receipt-key window rollover.

    A same-policy reissue refreshes publication time but deliberately cannot
    extend immutable profile or receipt-key windows. This command prepares
    the next explicit policy release by cloning one existing CPU-TDX profile
    under a new id, preserving all of its security controls and measurements,
    and adding a freshly generated Ed25519 receipt key under a new id. Existing
    profiles and keys are retained byte-for-byte for historical verification.

    The command does not install any artifact. It emits a mode-0600 signed
    registry and a separate mode-0600 receipt-key seed, proves the successor
    against a temporary copy of the anti-rollback state, and appends a
    non-secret audit record. The private seed is never printed or logged.
    """
    operator = _bounded_field(args.operator, "operator")
    reason = _bounded_field(args.reason, "reason")
    source_profile_id = _identifier(args.source_profile_id, "source profile id")
    new_profile_id = _identifier(args.new_profile_id, "new profile id")
    new_receipt_key_id = _identifier(args.new_receipt_key_id, "new receipt key id")
    registry_out = Path(args.out)
    receipt_key_out = Path(args.receipt_signing_key_out)
    if registry_out == receipt_key_out:
        raise SystemExit("registry and receipt key outputs must be different paths")

    current_bytes = _secure_read_bytes(args.registry, label="policy registry")
    registry = parse_registry_json(current_bytes)
    policy_seed = _load_signing_seed(args.signing_key_file)
    trusted = {
        registry["signing_key_id"]: base64.b64decode(_public_key_b64(policy_seed))
    }
    now = datetime.now(UTC).replace(microsecond=0)
    now_text = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    valid_until, valid_until_text = _parse_rollover_until(args.valid_until, now)
    current_snapshot = verify_registry(
        current_bytes,
        trusted,
        historical_at=now,
        now=now,
    )

    profiles = registry.get("profiles")
    keys = registry.get("receipt_signing_keys")
    if not isinstance(profiles, list) or not isinstance(keys, list):
        raise SystemExit("registry profiles or receipt signing keys are malformed")
    if any(row.get("id") == new_profile_id for row in profiles if isinstance(row, dict)):
        raise SystemExit("new profile id already exists")
    if any(row.get("id") == new_receipt_key_id for row in keys if isinstance(row, dict)):
        raise SystemExit("new receipt key id already exists")
    source_profile = next(
        (
            row
            for row in profiles
            if isinstance(row, dict) and row.get("id") == source_profile_id
        ),
        None,
    )
    if source_profile is None or source_profile.get("kind") != "cpu_tdx":
        raise SystemExit("source profile is not an existing CPU-TDX profile")
    if source_profile.get("status") != "active":
        raise SystemExit("source profile is not active")
    current_policy = current_snapshot.to_policy(at=now)
    if source_profile_id not in current_policy.registry_profile_ids:
        raise SystemExit("source profile is not currently eligible")

    doc = {
        key: value
        for key, value in registry.items()
        if key not in ("signature", "signature_base64")
    }
    doc = json.loads(json.dumps(doc, sort_keys=True))
    doc["release"] = int(registry["release"]) + 1
    doc["generated_at"] = now_text
    doc["valid_until"] = valid_until_text

    new_profile = json.loads(json.dumps(source_profile, sort_keys=True))
    new_profile["id"] = new_profile_id
    new_profile["status"] = "active"
    new_profile["status_changed_at"] = now_text
    new_profile["valid_from"] = now_text
    new_profile["valid_until"] = valid_until_text
    new_profile["retire_at"] = None
    profile_metadata = dict(new_profile.get("metadata", {}))
    profile_metadata["rollover_from"] = source_profile_id
    profile_metadata["rollover_release"] = doc["release"]
    new_profile["metadata"] = profile_metadata
    doc["profiles"].append(new_profile)

    receipt_seed = secrets.token_bytes(32)
    new_key = {
        "id": new_receipt_key_id,
        "algorithm": "ed25519",
        "public_key_base64": _public_key_b64(receipt_seed),
        "purpose": "assurance_receipt",
        "status": "active",
        "status_changed_at": now_text,
        "valid_from": now_text,
        "valid_until": valid_until_text,
        "revoked_at": None,
        "replacement_key_id": None,
        "metadata": {
            "rollover_from_profile": source_profile_id,
            "rollover_release": doc["release"],
        },
    }
    doc["receipt_signing_keys"].append(new_key)

    metadata = dict(doc.get("metadata", {}))
    rollovers = list(metadata.get("policy_rollovers", []))
    rollovers.append(
        {
            "at": now_text,
            "operator": operator,
            "reason": reason,
            "previous_release": int(registry["release"]),
            "new_profile_id": new_profile_id,
            "new_receipt_key_id": new_receipt_key_id,
            "valid_until": valid_until_text,
        }
    )
    metadata["policy_rollovers"] = rollovers[-MAX_ROLLOVER_AUDIT_ENTRIES:]
    doc["metadata"] = metadata

    signed = sign_registry(doc, policy_seed)
    encoded = json.dumps(signed, separators=(",", ":"), sort_keys=True).encode()
    successor_snapshot = verify_registry(encoded, trusted, now=now)
    successor_snapshot.to_policy(at=now, max_age_seconds=86400)
    future_policy = successor_snapshot.to_policy(
        at=valid_until - timedelta(seconds=1)
    )
    if new_profile_id not in future_policy.registry_profile_ids:
        raise SystemExit("new profile does not cover the requested window")
    _prove_registry_successor(
        current_snapshot=current_snapshot,
        successor_snapshot=successor_snapshot,
        current_release=int(registry["release"]),
        state_path=args.state,
    )

    registry_digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    receipt_public_digest = (
        "sha256:"
        + hashlib.sha256(base64.b64decode(new_key["public_key_base64"])).hexdigest()
    )
    record = {
        "at": now_text,
        "action": "policy_window_rolled_over",
        "operator": operator,
        "reason": reason,
        "previous_release": int(registry["release"]),
        "new_release": signed["release"],
        "registry_digest": registry_digest,
        "source_profile_id": source_profile_id,
        "new_profile_id": new_profile_id,
        "new_receipt_key_id": new_receipt_key_id,
        "receipt_public_key_digest": receipt_public_digest,
        "valid_from": now_text,
        "valid_until": valid_until_text,
    }

    created: list[Path] = []
    try:
        _secure_write_new(
            receipt_key_out,
            base64.b64encode(receipt_seed) + b"\n",
        )
        created.append(receipt_key_out)
        _secure_write_new(registry_out, encoded)
        created.append(registry_out)
        _secure_append_line(
            Path(args.approval_log),
            json.dumps(record, sort_keys=True),
        )
    except BaseException:
        _remove_created(created)
        raise

    print(f"rollover release {signed['release']} written to {registry_out}")
    print(f"registry_digest {registry_digest}")
    print(
        f"new profile {new_profile_id}; new receipt key {new_receipt_key_id} "
        f"(private seed written securely to {receipt_key_out}, never printed)"
    )
    print(
        "Existing profiles and receipt keys are preserved. Review and install "
        "the registry, receipt key, and issuer key-id change as one bounded "
        "operator transaction."
    )
    return 0


def _secure_directory(path: Path, label: str) -> None:
    before = path.lstat()
    if not stat.S_ISDIR(before.st_mode) or path.is_symlink():
        raise SystemExit(f"{label} must be a non-symlink directory")
    if before.st_mode & 0o022:
        raise SystemExit(f"{label} must not be group/world writable")
    if hasattr(os, "geteuid") and before.st_uid != os.geteuid():
        raise SystemExit(f"{label} must be owned by the invoking user")


def _open_lock(path: Path) -> int:
    """Open and exclusively lock a root/operator-owned local lock file."""
    _secure_directory(path.parent, "lock directory")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit("republisher lock must be a regular file")
        if info.st_mode & 0o077:
            raise SystemExit("republisher lock must not be group/world accessible")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise SystemExit("republisher lock must be owned by the invoking user")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            return -1
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _install_registry_successor(
    *,
    registry_path: Path,
    staging_path: Path,
    current_bytes: bytes,
    candidate_bytes: bytes,
    history_dir: Path,
    approval_log: Path,
    method: str,
    operator: str,
    reason: str,
) -> None:
    """Durably install one verified successor while the shared lock is held.

    The audit log is a two-record write-ahead journal. A crash before the
    atomic replace leaves only ``install_prepared`` and the unchanged live
    registry. A crash after replace leaves the new signed registry as the
    source of truth and may omit ``install_committed``; operators reconcile
    that exact digest and must never roll the release back.
    """
    current = parse_registry_json(current_bytes)
    candidate = parse_registry_json(candidate_bytes)
    current_digest = "sha256:" + hashlib.sha256(current_bytes).hexdigest()
    candidate_digest = "sha256:" + hashlib.sha256(candidate_bytes).hexdigest()
    archive = history_dir / (
        f"release-{int(current['release']):020d}-{current_digest.removeprefix('sha256:')}.json"
    )
    archive_exists = os.path.lexists(archive)
    if archive_exists:
        archived_bytes = _secure_read_bytes(
            archive, label="existing policy history artifact"
        )
        if archived_bytes != current_bytes:
            raise SystemExit("policy history path exists with different content")

    # The global policy-writer lock is the supported-writer CAS contract.
    # This exact-byte check catches an unsupported out-of-band write before
    # any filesystem mutation. Every supported live-registry writer uses the
    # same lock file.
    if (
        _secure_read_bytes(registry_path, label="installed policy registry")
        != current_bytes
    ):
        raise SystemExit("installed registry changed during locked installation")

    prepared_at = _now_iso()
    prepared_record = {
        "action": "policy_registry_install_prepared",
        "at": prepared_at,
        "method": method,
        "operator": operator,
        "reason": reason,
        "previous_release": int(current["release"]),
        "previous_registry_digest": current_digest,
        "new_release": int(candidate["release"]),
        "registry_digest": candidate_digest,
    }
    _secure_append_line(approval_log, json.dumps(prepared_record, sort_keys=True))

    if not archive_exists:
        _secure_write_new(archive, current_bytes)
        os.chmod(archive, 0o644, follow_symlinks=False)
        _fsync_parent(archive)

    os.chmod(staging_path, 0o644, follow_symlinks=False)
    os.replace(staging_path, registry_path)
    _fsync_parent(registry_path)
    installed = _secure_read_bytes(
        registry_path, label="installed policy registry"
    )
    if installed != candidate_bytes:
        raise SystemExit(
            "installed registry does not match the verified candidate; "
            "do not roll back, inspect the live signed release"
        )

    committed_record = {
        **prepared_record,
        "action": "policy_registry_install_committed",
        "at": _now_iso(),
        "prepared_at": prepared_at,
    }
    try:
        _secure_append_line(
            approval_log, json.dumps(committed_record, sort_keys=True)
        )
    except BaseException as exc:
        raise SystemExit(
            f"policy release {candidate['release']} is installed, but the "
            "commit audit append failed; do not roll back, reconcile the "
            f"live digest {candidate_digest}"
        ) from exc


def cmd_republish_install(args: argparse.Namespace) -> int:
    """Atomically install one same-policy freshness reissue.

    This is the narrow command intended for a systemd timer. It takes an
    exclusive local lock, creates and verifies a monotonically higher signed
    release through ``cmd_renew``, archives the exact outgoing registry, and
    atomically replaces the live public registry. It never modifies the
    anti-rollback state directly; the runtime accepts the successor on its
    next ordinary epoch.
    """
    registry_path = Path(args.registry)
    history_dir = Path(args.history_dir)
    lock_descriptor = _open_lock(Path(args.lock_file))
    if lock_descriptor == -1:
        raise SystemExit("another policy writer holds the shared lock")

    candidate: Path | None = None
    try:
        _secure_directory(registry_path.parent, "registry directory")
        _secure_directory(history_dir, "policy history directory")
        current_bytes = _secure_read_bytes(
            registry_path, label="installed policy registry"
        )
        current = parse_registry_json(current_bytes)
        policy_seed = _load_signing_seed(args.signing_key_file)
        verify_registry(
            current_bytes,
            {
                current["signing_key_id"]: base64.b64decode(
                    _public_key_b64(policy_seed)
                )
            },
            historical_at=datetime.now(UTC),
        )
        candidate = registry_path.parent / (
            f".{registry_path.name}.candidate-{os.getpid()}-{secrets.token_hex(8)}"
        )
        renew_args = argparse.Namespace(
            registry=str(registry_path),
            signing_key_file=args.signing_key_file,
            state=args.state,
            operator=args.operator,
            reason=args.reason,
            approval_log=args.approval_log,
            out=str(candidate),
        )
        cmd_renew(renew_args)
        candidate_bytes = _secure_read_bytes(
            candidate, label="candidate policy registry"
        )
        successor = parse_registry_json(candidate_bytes)
        if int(successor["release"]) != int(current["release"]) + 1:
            raise SystemExit("candidate release is not the exact next release")
        verify_registry(
            candidate_bytes,
            {
                successor["signing_key_id"]: base64.b64decode(
                    _public_key_b64(policy_seed)
                )
            },
            now=datetime.now(UTC),
        )
        _install_registry_successor(
            registry_path=registry_path,
            staging_path=candidate,
            current_bytes=current_bytes,
            candidate_bytes=candidate_bytes,
            history_dir=history_dir,
            approval_log=Path(args.approval_log),
            method="scheduled_republication",
            operator=_bounded_field(args.operator, "operator"),
            reason=_bounded_field(args.reason, "reason"),
        )
        candidate = None
        print(
            f"installed policy release {successor['release']} atomically; "
            f"archived release {current['release']}"
        )
        return 0
    finally:
        if candidate is not None:
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass
            else:
                _fsync_parent(candidate)
        os.close(lock_descriptor)


def cmd_install_candidate(args: argparse.Namespace) -> int:
    """Install one operator-reviewed signed registry through the shared lock."""
    operator = _bounded_field(args.operator, "operator")
    reason = _bounded_field(args.reason, "reason")
    expected_current = _require_digest_arg(
        args.expected_current_digest, "expected current registry digest"
    )
    expected_candidate = _require_digest_arg(
        args.expected_candidate_digest, "expected candidate registry digest"
    )
    registry_path = Path(args.registry)
    history_dir = Path(args.history_dir)
    lock_descriptor = _open_lock(Path(args.lock_file))
    if lock_descriptor == -1:
        raise SystemExit("another policy writer holds the shared lock")

    staging: Path | None = None
    try:
        _secure_directory(registry_path.parent, "registry directory")
        _secure_directory(history_dir, "policy history directory")
        current_bytes = _secure_read_bytes(
            registry_path, label="installed policy registry"
        )
        candidate_bytes = _secure_read_bytes(
            args.candidate, label="candidate policy registry"
        )
        if "sha256:" + hashlib.sha256(current_bytes).hexdigest() != expected_current:
            raise SystemExit("installed registry does not match the reviewed digest")
        if (
            "sha256:" + hashlib.sha256(candidate_bytes).hexdigest()
            != expected_candidate
        ):
            raise SystemExit("candidate registry does not match the reviewed digest")

        current = parse_registry_json(current_bytes)
        candidate = parse_registry_json(candidate_bytes)
        if int(candidate["release"]) != int(current["release"]) + 1:
            raise SystemExit("candidate release is not the exact next release")
        seed = _load_signing_seed(args.signing_key_file)
        trusted = {
            current["signing_key_id"]: base64.b64decode(_public_key_b64(seed))
        }
        now = datetime.now(UTC)
        current_snapshot = verify_registry(
            current_bytes, trusted, historical_at=now, now=now
        )
        successor_snapshot = verify_registry(candidate_bytes, trusted, now=now)
        _prove_registry_successor(
            current_snapshot=current_snapshot,
            successor_snapshot=successor_snapshot,
            current_release=int(current["release"]),
            state_path=args.state,
        )

        staging = registry_path.parent / (
            f".{registry_path.name}.operator-{os.getpid()}-{secrets.token_hex(8)}"
        )
        _secure_write_new(staging, candidate_bytes)
        _install_registry_successor(
            registry_path=registry_path,
            staging_path=staging,
            current_bytes=current_bytes,
            candidate_bytes=candidate_bytes,
            history_dir=history_dir,
            approval_log=Path(args.approval_log),
            method="operator_reviewed_candidate",
            operator=operator,
            reason=reason,
        )
        staging = None
        print(
            f"installed reviewed policy release {candidate['release']} "
            f"with digest {expected_candidate}"
        )
        return 0
    finally:
        if staging is not None:
            try:
                staging.unlink()
            except FileNotFoundError:
                pass
            else:
                _fsync_parent(staging)
        os.close(lock_descriptor)


def _require_digest_arg(value: str, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise SystemExit(f"{label} must be a canonical sha256 digest")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    show = sub.add_parser("show", help="show registry measurements and approvals")
    show.add_argument("--registry", required=True)
    show.set_defaults(func=cmd_show)

    approve = sub.add_parser("approve", help="capture, record, and sign a new measurement release")
    approve.add_argument("--registry", required=True)
    approve.add_argument(
        "--profile-id",
        required=True,
        help=(
            "id of the active CPU-TDX profile the measurement is added to. "
            "Required and verified: a registry carries every prior profile "
            "after a rollover, so the target is never inferred from position"
        ),
    )
    approve.add_argument("--signing-key-file", required=True)
    approve.add_argument("--endpoint", required=True)
    approve.add_argument("--cacert", required=True)
    approve.add_argument("--hotkey", required=True)
    approve.add_argument("--verifier", required=True)
    approve.add_argument("--operator", required=True)
    approve.add_argument("--reason", required=True)
    approve.add_argument("--approval-log", required=True)
    approve.add_argument("--out", required=True)
    approve.set_defaults(func=cmd_approve)

    renew = sub.add_parser(
        "renew",
        help="reissue the current policy unchanged with a fresh publication "
             "timestamp at the next release (restores the 24-hour freshness "
             "clock; changes nothing else)",
    )
    renew.add_argument("--registry", required=True)
    renew.add_argument("--signing-key-file", required=True)
    renew.add_argument("--operator", required=True)
    renew.add_argument("--reason", required=True)
    renew.add_argument("--approval-log", required=True)
    renew.add_argument("--out", required=True)
    renew.add_argument(
        "--state",
        help="production anti-rollback state DB; the acceptance proof runs "
             "against a temporary COPY of it (the live file is never touched)",
    )
    renew.set_defaults(func=cmd_renew)

    rollover = sub.add_parser(
        "rollover",
        help="prepare a bounded new CPU-TDX profile and receipt-key window",
    )
    rollover.add_argument("--registry", required=True)
    rollover.add_argument("--signing-key-file", required=True)
    rollover.add_argument("--state")
    rollover.add_argument("--source-profile-id", required=True)
    rollover.add_argument("--new-profile-id", required=True)
    rollover.add_argument("--new-receipt-key-id", required=True)
    rollover.add_argument("--valid-until", required=True)
    rollover.add_argument("--operator", required=True)
    rollover.add_argument("--reason", required=True)
    rollover.add_argument("--approval-log", required=True)
    rollover.add_argument("--out", required=True)
    rollover.add_argument("--receipt-signing-key-out", required=True)
    rollover.set_defaults(func=cmd_rollover)

    republish = sub.add_parser(
        "republish-install",
        help="atomically install a locked same-policy freshness reissue",
    )
    republish.add_argument("--registry", required=True)
    republish.add_argument("--signing-key-file", required=True)
    republish.add_argument("--state", required=True)
    republish.add_argument("--operator", required=True)
    republish.add_argument("--reason", required=True)
    republish.add_argument("--approval-log", required=True)
    republish.add_argument("--history-dir", required=True)
    republish.add_argument("--lock-file", required=True)
    republish.set_defaults(func=cmd_republish_install)

    install = sub.add_parser(
        "install-candidate",
        help="install a reviewed signed registry through the shared policy-writer lock",
    )
    install.add_argument("--registry", required=True)
    install.add_argument("--candidate", required=True)
    install.add_argument("--signing-key-file", required=True)
    install.add_argument("--state", required=True)
    install.add_argument("--expected-current-digest", required=True)
    install.add_argument("--expected-candidate-digest", required=True)
    install.add_argument("--operator", required=True)
    install.add_argument("--reason", required=True)
    install.add_argument("--approval-log", required=True)
    install.add_argument("--history-dir", required=True)
    install.add_argument("--lock-file", required=True)
    install.set_defaults(func=cmd_install_candidate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
