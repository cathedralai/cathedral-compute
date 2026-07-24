#!/usr/bin/env python3
"""Auditable measurement-approval flow for the SN39 CPU policy registry.

A TDX MRTD (launch measurement) can change when a confidential VM is fully
stopped and restarted onto a host with different guest firmware (TDVF). The
runtime already fails closed on any measurement not in the signed policy
registry. This tool is the only sanctioned way to add a new measurement: it
never trusts a measurement blindly. It

  1. captures the candidate measurement live from a named worker, through the
     pinned production verifier, proving intel_verified + report_data_match +
     an acceptable TCB status before the measurement is even eligible;
  2. records full provenance (endpoint, chip/platform id, TCB status, verifier,
     operator, UTC time, justification) into an append-only approval log;
  3. emits the next monotonic signed registry release adding exactly that one
     measurement, preserving every prior profile/key transition time so the
     registry's own anti-equivocation and unchanged-transition guards accept
     it.

It does not deploy. The operator reviews the emitted registry and approval
record and installs it deliberately. Unknown measurements continue to fail
closed until this flow is run for them.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import ssl
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.common import evidence_report_data
from cathedral.policy_registry import parse_registry_json, sign_registry, verify_registry
from cathedral.remote import RemoteMiner

MEASUREMENT_PREFIX = "tdx-measurement-sha256:"
ACCEPTABLE_TCB = {"UpToDate"}


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _public_key_b64(seed: bytes) -> str:
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(public).decode()


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


def _bump_release(registry: dict, measurement: str, operator: str, reason: str) -> dict:
    doc = {k: v for k, v in registry.items() if k not in ("signature", "signature_base64")}
    doc["release"] = int(doc["release"]) + 1
    profile = doc["profiles"][0]
    if measurement in profile["measurements"]:
        raise SystemExit("measurement already present in the registry; nothing to approve")
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
        "operator": operator,
        "reason": reason,
        "approved_at": _now_iso(),
        "release": doc["release"],
    })
    meta["measurement_approvals"] = approvals
    doc["metadata"] = meta
    return doc


def cmd_show(args: argparse.Namespace) -> int:
    registry = parse_registry_json(Path(args.registry).read_bytes())
    profile = registry["profiles"][0]
    print(f"release {registry['release']}  profile {profile['id']}")
    print(f"valid {registry['valid_from']} .. {registry['valid_until']}")
    for measurement in profile["measurements"]:
        print(f"  measurement {measurement}")
    for approval in registry.get("metadata", {}).get("measurement_approvals", []):
        print(f"  approval r{approval['release']} {approval['approved_at']} "
              f"by {approval['operator']}: {approval['reason']}")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    registry = parse_registry_json(Path(args.registry).read_bytes())
    candidate = _capture(args.endpoint, args.cacert, args.hotkey, args.verifier)
    measurement = candidate["measurement"]
    print(
        f"captured candidate {measurement} (tcb {candidate['tcb_status']}, "
        f"chip {str(candidate['chip_id'])[:16]}...)",
        file=sys.stderr,
    )

    operator = _bounded_field(args.operator, "operator")
    reason = _bounded_field(args.reason, "reason")
    doc = _bump_release(registry, measurement, operator, reason)
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
    current_bytes = Path(args.registry).read_bytes()
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
        "action": "registry_reissued",
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    show = sub.add_parser("show", help="show registry measurements and approvals")
    show.add_argument("--registry", required=True)
    show.set_defaults(func=cmd_show)

    approve = sub.add_parser("approve", help="capture, record, and sign a new measurement release")
    approve.add_argument("--registry", required=True)
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
