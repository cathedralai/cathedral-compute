#!/usr/bin/env python3
"""Operator tooling for the SN39 approved-coldkey enrollment allowlist.

docs/ENROLLMENT_ALLOWLIST.md defines the artifact; docs/ALLOWLIST_ROLLOUT.md
is the rollout runbook. This tool is the sanctioned way to produce and check
the two files the enrollment registry trusts, plus the extended registration
snapshot the coldkey gate needs:

  keygen    mint the Ed25519 signing seed and the trusted-key file, and print
            the key-file digest the registry must be pinned to;
  sign      emit a signed allowlist release, re-verifying it before it is
            written, and print the artifact digest to pin;
  verify    check a deployed pair against the pins and assert that a named
            coldkey is still approved (the pre-restart self-lockout check);
  snapshot  capture the live metagraph as the extended
            ``{"hotkeys": {hotkey: coldkey}}`` registration snapshot, the
            only format from which the gate can resolve ownership.

Signing keys never leave the operator host and are never printed. The tool
does not install anything: it writes files the operator reviews and moves
into place deliberately, exactly like cathedral_measurement_approval.py.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import secrets
import stat
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.coldkey_allowlist import (  # noqa: E402
    ALLOWLIST_SCHEMA,
    DEFAULT_ALLOWLIST_MAX_AGE_SECONDS,
    MAX_ALLOWLIST_COLDKEYS,
    load_allowlist_keys,
    sign_allowlist,
    verify_allowlist,
)
from cathedral.enroll import (  # noqa: E402
    MAX_SNAPSHOT_FILE_BYTES,
    MAX_SNAPSHOT_HOTKEYS,
    REGISTRATION_SNAPSHOT_SCHEMA,
)
from cathedral.policy_registry import canonical_json  # noqa: E402

# Same bounds the verifier enforces, so a rejected artifact is caught here
# rather than at the registry after an operator has already restarted it.
_SS58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,128}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
MAX_SNAPSHOT_BYTES = MAX_SNAPSHOT_FILE_BYTES


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _public_key_b64(seed: bytes) -> str:
    public = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return base64.b64encode(public).decode("ascii")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _fsync_parent(path: Path) -> None:
    parent = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _secure_write_new(path: Path, data: bytes, mode: int) -> None:
    """Create-only, non-symlink, durably fsynced write.

    Refuses to overwrite anything (a symlink at the path also fails EEXIST):
    silently replacing a signing seed or a live artifact is never a safe
    default for this tool.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        # Set the mode explicitly: the open() mode is masked by the caller's
        # umask, and the runbook states these modes as facts.
        os.fchmod(handle.fileno(), mode)
        os.fsync(handle.fileno())
    _fsync_parent(path)


def _atomic_replace(path: Path, data: bytes, mode: int) -> None:
    """Rotate a file in place with no window where readers see a partial doc.

    The registration snapshot is re-read on every enrollment request and is
    bounded by its own mtime, so it must be replaced whole and must land with
    a fresh mtime.
    """
    descriptor, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    _fsync_parent(path)


def _load_signing_seed(path: str) -> bytes:
    """Load the 32-byte Ed25519 seed with strict file hygiene.

    Rejects symlinks and non-regular files, group/world-accessible modes,
    foreign ownership, oversized content, and non-canonical base64. The seed
    is returned to the caller and never printed or logged. Same discipline as
    scripts/cathedral_measurement_approval.py: one signing-key policy across
    every artifact class.
    """
    target = Path(path)
    before = target.lstat()
    if not stat.S_ISREG(before.st_mode) or target.is_symlink():
        raise SystemExit("signing key must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags)
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
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


def _read_bounded(path: str, label: str, maximum: int) -> bytes:
    try:
        with open(path, "rb") as handle:
            data = handle.read(maximum + 1)
    except OSError as exc:
        raise SystemExit(f"unable to read {label}") from exc
    if len(data) > maximum:
        raise SystemExit(f"{label} exceeds the {maximum}-byte limit")
    return data


def _checked_ss58(value: str, label: str) -> str:
    if not isinstance(value, str) or _SS58_RE.fullmatch(value) is None:
        raise SystemExit(f"{label} is not an ss58-like address: {value!r}")
    return value


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> int:
    if _ID_RE.fullmatch(args.signing_key_id) is None:
        raise SystemExit("signing key id must match [a-z0-9][a-z0-9._-]{0,127}")
    seed = secrets.token_bytes(32)
    public = _public_key_b64(seed)
    keys_document = canonical_json({args.signing_key_id: public})

    _secure_write_new(Path(args.signing_key_out), base64.b64encode(seed) + b"\n", 0o600)
    try:
        _secure_write_new(Path(args.keys_out), keys_document, 0o644)
    except BaseException:
        # A seed with no published public key is unusable and is a live
        # secret: do not leave it behind when the pair is not complete.
        Path(args.signing_key_out).unlink(missing_ok=True)
        _fsync_parent(Path(args.signing_key_out))
        raise

    print(f"signing_key_id {args.signing_key_id}")
    print(f"public_key_base64 {public}")
    print(f"allowlist_keys_digest {_digest(keys_document)}")
    print(f"private seed written to {args.signing_key_out} (mode 0600, never printed)")
    return 0


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------


def cmd_sign(args: argparse.Namespace) -> int:
    if _ID_RE.fullmatch(args.signing_key_id) is None:
        raise SystemExit("signing key id must match [a-z0-9][a-z0-9._-]{0,127}")
    if args.release <= 0:
        raise SystemExit("release must be a positive integer")
    if args.valid_days <= 0:
        raise SystemExit("--valid-days must be a positive integer")

    coldkeys = [_checked_ss58(value, "coldkey") for value in args.coldkey]
    if len(set(coldkeys)) != len(coldkeys):
        raise SystemExit("duplicate coldkeys in the requested allowlist")
    if len(coldkeys) > MAX_ALLOWLIST_COLDKEYS:
        raise SystemExit(f"at most {MAX_ALLOWLIST_COLDKEYS} coldkeys may be approved")
    # An empty list is a valid artifact that rejects every enrollment. That is
    # a deliberate "approval paused" state, never something to type by mistake.
    if not coldkeys and not args.allow_empty:
        raise SystemExit("refusing to sign an empty allowlist without --allow-empty")

    generated = _now()
    unsigned = {
        "schema": ALLOWLIST_SCHEMA,
        "release": args.release,
        "generated_at": _iso(generated),
        "valid_from": _iso(generated),
        "valid_until": _iso(generated + timedelta(days=args.valid_days)),
        "signing_key_id": args.signing_key_id,
        "coldkeys": sorted(coldkeys),
    }

    seed = _load_signing_seed(args.signing_key_file)
    signed = sign_allowlist(unsigned, seed)
    encoded = canonical_json(signed)

    # Verify before writing: an artifact that cannot be admitted must never
    # reach the operator's hands looking deployable.
    snapshot = verify_allowlist(
        encoded,
        {args.signing_key_id: base64.b64decode(_public_key_b64(seed))},
        max_age_seconds=args.max_age_seconds,
    )
    digest = _digest(encoded)
    if snapshot.digest != digest:
        raise SystemExit("signed artifact digest is not reproducible")

    _secure_write_new(Path(args.out), encoded, 0o644)

    print(f"allowlist_release {snapshot.release}")
    print(f"allowlist_digest {digest}")
    print(f"coldkeys {len(snapshot.coldkeys)}")
    print(f"valid_from {unsigned['valid_from']}")
    print(f"valid_until {unsigned['valid_until']}")
    print(f"written to {args.out}")
    return 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def cmd_verify(args: argparse.Namespace) -> int:
    keys = load_allowlist_keys(args.allowlist_keys, pinned_digest=args.allowlist_keys_digest)
    encoded = _read_bounded(args.allowlist, "coldkey allowlist", MAX_SNAPSHOT_BYTES)
    snapshot = verify_allowlist(encoded, keys, max_age_seconds=args.max_age_seconds)
    digest = _digest(encoded)

    if args.expect_digest is not None and digest != args.expect_digest:
        raise SystemExit(f"allowlist digest {digest} does not match the pin {args.expect_digest}")
    missing = [key for key in args.expect_coldkey if key not in snapshot.coldkeys]
    if missing:
        # The self-lockout check: the operator's own coldkey must survive
        # every rotation or the miner cannot re-enroll after an IP change.
        raise SystemExit(f"coldkeys absent from the allowlist: {', '.join(sorted(missing))}")

    stale_at = snapshot.generated_at + timedelta(seconds=args.max_age_seconds)
    print(f"allowlist_release {snapshot.release}")
    print(f"allowlist_digest {digest}")
    print(f"signing_key_id {snapshot.signing_key_id}")
    print(f"coldkeys {len(snapshot.coldkeys)}")
    print(f"valid_until {_iso(snapshot.valid_until)}")
    print(f"stale_at {_iso(stale_at)}")
    print(f"expires_first {'staleness' if stale_at < snapshot.valid_until else 'validity'}")
    return 0


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------


def _finalized_block(subtensor: object) -> int:
    """Return the finalized head block number, or fail.

    The strict verifier only accepts a snapshot that declares a finalized
    block, so this must never fall back to the best (unfinalized) head: a
    reorg could otherwise retract the registrations the gate admitted on.
    """
    substrate = getattr(subtensor, "substrate", None)
    finalized_head = getattr(substrate, "get_chain_finalised_head", None)
    block_number = getattr(substrate, "get_block_number", None)
    if not callable(finalized_head) or not callable(block_number):
        raise SystemExit(
            "this bittensor build cannot report the finalized head; refusing to "
            "write a snapshot that claims finality it cannot prove"
        )
    number = block_number(finalized_head())
    if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
        raise SystemExit("finalized head did not resolve to a block number")
    return number


def _capture_metagraph(network: str, netuid: int) -> tuple[int, list[tuple[str, str]]]:
    """Read hotkey/coldkey pairs from the metagraph at the finalized head.

    Imported lazily: bittensor is a producer-host dependency, not a package
    dependency of this repo, and every other subcommand runs without it.
    """
    import bittensor  # noqa: PLC0415

    subtensor = bittensor.Subtensor(network=network)
    block = _finalized_block(subtensor)
    metagraph = subtensor.metagraph(netuid, lite=True, block=block)
    hotkeys = list(getattr(metagraph, "hotkeys", None) or [])
    coldkeys = list(getattr(metagraph, "coldkeys", None) or [])
    if len(hotkeys) != len(coldkeys):
        raise SystemExit("metagraph returned mismatched hotkey and coldkey lists")
    captured = int(getattr(metagraph, "block", block))
    if captured > block:
        raise SystemExit("metagraph returned a block ahead of the finalized head")
    return captured, list(zip(hotkeys, coldkeys))


def build_snapshot_document(
    pairs: list[tuple[str, str]],
    *,
    network: str,
    netuid: int,
    block: int,
    generated_at: str | None = None,
) -> dict[str, object]:
    """Build the extended registration snapshot the coldkey gate can read.

    ``hotkeys`` is the mapping form documented in docs/ENROLLMENT_ALLOWLIST.md.
    The surrounding fields are not decoration: the strict verifier in
    cathedral/enroll.py checks every one of them, so a snapshot captured for
    another subnet, another network, or an unfinalized block cannot be
    rotated into place and silently admit the wrong hotkeys.
    """
    if not pairs:
        raise SystemExit("metagraph returned no neurons; refusing to write an empty snapshot")
    if len(pairs) > MAX_SNAPSHOT_HOTKEYS:
        raise SystemExit(f"metagraph returned more than {MAX_SNAPSHOT_HOTKEYS} hotkeys")
    if isinstance(block, bool) or not isinstance(block, int) or block <= 0:
        raise SystemExit("snapshot block must be a positive integer")
    mapping: dict[str, str] = {}
    for hotkey, coldkey in pairs:
        _checked_ss58(hotkey, "hotkey")
        _checked_ss58(coldkey, "coldkey")
        if hotkey in mapping:
            raise SystemExit(f"metagraph returned duplicate hotkey {hotkey}")
        mapping[hotkey] = coldkey
    return {
        "schema": REGISTRATION_SNAPSHOT_SCHEMA,
        "network": network,
        "netuid": netuid,
        "block": block,
        "block_is_finalized": True,
        "generated_at": generated_at or _iso(_now()),
        "hotkeys": dict(sorted(mapping.items())),
    }


def cmd_snapshot(args: argparse.Namespace) -> int:
    block, pairs = _capture_metagraph(args.network, args.netuid)
    document = build_snapshot_document(
        pairs, network=args.network, netuid=args.netuid, block=block
    )
    mapping = document["hotkeys"]
    assert isinstance(mapping, dict)
    missing = [hotkey for hotkey in args.require_hotkey if hotkey not in mapping]
    if missing:
        # Rotating in a snapshot that has lost a live miner deregisters it
        # from the gate's point of view; fail before the file is replaced.
        raise SystemExit(f"required hotkeys absent from the metagraph: {', '.join(missing)}")

    encoded = canonical_json(document)
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise SystemExit("snapshot exceeds the maximum encoded size")
    _atomic_replace(Path(args.output), encoded, 0o644)

    print(f"network {args.network}")
    print(f"netuid {args.netuid}")
    print(f"block {block}")
    print(f"hotkeys {len(mapping)}")
    print(f"coldkeys {len(set(mapping.values()))}")
    print(f"written to {args.output}")
    return 0


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cathedral_enroll_allowlist.py",
        description="Produce and check SN39 enrollment allowlist artifacts",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="mint the signing seed and trusted-key file")
    keygen.add_argument("--signing-key-id", required=True)
    keygen.add_argument("--signing-key-out", required=True, help="mode-0600 seed, never shared")
    keygen.add_argument("--keys-out", required=True, help="trusted-key file given to the registry")
    keygen.set_defaults(func=cmd_keygen)

    sign = sub.add_parser("sign", help="emit a signed allowlist release")
    sign.add_argument("--signing-key-file", required=True)
    sign.add_argument("--signing-key-id", required=True)
    sign.add_argument("--release", type=int, required=True, help="must never decrease")
    sign.add_argument(
        "--coldkey",
        action="append",
        default=[],
        metavar="SS58",
        help="repeatable; every approved coldkey, including ones already approved",
    )
    sign.add_argument("--valid-days", type=int, default=30)
    sign.add_argument(
        "--max-age-seconds",
        type=int,
        default=DEFAULT_ALLOWLIST_MAX_AGE_SECONDS,
        help="the ceiling the registry will run with; used for the pre-write check",
    )
    sign.add_argument(
        "--allow-empty",
        action="store_true",
        help="sign an empty allowlist, which rejects every enrollment",
    )
    sign.add_argument("--out", required=True)
    sign.set_defaults(func=cmd_sign)

    verify = sub.add_parser("verify", help="check a deployed allowlist against its pins")
    verify.add_argument("--allowlist", required=True)
    verify.add_argument("--allowlist-keys", required=True)
    verify.add_argument("--allowlist-keys-digest", required=True, metavar="sha256:HEX")
    verify.add_argument("--expect-digest", metavar="sha256:HEX")
    verify.add_argument(
        "--expect-coldkey",
        action="append",
        default=[],
        metavar="SS58",
        help="repeatable; fail unless this coldkey is still approved",
    )
    verify.add_argument("--max-age-seconds", type=int, default=DEFAULT_ALLOWLIST_MAX_AGE_SECONDS)
    verify.set_defaults(func=cmd_verify)

    snapshot = sub.add_parser(
        "snapshot", help="write the extended hotkey-to-coldkey registration snapshot"
    )
    snapshot.add_argument("--network", required=True)
    snapshot.add_argument("--netuid", type=int, required=True)
    snapshot.add_argument("--output", required=True)
    snapshot.add_argument(
        "--require-hotkey",
        action="append",
        default=[],
        metavar="SS58",
        help="repeatable; abort without writing when this hotkey is not registered",
    )
    snapshot.set_defaults(func=cmd_snapshot)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
