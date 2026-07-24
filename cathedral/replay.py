"""Raw-evidence replay: the positive half of full provenance.

Receipt/report recomputation alone proves only that Cathedral's *signed
statements* are internally consistent — it is PARTIAL provenance and can
never be a submission authority. Positive full provenance additionally
replays the retained raw CPU-TDX evidence through Cathedral's pinned
production verifier using the CANONICAL strict verification path
(``cathedral.verify.replay_verify_tdx``): every parent-process invariant —
intel_verified, exact report_data bytes, claims_bound_to_quote, stable
platform identity, PCK/AK ids, TCB SVN grammar, status/advisory policy,
debug and collateral gates — is the same code production admission runs.

Chain of custody enforced here:

  public manifest ``envelope_digest``  ==  sha256(controlled envelope bytes)
  envelope ``evidence_digest``         ==  recomputed from raw components
  manifest ``verifier.binary_blob``    ==  sha256(verifier binary bytes)
  manifest/report ``verifier_digest``  ==  implementation digest recomputed
                                           from the declared argv/artifacts
                                           and those exact binary bytes
  verifier claims                      ==  bound to the original nonce /
                                           worker hotkey / channel binding
                                           and the receipt's measurement

The authenticated binary bytes are materialized into a private 0700
directory and executed from there — the caller-supplied path is never
executed, so there is no check-to-use window.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat as stat_module
import tempfile
from dataclasses import dataclass
from typing import Any

from cathedral.common import (
    ChannelBinding,
    ChannelBindingType,
    Evidence,
    EvidenceKind,
    Policy,
)
from cathedral.runtime import RETAINED_EVIDENCE_SCHEMA, _evidence_digest
from cathedral.verify import (
    replay_verify_tdx,
    tdx_implementation_digest_from_bytes,
)

MAX_ENVELOPE_BYTES = 4 * 1024 * 1024
MAX_QUOTE_BYTES = 1024 * 1024
MAX_CERT_CHAIN_ENTRIES = 8
MAX_CERT_BYTES = 64 * 1024
MAX_VERIFIER_BINARY_BYTES = 32 * 1024 * 1024

_ENVELOPE_KEYS = frozenset({"schema", "evidence_digest", "components"})
_COMPONENT_KEYS = frozenset(
    {
        "kind",
        "miner_hotkey",
        "report_data_version",
        "quote_base64",
        "nonce_base64",
        "channel_binding_base64",
        "ssh_host_key_base64",
        "cert_chain_base64",
    }
)


class ReplayError(Exception):
    """Raw-evidence replay failed; full provenance must fail closed."""


@dataclass(frozen=True)
class ReplayVerdict:
    hotkey: str
    measurement: str
    tcb_status: str | None
    stable_platform_id: str | None
    envelope_digest: str
    evidence_digest: str


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _strict_json(data: bytes) -> dict[str, Any]:
    def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate envelope JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=lambda _v: (_ for _ in ()).throw(
                ValueError("non-finite envelope JSON")
            ),
        )
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReplayError(f"controlled envelope is not strict JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ReplayError("controlled envelope is not a JSON object")
    canonical = json.dumps(
        document, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if canonical != data:
        raise ReplayError("controlled envelope bytes are not canonical JSON")
    return document


def _b64_field(
    component: dict[str, Any],
    name: str,
    *,
    optional: bool = False,
    max_bytes: int = MAX_QUOTE_BYTES,
) -> bytes | None:
    value = component.get(name)
    if value is None:
        if optional:
            return None
        raise ReplayError(f"envelope component is missing {name}")
    if not isinstance(value, str) or len(value) > max_bytes * 2:
        raise ReplayError(f"envelope component {name} is not bounded base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ReplayError(f"envelope component {name} is not valid base64") from exc
    if len(decoded) > max_bytes:
        raise ReplayError(f"envelope component {name} is oversized")
    return decoded


def _channel_binding_from_canonical(raw: bytes | None) -> ChannelBinding | None:
    if raw is None:
        return None
    prefix = b"cathedral.channel-binding\x00"
    if not raw.startswith(prefix) or len(raw) < len(prefix) + 2 + 32:
        raise ReplayError("envelope channel binding is malformed")
    body = raw[len(prefix):]
    name_length = int.from_bytes(body[:2], "big")
    name = body[2 : 2 + name_length]
    digest = body[2 + name_length :]
    if len(digest) != 32:
        raise ReplayError("envelope channel binding digest is malformed")
    try:
        binding_type = ChannelBindingType(name.decode("ascii"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReplayError("envelope channel binding type is unknown") from exc
    binding = ChannelBinding(binding_type=binding_type, digest=digest)
    if binding.canonical_bytes() != raw:
        raise ReplayError("envelope channel binding does not round-trip")
    return binding


def parse_envelope(
    envelope_bytes: bytes,
    *,
    expected_envelope_digest: str,
    expected_evidence_digest: str,
) -> Evidence:
    """Verify the envelope's digest chain and reconstruct the raw Evidence."""
    if len(envelope_bytes) > MAX_ENVELOPE_BYTES:
        raise ReplayError("controlled envelope is oversized")
    if _digest(envelope_bytes) != expected_envelope_digest:
        raise ReplayError(
            "controlled envelope bytes do not match the published manifest digest"
        )
    document = _strict_json(envelope_bytes)
    if frozenset(document) != _ENVELOPE_KEYS:
        raise ReplayError("controlled envelope has missing or unknown fields")
    if document["schema"] != RETAINED_EVIDENCE_SCHEMA:
        raise ReplayError("controlled envelope schema is unsupported")
    recorded_digest = document["evidence_digest"]
    normalized_expected = expected_evidence_digest.removeprefix("sha256:")
    if not isinstance(recorded_digest, str) or recorded_digest.removeprefix(
        "sha256:"
    ) != normalized_expected:
        raise ReplayError("controlled envelope does not bind the ledger evidence digest")
    components = document["components"]
    if not isinstance(components, list) or len(components) != 1:
        raise ReplayError("launch replay requires exactly one CPU-TDX component")
    component = components[0]
    if not isinstance(component, dict) or frozenset(component) != _COMPONENT_KEYS:
        raise ReplayError("envelope component has missing or unknown fields")
    if component["kind"] != EvidenceKind.TDX.value:
        raise ReplayError("launch replay requires a CPU-TDX component")
    hotkey = component["miner_hotkey"]
    version = component["report_data_version"]
    if not isinstance(hotkey, str) or not 1 <= len(hotkey.encode("utf-8")) <= 512:
        raise ReplayError("envelope component has an invalid hotkey")
    if version not in (1, 2):
        raise ReplayError("envelope component has an invalid report data version")
    chain_raw = component["cert_chain_base64"]
    if not isinstance(chain_raw, list) or len(chain_raw) > MAX_CERT_CHAIN_ENTRIES:
        raise ReplayError("envelope cert chain is malformed or oversized")
    cert_chain: list[bytes] = []
    for item in chain_raw:
        if not isinstance(item, str):
            raise ReplayError("envelope cert chain entry is not base64 text")
        try:
            decoded = base64.b64decode(item, validate=True)
        except (ValueError, TypeError) as exc:
            raise ReplayError("envelope cert chain entry is not valid base64") from exc
        if len(decoded) > MAX_CERT_BYTES:
            raise ReplayError("envelope cert chain entry is oversized")
        cert_chain.append(decoded)

    binding = _channel_binding_from_canonical(
        _b64_field(component, "channel_binding_base64", optional=True, max_bytes=1024)
    )
    evidence = Evidence(
        kind=EvidenceKind.TDX,
        quote=_b64_field(component, "quote_base64"),
        nonce=_b64_field(component, "nonce_base64", max_bytes=64),
        miner_hotkey=hotkey,
        cert_chain=cert_chain,
        ssh_host_key=_b64_field(
            component, "ssh_host_key_base64", optional=True, max_bytes=4096
        ),
        report_data_version=version,
        channel_binding=binding,
    )
    if _evidence_digest(evidence) != recorded_digest.removeprefix("sha256:"):
        raise ReplayError("reconstructed evidence does not reproduce the recorded digest")
    return evidence


def authenticate_verifier_bytes(
    binary_bytes: bytes,
    *,
    expected_blob_digest: str,
    declared_command: tuple[str, ...],
    declared_artifacts: tuple[str, ...],
    expected_implementation_digest: str,
) -> None:
    """Both pins must hold: raw content digest AND implementation digest."""
    if len(binary_bytes) > MAX_VERIFIER_BINARY_BYTES:
        raise ReplayError("verifier binary is oversized")
    if _digest(binary_bytes) != expected_blob_digest:
        raise ReplayError("verifier binary bytes do not match the pinned content digest")
    try:
        recomputed = tdx_implementation_digest_from_bytes(
            tuple(declared_command),
            tuple(declared_artifacts),
            {path: binary_bytes for path in declared_artifacts},
        )
    except ValueError as exc:
        raise ReplayError(f"verifier configuration is invalid: {exc}") from exc
    if recomputed != expected_implementation_digest:
        raise ReplayError(
            "verifier bytes and declared configuration do not reproduce the "
            "pinned implementation digest"
        )


def replay_evidence(
    envelope_bytes: bytes,
    *,
    expected_envelope_digest: str,
    expected_evidence_digest: str,
    expected_hotkey: str,
    expected_measurement: str,
    expected_quote_digest: str,
    verifier_binary: bytes,
    verifier_blob_digest: str,
    verifier_command: tuple[str, ...],
    verifier_artifacts: tuple[str, ...],
    verifier_implementation_digest: str,
    policy: Policy,
) -> ReplayVerdict:
    """Replay one retained CPU-TDX envelope through the canonical strict path."""
    evidence = parse_envelope(
        envelope_bytes,
        expected_envelope_digest=expected_envelope_digest,
        expected_evidence_digest=expected_evidence_digest,
    )
    if evidence.miner_hotkey != expected_hotkey:
        raise ReplayError("envelope worker hotkey does not match the receipt subject")
    # Cross-binding: the receipt's signed hardware claim hashes the raw quote
    # bytes. A valid-but-different envelope (evidence digest B paired with a
    # receipt for quote A) must never replay as full provenance.
    if _digest(evidence.quote) != expected_quote_digest:
        raise ReplayError(
            "raw quote bytes do not match the receipt's signed hardware "
            "evidence digest"
        )
    authenticate_verifier_bytes(
        verifier_binary,
        expected_blob_digest=verifier_blob_digest,
        declared_command=verifier_command,
        declared_artifacts=verifier_artifacts,
        expected_implementation_digest=verifier_implementation_digest,
    )

    with tempfile.TemporaryDirectory(prefix="cathedral-replay-") as scratch:
        os.chmod(scratch, 0o700)
        binary_path = os.path.join(scratch, "verifier")
        descriptor = os.open(
            binary_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o700,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(verifier_binary)
            handle.flush()
            os.fsync(handle.fileno())
        metadata = os.lstat(binary_path)
        if not stat_module.S_ISREG(metadata.st_mode) or metadata.st_size != len(
            verifier_binary
        ):
            raise ReplayError("materialized verifier binary is inconsistent")
        # The CANONICAL strict verification path: bounded subprocess, output
        # cap enforced during execution, sanitized environment, and every
        # strict parent-process claim gate.
        attested = replay_verify_tdx(
            evidence, evidence.nonce, policy, [binary_path]
        )
    if attested is None:
        raise ReplayError(
            "canonical strict verification rejected the raw quote "
            "(binding, policy, collateral, identity, or claim failure)"
        )
    if attested.measurement != expected_measurement:
        raise ReplayError("raw-quote measurement does not match the receipt measurement")
    return ReplayVerdict(
        hotkey=evidence.miner_hotkey,
        measurement=attested.measurement,
        tcb_status=attested.tcb_status,
        stable_platform_id=attested.chip_id,
        envelope_digest=expected_envelope_digest,
        evidence_digest=_evidence_digest(evidence),
    )
