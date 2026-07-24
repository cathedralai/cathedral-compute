"""Evidence store, signed index, retention, and the export→verify CLI loop.

Unlike tests/test_provenance.py (anchored at a fixed instant), the CLI
roundtrip here uses wall-clock-fresh fixtures because ``cathedral provenance
verify`` — like a real external validator — judges freshness against now.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.assurance import (
    AssuranceDimension,
    ClaimStatus,
    attestation_claims,
    evaluated_claim,
    with_verified_channel,
)
from cathedral.cli import main as cli_main
from cathedral.common import Attested, Tier
from cathedral.evidence import (
    EvidenceError,
    EvidenceStore,
    RetentionStore,
    build_manifest,
    build_signed_index,
    digest_bytes,
    parse_manifest,
    verify_index,
)
from cathedral.ledger import Ledger
from cathedral.lifecycle import (
    LifecycleReason,
    LifecycleSnapshot,
    WorkerLifecycleState,
)
from cathedral.policy_registry import canonical_json, sign_registry, verify_registry
from cathedral.receipt import ReceiptIssuer
from cathedral.runtime import SAT_WORK_POLICY_DIGEST
from cathedral.score_class import export_score_class_report

REGISTRY_SEED = bytes(range(32))
RECEIPT_SEED = bytes(range(32, 64))
REPORT_SEED = bytes(range(64, 96))
INDEX_SEED = bytes(range(96, 128))

NOW = datetime.now(UTC).replace(microsecond=0)
WINDOW_FROM = NOW - timedelta(hours=1)
WINDOW_UNTIL = NOW + timedelta(hours=47)
CHALLENGE_ID = "a" * 64
VERIFIER_DIGEST = "sha256:" + "d" * 64
NETWORK = "local"
NETUID = 1


def _registry_text(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _public_b64(seed: bytes) -> str:
    raw = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return base64.b64encode(raw).decode("ascii")


def _public_raw(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def fresh_registry_document() -> dict[str, object]:
    unsigned = {
        "schema": "cathedral_policy_registry_v1",
        "release": 1,
        "generated_at": _registry_text(WINDOW_FROM),
        "valid_from": _registry_text(WINDOW_FROM),
        "valid_until": _registry_text(WINDOW_UNTIL),
        "signing_key_id": "cathedral-policy-test-1",
        "receipt_signing_keys": [
            {
                "id": "receipt-test-1",
                "algorithm": "ed25519",
                "public_key_base64": _public_b64(RECEIPT_SEED),
                "purpose": "assurance_receipt",
                "status": "active",
                "status_changed_at": _registry_text(WINDOW_FROM),
                "valid_from": _registry_text(WINDOW_FROM),
                "valid_until": _registry_text(WINDOW_UNTIL),
                "revoked_at": None,
                "replacement_key_id": None,
                "metadata": {"environment": "test-only"},
            }
        ],
        "profiles": [
            {
                "id": "cpu-tdx-sample-v1",
                "kind": "cpu_tdx",
                "status": "active",
                "status_changed_at": _registry_text(WINDOW_FROM),
                "valid_from": _registry_text(WINDOW_FROM),
                "valid_until": _registry_text(WINDOW_UNTIL),
                "retire_at": None,
                "measurements": ["tdx-measurement-sha256:sample-v1"],
                "runtime_measurements": ["runtime-sha256:sample-v1"],
                "allowed_firmware": [],
                "min_tcb": 0,
                "tdx_allowed_tcb_statuses": ["UpToDate"],
                "tdx_allowed_advisories": [],
                "metadata": {"description": "test CPU profile"},
            }
        ],
        "metadata": {"purpose": "evidence tests"},
    }
    return sign_registry(unsigned, REGISTRY_SEED)


REGISTRY_DOCUMENT = fresh_registry_document()
REGISTRY_BYTES = canonical_json(REGISTRY_DOCUMENT)
TRUSTED = {"cathedral-policy-test-1": _public_raw(REGISTRY_SEED)}
SNAPSHOT = verify_registry(REGISTRY_BYTES, TRUSTED, now=NOW)


def _fresh_claims(policy):
    verified_text = NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    claims = attestation_claims(b"raw-quote-secret", policy, verified_at=verified_text)
    claims = with_verified_channel(
        claims, b"channel-binding-material", verified_at=verified_text
    )
    work = evaluated_claim(
        ClaimStatus.PASSED,
        b"work-result-material",
        SAT_WORK_POLICY_DIGEST,
        verified_at=verified_text,
    )
    return claims.with_claim(AssuranceDimension.WORK, work)


def _fresh_attested(claims) -> Attested:
    return Attested(
        tier=Tier.CC_CPU_TDX,
        chip_id="tdx-platform-sha256:" + "c" * 64,
        measurement="tdx-measurement-sha256:sample-v1",
        tcb=1,
        tcb_status="UpToDate",
        advisory_ids=(),
        debug_enabled=False,
        collateral_current=True,
        tcb_svn="01" * 16,
        policy_mode="strict",
        assurance=claims,
    )


def _fresh_lifecycle(claims, policy, hotkey: str) -> LifecycleSnapshot:
    return LifecycleSnapshot(
        hotkey=hotkey,
        state=WorkerLifecycleState.ATTESTED,
        generation=1,
        revision=2,
        event_id=2,
        reason=LifecycleReason.ATTESTATION_VERIFIED,
        state_changed_at=NOW,
        evidence_verified_at=NOW,
        evidence_expires_at=NOW + timedelta(hours=1),
        measurement="tdx-measurement-sha256:sample-v1",
        evidence_digest=claims.hardware.evidence_digest,
        policy_digest=claims.software.policy_digest,
        policy_registry_release=policy.registry_release,
        policy_registry_digest=policy.registry_digest,
    )


def _completed_fresh_epoch(tmp_path: Path) -> tuple[Ledger, int]:
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(
        11,
        policy_registry_release=SNAPSHOT.release,
        policy_registry_digest=SNAPSHOT.digest,
    )
    policy = SNAPSHOT.to_policy(at=NOW)
    claims = _fresh_claims(policy)
    receipt = ReceiptIssuer(SNAPSHOT, "receipt-test-1", RECEIPT_SEED).issue(
        epoch_id=epoch_id,
        source_epoch=11,
        subject_hotkey="public-hotkey",
        attested=_fresh_attested(claims),
        policy=policy,
        assurance=claims,
        worker_lifecycle=_fresh_lifecycle(claims, policy, "public-hotkey"),
        challenge_id=CHALLENGE_ID,
        manifest_digest="sha256:" + "b" * 64,
        work_units=20.0,
        issued_at=NOW,
    )
    ledger.issue_challenge(CHALLENGE_ID, "public-hotkey", epoch_id)
    ledger.resolve_challenge_with_receipt(
        CHALLENGE_ID,
        "verified",
        20.0,
        validator_derived=True,
        receipt_id=receipt.receipt_id,
        receipt_body=receipt.receipt_bytes,
        receipt_digest=receipt.receipt_digest,
        issued_at=NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    )
    ledger.add_attestation(
        epoch_id,
        "public-hotkey",
        verdict="VERIFIED",
        tee_type="TDX",
        workload="CPU",
        evidence_digest=claims.hardware.evidence_digest,
        policy_mode="strict",
    )
    ledger.add_lifecycle_snapshot(
        epoch_id,
        _fresh_lifecycle(claims, policy, "public-hotkey"),
        snapshot_at=NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    )
    ledger.complete_epoch(
        epoch_id,
        {"public-hotkey"},
        generated_at=NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        score_network=NETWORK,
        score_netuid=NETUID,
    )
    ledger.mark_published(epoch_id)
    return ledger, epoch_id


# ---------------------------------------------------------------------------
# Store primitives
# ---------------------------------------------------------------------------

def test_blob_roundtrip_and_corruption_detection(tmp_path: Path):
    store = EvidenceStore(tmp_path / "evidence")
    digest = store.put_blob(b"artifact-bytes")
    assert store.get_blob(digest) == b"artifact-bytes"
    assert store.put_blob(b"artifact-bytes") == digest  # idempotent
    store.blob_path(digest).write_bytes(b"tampered-bytes")
    with pytest.raises(EvidenceError, match="corrupt"):
        store.get_blob(digest)


def test_manifest_roundtrip_and_validation(tmp_path: Path):
    registry_blob = digest_bytes(REGISTRY_BYTES)
    manifest = build_manifest(
        network=NETWORK,
        netuid=NETUID,
        source_epoch=11,
        epoch_id=1,
        generated_at=None,
        mechanism_id="validated_supply_v1",
        mechanism_revision=1,
        source_revision="abc1234",
        registry_release=1,
        registry_digest=SNAPSHOT.digest,
        registry_blob=registry_blob,
        verifier_digest=VERIFIER_DIGEST,
        verifier_binary_blob=None,
        report_id="sha256:" + "1" * 64,
        report_blob="sha256:" + "2" * 64,
        report_signing_key_id="score-test-1",
        receipts=[
            {
                "receipt_id": "receipt-sha256:" + "3" * 64,
                "hotkey": "public-hotkey",
                "blob": "sha256:" + "4" * 64,
            }
        ],
        candidate_set={
            "source": "enrollment_registry",
            "finalized_block": None,
            "candidates": [
                {
                    "hotkey": "public-hotkey",
                    "outcome": "verified",
                    "reason": "receipt_verified",
                }
            ],
        },
        attestations=[
            {
                "hotkey": "public-hotkey",
                "verdict": "VERIFIED",
                "evidence_digest": "sha256:" + "5" * 64,
                "envelope_digest": "sha256:" + "9" * 64,
                "disclosure": "controlled",
            }
        ],
        wire_report_sha256="6" * 64,
    )
    document = parse_manifest(manifest)
    assert document["reward_mechanism"] == {"id": "validated_supply_v1", "revision": 1}
    assert document["attestations"][0]["disclosure"] == "controlled"

    mutated = json.loads(manifest)
    mutated["reward_mechanism"]["id"] = "Bad Mechanism!"
    with pytest.raises(EvidenceError):
        parse_manifest(canonical_json(mutated))


def test_signed_index_verification_and_tampering(tmp_path: Path):
    index = build_signed_index(
        network=NETWORK,
        netuid=NETUID,
        latest_source_epoch=11,
        latest_manifest_digest="sha256:" + "7" * 64,
        recent=[],
        signing_key_id="evidence-index-test-1",
        private_key_seed=INDEX_SEED,
    )
    keys = {"evidence-index-test-1": _public_raw(INDEX_SEED)}
    document = verify_index(
        index, keys, expected_network=NETWORK, expected_netuid=NETUID
    )
    assert document["latest"]["source_epoch"] == 11

    with pytest.raises(EvidenceError, match="unknown key"):
        verify_index(
            index,
            {"other-key": _public_raw(INDEX_SEED)},
            expected_network=NETWORK,
            expected_netuid=NETUID,
        )
    tampered = json.loads(index)
    tampered["latest"]["manifest"] = "sha256:" + "8" * 64
    with pytest.raises(EvidenceError, match="signature is invalid"):
        verify_index(
            canonical_json(tampered),
            keys,
            expected_network=NETWORK,
            expected_netuid=NETUID,
        )
    with pytest.raises(EvidenceError, match="network/netuid"):
        verify_index(index, keys, expected_network="finney", expected_netuid=39)
    with pytest.raises(EvidenceError, match="stale"):
        verify_index(
            index,
            keys,
            expected_network=NETWORK,
            expected_netuid=NETUID,
            max_age_seconds=60,
            now=datetime.now(UTC) + timedelta(hours=2),
        )


def test_retention_store_is_private_and_journals_without_content(tmp_path: Path):
    retention = RetentionStore(tmp_path / "retained")
    digest = retention.retain(
        b"raw-8000-byte-quote", kind="tdx_quote", hotkey="public-hotkey", epoch_id=4
    )
    blob = tmp_path / "retained" / "blobs" / "sha256" / digest.split(":", 1)[1]
    assert blob.read_bytes() == b"raw-8000-byte-quote"
    assert (blob.stat().st_mode & 0o777) == 0o600
    assert (tmp_path / "retained").stat().st_mode & 0o777 == 0o700
    journal = (tmp_path / "retained" / "log.jsonl").read_text()
    record = json.loads(journal.strip())
    assert record["digest"] == digest
    assert record["kind"] == "tdx_quote"
    assert "raw-8000-byte-quote" not in journal


# ---------------------------------------------------------------------------
# CLI roundtrip: export-score-class → export-evidence → provenance verify
# ---------------------------------------------------------------------------

def _write_key_file(path: Path, seed: bytes) -> None:
    path.write_text(base64.b64encode(seed).decode("ascii"))
    path.chmod(0o600)


def _write_pubkeys_file(path: Path, mapping: dict[str, bytes]) -> None:
    path.write_text(
        json.dumps(
            {kid: base64.b64encode(raw).decode("ascii") for kid, raw in mapping.items()}
        )
    )


@pytest.fixture()
def exported_evidence(tmp_path: Path, capsys):
    ledger, epoch_id = _completed_fresh_epoch(tmp_path)
    export_score_class_report(
        ledger,
        epoch_id,
        network=NETWORK,
        netuid=NETUID,
        class_id="confidential_compute",
        source_id="cathedralconfidential",
        signing_key_id="score-test-1",
        private_key_seed=REPORT_SEED,
        generated_at=NOW,
        valid_until=NOW + timedelta(minutes=30),
        valid_from_block=1,
        valid_until_block=10_000_000_000,
        verifier_digest=VERIFIER_DIGEST,
        evidence_base_uri="https://evidence.example/receipts/",
    )
    ledger.close()

    registry_path = tmp_path / "registry.json"
    registry_path.write_bytes(REGISTRY_BYTES)
    index_key_path = tmp_path / "index-signing.key"
    _write_key_file(index_key_path, INDEX_SEED)
    evidence_dir = tmp_path / "evidence"

    code = cli_main(
        [
            "runtime",
            "export-evidence",
            "--ledger-db",
            str(tmp_path / "ledger.sqlite"),
            "--evidence-dir",
            str(evidence_dir),
            "--score-network",
            NETWORK,
            "--score-netuid",
            str(NETUID),
            "--policy-registry",
            str(registry_path),
            "--verifier-digest",
            VERIFIER_DIGEST,
            "--mechanism",
            "validated_supply_v1",
            "--source-revision",
            "abc1234",
            "--index-signing-key-id",
            "evidence-index-test-1",
            "--index-signing-key-file",
            str(index_key_path),
        ]
    )
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert code == 0
    return evidence_dir, summary


def _verify_cli_args(tmp_path: Path, evidence_dir: Path) -> list[str]:
    registry_keys = tmp_path / "registry-keys.json"
    _write_pubkeys_file(registry_keys, TRUSTED)
    report_keys = tmp_path / "report-keys.json"
    _write_pubkeys_file(report_keys, {"score-test-1": _public_raw(REPORT_SEED)})
    index_keys = tmp_path / "index-keys.json"
    _write_pubkeys_file(
        index_keys, {"evidence-index-test-1": _public_raw(INDEX_SEED)}
    )
    return [
        "provenance",
        "verify",
        "--evidence-dir",
        str(evidence_dir),
        "--network",
        NETWORK,
        "--netuid",
        str(NETUID),
        "--registry-keys",
        str(registry_keys),
        "--report-keys",
        str(report_keys),
        "--index-keys",
        str(index_keys),
        "--verifier-digest",
        VERIFIER_DIGEST,
    ]


def test_cli_export_then_receipts_only_verify_is_not_proven(
    tmp_path: Path, exported_evidence, capsys
):
    """Without the controlled envelopes the chain verifies but the result is
    PARTIAL: NOT_PROVEN, exit 1 by default, exit 0 only with the explicit
    --allow-receipts-only acknowledgement (still recorded as NOT_PROVEN)."""
    evidence_dir, summary = exported_evidence
    assert summary["receipts"] == 1
    audit_path = tmp_path / "audit.json"
    code = cli_main(
        _verify_cli_args(tmp_path, evidence_dir) + ["--audit-out", str(audit_path)]
    )
    output = capsys.readouterr().out
    assert code == 1  # receipts-only can never be a clean PASS
    audit = json.loads(audit_path.read_text())
    assert audit["result"] == "NOT_PROVEN"
    assert audit["assurance"] == "receipts_only"
    assert audit["recomputed_hotkey_weights"] == {"public-hotkey": 1.0}
    events = [json.loads(line) for line in output.strip().splitlines()]
    codes = [event["event"] for event in events]
    assert "EVIDENCE_INDEX_VERIFIED" in codes
    assert "CHAIN_VERIFIED_AND_RECOMPUTED" in codes
    assert events[-1]["event"] == "PROVENANCE_RESULT"
    assert events[-1]["status"] == "NOT_PROVEN"
    assert "receipts-only" in events[-1]["detail"]

    acknowledged = cli_main(
        _verify_cli_args(tmp_path, evidence_dir)
        + ["--allow-receipts-only", "--audit-out", str(tmp_path / "audit2.json")]
    )
    capsys.readouterr()
    assert acknowledged == 0
    audit2 = json.loads((tmp_path / "audit2.json").read_text())
    assert audit2["result"] == "NOT_PROVEN"  # never upgraded by the flag


def test_cli_verify_fails_closed_on_tampered_receipt_blob(
    tmp_path: Path, exported_evidence, capsys
):
    evidence_dir, summary = exported_evidence
    manifest_bytes = EvidenceStore(evidence_dir).get_blob(summary["manifest"])
    manifest = json.loads(manifest_bytes)
    receipt_blob = manifest["receipts"][0]["blob"]
    blob_path = EvidenceStore(evidence_dir).blob_path(receipt_blob)
    blob_path.write_bytes(blob_path.read_bytes().replace(b"passed", b"passe_", 1))

    code = cli_main(_verify_cli_args(tmp_path, evidence_dir))
    output = capsys.readouterr().out
    assert code == 1
    events = [json.loads(line) for line in output.strip().splitlines()]
    assert events[-1]["event"] == "PROVENANCE_FAILED"
    assert events[-1]["status"] == "FAIL"
    assert events[-1]["remediation"]


def test_cli_verify_fails_closed_on_index_tampering(
    tmp_path: Path, exported_evidence, capsys
):
    evidence_dir, _summary = exported_evidence
    index_path = evidence_dir / "index.json"
    document = json.loads(index_path.read_text())
    document["latest"]["source_epoch"] = 999
    index_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":"))
    )
    code = cli_main(_verify_cli_args(tmp_path, evidence_dir))
    capsys.readouterr()
    assert code == 1


def test_cli_verify_rejects_wrong_mechanism_pin(
    tmp_path: Path, exported_evidence, capsys
):
    evidence_dir, _summary = exported_evidence
    code = cli_main(
        _verify_cli_args(tmp_path, evidence_dir)
        + ["--mechanism", "validated_supply_v2"]
    )
    capsys.readouterr()
    assert code == 1


# ---------------------------------------------------------------------------
# Admission-evidence retention (controlled disclosure)
# ---------------------------------------------------------------------------

def test_retained_envelope_reproduces_the_ledger_evidence_digest(tmp_path: Path):
    from cathedral.common import ChannelBinding, ChannelBindingType, Evidence, EvidenceKind
    from cathedral.runtime import _evidence_digest, _retained_evidence_envelope

    evidence = Evidence(
        kind=EvidenceKind.TDX,
        quote=b"\x01" * 64,
        nonce=b"\x02" * 32,
        miner_hotkey="public-hotkey",
        cert_chain=[b"cert-one", b"cert-two"],
        report_data_version=2,
        channel_binding=ChannelBinding(
            binding_type=ChannelBindingType.TLS_SPKI_SHA256, digest=b"\x03" * 32
        ),
    )
    recorded = _evidence_digest(evidence)
    envelope = json.loads(_retained_evidence_envelope((evidence,), recorded))
    assert envelope["schema"] == "cathedral_retained_evidence_v1"
    assert envelope["evidence_digest"] == recorded

    component = envelope["components"][0]
    rebuilt = Evidence(
        kind=EvidenceKind(component["kind"]),
        quote=base64.b64decode(component["quote_base64"]),
        nonce=base64.b64decode(component["nonce_base64"]),
        miner_hotkey=component["miner_hotkey"],
        cert_chain=[base64.b64decode(item) for item in component["cert_chain_base64"]],
        report_data_version=component["report_data_version"],
        channel_binding=evidence.channel_binding,
    )
    assert _evidence_digest(rebuilt) == recorded
    binding_bytes = base64.b64decode(component["channel_binding_base64"])
    assert binding_bytes == evidence.channel_binding.canonical_bytes()


def test_retention_is_mandatory_when_configured_and_in_production(tmp_path: Path):
    from types import SimpleNamespace

    from cathedral.common import Evidence, EvidenceKind
    from cathedral.runtime import ConfidentialRuntime, _evidence_digest

    evidence = Evidence(
        kind=EvidenceKind.TDX,
        quote=b"\x07" * 16,
        nonce=b"\x08" * 32,
        miner_hotkey="public-hotkey",
    )

    def _fake(retention_dir, *, production=False):
        return SimpleNamespace(
            config=SimpleNamespace(
                evidence_retention_dir=retention_dir,
                production_mode=production,
                expected_tier=Tier.CC_CPU_TDX,
            )
        )

    # Success returns the envelope digest and journals the retention.
    digest = ConfidentialRuntime._retain_admission_evidence(
        _fake(str(tmp_path / "retained")),
        (evidence,),
        _evidence_digest(evidence),
        "public-hotkey",
    )
    assert isinstance(digest, str) and digest.startswith("sha256:")
    journal = (tmp_path / "retained" / "log.jsonl").read_text()
    record = json.loads(journal.strip())
    assert record["kind"] == "admission_evidence"
    assert record["hotkey"] == "public-hotkey"
    assert record["digest"] == digest

    # A retention failure REFUSES admission — no silent best-effort path.
    blocked = tmp_path / "blocked"
    blocked.write_text("a file, not a directory")
    import cathedral.runtime as runtime_module

    with pytest.raises(runtime_module.RuntimeError, match="retention failed"):
        ConfidentialRuntime._retain_admission_evidence(
            _fake(str(blocked / "x")),
            (evidence,),
            _evidence_digest(evidence),
            "public-hotkey",
        )

    # Production CPU scoring without retention configured fails closed.
    with pytest.raises(runtime_module.RuntimeError, match="requires evidence retention"):
        ConfidentialRuntime._retain_admission_evidence(
            _fake(None, production=True),
            (evidence,),
            _evidence_digest(evidence),
            "public-hotkey",
        )

    # Token-shaped material is never persisted.
    gpu_like = Evidence(
        kind=EvidenceKind.TDX,
        quote=b"\x07" * 16,
        nonce=b"\x08" * 32,
        miner_hotkey="public-hotkey",
        composite_jwt="header.payload.signature",
    )
    with pytest.raises(runtime_module.RuntimeError, match="retention failed"):
        ConfidentialRuntime._retain_admission_evidence(
            _fake(str(tmp_path / "retained2")),
            (gpu_like,),
            _evidence_digest(gpu_like),
            "public-hotkey",
        )
    assert not (tmp_path / "retained2" / "log.jsonl").exists()


def test_fence_update_is_monotonic_under_out_of_order_writers(tmp_path: Path):
    """Counterexample G: epoch 12 then a late writer with 11 must end at 12;
    same-epoch different manifest never overwrites."""
    from cathedral.cli import _update_fences_monotonic

    fence = tmp_path / "fences.json"
    _update_fences_monotonic(fence, 12, "sha256:" + "a" * 64)
    _update_fences_monotonic(fence, 11, "sha256:" + "b" * 64)  # late, older
    state = json.loads(fence.read_text())
    assert state["index_source_epoch"] == 12
    assert state["index_manifest"] == "sha256:" + "a" * 64
    _update_fences_monotonic(fence, 12, "sha256:" + "c" * 64)  # equivocation
    state = json.loads(fence.read_text())
    assert state["index_manifest"] == "sha256:" + "a" * 64
    # Stale crash-left temp is cleared and does not brick the writer.
    (tmp_path / "fences.json.99999.tmp").write_text("stale")
    _update_fences_monotonic(fence, 13, "sha256:" + "d" * 64)
    assert json.loads(fence.read_text())["index_source_epoch"] == 13


def test_retention_store_rejects_drifted_blob_permissions(tmp_path: Path):
    """Counterexample L: an existing retained blob that drifted to 0644 is
    refused, not silently accepted."""
    retention = RetentionStore(tmp_path / "retained")
    digest = retention.retain(b"raw-quote-bytes", kind="admission_evidence")
    blob = tmp_path / "retained" / "blobs" / "sha256" / digest.split(":", 1)[1]
    blob.chmod(0o644)
    with pytest.raises(EvidenceError, match="unsafe on disk"):
        retention.retain(b"raw-quote-bytes", kind="admission_evidence")
