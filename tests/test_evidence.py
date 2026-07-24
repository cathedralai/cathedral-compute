"""Evidence store, signed index, retention, and the export→verify CLI loop.

Unlike tests/test_provenance.py (anchored at a fixed instant), the CLI
roundtrip here uses wall-clock-fresh fixtures because ``cathedral provenance
verify`` — like a real external validator — judges freshness against now.
"""

from __future__ import annotations

import base64
import json
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

from cathedral.lanes.sat import _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance as _SatInstance

NOW = datetime.now(UTC).replace(microsecond=0)
WINDOW_FROM = NOW - timedelta(hours=1)
WINDOW_UNTIL = NOW + timedelta(hours=47)
# The PRODUCER-DERIVED id for the standard work fixture (instance+seed):
# fabricated ids no longer replay under the shared contract.
CHALLENGE_ID = _compute_challenge_id(_SatInstance(n_vars=3, clauses=[[1, 2, -3]] * 20), 7)
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


def _work_fixture(challenge_id: str, hotkey: str, n_clauses: int = 20):
    """A REAL solvable SAT workload whose canonical bytes reproduce the
    receipt's manifest/result digests, so full provenance can replay it."""
    from cathedral.lanes.sat_types import SatCertificate, SatInstance, SatWorkItem
    from cathedral.runtime import _sat_manifest_bytes, _sat_result_bytes

    instance = SatInstance(n_vars=3, clauses=[[1, 2, -3]] * n_clauses)
    item = SatWorkItem(instance=instance, seed=7, challenge_id=challenge_id)
    certificate = SatCertificate(
        satisfiable=True,
        assignment=[1, 2, -3],
        work_units=float(n_clauses),
        challenge_id=challenge_id,
        assigned_hotkey=hotkey,
    )
    return _sat_manifest_bytes(item), _sat_result_bytes(item, certificate)


def _fresh_claims(policy, result_bytes: bytes = b"work-result-material"):
    verified_text = NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    claims = attestation_claims(b"raw-quote-secret", policy, verified_at=verified_text)
    claims = with_verified_channel(claims, b"channel-binding-material", verified_at=verified_text)
    work = evaluated_claim(
        ClaimStatus.PASSED,
        result_bytes,
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


CANDIDATE_SNAPSHOT_DOC = {
    "schema": "cathedral_candidate_snapshot_v1",
    "network": NETWORK,
    "netuid": NETUID,
    "block": 100,
    "block_hash": "0x" + "ab" * 32,
    "hotkeys": ["public-hotkey"],
}


def _completed_fresh_epoch(tmp_path: Path) -> tuple[Ledger, int]:
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(
        11,
        policy_registry_release=SNAPSHOT.release,
        policy_registry_digest=SNAPSHOT.digest,
        network=NETWORK,
        netuid=NETUID,
        challenge_anchor_block=100,
        challenge_anchor_hash="0x" + "ab" * 32,
    )
    policy = SNAPSHOT.to_policy(at=NOW)
    work_item_bytes, result_bytes = _work_fixture(CHALLENGE_ID, "public-hotkey")
    from cathedral.assurance import sha256_digest as _sha

    claims = _fresh_claims(policy, result_bytes)
    receipt = ReceiptIssuer(SNAPSHOT, "receipt-test-1", RECEIPT_SEED).issue(
        epoch_id=epoch_id,
        source_epoch=11,
        subject_hotkey="public-hotkey",
        attested=_fresh_attested(claims),
        policy=policy,
        assurance=claims,
        worker_lifecycle=_fresh_lifecycle(claims, policy, "public-hotkey"),
        challenge_id=CHALLENGE_ID,
        manifest_digest=_sha(work_item_bytes),
        work_units=20.0,
        issued_at=NOW,
    )
    ledger.record_work_artifacts(CHALLENGE_ID, work_item_bytes, result_bytes)
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
        envelope_digest="sha256:" + "e" * 64,
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
                "work_item_blob": "sha256:" + "6" * 64,
                "result_blob": "sha256:" + "7" * 64,
            }
        ],
        candidate_set={
            "source": "sn39_metagraph",
            "network": NETWORK,
            "netuid": NETUID,
            "block": 100,
            "block_hash": "0x" + "ab" * 32,
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
                "challenge_digest": "sha256:" + "8" * 64,
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
    document = verify_index(index, keys, expected_network=NETWORK, expected_netuid=NETUID)
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
        json.dumps({kid: base64.b64encode(raw).decode("ascii") for kid, raw in mapping.items()})
    )


def _prepared_export_workspace(tmp_path: Path) -> Path:
    """Frozen epoch + signed report + on-disk export inputs, WITHOUT running
    the export itself — tests exercising export failure modes start here."""
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
        valid_from_block=100,
        valid_until_block=10_000_000_000,
        verifier_digest=VERIFIER_DIGEST,
        candidate_snapshot=CANDIDATE_SNAPSHOT_DOC,
        evidence_base_uri="https://evidence.example/receipts/",
    )
    ledger.close()

    registry_path = tmp_path / "registry.json"
    registry_path.write_bytes(REGISTRY_BYTES)
    _write_key_file(tmp_path / "index-signing.key", INDEX_SEED)
    snapshot_path = tmp_path / "candidate-snapshot.json"
    snapshot_path.write_text(
        json.dumps(CANDIDATE_SNAPSHOT_DOC, sort_keys=True, separators=(",", ":"))
    )
    return tmp_path / "evidence"


@pytest.fixture()
def exported_evidence(tmp_path: Path, capsys):
    evidence_dir = _prepared_export_workspace(tmp_path)
    registry_path = tmp_path / "registry.json"
    index_key_path = tmp_path / "index-signing.key"
    snapshot_path = tmp_path / "candidate-snapshot.json"

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
            "--candidate-snapshot",
            str(snapshot_path),
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
    _write_pubkeys_file(index_keys, {"evidence-index-test-1": _public_raw(INDEX_SEED)})
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
    code = cli_main(_verify_cli_args(tmp_path, evidence_dir) + ["--audit-out", str(audit_path)])
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


def test_cli_verify_fails_closed_on_index_tampering(tmp_path: Path, exported_evidence, capsys):
    evidence_dir, _summary = exported_evidence
    index_path = evidence_dir / "index.json"
    document = json.loads(index_path.read_text())
    document["latest"]["source_epoch"] = 999
    index_path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")))
    code = cli_main(_verify_cli_args(tmp_path, evidence_dir))
    capsys.readouterr()
    assert code == 1


def test_cli_verify_rejects_wrong_mechanism_pin(tmp_path: Path, exported_evidence, capsys):
    evidence_dir, _summary = exported_evidence
    code = cli_main(
        _verify_cli_args(tmp_path, evidence_dir) + ["--mechanism", "validated_supply_v2"]
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


def test_fence_reservation_conflicts_fail_never_keep_silently(tmp_path: Path):
    """Defect-4 proof: a late epoch-11 writer after 12, a same-epoch manifest
    fork, policy rollback/equivocation, and a non-chaining report all RAISE;
    stale temps recover; forward reservations advance."""
    from cathedral.cli import _reserve_fences

    fence = tmp_path / "fences.json"
    base = {
        "policy_release": 6,
        "policy_digest": "sha256:" + "0" * 64,
        "report_id": "sha256:" + "1" * 64,
        "previous_report_id": None,
        "source_epoch": 12,
    }
    _reserve_fences(fence, index_epoch=12, index_manifest="sha256:" + "a" * 64, **base)
    with pytest.raises(ValueError, match="index rollback"):
        _reserve_fences(fence, index_epoch=11, index_manifest="sha256:" + "b" * 64, **base)
    with pytest.raises(ValueError, match="index equivocation"):
        _reserve_fences(fence, index_epoch=12, index_manifest="sha256:" + "c" * 64, **base)
    state = json.loads(fence.read_text())
    assert state["index_source_epoch"] == 12
    assert state["index_manifest"] == "sha256:" + "a" * 64

    with pytest.raises(ValueError, match="policy rollback"):
        _reserve_fences(
            fence,
            index_epoch=13,
            index_manifest="sha256:" + "d" * 64,
            policy_release=5,
            policy_digest="sha256:" + "0" * 64,
            report_id="sha256:" + "2" * 64,
            previous_report_id="sha256:" + "1" * 64,
            source_epoch=13,
        )
    with pytest.raises(ValueError, match="policy equivocation"):
        _reserve_fences(
            fence,
            index_epoch=13,
            index_manifest="sha256:" + "d" * 64,
            policy_release=6,
            policy_digest="sha256:" + "9" * 64,
            report_id="sha256:" + "2" * 64,
            previous_report_id="sha256:" + "1" * 64,
            source_epoch=13,
        )
    with pytest.raises(ValueError, match="does not chain"):
        _reserve_fences(
            fence,
            index_epoch=13,
            index_manifest="sha256:" + "d" * 64,
            policy_release=6,
            policy_digest="sha256:" + "0" * 64,
            report_id="sha256:" + "2" * 64,
            previous_report_id="sha256:" + "f" * 64,
            source_epoch=13,
        )
    # Stale crash-left temp recovers; a proper forward reservation advances.
    (tmp_path / "fences.json.99999.tmp").write_text("stale")
    _reserve_fences(
        fence,
        index_epoch=13,
        index_manifest="sha256:" + "d" * 64,
        policy_release=6,
        policy_digest="sha256:" + "0" * 64,
        report_id="sha256:" + "2" * 64,
        previous_report_id="sha256:" + "1" * 64,
        source_epoch=13,
    )
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


def test_command_budget_enforces_deadline_bytes_and_artifacts():
    """Counterexample M: one command-wide budget gates every operation."""
    from cathedral.cli import _FetchBudget

    budget = _FetchBudget(deadline_seconds=60, max_total_bytes=10, max_artifacts=2)
    budget.start_artifact()
    budget.charge(6)
    budget.start_artifact()
    with pytest.raises(ValueError, match="aggregate byte cap"):
        budget.charge(6)
    fresh = _FetchBudget(deadline_seconds=60, max_total_bytes=100, max_artifacts=1)
    fresh.start_artifact()
    with pytest.raises(ValueError, match="artifact cap"):
        fresh.start_artifact()
    expired = _FetchBudget(deadline_seconds=60, max_total_bytes=100, max_artifacts=5)
    expired.deadline = expired._clock() - 1
    with pytest.raises(ValueError, match="total deadline"):
        expired.start_artifact()


def test_dns_resolution_is_capped_by_the_command_deadline(monkeypatch):
    """Defect-7 proof: a ~1ms budget with a 50ms resolver fails promptly."""
    import socket
    import time

    from cathedral.cli import _FetchBudget, _resolved_public_address

    def slow_resolver(*_a, **_k):
        time.sleep(0.25)  # a genuinely slow resolver
        return [(socket.AF_INET, 0, 6, "", ("34.71.88.140", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", slow_resolver)
    budget = _FetchBudget(deadline_seconds=0.001)
    started = time.monotonic()
    with pytest.raises(ValueError, match="exceeded the command deadline"):
        _resolved_public_address("example.com", 443, allow_private=False, budget=budget)
    elapsed = time.monotonic() - started
    # The failure lands at ~the 1ms budget, NOT after the 250ms resolver.
    assert elapsed < 0.1, elapsed


def test_production_refuses_the_private_host_bypass(tmp_path, capsys):
    """Defect-8 proof: --production + --allow-private-evidence-host fails."""
    from cathedral.cli import main as cli_main

    code = cli_main(
        [
            "provenance",
            "verify",
            "--evidence-dir",
            str(tmp_path),
            "--registry-keys",
            "r.json",
            "--report-keys",
            "p.json",
            "--index-keys",
            "i.json",
            "--verifier-digest",
            "sha256:" + "d" * 64,
            "--production",
            "--allow-private-evidence-host",
        ]
    )
    output = capsys.readouterr().out
    assert code == 1
    assert "testing-only" in output


def test_corrupt_index_recovery_cannot_roll_back_highwater(tmp_path):
    """Defect-5 proof: with index.json corrupted, the durable high-water
    still refuses publishing an OLDER latest."""
    from cathedral.evidence import EvidenceError, EvidenceStore

    store = EvidenceStore(tmp_path / "store")
    index_13 = build_signed_index(
        network=NETWORK,
        netuid=NETUID,
        latest_source_epoch=13,
        latest_manifest_digest="sha256:" + "a" * 64,
        recent=[],
        signing_key_id="evidence-index-test-1",
        private_key_seed=INDEX_SEED,
    )
    store.write_index(index_13)
    (tmp_path / "store" / "index.json").write_bytes(b"CORRUPT")
    index_12 = build_signed_index(
        network=NETWORK,
        netuid=NETUID,
        latest_source_epoch=12,
        latest_manifest_digest="sha256:" + "b" * 64,
        recent=[],
        signing_key_id="evidence-index-test-1",
        private_key_seed=INDEX_SEED,
    )
    with pytest.raises(EvidenceError, match="durable\\s+high-water"):
        store.write_index(index_12)


def test_evidence_export_refuses_a_swapped_candidate_snapshot(
    tmp_path: Path, exported_evidence, capsys
):
    """Defect-3 evidence side: export-evidence must REUSE the exact snapshot
    the signed report bound — a later, different snapshot fails; the exact
    original stays idempotently retryable."""
    evidence_dir, _summary = exported_evidence
    snapshot_path = tmp_path / "candidate-snapshot.json"
    export_args = [
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
        str(tmp_path / "registry.json"),
        "--verifier-digest",
        VERIFIER_DIGEST,
        "--mechanism",
        "validated_supply_v1",
        "--source-revision",
        "abc1234",
        "--index-signing-key-id",
        "evidence-index-test-1",
        "--index-signing-key-file",
        str(tmp_path / "index-signing.key"),
        "--candidate-snapshot",
        str(snapshot_path),
    ]

    for swap in (
        {"hotkeys": ["late-arrival", "public-hotkey"]},
        {"block": 101},
        {"block_hash": "0x" + "cd" * 32},
    ):
        snapshot_path.write_text(
            json.dumps(
                {**CANDIDATE_SNAPSHOT_DOC, **swap},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        assert cli_main(export_args) != 0
        assert "must reuse the exact frozen snapshot" in capsys.readouterr().err

    # The exact original snapshot remains an idempotent retry.
    snapshot_path.write_text(
        json.dumps(CANDIDATE_SNAPSHOT_DOC, sort_keys=True, separators=(",", ":"))
    )
    assert cli_main(export_args) == 0
    capsys.readouterr()


def test_resolver_slot_pool_bounds_abandoned_lookups(monkeypatch):
    """Defect-5 stress proof: abandoned slow lookups retain a bounded slot
    until the resolver returns, capacity exhaustion fails promptly, threads
    never accumulate past the cap, and drained slots are reusable."""
    import socket
    import threading
    import time

    import cathedral.cli as cli_module
    from cathedral.cli import RESOLVER_SLOT_CAP, _getaddrinfo_bounded

    # A fresh pool for this test; restored automatically by monkeypatch.
    monkeypatch.setattr(cli_module, "_RESOLVER_SLOTS", None)
    release = threading.Event()

    def hung_resolver(*_a, **_k):
        release.wait(10)
        return [(socket.AF_INET, 0, 6, "", ("34.71.88.140", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", hung_resolver)
    baseline_threads = threading.active_count()

    # Fill EVERY slot with an abandoned lookup: each caller times out
    # promptly while its resolver thread keeps holding the slot.
    for _ in range(RESOLVER_SLOT_CAP):
        started = time.monotonic()
        with pytest.raises(ValueError, match="exceeded the command deadline"):
            _getaddrinfo_bounded("example.com", 443, 0.001)
        assert time.monotonic() - started < 0.5

    # Capacity exhaustion is a PROMPT failure, not an unbounded queue …
    started = time.monotonic()
    with pytest.raises(ValueError, match="capacity exhausted"):
        _getaddrinfo_bounded("example.com", 443, 0.001)
    assert time.monotonic() - started < 0.5
    # … and the thread population is bounded by the cap, not by call count.
    assert threading.active_count() <= baseline_threads + RESOLVER_SLOT_CAP + 1

    # Once the resolvers actually return, their slots are RELEASED and the
    # pool is reusable.
    release.set()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            result = _getaddrinfo_bounded("example.com", 443, 1.0)
            break
        except ValueError:
            time.sleep(0.05)
    else:
        pytest.fail("resolver slots were never released after completion")
    assert result[0][4][0] == "34.71.88.140"


def test_resolver_slot_pool_survives_repeated_timeout_storms(monkeypatch):
    """Defect-5 stress proof: 3x-cap repeated timeouts recycle slots as
    resolvers finish; every failure stays prompt and the pool never wedges."""
    import socket
    import threading
    import time

    import cathedral.cli as cli_module
    from cathedral.cli import RESOLVER_SLOT_CAP, _getaddrinfo_bounded

    monkeypatch.setattr(cli_module, "_RESOLVER_SLOTS", None)

    def slow_resolver(*_a, **_k):
        time.sleep(0.05)
        return [(socket.AF_INET, 0, 6, "", ("34.71.88.140", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", slow_resolver)
    baseline_threads = threading.active_count()

    for _ in range(3 * RESOLVER_SLOT_CAP):
        started = time.monotonic()
        with pytest.raises(ValueError, match="exceeded the command deadline|capacity exhausted"):
            _getaddrinfo_bounded("example.com", 443, 0.001)
        assert time.monotonic() - started < 0.5
        assert threading.active_count() <= baseline_threads + RESOLVER_SLOT_CAP + 1

    time.sleep(0.2)  # let the in-flight resolvers drain
    assert _getaddrinfo_bounded("example.com", 443, 1.0)


# ---------------------------------------------------------------------------
# Round-six adversarial regressions
# ---------------------------------------------------------------------------


def _export_evidence_args(
    tmp_path: Path, snapshot_path: Path, evidence_dir: Path | None = None, **extra
) -> list[str]:
    arguments = [
        "runtime",
        "export-evidence",
        "--ledger-db",
        str(tmp_path / "ledger.sqlite"),
        "--evidence-dir",
        str(evidence_dir or (tmp_path / "evidence")),
        "--score-network",
        NETWORK,
        "--score-netuid",
        str(NETUID),
        "--policy-registry",
        str(tmp_path / "registry.json"),
        "--verifier-digest",
        VERIFIER_DIGEST,
        "--mechanism",
        "validated_supply_v1",
        "--source-revision",
        "abc1234",
        "--index-signing-key-id",
        "evidence-index-test-1",
        "--index-signing-key-file",
        str(tmp_path / "index-signing.key"),
        "--candidate-snapshot",
        str(snapshot_path),
    ]
    for flag, value in extra.items():
        arguments += ["--" + flag.replace("_", "-"), value]
    return arguments


def test_cli_full_replay_wires_anchor_and_all_rejected_state(
    tmp_path: Path, exported_evidence, capsys, monkeypatch
):
    """Round-six C1 (positive half): the CLI full-replay path must hand
    replay_positive_miners the EXACT verified challenge anchor (network,
    netuid, finalized height AND hash) and the derived all-rejected state —
    previously it passed neither, so positive FULL raised."""
    import dataclasses

    from cathedral import provenance as provenance_module

    _fixture_dir, _summary = exported_evidence
    controlled = tmp_path / "controlled"
    controlled.mkdir()
    (controlled / ("e" * 64 + ".json")).write_bytes(b"{}")
    verifier_path = tmp_path / "verifier.bin"
    verifier_path.write_bytes(b"\x7fELF-test-bytes")
    # A SEPARATE export carrying the verifier bindings full mode requires.
    snapshot_path = tmp_path / "candidate-snapshot.json"
    full_dir = tmp_path / "evidence-full"
    assert (
        cli_main(
            _export_evidence_args(
                tmp_path,
                snapshot_path,
                evidence_dir=full_dir,
                verifier_binary=str(verifier_path),
                verifier_production_path="/opt/cathedral/bin/verifier",
            )
        )
        == 0
    )
    capsys.readouterr()
    captured: dict = {}
    real = provenance_module.replay_positive_miners

    def spy(result, **kwargs):
        captured.update(kwargs)
        return dataclasses.replace(result, assurance_level="full")

    monkeypatch.setattr(provenance_module, "replay_positive_miners", spy)
    independent_path = tmp_path / "independent-snapshot.json"
    independent_path.write_text(
        json.dumps(CANDIDATE_SNAPSHOT_DOC, sort_keys=True, separators=(",", ":"))
    )
    base_arguments = [
        *_verify_cli_args(tmp_path, full_dir),
        "--controlled-dir",
        str(controlled),
        "--verifier-binary",
        str(verifier_path),
    ]
    # Without the independent oracle, FULL refuses outright.
    assert cli_main(base_arguments) != 0
    output = capsys.readouterr()
    assert "independent-candidate-snapshot" in output.out + output.err
    assert not captured  # the replay was never even attempted

    code = cli_main([*base_arguments, "--independent-candidate-snapshot", str(independent_path)])
    capsys.readouterr()
    assert code == 0
    assert real is not provenance_module.replay_positive_miners
    assert captured["candidate_outcomes"] == {"public-hotkey": "verified"}
    assert captured["challenge_anchor"] == {
        "block": 100,
        "block_hash": "0x" + "ab" * 32,
        "network": NETWORK,
        "netuid": NETUID,
    }
    assert captured["independent_candidates"] == ["public-hotkey"]
    assert captured["independent_block_hash"] == "ab" * 32


def test_cli_all_rejected_epoch_fails_closed_without_rejection_evidence(
    tmp_path: Path, capsys, monkeypatch
):
    """Round-seven F3 (supersedes the round-six expectation): with zero raw
    replays, an all-rejected epoch (a) hard-fails when the pinned verifier
    bytes do not authenticate, and (b) with authenticated bytes stays
    receipts_only/NOT_PROVEN because exhaustive raw rejection evidence is
    not published by the current artifact model — FULL is never minted
    unexercised. The anchor/all-rejected wiring itself remains covered by
    the spy test above."""
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(
        11,
        policy_registry_release=SNAPSHOT.release,
        policy_registry_digest=SNAPSHOT.digest,
        network=NETWORK,
        netuid=NETUID,
        challenge_anchor_block=100,
        challenge_anchor_hash="0x" + "ab" * 32,
    )
    ledger.complete_epoch(
        epoch_id,
        {"idle-hotkey"},
        generated_at=NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        score_network=NETWORK,
        score_netuid=NETUID,
    )
    ledger.mark_published(epoch_id)
    snapshot_doc = {
        "schema": "cathedral_candidate_snapshot_v1",
        "network": NETWORK,
        "netuid": NETUID,
        "block": 100,
        "block_hash": "0x" + "ab" * 32,
        "hotkeys": ["idle-hotkey"],
    }
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
        valid_from_block=100,
        valid_until_block=10_000_000_000,
        verifier_digest=VERIFIER_DIGEST,
        candidate_snapshot=snapshot_doc,
        evidence_base_uri="https://evidence.example/receipts/",
    )
    ledger.close()
    (tmp_path / "registry.json").write_bytes(REGISTRY_BYTES)
    _write_key_file(tmp_path / "index-signing.key", INDEX_SEED)
    snapshot_path = tmp_path / "candidate-snapshot.json"
    snapshot_path.write_text(json.dumps(snapshot_doc, sort_keys=True))
    verifier_path = tmp_path / "verifier.bin"
    verifier_path.write_bytes(b"\x7fELF-inert-test-verifier")
    assert (
        cli_main(
            _export_evidence_args(
                tmp_path,
                snapshot_path,
                verifier_binary=str(verifier_path),
                verifier_production_path="/opt/cathedral/bin/verifier",
            )
        )
        == 0
    )
    capsys.readouterr()
    controlled = tmp_path / "controlled"
    controlled.mkdir()
    audit_out = tmp_path / "audit.json"
    independent_path = tmp_path / "independent-snapshot.json"
    independent_path.write_text(json.dumps(snapshot_doc, sort_keys=True))
    arguments = [
        *_verify_cli_args(tmp_path, tmp_path / "evidence"),
        "--controlled-dir",
        str(controlled),
        "--verifier-binary",
        str(verifier_path),
        "--independent-candidate-snapshot",
        str(independent_path),
        "--audit-out",
        str(audit_out),
    ]
    # (a) The inert test bytes match the manifest blob digest but cannot
    # reproduce the pinned implementation digest: hard failure, exit != 0.
    code = cli_main(arguments)
    output = capsys.readouterr()
    assert code != 0
    assert "failed authentication" in output.out + output.err
    # (b) With verifier-bytes authentication satisfied (stubbed exactly as
    # in the ELF adversarial matrix), the claim STILL stays receipts_only:
    # no raw rejection evidence exists, so NOT_PROVEN — fail closed.
    from unittest import mock

    with mock.patch("cathedral.replay.authenticate_verifier_bytes"):
        code = cli_main(arguments)
    capsys.readouterr()
    audit = json.loads(audit_out.read_text())
    assert code != 0
    assert audit["assurance"] == "receipts_only"
    assert audit["result"] == "NOT_PROVEN"


def test_zero_work_receipt_never_mints_a_verified_manifest_outcome(tmp_path: Path, capsys):
    """Round-six C4: a FAILED receipt (receipt bytes exist, zero verified
    work) must produce manifest outcome 'rejected' — never a 'verified'
    outcome the verifier will later reject."""
    from cathedral.assurance import ReasonCategory

    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(
        11,
        policy_registry_release=SNAPSHOT.release,
        policy_registry_digest=SNAPSHOT.digest,
        network=NETWORK,
        netuid=NETUID,
        challenge_anchor_block=100,
        challenge_anchor_hash="0x" + "ab" * 32,
    )
    policy = SNAPSHOT.to_policy(at=NOW)
    verified_text = NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    failed_challenge = "f" * 64
    claims = attestation_claims(b"raw-quote-secret", policy, verified_at=verified_text)
    claims = with_verified_channel(claims, b"channel-binding-material", verified_at=verified_text)
    failed_work = evaluated_claim(
        ClaimStatus.FAILED,
        b"failed-work-material",
        SAT_WORK_POLICY_DIGEST,
        verified_at=verified_text,
        reason=ReasonCategory.WORK_INVALID,
    )
    claims = claims.with_claim(AssuranceDimension.WORK, failed_work)
    receipt = ReceiptIssuer(SNAPSHOT, "receipt-test-1", RECEIPT_SEED).issue(
        epoch_id=epoch_id,
        source_epoch=11,
        subject_hotkey="failed-worker",
        attested=_fresh_attested(claims),
        policy=policy,
        assurance=claims,
        worker_lifecycle=_fresh_lifecycle(claims, policy, "failed-worker"),
        challenge_id=failed_challenge,
        manifest_digest="sha256:" + "b" * 64,
        work_units=0.0,
        issued_at=NOW,
    )
    ledger.issue_challenge(failed_challenge, "failed-worker", epoch_id)
    ledger.resolve_challenge_with_receipt(
        failed_challenge,
        "failed",
        0.0,
        validator_derived=True,
        receipt_id=receipt.receipt_id,
        receipt_body=receipt.receipt_bytes,
        receipt_digest=receipt.receipt_digest,
        issued_at=verified_text,
    )
    ledger.complete_epoch(
        epoch_id,
        {"failed-worker"},
        generated_at=verified_text,
        score_network=NETWORK,
        score_netuid=NETUID,
    )
    ledger.mark_published(epoch_id)
    snapshot_doc = {
        "schema": "cathedral_candidate_snapshot_v1",
        "network": NETWORK,
        "netuid": NETUID,
        "block": 100,
        "block_hash": "0x" + "ab" * 32,
        "hotkeys": ["failed-worker"],
    }
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
        valid_from_block=100,
        valid_until_block=10_000_000_000,
        verifier_digest=VERIFIER_DIGEST,
        candidate_snapshot=snapshot_doc,
        evidence_base_uri="https://evidence.example/receipts/",
    )
    ledger.close()
    (tmp_path / "registry.json").write_bytes(REGISTRY_BYTES)
    _write_key_file(tmp_path / "index-signing.key", INDEX_SEED)
    snapshot_path = tmp_path / "candidate-snapshot.json"
    snapshot_path.write_text(json.dumps(snapshot_doc, sort_keys=True))
    assert cli_main(_export_evidence_args(tmp_path, snapshot_path)) == 0
    capsys.readouterr()

    store = EvidenceStore(tmp_path / "evidence")
    index = json.loads((tmp_path / "evidence" / "index.json").read_bytes())
    manifest = parse_manifest(store.get_blob(index["latest"]["manifest"]))
    outcomes = {row["hotkey"]: row["outcome"] for row in manifest["candidate_set"]["candidates"]}
    assert outcomes == {"failed-worker": "rejected"}
    # The chain still verifies end-to-end: the manifest is NOT self-rejecting.
    from cathedral.provenance import verify_and_recompute

    report_bytes = store.get_blob(manifest["score_report"]["blob"])
    verify_and_recompute(
        report_bytes=report_bytes,
        receipts_by_id={},
        registry_bytes=REGISTRY_BYTES,
        trusted_registry_keys=TRUSTED,
        report_signing_keys={"score-test-1": _public_raw(REPORT_SEED)},
        expected_network=NETWORK,
        expected_netuid=NETUID,
        expected_verifier_digest=VERIFIER_DIGEST,
        candidate_set=manifest["candidate_set"],
    )


def test_departed_zero_row_is_omitted_but_positive_departure_refuses(
    tmp_path: Path,
):
    """Round-six C5: a deregistered hotkey's zero-valued historical row is
    silently omitted (it must not permanently block future epochs); a
    POSITIVE row outside the snapshot still refuses to sign."""
    ledger, epoch_id = _completed_fresh_epoch(tmp_path)
    # 'departed-hotkey' got a zero score row via the completion universe of
    # a fresh epoch; simulate by exporting with a snapshot that excludes it.
    # The fixture's completion universe is only public-hotkey, so build the
    # zero row directly through a snapshot that omits a zero universe member
    # is impossible here — instead prove both halves against the fixture:
    # (a) positive outside snapshot refuses:
    with pytest.raises(Exception, match="POSITIVE work"):
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
            valid_from_block=100,
            valid_until_block=10_000_000_000,
            verifier_digest=VERIFIER_DIGEST,
            candidate_snapshot={
                "schema": "cathedral_candidate_snapshot_v1",
                "network": NETWORK,
                "netuid": NETUID,
                "block": 100,
                "block_hash": "0x" + "ab" * 32,
                "hotkeys": ["someone-else"],
            },
        )
    ledger.close()


def test_departed_zero_universe_member_does_not_block_export(tmp_path: Path):
    """Round-six C5 (zero half): a zero-scored universe member that later
    deregisters is omitted from the report, whose entry set stays exactly
    the signed snapshot."""
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(
        11,
        policy_registry_release=SNAPSHOT.release,
        policy_registry_digest=SNAPSHOT.digest,
        network=NETWORK,
        netuid=NETUID,
        challenge_anchor_block=100,
        challenge_anchor_hash="0x" + "ab" * 32,
    )
    ledger.complete_epoch(
        epoch_id,
        {"staying-hotkey", "departed-hotkey"},
        generated_at=NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        score_network=NETWORK,
        score_netuid=NETUID,
    )
    report = json.loads(
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
            valid_from_block=100,
            valid_until_block=10_000_000_000,
            verifier_digest=VERIFIER_DIGEST,
            candidate_snapshot={
                "schema": "cathedral_candidate_snapshot_v1",
                "network": NETWORK,
                "netuid": NETUID,
                "block": 100,
                "block_hash": "0x" + "ab" * 32,
                "hotkeys": ["staying-hotkey"],  # departed-hotkey deregistered
            },
        )
    )
    assert [entry["miner_hotkey"] for entry in report["entries"]] == ["staying-hotkey"]
    ledger.close()


def test_report_window_cannot_start_before_the_anchored_block(tmp_path: Path):
    """Round-six C3: producer refuses valid_from_block < snapshot.block, and
    the verifier rejects a re-signed report violating the same bound."""
    from cathedral.score_class import ScoreClassError, _sign_report

    ledger, epoch_id = _completed_fresh_epoch(tmp_path)
    with pytest.raises(ScoreClassError, match="precedes the anchored"):
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
            valid_from_block=99,
            valid_until_block=10_000_000_000,
            verifier_digest=VERIFIER_DIGEST,
            candidate_snapshot=CANDIDATE_SNAPSHOT_DOC,
        )
    report = export_score_class_report(
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
        valid_from_block=100,
        valid_until_block=10_000_000_000,
        verifier_digest=VERIFIER_DIGEST,
        candidate_snapshot=CANDIDATE_SNAPSHOT_DOC,
    )
    ledger.close()
    document = json.loads(report)
    document.pop("report_id", None)
    document.pop("signature", None)
    document["valid_from_block"] = 50
    forged = _sign_report(document, REPORT_SEED)
    from cathedral.provenance import ProvenanceError, verify_and_recompute

    with pytest.raises(ProvenanceError, match="precedes the anchored"):
        verify_and_recompute(
            report_bytes=forged,
            receipts_by_id={},
            registry_bytes=REGISTRY_BYTES,
            trusted_registry_keys=TRUSTED,
            report_signing_keys={"score-test-1": _public_raw(REPORT_SEED)},
            expected_network=NETWORK,
            expected_netuid=NETUID,
            expected_verifier_digest=VERIFIER_DIGEST,
        )


def test_fetch_recomputes_the_remaining_deadline_after_dns(monkeypatch):
    """Round-six C6: the connect phase must run under the remaining
    command-wide budget as recomputed AFTER DNS — never the original
    per-call ceiling."""
    import socket
    import time

    from cathedral.cli import _bounded_https_fetch, _FetchBudget

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, 0, 6, "", ("34.71.88.140", 443))],
    )
    captured: dict = {}

    def fake_create_connection(address, timeout):
        captured["timeout"] = timeout
        raise OSError("stop before any real connection")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    budget = _FetchBudget(deadline_seconds=0.5)
    time.sleep(0.3)  # most of the command budget is already consumed
    with pytest.raises(OSError, match="stop before"):
        _bounded_https_fetch("https://evidence.example/index.json", budget=budget, timeout=30.0)
    assert captured["timeout"] < 0.25  # remaining budget, NOT the 30s ceiling


def test_bounded_local_reads_fail_closed(tmp_path: Path):
    """Round-six C7: symlinks, non-regular files, and oversized inputs are
    rejected by the O_NOFOLLOW bounded reader used for controlled envelopes
    and verifier binaries."""
    from cathedral.cli import _read_bounded_local_file

    real = tmp_path / "artifact.bin"
    real.write_bytes(b"12345")
    assert _read_bounded_local_file(real, 5, "artifact") == b"12345"
    with pytest.raises(ValueError, match="bounded size limit"):
        _read_bounded_local_file(real, 4, "artifact")
    link = tmp_path / "link.bin"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="opened safely"):
        _read_bounded_local_file(link, 100, "artifact")
    with pytest.raises(ValueError, match="regular file"):
        _read_bounded_local_file(tmp_path, 100, "artifact")
    with pytest.raises(ValueError, match="opened safely"):
        _read_bounded_local_file(tmp_path / "missing.bin", 100, "artifact")


# ---------------------------------------------------------------------------
# Codex launch-hardening regressions (findings 2-8)
# ---------------------------------------------------------------------------


def test_artifact_and_byte_budgets_are_coherent_with_the_manifest_grammar():
    """Repair 7: the manifest grammar and the verifier's aggregate budget
    are ONE derived contract. The worst-case maximal valid epoch — every
    artifact at its per-kind cap, FULL mode included — must fit the 64 MiB
    aggregate and the artifact ceiling; one receipt past the grammar bound
    refuses. No cap here is ever multi-gigabyte."""
    from cathedral import replay, workproof
    from cathedral.cli import COMMAND_ARTIFACT_OVERHEAD, MAX_COMMAND_ARTIFACTS, _FetchBudget
    from cathedral.evidence import (
        MAX_CONTROLLED_ENVELOPE_BYTES,
        MAX_MANIFEST_RECEIPTS,
        MAX_RECEIPT_ARTIFACT_BYTES,
        MAX_VERIFIER_ARTIFACT_BYTES,
        MAX_WORK_ITEM_ARTIFACT_BYTES,
        PER_VERIFIED_CANDIDATE_BYTES,
        VERIFY_AGGREGATE_BUDGET_BYTES,
        VERIFY_FIXED_OVERHEAD_BYTES,
    )
    from cathedral.receipt import MAX_RECEIPT_BYTES

    # Byte coherence: worst-case fixed overhead plus the supported verified
    # cardinality at worst-case per-candidate cost fits the aggregate.
    worst_case = VERIFY_FIXED_OVERHEAD_BYTES + (
        MAX_MANIFEST_RECEIPTS * PER_VERIFIED_CANDIDATE_BYTES
    )
    assert worst_case <= VERIFY_AGGREGATE_BUDGET_BYTES
    assert (
        VERIFY_FIXED_OVERHEAD_BYTES + (MAX_MANIFEST_RECEIPTS + 1) * PER_VERIFIED_CANDIDATE_BYTES
        > VERIFY_AGGREGATE_BUDGET_BYTES
    )  # the derived bound is tight, not arbitrary
    assert MAX_MANIFEST_RECEIPTS >= 16  # launch-safe floor
    assert VERIFY_AGGREGATE_BUDGET_BYTES == 64 * 1024 * 1024  # never raised
    # Per-kind caps stay within the defensive parser ceilings they feed.
    assert MAX_VERIFIER_ARTIFACT_BYTES == replay.MAX_VERIFIER_BINARY_BYTES
    assert MAX_CONTROLLED_ENVELOPE_BYTES <= replay.MAX_ENVELOPE_BYTES
    assert MAX_RECEIPT_ARTIFACT_BYTES <= MAX_RECEIPT_BYTES
    assert MAX_WORK_ITEM_ARTIFACT_BYTES <= workproof.MAX_WORK_ARTIFACT_BYTES

    # Artifact-count coherence: index + manifest + registry + report +
    # verifier + vector + snapshot overhead, plus receipt + two work
    # artifacts + one envelope per verified candidate.
    fixed_overhead = 7
    supported_maximum = fixed_overhead + 4 * MAX_MANIFEST_RECEIPTS
    assert COMMAND_ARTIFACT_OVERHEAD >= fixed_overhead
    assert MAX_COMMAND_ARTIFACTS >= supported_maximum

    budget = _FetchBudget(deadline_seconds=60)
    for _ in range(supported_maximum):
        budget.start_artifact()  # the maximal valid epoch fits

    boundary = _FetchBudget(deadline_seconds=60)
    for _ in range(MAX_COMMAND_ARTIFACTS):
        boundary.start_artifact()
    with pytest.raises(ValueError, match="artifact cap"):
        boundary.start_artifact()  # one over the ceiling refuses


def test_manifest_candidate_and_receipt_cardinality_boundaries():
    """Repair 7 grammar half: the manifest accepts exactly the supported
    cardinality and rejects one over it — for candidate rows, receipt
    rows, AND the count of verified outcomes (each verified candidate
    costs receipt + work artifacts + envelope in the byte budget)."""
    from cathedral.evidence import MAX_MANIFEST_CANDIDATES, MAX_MANIFEST_RECEIPTS

    registry_blob = digest_bytes(REGISTRY_BYTES)

    def build(candidate_count: int, receipt_count: int = 0, verified_count: int = 0) -> bytes:
        return build_manifest(
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
                    "receipt_id": "receipt-sha256:" + f"{index:064x}",
                    "hotkey": f"miner-{index}",
                    "blob": "sha256:" + "4" * 64,
                    "work_item_blob": "sha256:" + "6" * 64,
                    "result_blob": "sha256:" + "7" * 64,
                }
                for index in range(receipt_count)
            ],
            candidate_set={
                "source": "sn39_metagraph",
                "network": NETWORK,
                "netuid": NETUID,
                "block": 100,
                "block_hash": "0x" + "ab" * 32,
                "candidates": [
                    {
                        "hotkey": f"miner-{index}",
                        "outcome": ("verified" if index < verified_count else "rejected"),
                        "reason": (
                            "receipt_verified" if index < verified_count else "no_verified_work"
                        ),
                    }
                    for index in range(candidate_count)
                ],
            },
            attestations=[],
            wire_report_sha256=None,
        )

    parse_manifest(build(MAX_MANIFEST_CANDIDATES))
    with pytest.raises(EvidenceError, match="candidates list is invalid"):
        build(MAX_MANIFEST_CANDIDATES + 1)
    parse_manifest(build(1, receipt_count=MAX_MANIFEST_RECEIPTS))
    with pytest.raises(EvidenceError, match="receipts is invalid"):
        build(1, receipt_count=MAX_MANIFEST_RECEIPTS + 1)
    parse_manifest(build(MAX_MANIFEST_RECEIPTS, verified_count=MAX_MANIFEST_RECEIPTS))
    with pytest.raises(EvidenceError, match="verified-candidate count exceeds"):
        build(MAX_MANIFEST_RECEIPTS + 1, verified_count=MAX_MANIFEST_RECEIPTS + 1)


def test_cli_verify_artifact_accounting_three_per_receipt_plus_overhead(
    tmp_path: Path, exported_evidence, capsys, monkeypatch
):
    """Finding 2 accounting proof on the REAL command path: a local verify
    of a one-receipt epoch consumes exactly index + manifest + registry +
    report (4) plus three artifacts for the receipt — a ceiling one short
    fails on the artifact cap, the exact ceiling verifies."""
    import cathedral.cli as cli_module

    evidence_dir, summary = exported_evidence
    assert summary["receipts"] == 1
    needed = 4 + 3 * summary["receipts"]

    monkeypatch.setattr(cli_module, "MAX_COMMAND_ARTIFACTS", needed - 1)
    code = cli_main(_verify_cli_args(tmp_path, evidence_dir))
    output = capsys.readouterr().out
    assert code == 1
    assert "artifact cap" in output

    monkeypatch.setattr(cli_module, "MAX_COMMAND_ARTIFACTS", needed)
    code = cli_main(_verify_cli_args(tmp_path, evidence_dir) + ["--allow-receipts-only"])
    capsys.readouterr()
    assert code == 0


def test_export_evidence_requires_source_revision_before_any_publication(tmp_path: Path, capsys):
    """Finding 3: a non-development export without a valid --source-revision
    fails BEFORE any publication side effect — the immutable manifest/epoch
    copy is never written with a null revision that production verification
    would reject forever — and the corrected retry publishes cleanly."""
    evidence_dir = _prepared_export_workspace(tmp_path)
    snapshot_path = tmp_path / "candidate-snapshot.json"
    arguments = _export_evidence_args(tmp_path, snapshot_path)
    position = arguments.index("--source-revision")
    del arguments[position : position + 2]

    assert cli_main(arguments) != 0
    assert "source-revision" in capsys.readouterr().err
    assert not evidence_dir.exists()  # nothing was published at all

    assert cli_main([*arguments, "--source-revision", "NOT-HEX"]) != 0
    assert "source-revision" in capsys.readouterr().err
    assert not evidence_dir.exists()

    # The epoch is NOT bricked: the corrected export succeeds afterwards.
    assert cli_main([*arguments, "--source-revision", "abc1234"]) == 0
    capsys.readouterr()
    assert (evidence_dir / "index.json").exists()

    # Development mode keeps its explicit relaxation: the manifest records
    # a null source_revision (and only development verification accepts it).
    development_dir = tmp_path / "evidence-dev"
    development_arguments = _export_evidence_args(
        tmp_path, snapshot_path, evidence_dir=development_dir
    )
    position = development_arguments.index("--source-revision")
    del development_arguments[position : position + 2]
    assert cli_main([*development_arguments, "--development"]) == 0
    capsys.readouterr()
    index_document = json.loads((development_dir / "index.json").read_bytes())
    manifest_document = parse_manifest(
        EvidenceStore(development_dir).get_blob(index_document["latest"]["manifest"])
    )
    assert manifest_document["source_revision"] is None


VECTOR_SEED = bytes(range(128, 160))


WIRE_BURN_HOTKEY = "burn-destination-hotkey"


def _signed_wire_vector(rows: list[dict], *, source_epoch: int = 11) -> bytes:
    """A publisher wire vector signed exactly as the thin validator (and
    _verify_wire_vector) expects — ed25519 over sorted compact JSON minus
    ``signature`` — carrying the REAL validated_supply_v1 launch shape:
    pre-burn confidential_primary rows, burn_uid null with the configured
    burn hotkey, fixed 10% burn, and the signed policy/ingest blocks."""
    positive = any(float(row.get("weight") or 0.0) > 0.0 for row in rows)
    body = {
        "key_id": "cathedral-weight-policy",
        "network": NETWORK,
        "netuid": NETUID,
        "vector_id": "vector-test-1",
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "burn_snapshot": {
            "burn_uid": None,
            "burn_hotkey": WIRE_BURN_HOTKEY,
            "forced_burn_percentage": 10.0,
        },
        "policy_metadata": {
            "score_source": "confidential_primary:cathedral_confidential_tdx",
            "validated_supply": {
                "contract_version": "v1",
                "intel_tdx_allocation": 0.90,
                "verified_gpu_allocation": 0.10,
                "verified_gpu_admitted": False,
                "burn_hotkey": WIRE_BURN_HOTKEY,
            },
            "confidential_primary": {
                "contract_version": "v1",
                "mode": "confidential_primary",
                "source": "cathedral_confidential_tdx",
                "base_mass": 0.0,
                "confidential_mass": 1.0 if positive else 0.0,
                "complete": True,
                "fresh": True,
                "confirmed": True,
            },
            "external_scores": {
                "enabled": True,
                "source": "cathedral_confidential_tdx",
                "mode": "confidential_primary",
                "latest_epoch": source_epoch,
                "latest_complete": True,
                "latest_fresh": True,
                "latest_report_sha256": "11" * 32,
            },
        },
        "weights": [dict(row) for row in rows],
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    signature = Ed25519PrivateKey.from_private_bytes(VECTOR_SEED).sign(canonical)
    payload = dict(body)
    payload["signature"] = base64.b64encode(signature).decode("ascii")
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _vector_row(hotkey: str, external: float) -> dict:
    return {
        "miner_hotkey": hotkey,
        "weight": external,
        "base_component": 0.0,
        "external_component": external,
    }


def test_vector_mismatch_stays_fail_and_never_reserves_fences(
    tmp_path: Path, exported_evidence, capsys, monkeypatch
):
    """Finding 4: a receipts-only run whose signed vector DISAGREES with the
    recomputation is a concrete FAIL — never reclassified as NOT_PROVEN,
    never reserving anti-rollback fences. Only an otherwise-passing partial
    chain is NOT_PROVEN (and may reserve fences as before)."""
    import cathedral.cli as cli_module

    evidence_dir, _summary = exported_evidence
    public_hex = (
        Ed25519PrivateKey.from_private_bytes(VECTOR_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    state_path = tmp_path / "verifier-state.json"
    audit_path = tmp_path / "audit-vector.json"

    served = {"payload": _signed_wire_vector([_vector_row("unverified-hotkey", 1.0)])}
    real_fetch = cli_module._bounded_https_fetch

    def fake_fetch(url: str, **kwargs):
        assert url.endswith("/v1/validator/weights/next")
        return served["payload"]

    monkeypatch.setattr(cli_module, "_bounded_https_fetch", fake_fetch)
    arguments = _verify_cli_args(tmp_path, evidence_dir) + [
        "--publisher-url",
        "https://publisher.example",
        "--weight-policy-public-key-hex",
        public_hex,
        "--state-file",
        str(state_path),
        "--audit-out",
        str(audit_path),
        "--allow-receipts-only",
    ]

    code = cli_main(arguments)
    output = capsys.readouterr().out
    events = [json.loads(line) for line in output.strip().splitlines()]
    codes = [event["event"] for event in events]
    audit = json.loads(audit_path.read_text())

    assert code == 1  # even with --allow-receipts-only: a FAIL is a FAIL
    assert audit["result"] == "FAIL"
    assert audit["assurance"] == "receipts_only"
    assert audit["vector_agrees"] is False
    assert "VECTOR_COMPARE_MISMATCH" in codes
    assert events[-1]["event"] == "PROVENANCE_RESULT"
    assert events[-1]["status"] == "FAIL"
    assert all(event["status"] != "NOT_PROVEN" for event in events)
    assert not state_path.exists()  # fences are NEVER reserved on failure

    # Control: the agreeing vector on the same chain is classified
    # NOT_PROVEN (receipts-only) and reserves fences exactly as before.
    served["payload"] = _signed_wire_vector([_vector_row("public-hotkey", 1.0)])
    code = cli_main(arguments)
    output = capsys.readouterr().out
    events = [json.loads(line) for line in output.strip().splitlines()]
    audit = json.loads(audit_path.read_text())
    assert code == 0
    assert audit["result"] == "NOT_PROVEN"
    assert audit["vector_agrees"] is True
    assert any(event["event"] == "VECTOR_COMPARE_AGREES" for event in events)
    assert events[-1]["status"] == "NOT_PROVEN"
    assert state_path.exists()
    assert real_fetch is not cli_module._bounded_https_fetch


def test_bounded_local_reads_charge_the_shared_budget(tmp_path: Path):
    """Finding 5 unit half: budget-charged local reads consume an artifact
    slot BEFORE the open and charge every chunk against the aggregate byte
    cap DURING the read — never after full materialization."""
    from cathedral.cli import _FetchBudget, _read_bounded_local_file

    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"0123456789")

    spent = _FetchBudget(deadline_seconds=60, max_total_bytes=5, max_artifacts=4)
    with pytest.raises(ValueError, match="aggregate byte cap"):
        _read_bounded_local_file(artifact, 100, "artifact", budget=spent)

    exhausted = _FetchBudget(deadline_seconds=60, max_total_bytes=100, max_artifacts=0)
    with pytest.raises(ValueError, match="artifact cap"):
        _read_bounded_local_file(artifact, 100, "artifact", budget=exhausted)

    healthy = _FetchBudget(deadline_seconds=60, max_total_bytes=100, max_artifacts=2)
    assert _read_bounded_local_file(artifact, 100, "artifact", budget=healthy) == b"0123456789"
    assert healthy.bytes_remaining == 90
    assert healthy.artifacts_remaining == 1


def test_local_evidence_reads_reject_symlinks_and_oversize(
    tmp_path: Path, exported_evidence, capsys
):
    """Finding 5 CLI half: --evidence-dir index and blob reads are bounded
    O_NOFOLLOW regular-file reads. A symlinked artifact with the CORRECT
    bytes still refuses; an oversized artifact fails the per-artifact bound
    instead of being materialized whole."""
    import shutil

    evidence_dir, summary = exported_evidence
    store = EvidenceStore(evidence_dir)
    manifest = parse_manifest(store.get_blob(summary["manifest"]))
    registry_blob_name = manifest["policy_registry"]["blob"].split(":", 1)[1]
    oversized = b"\x00" * (4 * 1024 * 1024 + 1)

    blob_symlink = tmp_path / "evidence-blob-symlink"
    shutil.copytree(evidence_dir, blob_symlink)
    target = blob_symlink / "blobs" / "sha256" / registry_blob_name
    aside = tmp_path / "aside-registry.bin"
    shutil.move(target, aside)
    target.symlink_to(aside)
    code = cli_main(_verify_cli_args(tmp_path, blob_symlink))
    output = capsys.readouterr().out
    assert code == 1
    assert "cannot be opened safely" in output

    blob_oversize = tmp_path / "evidence-blob-oversize"
    shutil.copytree(evidence_dir, blob_oversize)
    (blob_oversize / "blobs" / "sha256" / registry_blob_name).write_bytes(oversized)
    code = cli_main(_verify_cli_args(tmp_path, blob_oversize))
    output = capsys.readouterr().out
    assert code == 1
    assert "bounded size limit" in output

    index_symlink = tmp_path / "evidence-index-symlink"
    shutil.copytree(evidence_dir, index_symlink)
    index_path = index_symlink / "index.json"
    aside_index = tmp_path / "aside-index.json"
    shutil.move(index_path, aside_index)
    index_path.symlink_to(aside_index)
    code = cli_main(_verify_cli_args(tmp_path, index_symlink))
    output = capsys.readouterr().out
    assert code == 1
    assert "cannot be opened safely" in output

    index_oversize = tmp_path / "evidence-index-oversize"
    shutil.copytree(evidence_dir, index_oversize)
    (index_oversize / "index.json").write_bytes(oversized)
    code = cli_main(_verify_cli_args(tmp_path, index_oversize))
    output = capsys.readouterr().out
    assert code == 1
    assert "bounded size limit" in output


def test_export_evidence_releases_the_index_lock_on_failure_then_retries(tmp_path: Path, capsys):
    """Finding 6: a failure INSIDE the exclusive index critical section
    releases the flock and its descriptor (context manager), so the SAME
    process can retry successfully — a leaked exclusive flock would block
    that retry forever."""
    import fcntl
    import os

    evidence_dir = _prepared_export_workspace(tmp_path)
    snapshot_path = tmp_path / "candidate-snapshot.json"
    arguments = _export_evidence_args(tmp_path, snapshot_path)

    # Force the failure after the lock is taken: the immutable epoch copy
    # for source_epoch 11 already exists with foreign bytes.
    epochs_dir = evidence_dir / "epochs"
    epochs_dir.mkdir(parents=True)
    (epochs_dir / "11.json").write_bytes(b"foreign-bytes")
    assert cli_main(arguments) != 0
    assert "already exists with other content" in capsys.readouterr().err

    # The lock must be FREE in this same process: a non-blocking exclusive
    # probe succeeds only if the failed export released its flock.
    lock_path = evidence_dir / ".index.lock"
    probe = os.open(lock_path, os.O_WRONLY)
    try:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(probe, fcntl.LOCK_UN)
    finally:
        os.close(probe)

    (epochs_dir / "11.json").unlink()
    assert cli_main(arguments) == 0
    capsys.readouterr()
    assert (evidence_dir / "index.json").exists()


def test_tls_handshake_deadline_is_recomputed_after_tcp(monkeypatch):
    """Finding 7: TCP connect time consumes the shared budget, so the TLS
    handshake must run under the RECOMPUTED absolute remainder — the stale
    pre-connect timeout would silently extend the deadline."""
    import socket
    import ssl
    import time

    from cathedral.cli import _bounded_https_fetch

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, 0, 6, "", ("34.71.88.140", 443))],
    )
    captured: dict = {}

    class _FakeRaw:
        def __init__(self, timeout):
            self._timeout = timeout

        def settimeout(self, value):
            self._timeout = value

        def gettimeout(self):
            return self._timeout

        def close(self):
            pass

    def fake_create_connection(address, timeout):
        captured["tcp_timeout"] = timeout
        time.sleep(0.4)  # the TCP phase consumes real wall-clock budget
        return _FakeRaw(timeout)

    class _WrapRecorder:
        def wrap_socket(self, sock, server_hostname=None):
            captured["tls_timeout"] = sock.gettimeout()
            raise RuntimeError("stop-at-wrap")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    monkeypatch.setattr(ssl, "create_default_context", lambda: _WrapRecorder())

    with pytest.raises(RuntimeError, match="stop-at-wrap"):
        _bounded_https_fetch("https://evidence.example/index.json", timeout=2.0)
    # The TLS phase saw a bound REDUCED by the 0.4s the TCP phase consumed.
    assert captured["tls_timeout"] > 0
    assert captured["tls_timeout"] < captured["tcp_timeout"] - 0.3


def test_trickled_body_cannot_outlive_the_absolute_deadline(monkeypatch):
    """Finding 8 deterministic counterexample: a server trickling one byte
    per 0.25s never trips a per-receive inactivity timeout, but the fetch
    must still die at its ABSOLUTE deadline. Before the one-receive loop,
    HTTPResponse.read(65536) kept receiving for hours (65536 bytes x 0.25s
    with the inactivity timer re-armed by every byte)."""
    import socket
    import ssl
    import threading
    import time

    from cathedral.cli import _bounded_https_fetch

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        try:
            connection, _address = listener.accept()
        except OSError:
            return
        with connection:
            connection.settimeout(5.0)
            try:
                request = b""
                while b"\r\n\r\n" not in request:
                    request += connection.recv(1024)
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/octet-stream\r\n"
                    b"Content-Length: 65536\r\n\r\n"
                )
                while not stop.is_set():
                    connection.sendall(b"x")  # one byte per interval, forever
                    if stop.wait(0.25):
                        break
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    class _NoTls:
        def wrap_socket(self, sock, server_hostname=None):
            return sock  # transport logic under test is TLS-agnostic

    monkeypatch.setattr(ssl, "create_default_context", lambda: _NoTls())
    started = time.monotonic()
    try:
        with pytest.raises((ValueError, OSError)):
            _bounded_https_fetch(
                f"https://127.0.0.1:{port}/blobs/sha256/deadbeef",
                allow_private=True,
                timeout=1.2,
            )
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=5)
    elapsed = time.monotonic() - started
    # Dead at ~the 1.2s absolute deadline — not after 65536 trickled bytes.
    assert elapsed < 5.0, elapsed
    assert elapsed > 0.9, elapsed


# ---------------------------------------------------------------------------
# Launch repairs: mechanism pair (2), fence ordering (4), FULL-mode budget
# (6), and the export/verify receipt-budget boundary (7).
# ---------------------------------------------------------------------------


def test_manifest_carries_the_exact_frozen_mechanism_pair(tmp_path: Path, exported_evidence):
    """Repair 2 producer half: the published manifest pins BOTH halves of
    the mechanism pair, and export refuses any unsupported revision."""
    evidence_dir, _summary = exported_evidence
    manifest = parse_manifest((evidence_dir / "epochs" / "11.json").read_bytes())
    assert manifest["reward_mechanism"] == {"id": "validated_supply_v1", "revision": 1}


def test_export_refuses_an_unsupported_mechanism_pair(tmp_path: Path, capsys):
    evidence_dir = _prepared_export_workspace(tmp_path)
    snapshot_path = tmp_path / "candidate-snapshot.json"
    code = cli_main(_export_evidence_args(tmp_path, snapshot_path, mechanism_revision="2"))
    assert code != 0
    assert "not a frozen supported pair" in capsys.readouterr().err
    assert not evidence_dir.exists()  # refused before any publication


def test_verify_rejects_a_mismatched_mechanism_revision_before_recompute(
    tmp_path: Path, exported_evidence, capsys
):
    """Repair 2 verifier half: an unsupported revision fails BEFORE any
    recomputation and BEFORE any fence reservation."""
    evidence_dir, _summary = exported_evidence
    state_path = tmp_path / "revision-state.json"
    code = cli_main(
        _verify_cli_args(tmp_path, evidence_dir)
        + ["--mechanism-revision", "2", "--state-file", str(state_path)]
    )
    output = capsys.readouterr().out
    events = [json.loads(line) for line in output.strip().splitlines()]
    assert code == 1
    assert any("does not match the pinned pair" in event.get("detail", "") for event in events)
    assert all(event["event"] != "CHAIN_VERIFIED_AND_RECOMPUTED" for event in events)
    assert not state_path.exists()  # never reserved


def test_reservation_conflict_emits_only_terminal_fail(
    tmp_path: Path, exported_evidence, capsys, monkeypatch
):
    """Repair 4: a fence-reservation conflict discovered AFTER every check
    passed (a concurrent verifier won the race) emits NO accepting terminal
    event — no PASS, no NOT_PROVEN — only a terminal FAIL, and the audit
    file reports FAIL, never acceptance."""
    import cathedral.cli as cli_module

    evidence_dir, _summary = exported_evidence
    state_path = tmp_path / "conflict-state.json"
    audit_path = tmp_path / "conflict-audit.json"
    real_reserve = cli_module._reserve_fences

    def racing_reserve(fence_path, **kwargs):
        # A concurrent run commits a HIGHER high-water in the window between
        # this run's checks and its reservation; the atomic reserve must
        # then refuse, and no accepting event may already have been emitted.
        fence_path.write_text(
            json.dumps(
                {"index_source_epoch": 999, "index_manifest": "sha256:" + "f" * 64},
                sort_keys=True,
            )
        )
        return real_reserve(fence_path, **kwargs)

    monkeypatch.setattr(cli_module, "_reserve_fences", racing_reserve)
    code = cli_main(
        _verify_cli_args(tmp_path, evidence_dir)
        + [
            "--allow-receipts-only",
            "--state-file",
            str(state_path),
            "--audit-out",
            str(audit_path),
        ]
    )
    output = capsys.readouterr().out
    events = [json.loads(line) for line in output.strip().splitlines()]
    assert code == 1
    assert all(event["event"] != "PROVENANCE_RESULT" for event in events)
    assert all(event["status"] != "NOT_PROVEN" for event in events)
    assert all(event["status"] != "PASS" or event["stage"] != "result" for event in events)
    assert events[-1]["event"] == "PROVENANCE_FAILED"
    assert events[-1]["status"] == "FAIL"
    assert "rollback" in events[-1]["detail"]
    audit = json.loads(audit_path.read_text())
    assert audit["result"] == "FAIL"
    assert "rollback" in audit["error"]


def _full_mode_workspace(tmp_path: Path, capsys) -> tuple[Path, Path, Path, Path]:
    """A verifier-bound export plus the controlled/independent inputs FULL
    mode reads locally: (evidence dir, controlled dir, verifier, snapshot)."""
    _prepared_export_workspace(tmp_path)
    verifier_path = tmp_path / "verifier.bin"
    verifier_path.write_bytes(b"\x7fELF-test-bytes")
    snapshot_path = tmp_path / "candidate-snapshot.json"
    full_dir = tmp_path / "evidence-full"
    assert (
        cli_main(
            _export_evidence_args(
                tmp_path,
                snapshot_path,
                evidence_dir=full_dir,
                verifier_binary=str(verifier_path),
                verifier_production_path="/opt/cathedral/bin/verifier",
            )
        )
        == 0
    )
    capsys.readouterr()
    controlled = tmp_path / "controlled"
    controlled.mkdir()
    independent_path = tmp_path / "independent-snapshot.json"
    independent_path.write_text(
        json.dumps(CANDIDATE_SNAPSHOT_DOC, sort_keys=True, separators=(",", ":"))
    )
    return full_dir, controlled, verifier_path, independent_path


def _full_mode_arguments(
    tmp_path: Path, full_dir: Path, controlled: Path, verifier_path: Path, independent_path: Path
) -> list[str]:
    return [
        *_verify_cli_args(tmp_path, full_dir),
        "--controlled-dir",
        str(controlled),
        "--verifier-binary",
        str(verifier_path),
        "--independent-candidate-snapshot",
        str(independent_path),
    ]


def test_full_mode_local_inputs_share_the_command_budget(tmp_path: Path, capsys, monkeypatch):
    """Repair 6: the independent snapshot, the local verifier binary, and
    every controlled envelope (streamed lazily, one at a time) are charged
    to the SAME command artifact/byte/deadline budget as public evidence
    reads — positive path plus symlink, oversize, and aggregate-cap
    counterexamples."""
    import dataclasses

    import cathedral.cli as cli_module
    from cathedral import provenance as provenance_module
    from cathedral.evidence import MAX_CONTROLLED_ENVELOPE_BYTES

    full_dir, controlled, verifier_path, independent_path = _full_mode_workspace(tmp_path, capsys)
    envelope_path = controlled / ("e" * 64 + ".json")
    envelope_path.write_bytes(b"{}")
    arguments = _full_mode_arguments(
        tmp_path, full_dir, controlled, verifier_path, independent_path
    )

    budgets: list = []
    real_budget = cli_module._FetchBudget

    def tracking_budget(**kwargs):
        budget = real_budget(**kwargs)
        budgets.append(budget)
        return budget

    monkeypatch.setattr(cli_module, "_FetchBudget", tracking_budget)

    streamed: dict = {}

    def spy(result, **kwargs):
        # Exercise the CLI-built lazy loader exactly as the replay loop
        # would: one .get() per positive miner, at replay time.
        streamed["envelope"] = kwargs["envelopes_by_hotkey"].get("public-hotkey")
        return dataclasses.replace(result, assurance_level="full")

    monkeypatch.setattr(provenance_module, "replay_positive_miners", spy)

    # Positive path: everything within budget verifies, the envelope is
    # streamed through the loader, and exactly index + manifest + registry
    # + report + receipt + 2 work artifacts + snapshot + verifier +
    # envelope = 10 artifact slots were consumed.
    assert cli_main(arguments) == 0
    capsys.readouterr()
    assert streamed["envelope"] == b"{}"
    consumed = cli_module.MAX_COMMAND_ARTIFACTS - budgets[0].artifacts_remaining
    assert consumed == 10
    assert budgets[0].bytes_remaining < cli_module.MAX_COMMAND_FETCH_BYTES

    # Symlinked envelope: refused at the read, fail closed.
    envelope_path.unlink()
    envelope_path.symlink_to(verifier_path)
    budgets.clear()
    code = cli_main(arguments)
    output = capsys.readouterr().out
    assert code == 1
    assert "cannot be opened safely" in output

    # Oversized envelope: the per-artifact disclosure cap refuses.
    envelope_path.unlink()
    envelope_path.write_bytes(b"x" * (MAX_CONTROLLED_ENVELOPE_BYTES + 1))
    budgets.clear()
    code = cli_main(arguments)
    output = capsys.readouterr().out
    assert code == 1
    assert "exceeds the bounded size limit" in output

    # Aggregate byte cap: an in-cap envelope still cannot exceed the shared
    # command budget mid-read.
    envelope_path.unlink()
    envelope_path.write_bytes(b"y" * 200_000)
    budgets.clear()
    monkeypatch.setattr(
        cli_module,
        "_FetchBudget",
        lambda **kwargs: real_budget(**{**kwargs, "max_total_bytes": 100_000}),
    )
    code = cli_main(arguments)
    output = capsys.readouterr().out
    assert code == 1
    assert "aggregate byte cap" in output


def test_full_mode_symlinked_independent_snapshot_is_refused(tmp_path: Path, capsys, monkeypatch):
    import cathedral.cli as cli_module  # noqa: F401 - parity with sibling test

    full_dir, controlled, verifier_path, independent_path = _full_mode_workspace(tmp_path, capsys)
    (controlled / ("e" * 64 + ".json")).write_bytes(b"{}")
    independent_path.unlink()
    independent_path.symlink_to(verifier_path)
    code = cli_main(
        _full_mode_arguments(tmp_path, full_dir, controlled, verifier_path, independent_path)
    )
    output = capsys.readouterr().out
    assert code == 1
    assert "cannot be opened safely" in output


def test_budget_deadline_covers_budget_charged_local_reads(tmp_path: Path):
    """Repair 6 deadline half: a budget-charged local read (the same path
    envelopes, the snapshot, and the verifier binary use) refuses once the
    ONE command deadline is exhausted."""
    from cathedral.cli import _FetchBudget, _read_bounded_local_file

    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"0123456789")
    budget = _FetchBudget(deadline_seconds=60)
    budget.deadline = budget._clock() - 1.0  # the single deadline has passed
    with pytest.raises(ValueError, match="total deadline"):
        _read_bounded_local_file(artifact, 100, "artifact", budget=budget)


def test_receipt_budget_boundary_is_enforced_at_export_and_verify(
    tmp_path: Path, exported_evidence, capsys, monkeypatch
):
    """Repair 7 on the real command paths: with the receipt budget forced
    to zero, the SAME constant makes export refuse to build the manifest
    and verify refuse to accept a previously exported one."""
    from cathedral import evidence as evidence_module

    evidence_dir, summary = exported_evidence
    assert summary["receipts"] == 1

    monkeypatch.setattr(evidence_module, "MAX_MANIFEST_RECEIPTS", 0)
    code = cli_main(_verify_cli_args(tmp_path, evidence_dir) + ["--allow-receipts-only"])
    output = capsys.readouterr().out
    assert code == 1
    assert "receipts is invalid" in output

    export_dir = tmp_path / "evidence-over-budget"
    snapshot_path = tmp_path / "candidate-snapshot.json"
    code = cli_main(_export_evidence_args(tmp_path, snapshot_path, evidence_dir=export_dir))
    assert code != 0
    assert "receipts is invalid" in capsys.readouterr().err
    # Content-addressed blobs may exist, but nothing was PUBLISHED: no
    # signed index and no immutable epoch manifest copy.
    assert not (export_dir / "index.json").exists()
    assert not (export_dir / "epochs").exists()


def test_retention_refuses_an_oversized_controlled_envelope(tmp_path: Path):
    """Repair 7 retention half: an envelope past the launch disclosure cap
    is refused AT RETENTION TIME, so an unfetchable envelope can never
    silently unprove a published epoch later."""
    from cathedral.evidence import MAX_CONTROLLED_ENVELOPE_BYTES, RetentionStore

    store = RetentionStore(tmp_path / "retention")
    with pytest.raises(EvidenceError, match="disclosure cap"):
        store.retain(
            b"x" * (MAX_CONTROLLED_ENVELOPE_BYTES + 1),
            kind="admission_evidence",
            hotkey="miner",
        )
    digest = store.retain(b"x" * 1024, kind="admission_evidence", hotkey="miner")
    assert digest.startswith("sha256:")
