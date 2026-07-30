"""Enrollment under the signed admission policy (selected and open modes).

Enrollment is permission to be tested. Every test here asserts against the
pending record and the gate outcome; none of it touches a score or a weight,
and `test_enrollment_never_produces_a_verified_worker` states that directly.

Covers:
  1. Selected and open happy paths, both landing in PENDING only.
  2. Unregistered hotkey, non-selected coldkey, coldkey spoof, unresolvable
     coldkey.
  3. Hotkey rotation under one coldkey; a rotation that moves a hotkey to a
     different coldkey.
  4. Stale and replayed signatures, expired requests, endpoint substitution,
     wrong profile, wrong network/netuid, malformed input.
  5. Caps: per-coldkey endpoints, total workers, concurrent duplicates,
     idempotent retries.
  6. Policy unavailability, rollback, and expiry all fail closed.
  7. No downgrade: a v1 request cannot satisfy a policy-gated service.
"""

from __future__ import annotations

import base64
import io
import json
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from substrateinterface import Keypair, KeypairType

from cathedral.admission_policy import (
    ADMISSION_POLICY_SCHEMA,
    SignedAdmissionPolicyProvider,
    sign_admission_policy,
)
from cathedral.enroll import (
    JsonHotkeyRegistrationProvider,
    RegistryApp,
    RegistryStore,
    canonical_enroll_payload,
    canonical_enroll_payload_v2,
    now_iso,
)
from cathedral.lifecycle import WorkerLifecycleState
from cathedral.policy_registry import canonical_json

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

MINER = Keypair.create_from_uri("//Miner", crypto_type=KeypairType.SR25519)
MINER_TWO = Keypair.create_from_uri("//MinerTwo", crypto_type=KeypairType.SR25519)
STRANGER = Keypair.create_from_uri("//Stranger", crypto_type=KeypairType.SR25519)

HOTKEY = MINER.ss58_address
HOTKEY_TWO = MINER_TWO.ss58_address
STRANGER_HOTKEY = STRANGER.ss58_address

COLDKEY = Keypair.create_from_uri("//Cold", crypto_type=KeypairType.SR25519).ss58_address
OTHER_COLDKEY = Keypair.create_from_uri("//Cold2", crypto_type=KeypairType.SR25519).ss58_address

SEED = bytes(range(192, 224))
KEY_ID = "cathedral-admission-enroll-test-1"
PUBLIC = (
    Ed25519PrivateKey.from_private_bytes(SEED)
    .public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
)
TRUSTED = {KEY_ID: PUBLIC}

NETWORK = "finney"
NETUID = 39
PROFILE = "cpu-tdx-sn39-v2"
ENDPOINT = "https://8.8.8.8:8443"
ENDPOINT_TWO = "https://9.9.9.9:8443"


def _text(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def policy_bytes(
    *,
    mode: str = "selected",
    coldkeys: list[str] | None = None,
    network: str = NETWORK,
    netuid: int = NETUID,
    profiles: list[str] | None = None,
    max_endpoints: int = 2,
    max_total: int = 16,
    config_version: int = 1,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> bytes:
    now = datetime.now(UTC).replace(microsecond=0)
    document = {
        "schema": ADMISSION_POLICY_SCHEMA,
        "mode": mode,
        "coldkeys": ([COLDKEY] if coldkeys is None and mode == "selected" else (coldkeys or [])),
        "network": network,
        "netuid": netuid,
        "required_profile_ids": [PROFILE] if profiles is None else profiles,
        "max_enrolled_endpoints_per_coldkey": max_endpoints,
        "max_admitted_workers_total": max_total,
        "config_version": config_version,
        "issued_at": _text(issued_at or (now - timedelta(minutes=1))),
        "expires_at": _text(expires_at or (now + timedelta(days=7))),
        "signing_key_id": KEY_ID,
    }
    return canonical_json(sign_admission_policy(document, SEED))


def snapshot_file(tmp_path: Path, mapping: dict[str, str] | list[str]) -> str:
    path = tmp_path / "registered.json"
    path.write_text(json.dumps({"hotkeys": mapping}))
    return str(path)


def build_app(
    tmp_path: Path,
    *,
    policy: bytes | None = None,
    registered: dict[str, str] | list[str] | None = None,
    production_mode: bool = True,
    store: RegistryStore | None = None,
    pinned_digest: str | None = None,
) -> tuple[RegistryApp, RegistryStore, Path]:
    policy_path = tmp_path / "admission-policy.json"
    policy_path.write_bytes(policy if policy is not None else policy_bytes())
    provider = JsonHotkeyRegistrationProvider(
        snapshot_file(
            tmp_path,
            registered if registered is not None else {HOTKEY: COLDKEY, HOTKEY_TWO: COLDKEY},
        ),
        max_age_seconds=3600,
    )
    store = store or RegistryStore(str(tmp_path / "registry.sqlite"))
    app = RegistryApp(
        store,
        registration_provider=provider,
        admission_policy=SignedAdmissionPolicyProvider(
            str(policy_path),
            TRUSTED,
            network=NETWORK,
            netuid=NETUID,
            pinned_digest=pinned_digest,
        ),
        production_mode=production_mode,
        hotkey_enroll_limit=1000,
    )
    return app, store, policy_path


def v2_payload(
    *,
    keypair: Keypair = MINER,
    hotkey: str | None = None,
    coldkey: str = COLDKEY,
    network: str = NETWORK,
    netuid: int = NETUID,
    endpoint_url: str = ENDPOINT,
    profile: str = PROFILE,
    nonce: str = "a1" * 16,
    timestamp: str | None = None,
    expires_at: str | None = None,
    sign_with: dict | None = None,
) -> dict:
    hotkey = hotkey if hotkey is not None else keypair.ss58_address
    ts = timestamp if timestamp is not None else now_iso()
    expiry = expires_at if expires_at is not None else _text(
        datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5)
    )
    signed = {
        "hotkey": hotkey,
        "coldkey": coldkey,
        "network": network,
        "netuid": netuid,
        "endpoint_url": endpoint_url,
        "requested_profile_id": profile,
        "nonce": nonce,
        "timestamp": ts,
        "expires_at": expiry,
    }
    # sign_with lets a test sign one thing and send another.
    message = canonical_enroll_payload_v2(**(sign_with or signed))
    return {**signed, "signature_b64": base64.b64encode(keypair.sign(message)).decode("ascii")}


def call(app: RegistryApp, payload: dict, *, remote_addr: str = "1.2.3.4") -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/v1/enroll",
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
        "REMOTE_ADDR": remote_addr,
    }
    seen: dict = {}

    def start_response(status: str, headers: list) -> None:
        seen["status"] = status

    raw = b"".join(app(environ, start_response))
    return int(seen["status"].split()[0]), json.loads(raw.decode("utf-8"))


def row(store: RegistryStore, hotkey: str) -> sqlite3.Row | None:
    with sqlite3.connect(store.path) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM enrollments WHERE hotkey = ?", (hotkey,)
        ).fetchone()


# ---------------------------------------------------------------------------
# 1. Happy paths — pending only
# ---------------------------------------------------------------------------

def test_selected_mode_admits_an_approved_coldkey_into_pending(tmp_path: Path):
    app, store, _ = build_app(tmp_path)
    status, body = call(app, v2_payload())

    assert status == 200
    assert body["status"] == "pending"
    assert body["lifecycle_state"] == WorkerLifecycleState.PENDING.value
    assert body["admission_config_version"] == 1

    stored = row(store, HOTKEY)
    assert stored["endpoint_url"] == ENDPOINT
    assert stored["coldkey"] == COLDKEY
    assert stored["requested_profile_id"] == PROFILE
    assert store.lifecycle_snapshot(HOTKEY).state is WorkerLifecycleState.PENDING


def test_open_mode_admits_any_registered_hotkey_into_pending(tmp_path: Path):
    app, store, _ = build_app(
        tmp_path,
        policy=policy_bytes(mode="all_registered", coldkeys=[]),
        registered={STRANGER_HOTKEY: OTHER_COLDKEY},
    )
    status, body = call(
        app, v2_payload(keypair=STRANGER, coldkey=OTHER_COLDKEY)
    )
    assert status == 200
    assert body["status"] == "pending"
    assert row(store, STRANGER_HOTKEY)["coldkey"] == OTHER_COLDKEY
    assert store.lifecycle_snapshot(STRANGER_HOTKEY).state is WorkerLifecycleState.PENDING


def test_enrollment_never_produces_a_verified_worker(tmp_path: Path):
    """The whole point: enrollment is permission to be tested, nothing more."""
    app, store, _ = build_app(tmp_path, policy=policy_bytes(mode="all_registered", coldkeys=[]))
    assert call(app, v2_payload())[0] == 200

    board = store.board()
    assert board["count"] == 0
    assert [m["verification_status"] for m in board["miners"]] == ["PENDING"]
    # No attestation row exists at all, so nothing downstream can read a
    # verdict this enrollment did not produce.
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM attestations").fetchone()[0] == 0


# ---------------------------------------------------------------------------
# 2. Identity gates
# ---------------------------------------------------------------------------

def test_unregistered_hotkey_is_refused_in_both_modes(tmp_path: Path):
    for mode, coldkeys in (("selected", [COLDKEY]), ("all_registered", [])):
        case = tmp_path / mode
        case.mkdir()
        app, store, _ = build_app(
            case,
            policy=policy_bytes(mode=mode, coldkeys=coldkeys),
            registered={HOTKEY_TWO: COLDKEY},
        )
        status, body = call(app, v2_payload())
        assert status == 403
        assert body["error"] == "hotkey not registered on subnet"
        assert row(store, HOTKEY) is None


def test_non_selected_coldkey_is_refused(tmp_path: Path):
    app, store, _ = build_app(
        tmp_path,
        policy=policy_bytes(coldkeys=[OTHER_COLDKEY]),
    )
    status, body = call(app, v2_payload())
    assert status == 403
    assert body["error"] == "coldkey is not approved for enrollment"
    assert row(store, HOTKEY) is None


def test_a_spoofed_coldkey_is_refused_even_when_it_is_the_approved_one(tmp_path: Path):
    """The submitted coldkey is signed, compared, and never trusted."""
    app, store, _ = build_app(
        tmp_path,
        # The chain says this hotkey belongs to OTHER_COLDKEY...
        registered={HOTKEY: OTHER_COLDKEY},
        # ...and only COLDKEY is approved.
        policy=policy_bytes(coldkeys=[COLDKEY]),
    )
    # The miner claims the approved coldkey and signs that claim.
    status, body = call(app, v2_payload(coldkey=COLDKEY))
    assert status == 403
    assert body["error"] == "submitted coldkey does not own this hotkey"
    assert row(store, HOTKEY) is None


def test_unresolvable_coldkey_fails_closed(tmp_path: Path):
    # A hotkeys-only snapshot proves registration but cannot prove ownership.
    app, store, _ = build_app(tmp_path, registered=[HOTKEY])
    status, body = call(app, v2_payload())
    assert status == 403
    assert body["error"] == "hotkey coldkey could not be resolved"
    assert row(store, HOTKEY) is None


def test_stale_registration_snapshot_fails_closed(tmp_path: Path):
    import os
    import time

    app, store, _ = build_app(tmp_path)
    snapshot = tmp_path / "registered.json"
    old = time.time() - 7200
    os.utime(snapshot, (old, old))

    status, _ = call(app, v2_payload())
    assert status == 403
    assert row(store, HOTKEY) is None


# ---------------------------------------------------------------------------
# 3. Hotkey rotation
# ---------------------------------------------------------------------------

def test_a_second_hotkey_under_the_same_coldkey_enrolls(tmp_path: Path):
    app, store, _ = build_app(tmp_path)
    assert call(app, v2_payload())[0] == 200
    assert (
        call(
            app,
            v2_payload(keypair=MINER_TWO, endpoint_url=ENDPOINT_TWO, nonce="b2" * 16),
        )[0]
        == 200
    )
    assert row(store, HOTKEY)["coldkey"] == COLDKEY
    assert row(store, HOTKEY_TWO)["coldkey"] == COLDKEY


def test_a_hotkey_that_moves_to_an_unapproved_coldkey_is_refused_on_re_enrollment(
    tmp_path: Path,
):
    """Selected mode re-checks ownership on every request, not once."""
    app, store, _ = build_app(tmp_path)
    assert call(app, v2_payload())[0] == 200

    # The on-chain binding changes: the same hotkey now sits under a coldkey
    # nobody approved.
    (tmp_path / "registered.json").write_text(
        json.dumps({"hotkeys": {HOTKEY: OTHER_COLDKEY}})
    )
    status, body = call(
        app, v2_payload(coldkey=OTHER_COLDKEY, nonce="c3" * 16, endpoint_url=ENDPOINT_TWO)
    )
    assert status == 403
    assert body["error"] == "coldkey is not approved for enrollment"
    # The pre-existing row is untouched; revoking it is the reconcile path.
    assert row(store, HOTKEY)["endpoint_url"] == ENDPOINT


# ---------------------------------------------------------------------------
# 4. Request integrity
# ---------------------------------------------------------------------------

def test_a_replayed_request_is_refused(tmp_path: Path):
    app, store, _ = build_app(tmp_path)
    payload = v2_payload()
    assert call(app, payload)[0] == 200
    status, body = call(app, payload)
    assert status == 400
    assert "nonce already used" in body["error"]


def test_a_stale_timestamp_is_refused(tmp_path: Path):
    app, _, _ = build_app(tmp_path)
    old = _text(datetime.now(UTC).replace(microsecond=0) - timedelta(hours=2))
    status, _ = call(app, v2_payload(timestamp=old))
    assert status == 400


def test_an_expired_request_is_refused(tmp_path: Path):
    app, store, _ = build_app(tmp_path)
    past = _text(datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=1))
    status, body = call(app, v2_payload(expires_at=past))
    assert status == 400
    assert "expired" in body["error"] or "follow the request timestamp" in body["error"]
    assert row(store, HOTKEY) is None


def test_an_over_long_expiry_is_refused(tmp_path: Path):
    app, _, _ = build_app(tmp_path)
    far = _text(datetime.now(UTC).replace(microsecond=0) + timedelta(days=30))
    status, body = call(app, v2_payload(expires_at=far))
    assert status == 400
    assert "maximum enrollment request lifetime" in body["error"]


def test_endpoint_substitution_after_signing_is_refused(tmp_path: Path):
    app, store, _ = build_app(tmp_path)
    payload = v2_payload(nonce="d4" * 16)
    # Everything else is byte-identical to what the hotkey signed, so the
    # only thing that can reject this is the endpoint binding.
    payload["endpoint_url"] = "https://9.9.9.9:9443"
    status, body = call(app, payload)
    assert status == 400
    assert body["error"] == "invalid enroll signature"
    assert row(store, HOTKEY) is None


def test_a_profile_swap_after_signing_is_refused(tmp_path: Path):
    app, _, _ = build_app(tmp_path, policy=policy_bytes(profiles=[PROFILE, "cpu-tdx-sn39-v3"]))
    payload = v2_payload()
    payload["requested_profile_id"] = "cpu-tdx-sn39-v3"
    status, body = call(app, payload)
    assert status == 400
    assert body["error"] == "invalid enroll signature"


def test_a_profile_outside_the_policy_is_refused(tmp_path: Path):
    app, store, _ = build_app(tmp_path)
    status, body = call(app, v2_payload(profile="cpu-tdx-sn39-v1"))
    assert status == 403
    assert body["error"] == "requested profile is not offered by the current policy"
    assert row(store, HOTKEY) is None


def test_a_request_aimed_at_another_subnet_is_refused(tmp_path: Path):
    app, store, _ = build_app(tmp_path)
    # Correctly signed, but for netuid 292.
    status, body = call(app, v2_payload(netuid=292))
    assert status == 403
    assert body["error"] == "request is bound to a different network or netuid"
    assert row(store, HOTKEY) is None

    status, body = call(app, v2_payload(network="test", nonce="e5" * 16))
    assert status == 403
    assert body["error"] == "request is bound to a different network or netuid"


def test_a_v1_request_cannot_satisfy_a_policy_gated_service(tmp_path: Path):
    """No downgrade: the v1 and v2 signed byte strings cannot collide."""
    app, store, _ = build_app(tmp_path)
    ts = now_iso()
    nonce = "f6" * 16
    message = canonical_enroll_payload(HOTKEY, ENDPOINT, nonce, ts)
    status, _ = call(
        app,
        {
            "hotkey": HOTKEY,
            "endpoint_url": ENDPOINT,
            "nonce": nonce,
            "timestamp": ts,
            "signature_b64": base64.b64encode(MINER.sign(message)).decode("ascii"),
        },
    )
    assert status == 400  # missing v2 fields, and the v1 signature cannot verify
    assert row(store, HOTKEY) is None


def test_v2_cannot_collide_with_the_domain_tagged_v1_payload(tmp_path: Path):
    """Cross-branch contract with the unmerged enrollment hardening.

    `origin/feat/allowlist-rollout` (the code currently deployed) binds
    network and netuid inside a `domain`-tagged v1 document. That shape is
    reproduced literally here rather than imported, because it does not exist
    on this branch. The two documents must stay mutually unusable: a
    signature over either can never satisfy the other.
    """
    deployed_shape = {
        "domain": "cathedral-enroll-v1",
        "endpoint_url": ENDPOINT,
        "hotkey": HOTKEY,
        "netuid": NETUID,
        "network": NETWORK,
        "nonce": "80" * 16,
        "timestamp": now_iso(),
    }
    deployed_bytes = json.dumps(
        deployed_shape, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    v2_bytes = canonical_enroll_payload_v2(
        hotkey=HOTKEY,
        coldkey=COLDKEY,
        network=NETWORK,
        netuid=NETUID,
        endpoint_url=ENDPOINT,
        requested_profile_id=PROFILE,
        nonce=deployed_shape["nonce"],
        timestamp=deployed_shape["timestamp"],
        expires_at=_text(datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5)),
    )
    assert deployed_bytes != v2_bytes
    assert b'"schema":"cathedral_enroll_request_v2"' in v2_bytes
    assert b'"domain"' not in v2_bytes

    # And a signature over the deployed shape does not enroll here.
    app, store, _ = build_app(tmp_path)
    status, _ = call(
        app,
        {
            **deployed_shape,
            "coldkey": COLDKEY,
            "requested_profile_id": PROFILE,
            "expires_at": _text(
                datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5)
            ),
            "signature_b64": base64.b64encode(MINER.sign(deployed_bytes)).decode("ascii"),
        },
    )
    assert status == 400
    assert row(store, HOTKEY) is None


@pytest.mark.parametrize(
    "mutation",
    [
        {"hotkey": "not-a-key"},
        {"netuid": "39"},
        {"netuid": 99999},
        {"network": "FINNEY"},
        {"requested_profile_id": "../../etc/passwd"},
        {"nonce": "zz"},
        {"coldkey": 12345},
        {"expires_at": 1234},
        {"signature_b64": "not base64"},
        {"endpoint_url": "https://127.0.0.1:8443"},
        {"endpoint_url": "ftp://8.8.8.8"},
    ],
)
def test_malformed_input_is_refused(tmp_path: Path, mutation: dict):
    app, store, _ = build_app(tmp_path)
    payload = v2_payload()
    payload.update(mutation)
    status, _ = call(app, payload)
    assert status in (400, 403)
    assert row(store, HOTKEY) is None


# ---------------------------------------------------------------------------
# 5. Caps
# ---------------------------------------------------------------------------

def test_retrying_the_same_request_shape_is_idempotent(tmp_path: Path):
    app, store, _ = build_app(tmp_path, policy=policy_bytes(max_endpoints=1))
    assert call(app, v2_payload(nonce="10" * 16))[0] == 200
    # Same hotkey, same endpoint, fresh nonce: a refresh, not new capacity.
    assert call(app, v2_payload(nonce="11" * 16))[0] == 200
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0] == 1


def test_the_per_coldkey_endpoint_cap_is_enforced(tmp_path: Path):
    app, store, _ = build_app(tmp_path, policy=policy_bytes(max_endpoints=1))
    assert call(app, v2_payload())[0] == 200

    status, body = call(
        app, v2_payload(keypair=MINER_TWO, endpoint_url=ENDPOINT_TWO, nonce="20" * 16)
    )
    assert status == 403
    assert body["error"] == "coldkey has reached its enrolled endpoint cap"
    assert row(store, HOTKEY_TWO) is None


def test_retiring_a_worker_frees_capacity(tmp_path: Path):
    app, store, _ = build_app(tmp_path, policy=policy_bytes(max_endpoints=1))
    assert call(app, v2_payload())[0] == 200
    store.remove_enrollment(HOTKEY)

    status, _ = call(
        app, v2_payload(keypair=MINER_TWO, endpoint_url=ENDPOINT_TWO, nonce="21" * 16)
    )
    assert status == 200


def test_the_total_worker_cap_is_enforced(tmp_path: Path):
    app, store, _ = build_app(
        tmp_path,
        policy=policy_bytes(mode="all_registered", coldkeys=[], max_total=1),
        registered={HOTKEY: COLDKEY, STRANGER_HOTKEY: OTHER_COLDKEY},
    )
    assert call(app, v2_payload())[0] == 200

    status, body = call(
        app,
        v2_payload(
            keypair=STRANGER,
            coldkey=OTHER_COLDKEY,
            endpoint_url=ENDPOINT_TWO,
            nonce="30" * 16,
        ),
    )
    assert status == 403
    assert body["error"] == "the subnet has reached its worker cap"
    assert row(store, STRANGER_HOTKEY) is None


def test_two_hotkeys_cannot_claim_one_endpoint(tmp_path: Path):
    app, store, _ = build_app(
        tmp_path,
        policy=policy_bytes(mode="all_registered", coldkeys=[]),
        registered={HOTKEY: COLDKEY, STRANGER_HOTKEY: OTHER_COLDKEY},
    )
    assert call(app, v2_payload())[0] == 200
    status, body = call(
        app,
        v2_payload(keypair=STRANGER, coldkey=OTHER_COLDKEY, nonce="40" * 16),
    )
    assert status == 403
    assert body["error"] == "endpoint is already enrolled by another worker"
    assert row(store, STRANGER_HOTKEY) is None


def test_concurrent_duplicate_enrollments_cannot_both_take_the_last_slot(tmp_path: Path):
    """The cap is evaluated inside the write transaction, not before it."""
    app, store, _ = build_app(
        tmp_path,
        policy=policy_bytes(mode="all_registered", coldkeys=[], max_total=1),
        registered={HOTKEY: COLDKEY, STRANGER_HOTKEY: OTHER_COLDKEY},
    )
    barrier = threading.Barrier(2)
    results: list[int] = []
    lock = threading.Lock()

    def attempt(payload: dict) -> None:
        barrier.wait()
        status, _ = call(app, payload)
        with lock:
            results.append(status)

    threads = [
        threading.Thread(target=attempt, args=(v2_payload(nonce="50" * 16),)),
        threading.Thread(
            target=attempt,
            args=(
                v2_payload(
                    keypair=STRANGER,
                    coldkey=OTHER_COLDKEY,
                    endpoint_url=ENDPOINT_TWO,
                    nonce="51" * 16,
                ),
            ),
        ),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(results) == [200, 403]
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0] == 1


# ---------------------------------------------------------------------------
# 6. Policy availability
# ---------------------------------------------------------------------------

def test_a_missing_policy_rejects_every_enrollment(tmp_path: Path):
    app, store, policy_path = build_app(tmp_path)
    policy_path.unlink()
    status, body = call(app, v2_payload())
    assert status == 403
    assert body["error"] == "admission policy unavailable"
    assert row(store, HOTKEY) is None


def test_an_expired_policy_rejects_every_enrollment(tmp_path: Path):
    now = datetime.now(UTC).replace(microsecond=0)
    app, store, _ = build_app(
        tmp_path,
        policy=policy_bytes(
            issued_at=now - timedelta(days=3), expires_at=now - timedelta(days=1)
        ),
    )
    status, body = call(app, v2_payload())
    assert status == 403
    assert body["error"] == "admission policy unavailable"


def test_a_policy_rollback_rejects_every_enrollment(tmp_path: Path):
    app, store, policy_path = build_app(tmp_path, policy=policy_bytes(config_version=5))
    assert call(app, v2_payload())[0] == 200

    # A validly signed but superseded policy that would re-open approval.
    policy_path.write_bytes(policy_bytes(config_version=4, coldkeys=[COLDKEY, OTHER_COLDKEY]))
    status, body = call(app, v2_payload(nonce="60" * 16, endpoint_url=ENDPOINT_TWO))
    assert status == 403
    assert body["error"] == "admission policy unavailable"


def test_a_pinned_policy_cannot_be_swapped_at_runtime(tmp_path: Path):
    import hashlib

    pinned = policy_bytes(config_version=1)
    app, _, policy_path = build_app(
        tmp_path,
        policy=pinned,
        pinned_digest="sha256:" + hashlib.sha256(pinned).hexdigest(),
    )
    assert call(app, v2_payload())[0] == 200

    policy_path.write_bytes(policy_bytes(config_version=2, coldkeys=[COLDKEY, OTHER_COLDKEY]))
    status, body = call(app, v2_payload(nonce="70" * 16, endpoint_url=ENDPOINT_TWO))
    assert status == 403
    assert body["error"] == "admission policy unavailable"


def test_a_policy_and_an_allowlist_cannot_both_be_configured(tmp_path: Path):
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    with pytest.raises(ValueError, match="not both"):
        RegistryApp(store, admission_policy=object(), coldkey_allowlist=object())
