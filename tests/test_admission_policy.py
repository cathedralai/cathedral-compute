"""Signed admission policy artifact (cathedral_admission_policy_v1).

Covers:
  1. A well-formed policy verifies in both modes and reports its caps.
  2. Signature, signer, and canonical-encoding failures fail closed.
  3. Network/netuid binding: a policy signed for another subnet or network
     never gates this service, even with a trusted signer.
  4. Window and freshness: future issue, expiry, and the staleness ceiling.
  5. config_version monotonicity and rollback.
  6. Mode invariants, including the refusal to carry a coldkey list in open
     mode, and the empty-list-pauses-approval behaviour of selected mode.
  7. Cap and profile-list bounds.
  8. Provider fail-closed behaviour: missing, oversized, malformed, stale,
     rolled-back, and digest-mismatched artifacts all load as None.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.admission_policy import (
    ADMISSION_POLICY_SCHEMA,
    MAX_CAP_VALUE,
    AdmissionPolicyError,
    SignedAdmissionPolicyProvider,
    load_policy_keys,
    sign_admission_policy,
    verify_admission_policy,
)
from cathedral.policy_registry import canonical_json

SEED = bytes(range(128, 160))
OTHER_SEED = bytes(range(160, 192))
KEY_ID = "cathedral-admission-test-1"
PUBLIC = (
    Ed25519PrivateKey.from_private_bytes(SEED)
    .public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
)
OTHER_PUBLIC = (
    Ed25519PrivateKey.from_private_bytes(OTHER_SEED)
    .public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
)
TRUSTED = {KEY_ID: PUBLIC}

NETWORK = "finney"
NETUID = 39
PROFILE = "cpu-tdx-sn39-v2"
COLDKEY = "5FghSHp7DXzhoiCaBQ9qmz6QRb6C94KehEKDHZ8vq6QyE29C"
OTHER_COLDKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"

NOW = datetime.now(UTC).replace(microsecond=0)


def _text(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def policy_document(
    *,
    mode: str = "selected",
    coldkeys: list[str] | None = None,
    network: str = NETWORK,
    netuid: int = NETUID,
    required_profile_ids: list[str] | None = None,
    max_endpoints: int = 2,
    max_total: int = 16,
    config_version: int = 1,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    signing_key_id: str = KEY_ID,
    seed: bytes = SEED,
) -> dict:
    document = {
        "schema": ADMISSION_POLICY_SCHEMA,
        "mode": mode,
        "coldkeys": [COLDKEY] if coldkeys is None and mode == "selected" else (coldkeys or []),
        "network": network,
        "netuid": netuid,
        "required_profile_ids": (
            [PROFILE] if required_profile_ids is None else required_profile_ids
        ),
        "max_enrolled_endpoints_per_coldkey": max_endpoints,
        "max_admitted_workers_total": max_total,
        "config_version": config_version,
        "issued_at": _text(issued_at or (NOW - timedelta(minutes=5))),
        "expires_at": _text(expires_at or (NOW + timedelta(days=7))),
        "signing_key_id": signing_key_id,
    }
    return sign_admission_policy(document, seed)


def policy_bytes(**kwargs) -> bytes:
    return canonical_json(policy_document(**kwargs))


def verify(data: bytes, **kwargs):
    params = {"network": NETWORK, "netuid": NETUID, "now": NOW}
    params.update(kwargs)
    return verify_admission_policy(data, TRUSTED, **params)


# ---------------------------------------------------------------------------
# 1. Happy paths
# ---------------------------------------------------------------------------

def test_selected_mode_verifies_and_reports_its_terms():
    snapshot = verify(policy_bytes())
    assert snapshot.mode == "selected"
    assert snapshot.coldkeys == frozenset({COLDKEY})
    assert snapshot.network == NETWORK and snapshot.netuid == NETUID
    assert snapshot.required_profile_ids == (PROFILE,)
    assert snapshot.max_enrolled_endpoints_per_coldkey == 2
    assert snapshot.max_admitted_workers_total == 16
    assert snapshot.config_version == 1
    assert snapshot.digest.startswith("sha256:")

    assert snapshot.admits_coldkey(COLDKEY) is True
    assert snapshot.admits_coldkey(OTHER_COLDKEY) is False
    assert snapshot.admits_profile(PROFILE) is True
    assert snapshot.admits_profile("cpu-tdx-sn39-v1") is False


def test_open_mode_admits_any_coldkey_but_still_binds_profile_and_caps():
    snapshot = verify(policy_bytes(mode="all_registered", coldkeys=[]))
    assert snapshot.mode == "all_registered"
    assert snapshot.coldkeys == frozenset()
    assert snapshot.admits_coldkey(OTHER_COLDKEY) is True
    # Open mode widens who may ask; it never widens what is accepted.
    assert snapshot.admits_profile("cpu-tdx-sn39-v1") is False
    assert snapshot.max_admitted_workers_total == 16


def test_selected_mode_with_an_empty_list_pauses_approval_without_failing_open():
    snapshot = verify(policy_bytes(coldkeys=[]))
    assert snapshot.coldkeys == frozenset()
    assert snapshot.admits_coldkey(COLDKEY) is False


# ---------------------------------------------------------------------------
# 2. Signature and encoding
# ---------------------------------------------------------------------------

def test_untrusted_signer_is_refused():
    with pytest.raises(AdmissionPolicyError, match="not trusted"):
        verify(policy_bytes(signing_key_id="cathedral-admission-unknown"))


def test_signature_by_the_wrong_key_is_refused():
    with pytest.raises(AdmissionPolicyError, match="signature verification failed"):
        verify(policy_bytes(seed=OTHER_SEED))


def test_a_tampered_field_invalidates_the_signature():
    document = policy_document()
    document["coldkeys"] = [OTHER_COLDKEY]
    with pytest.raises(AdmissionPolicyError, match="signature verification failed"):
        verify(canonical_json(document))


def test_unknown_or_missing_top_level_fields_are_refused():
    document = policy_document()
    document["extra"] = 1
    with pytest.raises(AdmissionPolicyError, match="unknown critical fields"):
        verify(canonical_json(document))

    document = policy_document()
    del document["netuid"]
    with pytest.raises(AdmissionPolicyError, match="unknown critical fields"):
        verify(canonical_json(document))


def test_non_canonical_signature_encoding_is_refused():
    document = policy_document()
    raw = base64.b64decode(document["signature"]["value_base64"])
    document["signature"]["value_base64"] = base64.b64encode(raw).decode().replace("=", "") + "="
    with pytest.raises(AdmissionPolicyError, match="signature"):
        verify(canonical_json(document))


def test_wrong_schema_is_refused():
    document = policy_document()
    document.pop("signature")
    document["schema"] = "cathedral_coldkey_allowlist_v1"
    with pytest.raises(AdmissionPolicyError, match="schema is unsupported"):
        verify(canonical_json(sign_admission_policy(document, SEED)))


def test_malformed_json_is_refused():
    with pytest.raises(ValueError):
        verify(b"{not json")


# ---------------------------------------------------------------------------
# 3. Network and netuid binding
# ---------------------------------------------------------------------------

def test_a_policy_for_another_netuid_never_gates_this_service():
    with pytest.raises(AdmissionPolicyError, match="different network or netuid"):
        verify(policy_bytes(netuid=292))


def test_a_policy_for_another_network_never_gates_this_service():
    with pytest.raises(AdmissionPolicyError, match="different network or netuid"):
        verify(policy_bytes(network="test"))


def test_the_service_must_state_a_valid_expectation():
    with pytest.raises(AdmissionPolicyError, match="expected network"):
        verify(policy_bytes(), network="Finney")
    with pytest.raises(AdmissionPolicyError, match="expected netuid"):
        verify(policy_bytes(), netuid=-1)
    with pytest.raises(AdmissionPolicyError, match="expected netuid"):
        verify(policy_bytes(), netuid=True)


# ---------------------------------------------------------------------------
# 4. Window and freshness
# ---------------------------------------------------------------------------

def test_expired_policy_is_refused():
    with pytest.raises(AdmissionPolicyError, match="outside its validity window"):
        verify(
            policy_bytes(
                issued_at=NOW - timedelta(days=3), expires_at=NOW - timedelta(days=1)
            )
        )


def test_policy_issued_in_the_future_is_refused():
    with pytest.raises(AdmissionPolicyError, match="outside its validity window"):
        verify(policy_bytes(issued_at=NOW + timedelta(hours=1)))


def test_stale_policy_is_refused_at_the_ceiling():
    stale = policy_bytes(issued_at=NOW - timedelta(days=2), expires_at=NOW + timedelta(days=7))
    with pytest.raises(AdmissionPolicyError, match="too stale"):
        verify(stale)
    # The same artifact verifies under an explicitly widened ceiling, proving
    # the rejection is the freshness rule and not a window error.
    assert verify(stale, max_age_seconds=3 * 86400).config_version == 1


def test_inverted_window_is_refused():
    with pytest.raises(AdmissionPolicyError, match="validity window is invalid"):
        verify(policy_bytes(issued_at=NOW, expires_at=NOW - timedelta(days=1)))


def test_verification_time_must_be_utc():
    with pytest.raises(AdmissionPolicyError, match="must be UTC"):
        verify(policy_bytes(), now=datetime.now())


# ---------------------------------------------------------------------------
# 5. config_version
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version", [0, -1, True, "1", 1.0])
def test_config_version_must_be_a_bounded_positive_integer(version):
    document = policy_document()
    document.pop("signature")
    document["config_version"] = version
    encoded = json.dumps(sign_admission_policy(document, SEED)).encode()
    with pytest.raises(ValueError):
        verify(encoded)


def test_provider_refuses_a_config_version_rollback(tmp_path: Path):
    path = tmp_path / "policy.json"
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({KEY_ID: base64.b64encode(PUBLIC).decode()}))
    provider = SignedAdmissionPolicyProvider(
        str(path), load_policy_keys(str(keys)), network=NETWORK, netuid=NETUID
    )

    path.write_bytes(policy_bytes(config_version=7))
    assert provider.load().config_version == 7

    path.write_bytes(policy_bytes(config_version=6))
    assert provider.load() is None  # rollback fails closed

    path.write_bytes(policy_bytes(config_version=8))
    assert provider.load().config_version == 8


# ---------------------------------------------------------------------------
# 6. Mode invariants
# ---------------------------------------------------------------------------

def test_open_mode_may_not_carry_a_coldkey_list():
    with pytest.raises(AdmissionPolicyError, match="open mode must carry an empty coldkey list"):
        verify(policy_bytes(mode="all_registered", coldkeys=[COLDKEY]))


def test_unknown_mode_is_refused():
    with pytest.raises(AdmissionPolicyError, match="mode is unsupported"):
        verify(policy_bytes(mode="everyone"))


def test_duplicate_or_malformed_coldkeys_are_refused():
    with pytest.raises(AdmissionPolicyError, match="cannot contain duplicates"):
        verify(policy_bytes(coldkeys=[COLDKEY, COLDKEY]))
    with pytest.raises(AdmissionPolicyError, match="ss58-like"):
        verify(policy_bytes(coldkeys=["not a key!"]))


# ---------------------------------------------------------------------------
# 7. Caps and profiles
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [0, -1, MAX_CAP_VALUE + 1, True, "4"])
def test_caps_must_be_bounded_positive_integers(value):
    with pytest.raises(ValueError):
        verify(policy_bytes(max_endpoints=value))
    with pytest.raises(ValueError):
        verify(policy_bytes(max_total=value))


def test_required_profile_ids_must_be_a_bounded_non_empty_identifier_list():
    with pytest.raises(AdmissionPolicyError, match="non-empty"):
        verify(policy_bytes(required_profile_ids=[]))
    with pytest.raises(AdmissionPolicyError, match="identifiers"):
        verify(policy_bytes(required_profile_ids=["../etc/passwd"]))
    with pytest.raises(AdmissionPolicyError, match="duplicates"):
        verify(policy_bytes(required_profile_ids=[PROFILE, PROFILE]))


# ---------------------------------------------------------------------------
# 8. Provider fail-closed behaviour
# ---------------------------------------------------------------------------

@pytest.fixture
def provider_factory(tmp_path: Path):
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({KEY_ID: base64.b64encode(PUBLIC).decode()}))

    def _make(**kwargs) -> tuple[Path, SignedAdmissionPolicyProvider]:
        path = tmp_path / "policy.json"
        return path, SignedAdmissionPolicyProvider(
            str(path),
            load_policy_keys(str(keys)),
            network=NETWORK,
            netuid=NETUID,
            **kwargs,
        )

    return _make


def test_missing_artifact_loads_as_none(provider_factory):
    _, provider = provider_factory()
    assert provider.load() is None


def test_malformed_stale_and_misbound_artifacts_load_as_none(provider_factory):
    path, provider = provider_factory()

    path.write_bytes(b"{")
    assert provider.load() is None

    path.write_bytes(policy_bytes(issued_at=NOW - timedelta(days=2)))
    assert provider.load() is None

    path.write_bytes(policy_bytes(netuid=292))
    assert provider.load() is None

    path.write_bytes(policy_bytes(seed=OTHER_SEED))
    assert provider.load() is None

    path.write_bytes(policy_bytes())
    assert provider.load() is not None  # the fixture itself is loadable


def test_oversized_artifact_loads_as_none(provider_factory):
    path, provider = provider_factory()
    path.write_bytes(b"x" * (1024 * 1024 + 1))
    assert provider.load() is None


def test_pinned_digest_mismatch_loads_as_none(provider_factory):
    good = policy_bytes()
    import hashlib

    digest = "sha256:" + hashlib.sha256(good).hexdigest()
    path, provider = provider_factory(pinned_digest=digest)
    path.write_bytes(good)
    assert provider.load() is not None

    # A validly signed successor is still refused while the pin stands: this
    # is what makes a revocation durable across a restart.
    path.write_bytes(policy_bytes(config_version=2, coldkeys=[COLDKEY, OTHER_COLDKEY]))
    assert provider.load() is None


def test_provider_rejects_invalid_construction(tmp_path: Path):
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({KEY_ID: base64.b64encode(PUBLIC).decode()}))
    loaded = load_policy_keys(str(keys))
    with pytest.raises(ValueError, match="netuid"):
        SignedAdmissionPolicyProvider(
            str(tmp_path / "p.json"), loaded, network=NETWORK, netuid=99999
        )
    with pytest.raises(ValueError, match="network"):
        SignedAdmissionPolicyProvider(
            str(tmp_path / "p.json"), loaded, network="FINNEY", netuid=NETUID
        )
    with pytest.raises(ValueError, match="max_age_seconds"):
        SignedAdmissionPolicyProvider(
            str(tmp_path / "p.json"),
            loaded,
            network=NETWORK,
            netuid=NETUID,
            max_age_seconds=0,
        )


def test_production_keys_require_a_pin(tmp_path: Path):
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({KEY_ID: base64.b64encode(PUBLIC).decode()}))
    with pytest.raises(AdmissionPolicyError, match="require a pinned digest"):
        load_policy_keys(str(keys), production_mode=True)
    with pytest.raises(AdmissionPolicyError, match="does not match"):
        load_policy_keys(str(keys), pinned_digest="sha256:" + "00" * 32)


def test_empty_or_malformed_key_file_is_refused(tmp_path: Path):
    keys = tmp_path / "keys.json"
    keys.write_text("{}")
    with pytest.raises(AdmissionPolicyError, match="cannot be empty"):
        load_policy_keys(str(keys))
    keys.write_text(json.dumps({KEY_ID: "not-base64!"}))
    with pytest.raises(AdmissionPolicyError, match="32-byte base64"):
        load_policy_keys(str(keys))


def test_signing_refuses_a_presigned_document():
    with pytest.raises(AdmissionPolicyError, match="must not contain signature"):
        sign_admission_policy(policy_document(), SEED)
