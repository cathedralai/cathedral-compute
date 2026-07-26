from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cathedral import self_check
from cathedral.cli import build_parser, main
from cathedral.common import report_data
from cathedral.verify.tdx_quote import parse_tdx_quote
from cathedral.self_check import (
    SelfCheckError,
    detect_tdx,
    measurement_of,
    normalize_measurements,
    render,
    run_self_check,
)
from tests.tdx_quote_fixtures import synthetic_tdx_quote

# The production verifier is Go (cmd/cathedral-tdx-verifier). Its
# TestMeasurementMatchesPythonContractVector pins measurementID() to this exact
# string for the exact field bytes synthetic_tdx_quote() writes. Asserting the
# same constant here is what makes a self-check answer and an admission
# decision incapable of disagreeing about the value: changing either
# derivation breaks one of the two tests.
GO_VERIFIER_CONTRACT_VECTOR = (
    "tdx-measurement-sha256:b3cf84af07e6fb79dce23c46eef78eb627b39989814fcf1b6ea42fd93fea1585"
)

DOCUMENTED_COMMAND_SOURCES = ("MINING.md", "docs/TDX_LAUNCH.md")

# An allowlist that does not contain the fixture's measurement. Deliberately not
# a real approved value: the repo ships no approved measurements, and a test
# must never be the place one gets introduced.
OTHER_APPROVED_LIST = ("tdx-measurement-sha256:" + "ab" * 32,)


def _quote(**kwargs) -> bytes:
    return synthetic_tdx_quote(report_data=report_data(b"n" * 32, "hotkey-self-check"), **kwargs)


def _fake_verifier(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "fake-verifier"
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def _claims_verifier(tmp_path: Path, record: Path | None = None, **claims) -> Path:
    """A stand-in verifier that prints one claims object, like the real one."""

    body = "import json, sys\n"
    if record is not None:
        body += f"open({str(record)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
    body += f"print(json.dumps({claims!r}))\n"
    return _fake_verifier(tmp_path, body)


def _ready_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Make detect_tdx() report a usable TD without needing real hardware."""

    marker = tmp_path / "tdx_guest"
    marker.touch()
    monkeypatch.setattr(self_check, "_TDX_GUEST_MARKERS", (marker,))
    root = tmp_path / "tsm-report"
    root.mkdir()
    return root


def test_measurement_matches_the_go_verifier_contract_vector():
    assert measurement_of(_quote()) == GO_VERIFIER_CONTRACT_VECTOR


def test_measurement_tracks_the_quote_not_the_caller():
    assert measurement_of(_quote(mr_td=b"A" * 48)) != measurement_of(_quote(mr_td=b"B" * 48))


def test_missing_configfs_tsm_reports_instead_of_raising(tmp_path):
    result = run_self_check(
        approved_measurements=OTHER_APPROVED_LIST,
        allowlist_source="test",
        tsm_report_root=tmp_path / "absent",
    )

    assert result.verdict == self_check.VERDICT_NO_TDX
    assert result.measurement is None
    assert "configfs-tsm" in result.error
    assert result.exit_code == 5
    assert "cannot produce a TDX quote" in render(result)


def test_collection_failure_is_reported_not_raised(monkeypatch, tmp_path):
    root = _ready_environment(monkeypatch, tmp_path)

    def explode(*_args, **_kwargs):
        raise PermissionError("Permission denied")

    monkeypatch.setattr(self_check, "collect_tdx", explode)

    result = run_self_check(
        approved_measurements=OTHER_APPROVED_LIST,
        allowlist_source="test",
        tsm_report_root=root,
    )

    assert result.verdict == self_check.VERDICT_COLLECTION_FAILED
    assert "PermissionError" in result.error
    assert "sudo" in render(result)


def test_unparsable_quote_is_reported_not_raised(tmp_path):
    result = run_self_check(
        approved_measurements=OTHER_APPROVED_LIST,
        allowlist_source="test",
        quote=b"\x00" * 64,
    )

    assert result.verdict == self_check.VERDICT_COLLECTION_FAILED
    assert "Intel TDX quote v4" in result.error


def test_approved_measurement_without_a_verifier_says_tcb_was_not_checked():
    result = run_self_check(
        approved_measurements=(GO_VERIFIER_CONTRACT_VECTOR,),
        allowlist_source="test",
        quote=_quote(),
    )

    assert result.verdict == self_check.VERDICT_APPROVED_TCB_UNCHECKED
    assert result.measurement_approved is True
    assert result.tcb_status is None
    assert result.exit_code == 0
    assert "TCB status was not checked here" in render(result)


def test_unapproved_measurement_prints_the_exact_string_to_send():
    result = run_self_check(
        approved_measurements=OTHER_APPROVED_LIST,
        allowlist_source="test",
        quote=_quote(),
    )

    assert result.verdict == self_check.VERDICT_NOT_APPROVED
    assert result.measurement_approved is False
    assert result.exit_code == 3
    report = render(result)
    assert "NOT approved" in report
    assert f"    {GO_VERIFIER_CONTRACT_VECTOR}" in report
    assert "human step" in report


def test_debug_td_is_named_as_permanently_unapprovable():
    debug_quote = _quote(td_attributes=(1).to_bytes(8, "little"))

    result = run_self_check(
        approved_measurements=OTHER_APPROVED_LIST,
        allowlist_source="test",
        quote=debug_quote,
    )

    assert result.debug_enabled is True
    assert result.verdict == self_check.VERDICT_NOT_APPROVED
    assert "debug attribute" in render(result)


def test_verifier_confirming_uptodate_tcb_gives_the_admitted_verdict(tmp_path):
    verifier = _claims_verifier(
        tmp_path,
        measurement=GO_VERIFIER_CONTRACT_VECTOR,
        tcb_status="UpToDate",
        intel_verified=True,
        report_data_match=True,
    )

    result = run_self_check(
        approved_measurements=(GO_VERIFIER_CONTRACT_VECTOR,),
        allowlist_source="test",
        quote=_quote(),
        verifier=[str(verifier)],
    )

    assert result.verdict == self_check.VERDICT_APPROVED
    assert result.tcb_status == "UpToDate"
    assert result.exit_code == 0
    assert "passes the measurement and TCB gates" in render(result)


def test_verifier_reporting_stale_tcb_is_classified_and_explained(tmp_path):
    verifier = _claims_verifier(
        tmp_path,
        measurement=GO_VERIFIER_CONTRACT_VECTOR,
        tcb_status="OutOfDate",
        intel_verified=True,
        report_data_match=True,
    )

    result = run_self_check(
        approved_measurements=(GO_VERIFIER_CONTRACT_VECTOR,),
        allowlist_source="test",
        quote=_quote(),
        verifier=[str(verifier)],
    )

    assert result.verdict == self_check.VERDICT_TCB_NOT_CURRENT
    assert result.tcb_status == "OutOfDate"
    assert result.exit_code == 4
    report = render(result)
    assert "TCB is not current" in report
    assert "stop and start" in report


def test_verifier_failing_closed_still_classifies_the_measurement(tmp_path):
    # The pinned Go verifier exits nonzero and does not name the failing
    # component when Intel collateral says the platform is not current.
    verifier = _fake_verifier(
        tmp_path,
        "import sys\n"
        "sys.stderr.write('cathedral TDX verification failed: Intel platform, TDX module, "
        "or QE is not fully current\\n')\n"
        "sys.exit(1)\n",
    )

    approved = run_self_check(
        approved_measurements=(GO_VERIFIER_CONTRACT_VECTOR,),
        allowlist_source="test",
        quote=_quote(),
        verifier=[str(verifier)],
    )
    unapproved = run_self_check(
        approved_measurements=OTHER_APPROVED_LIST,
        allowlist_source="test",
        quote=_quote(),
        verifier=[str(verifier)],
    )

    assert approved.verdict == self_check.VERDICT_TCB_NOT_CURRENT
    assert "not fully current" in approved.error
    assert unapproved.verdict == self_check.VERDICT_NOT_APPROVED


@pytest.mark.parametrize(
    ("intel_verified", "report_data_match"),
    [(False, True), (True, False)],
)
def test_tcb_status_without_intel_verification_is_not_believed(
    tmp_path, intel_verified, report_data_match
):
    """A status string is worthless unless the verifier actually verified."""

    verifier = _claims_verifier(
        tmp_path,
        measurement=GO_VERIFIER_CONTRACT_VECTOR,
        tcb_status="UpToDate",
        intel_verified=intel_verified,
        report_data_match=report_data_match,
    )

    result = run_self_check(
        approved_measurements=(GO_VERIFIER_CONTRACT_VECTOR,),
        allowlist_source="test",
        quote=_quote(),
        verifier=[str(verifier)],
    )

    assert result.verdict == self_check.VERDICT_VERIFIER_FAILED
    assert result.tcb_status is None
    assert "means nothing" in result.error


def test_verifier_disagreeing_about_the_measurement_fails_loudly(tmp_path):
    verifier = _claims_verifier(
        tmp_path,
        measurement="tdx-measurement-sha256:" + "0" * 64,
        tcb_status="UpToDate",
        intel_verified=True,
        report_data_match=True,
    )

    result = run_self_check(
        approved_measurements=(GO_VERIFIER_CONTRACT_VECTOR,),
        allowlist_source="test",
        quote=_quote(),
        verifier=[str(verifier)],
    )

    assert result.verdict == self_check.VERDICT_DERIVATION_MISMATCH
    assert result.exit_code == 7
    assert "STOP" in render(result)


def test_verifier_is_invoked_with_the_production_argument_contract(tmp_path):
    record = tmp_path / "argv.json"
    verifier = _claims_verifier(
        tmp_path,
        record=record,
        measurement=GO_VERIFIER_CONTRACT_VECTOR,
        tcb_status="UpToDate",
        intel_verified=True,
        report_data_match=True,
    )
    quote = _quote()

    run_self_check(
        approved_measurements=(GO_VERIFIER_CONTRACT_VECTOR,),
        allowlist_source="test",
        quote=quote,
        verifier=[str(verifier)],
    )

    quote_path, report_data_hex = json.loads(record.read_text())
    assert Path(quote_path).is_absolute()
    assert re.fullmatch(r"[0-9a-f]{128}", report_data_hex)


def test_missing_verifier_binary_does_not_discard_the_measurement(tmp_path):
    result = run_self_check(
        approved_measurements=(GO_VERIFIER_CONTRACT_VECTOR,),
        allowlist_source="test",
        quote=_quote(),
        verifier=[str(tmp_path / "not-installed")],
    )

    assert result.verdict == self_check.VERDICT_VERIFIER_FAILED
    assert result.measurement == GO_VERIFIER_CONTRACT_VECTOR
    assert "derived locally and is still correct" in render(result)


def _signed_registry_now(measurement: str) -> tuple[bytes, dict[str, bytes]]:
    """A signed registry that is current, so freshness checks accept it."""

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from cathedral.policy_registry import canonical_json, sign_registry

    seed = bytes(range(32))
    public_key = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    receipt_public_key = (
        Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )

    def stamp(offset_hours: int) -> str:
        moment = datetime.now(UTC).replace(microsecond=0)
        return (moment + timedelta(hours=offset_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    window = {"valid_from": stamp(-2), "valid_until": stamp(48)}
    document = {
        "schema": "cathedral_policy_registry_v1",
        "release": 1,
        "generated_at": stamp(-1),
        **window,
        "signing_key_id": "cathedral-policy-test-1",
        "receipt_signing_keys": [
            {
                "id": "cathedral-receipt-test-1",
                "algorithm": "ed25519",
                "public_key_base64": base64.b64encode(receipt_public_key).decode("ascii"),
                "purpose": "assurance_receipt",
                "status": "active",
                "status_changed_at": window["valid_from"],
                **window,
                "revoked_at": None,
                "replacement_key_id": None,
                "metadata": {"environment": "test-only"},
            }
        ],
        "profiles": [
            {
                "id": "cpu-tdx-self-check-v1",
                "kind": "cpu_tdx",
                "status": "active",
                "status_changed_at": window["valid_from"],
                **window,
                "retire_at": None,
                "measurements": [measurement],
                "runtime_measurements": ["runtime-sha256:self-check"],
                "allowed_firmware": [],
                "min_tcb": 0,
                "tdx_allowed_tcb_statuses": ["UpToDate"],
                "tdx_allowed_advisories": [],
                "metadata": {"description": "self-check test profile"},
            }
        ],
        "metadata": {"purpose": "self-check test policy", "critical": True},
    }
    signed = sign_registry(document, seed)
    return canonical_json(signed), {"cathedral-policy-test-1": public_key}


def test_signed_registry_is_the_authoritative_allowlist_source():
    registry_bytes, keys = _signed_registry_now(GO_VERIFIER_CONTRACT_VECTOR)

    approved, source = self_check.registry_allowlist(registry_bytes, keys)
    result = run_self_check(
        approved_measurements=approved,
        allowlist_source=source,
        quote=_quote(),
    )

    assert approved == (GO_VERIFIER_CONTRACT_VECTOR,)
    assert source.startswith("signed policy registry release 1 (sha256:")
    assert result.verdict == self_check.VERDICT_APPROVED_TCB_UNCHECKED
    # A registry answer carries no "confirm this with the operator" caveat.
    assert "hand-copied list" not in render(result)


def test_hand_supplied_allowlist_answer_is_qualified():
    result = run_self_check(
        approved_measurements=(GO_VERIFIER_CONTRACT_VECTOR,),
        allowlist_source="1 measurement(s) supplied on the command line",
        quote=_quote(),
    )

    assert "hand-copied list" in render(result)


def test_cli_self_check_reads_a_signed_registry(tmp_path, capsys):
    registry_bytes, keys = _signed_registry_now(GO_VERIFIER_CONTRACT_VECTOR)
    registry_file = tmp_path / "registry.json"
    registry_file.write_bytes(registry_bytes)
    keys_file = tmp_path / "keys.json"
    keys_file.write_text(
        json.dumps({key: base64.b64encode(value).decode("ascii") for key, value in keys.items()}),
        encoding="utf-8",
    )
    quote_file = tmp_path / "quote.bin"
    quote_file.write_bytes(_quote())

    code = main(
        [
            "worker",
            "self-check",
            "--quote-file",
            str(quote_file),
            "--policy-registry",
            str(registry_file),
            "--trusted-keys",
            str(keys_file),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["measurement_approved"] is True
    assert payload["allowlist_source"].startswith("signed policy registry release 1")


def test_normalize_measurements_rejects_anything_that_is_not_a_measurement():
    assert normalize_measurements([" " + GO_VERIFIER_CONTRACT_VECTOR + " "]) == (
        GO_VERIFIER_CONTRACT_VECTOR,
    )
    with pytest.raises(SelfCheckError):
        normalize_measurements(["b3cf84af" * 8])
    with pytest.raises(SelfCheckError):
        normalize_measurements(["tdx-measurement-sha256:" + "Z" * 64])
    with pytest.raises(SelfCheckError):
        normalize_measurements(["tdx-measurement-sha256:" + "b3" * 8])


def test_detect_tdx_is_read_only_and_explains_itself(tmp_path):
    environment = detect_tdx(tmp_path / "absent")

    assert environment.ready is False
    assert environment.reasons()
    assert not (tmp_path / "absent").exists()


def test_cli_self_check_reports_the_verdict_as_an_exit_code(tmp_path, capsys):
    quote_file = tmp_path / "quote.bin"
    quote_file.write_bytes(_quote())

    unapproved = main(
        [
            "worker",
            "self-check",
            "--quote-file",
            str(quote_file),
            "--approved-measurement",
            OTHER_APPROVED_LIST[0],
        ]
    )
    approved = main(
        [
            "worker",
            "self-check",
            "--quote-file",
            str(quote_file),
            "--approved-measurement",
            GO_VERIFIER_CONTRACT_VECTOR,
        ]
    )

    assert unapproved == 3
    assert approved == 0
    assert GO_VERIFIER_CONTRACT_VECTOR in capsys.readouterr().out


def test_cli_self_check_without_an_allowlist_reports_but_does_not_classify(tmp_path, capsys):
    """No built-in list exists, so the tool must say so instead of guessing."""

    quote_file = tmp_path / "quote.bin"
    quote_file.write_bytes(_quote())

    code = main(["worker", "self-check", "--quote-file", str(quote_file), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 8
    assert payload["verdict"] == "no-allowlist"
    assert payload["measurement"] == GO_VERIFIER_CONTRACT_VECTOR
    assert payload["measurement_approved"] is False
    assert payload["approved_measurements"] == []
    assert payload["allowlist_source"] == "none supplied"


def test_no_approved_measurement_ships_in_the_repository():
    """A hardcoded approved list would eventually assert something false."""

    source = (Path(__file__).resolve().parents[1] / "cathedral/self_check.py").read_text(
        encoding="utf-8"
    )

    assert "SNAPSHOT_MEASUREMENTS" not in source
    assert re.search(r"tdx-measurement-sha256:[0-9a-f]{64}", source) is None


def test_cli_self_check_json_output_is_machine_readable(tmp_path, capsys):
    quote_file = tmp_path / "quote.bin"
    quote_file.write_bytes(_quote())

    code = main(
        [
            "worker",
            "self-check",
            "--quote-file",
            str(quote_file),
            "--approved-measurement",
            OTHER_APPROVED_LIST[0],
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == 3
    assert payload["measurement"] == GO_VERIFIER_CONTRACT_VECTOR
    assert payload["measurement_approved"] is False
    assert payload["verdict"] == "measurement-not-approved"
    assert payload["exit_code"] == 3


def test_cli_self_check_reads_an_operator_allowlist_file(tmp_path, capsys):
    quote_file = tmp_path / "quote.bin"
    quote_file.write_bytes(_quote())
    allowlist = tmp_path / "approved.txt"
    allowlist.write_text(
        f"# sent by the operator\n{GO_VERIFIER_CONTRACT_VECTOR}\n\n", encoding="utf-8"
    )

    code = main(
        [
            "worker",
            "self-check",
            "--quote-file",
            str(quote_file),
            "--allowlist-file",
            str(allowlist),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["measurement_approved"] is True
    assert payload["allowlist_source"].startswith("operator list ")


def test_cli_self_check_rejects_two_conflicting_allowlists(tmp_path):
    code = main(
        [
            "worker",
            "self-check",
            "--policy-registry",
            str(tmp_path / "registry.json"),
            "--approved-measurement",
            GO_VERIFIER_CONTRACT_VECTOR,
        ]
    )

    assert code == 2


def _fenced_blocks(text: str) -> list[str]:
    """Fenced block bodies, paired by line so a closing fence never opens one."""

    blocks: list[str] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("```"):
            if current is None:
                current = []
            else:
                blocks.append("\n".join(current))
                current = None
            continue
        if current is not None:
            current.append(line)
    return blocks


def _documented_cathedral_commands(text: str) -> list[list[str]]:
    """Every `cathedral ...` invocation inside a fenced block, args only."""

    found: list[list[str]] = []
    for block in _fenced_blocks(text):
        for line in re.sub(r"\\\n\s*", " ", block).splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                tokens = shlex.split(stripped)
            except ValueError:
                continue
            for index, token in enumerate(tokens):
                if token.split("/")[-1] == "cathedral" and index + 1 < len(tokens):
                    found.append(tokens[index + 1 :])
                    break
    return found


@pytest.mark.parametrize("source", DOCUMENTED_COMMAND_SOURCES)
def test_documented_commands_match_the_real_cli_surface(source):
    """Docs that tell a miner to run something must name a command that exists."""

    text = (Path(__file__).resolve().parents[1] / source).read_text(encoding="utf-8")
    commands = _documented_cathedral_commands(text)
    assert commands, f"{source} documents no cathedral commands"

    for argv in commands:
        try:
            build_parser().parse_args(argv)
        except SystemExit as exc:  # argparse exits instead of raising
            raise AssertionError(
                f"{source} documents an invalid command: cathedral {' '.join(argv)}"
            ) from exc


def test_documented_self_check_is_reachable_from_the_mining_guide():
    text = (Path(__file__).resolve().parents[1] / "MINING.md").read_text(encoding="utf-8")
    commands = [" ".join(argv) for argv in _documented_cathedral_commands(text)]

    assert any(argv.startswith("worker self-check") for argv in commands)


def test_go_verifier_measurement_contract_vector_is_still_pinned_on_the_go_side():
    """Guard the other half of the cross-language pin from silent removal."""

    go_test = (
        Path(__file__).resolve().parents[1] / "cmd/cathedral-tdx-verifier/main_test.go"
    ).read_text(encoding="utf-8")

    assert "TestMeasurementMatchesPythonContractVector" in go_test
    assert GO_VERIFIER_CONTRACT_VECTOR in go_test


# cmd/cathedral-tdx-verifier/main_test.go TestOfficialQuoteFixtureProducesCanonicalClaimFields
# asserts that the Go verifier's own claims path derives exactly these values
# from go-tdx-guest's production Sapphire Rapids quote. Deriving the same values
# here from the same raw bytes is what covers field OFFSETS: the synthetic
# fixture above shares this parser's layout assumptions, so on its own it can
# only prove the two implementations hash identical field values, not that they
# read the same fields out of a real quote.
PRODUCTION_QUOTE_SHA256 = "6dde5548bec99147fef832643301f113df99931547be26df8ac376c4eaa5b5a7"
PRODUCTION_QUOTE_MEASUREMENT = (
    "tdx-measurement-sha256:306d11c6a17f18fdad1fabd0147ab4c3c625cab9cf89d5f8146a5f6e0345171c"
)
PRODUCTION_QUOTE_TCB_SVN = "03000400000000000000000000000000"


def _production_quote() -> bytes | None:
    """go-tdx-guest's real production quote, from the Go module cache."""

    go_mod = Path(__file__).resolve().parents[1] / "cmd/cathedral-tdx-verifier/go.mod"
    match = re.search(r"github\.com/google/go-tdx-guest (\S+)", go_mod.read_text(encoding="utf-8"))
    if match is None:
        return None
    try:
        cache = subprocess.run(
            ["go", "env", "GOMODCACHE"],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    quote_path = (
        Path(cache)
        / f"github.com/google/go-tdx-guest@{match.group(1)}"
        / "testing/testdata/tdx_prod_quote_SPR_E4.dat"
    )
    if not quote_path.is_file():
        return None
    return quote_path.read_bytes()


def test_python_and_go_derive_the_same_measurement_from_a_real_production_quote():
    quote = _production_quote()
    if quote is None:
        pytest.skip("go-tdx-guest production quote unavailable without a Go module cache")

    assert hashlib.sha256(quote).hexdigest() == PRODUCTION_QUOTE_SHA256
    parsed = parse_tdx_quote(quote)

    assert parsed.measurement == PRODUCTION_QUOTE_MEASUREMENT
    assert parsed.tcb_svn == PRODUCTION_QUOTE_TCB_SVN
    assert parsed.debug_enabled is False


def test_the_go_side_still_pins_the_production_quote_values():
    """Guard the Go half of the real-quote pin from silent removal."""

    go_test = (
        Path(__file__).resolve().parents[1] / "cmd/cathedral-tdx-verifier/main_test.go"
    ).read_text(encoding="utf-8")

    assert "TestOfficialQuoteFixtureProducesCanonicalClaimFields" in go_test
    assert PRODUCTION_QUOTE_MEASUREMENT in go_test
    assert PRODUCTION_QUOTE_TCB_SVN in go_test


def test_go_verifier_and_python_agree_when_go_is_available():
    """Run the Go half of the pin for real when a toolchain is present.

    Skipped rather than failed without Go or its module cache: the constant
    assertions above already hold the contract on both sides.
    """

    go_directory = Path(__file__).resolve().parents[1] / "cmd/cathedral-tdx-verifier"
    try:
        completed = subprocess.run(
            ["go", "test", "-run", "TestMeasurementMatchesPythonContractVector", "./..."],
            cwd=go_directory,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("Go toolchain unavailable")
    output = completed.stdout + completed.stderr
    offline = ("cannot find module", "dial tcp", "connection refused", "no required module")
    if completed.returncode != 0 and any(marker in output for marker in offline):
        pytest.skip("Go module cache unavailable offline")
    assert completed.returncode == 0, output
