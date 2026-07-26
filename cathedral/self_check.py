"""Pre-enrollment TDX admission self-check for prospective miners.

Cathedral admits a worker only when the launch measurement in its TDX quote is
already listed in the signed policy registry. Without this check a miner learns
that only after enrolling, by being scored zero every epoch with no stated
reason. This module answers, before enrollment and without any Cathedral
secret:

  1. what launch measurement does THIS machine produce, and
  2. is that measurement on the approved list.

The measurement is derived by ``cathedral.verify.tdx_quote.parse_tdx_quote``,
which is the same derivation the production Go verifier implements
(``cmd/cathedral-tdx-verifier`` ``measurementID``).

What is actually pinned, and what is not:

- Both implementations agree on a shared field-value vector
  (``tests/test_self_check.py`` and the Go
  ``TestMeasurementMatchesPythonContractVector``).
- Both implementations agree on one real production quote: this parser and the
  Go verifier's own claims path derive the identical measurement and TCB SVN
  from ``tdx_prod_quote_SPR_E4.dat``, which covers field offsets and not just
  field values.
- Neither of those is a demonstration on live TDX hardware end to end. No claim
  is made here that a quote collected from a particular machine will verify, or
  that its measurement will be approved. That is exactly the question this
  command exists to ask rather than to answer in advance.

When a verifier binary is supplied, its ``measurement`` claim is compared
against the local derivation at run time as well, and any disagreement is
reported as a hard failure rather than a verdict.

TCB status is a different kind of claim: it is decided by Intel collateral, not
by the quote alone, so this check reports it only when a verifier binary
actually evaluated it, and says so plainly otherwise.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cathedral.attest import collect_tdx
from cathedral.common import evidence_report_data
from cathedral.verify.tdx_quote import TdxQuoteParseError, parse_tdx_quote

MEASUREMENT_PREFIX = "tdx-measurement-sha256:"

# There is deliberately no built-in approved list. The signed policy registry is
# the only measurement authority and it changes without this file changing, so a
# constant here would eventually tell a miner something false with the same
# confidence as something true. The allowlist is always supplied by the caller:
# the signed registry, an operator-provided list, or nothing, in which case the
# check reports the measurement and declines to classify it.

# REPORT_DATA binds a nonce and hotkey into the quote. A self-check quote is
# never submitted for admission, so it binds a locally generated nonce and does
# not require the real hotkey, a channel binding, or TLS to exist yet.
SELF_CHECK_HOTKEY = "self-check"
_NONCE_BYTES = 32

DEFAULT_TSM_REPORT_ROOT = Path("/sys/kernel/config/tsm/report")
_TDX_GUEST_MARKERS = (Path("/sys/module/tdx_guest"), Path("/dev/tdx_guest"))

_DEFAULT_VERIFIER_TIMEOUT = 60.0
_MAX_VERIFIER_OUTPUT = 1024 * 1024
_MAX_REPORTED_STDERR = 2000

VERDICT_APPROVED = "approved"
VERDICT_APPROVED_TCB_UNCHECKED = "approved-tcb-unchecked"
VERDICT_TCB_NOT_CURRENT = "tcb-not-current"
VERDICT_NOT_APPROVED = "measurement-not-approved"
VERDICT_NO_TDX = "no-tdx"
VERDICT_COLLECTION_FAILED = "collection-failed"
VERDICT_VERIFIER_FAILED = "verifier-failed"
VERDICT_DERIVATION_MISMATCH = "derivation-mismatch"
VERDICT_NO_ALLOWLIST = "no-allowlist"

# Distinct exit codes so a provisioning script can branch on the outcome
# instead of parsing text. Documented in MINING.md. 1 and 2 are left alone
# because cathedral.cli.main already returns 2 when a command itself errors.
EXIT_CODES: Mapping[str, int] = {
    VERDICT_APPROVED: 0,
    VERDICT_APPROVED_TCB_UNCHECKED: 0,
    VERDICT_NOT_APPROVED: 3,
    VERDICT_TCB_NOT_CURRENT: 4,
    VERDICT_NO_TDX: 5,
    VERDICT_COLLECTION_FAILED: 5,
    VERDICT_VERIFIER_FAILED: 6,
    VERDICT_DERIVATION_MISMATCH: 7,
    VERDICT_NO_ALLOWLIST: 8,
}


class SelfCheckError(RuntimeError):
    """Raised for caller mistakes, never for an unfavourable verdict."""


@dataclass(frozen=True)
class TdxEnvironment:
    """What the local machine exposes for TDX quote collection."""

    tdx_guest: bool
    tsm_report_root: Path
    tsm_report_root_present: bool

    @property
    def ready(self) -> bool:
        return self.tdx_guest and self.tsm_report_root_present

    def reasons(self) -> tuple[str, ...]:
        """Why collection cannot work here, most specific first."""

        reasons: list[str] = []
        if not self.tdx_guest:
            reasons.append(
                "No Intel TDX guest marker: neither /sys/module/tdx_guest nor /dev/tdx_guest "
                "exists. This machine is not running as an Intel TD. A confidential VM that "
                "uses a different TEE (for example AMD SEV-SNP) reports the same way here, "
                "and Cathedral does not currently admit it."
            )
        if not self.tsm_report_root_present:
            reasons.append(
                f"No configfs-tsm report directory at {self.tsm_report_root}. Mount configfs "
                "and load the TSM report interface, or use a kernel that provides it "
                "(Ubuntu 24.04 LTS does)."
            )
        return tuple(reasons)


@dataclass(frozen=True)
class VerifierOutcome:
    """Result of running a TDX verifier binary over the collected quote."""

    command: str
    ran: bool
    exit_code: int | None
    claims: Mapping[str, object] | None
    stderr: str

    @property
    def measurement(self) -> str | None:
        return _claim_str(self.claims, "measurement")

    @property
    def tcb_status(self) -> str | None:
        return _claim_str(self.claims, "tcb_status")

    @property
    def intel_verified(self) -> bool:
        return bool(self.claims and self.claims.get("intel_verified") is True)


@dataclass(frozen=True)
class SelfCheckResult:
    """Everything the check established, and what it could not establish."""

    verdict: str
    measurement: str | None = None
    tcb_svn: str | None = None
    tcb_status: str | None = None
    debug_enabled: bool | None = None
    quote_bytes: int | None = None
    quote_source: str = "collected"
    approved_measurements: tuple[str, ...] = ()
    allowlist_source: str = ""
    environment: TdxEnvironment | None = None
    verifier: VerifierOutcome | None = None
    error: str | None = None

    @property
    def exit_code(self) -> int:
        return EXIT_CODES.get(self.verdict, 1)

    @property
    def measurement_approved(self) -> bool:
        return self.measurement is not None and self.measurement in self.approved_measurements

    def to_json(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "measurement": self.measurement,
            "measurement_approved": self.measurement_approved,
            "tcb_svn": self.tcb_svn,
            "tcb_status": self.tcb_status,
            "debug_enabled": self.debug_enabled,
            "quote_bytes": self.quote_bytes,
            "quote_source": self.quote_source,
            "allowlist_source": self.allowlist_source,
            "approved_measurements": list(self.approved_measurements),
            "verifier_ran": bool(self.verifier and self.verifier.ran),
            "error": self.error,
            "exit_code": self.exit_code,
        }


def detect_tdx(tsm_report_root: Path | None = None) -> TdxEnvironment:
    """Read-only probe of the local TDX interfaces. Never collects a quote."""

    root = tsm_report_root or Path(
        os.environ.get("CATHEDRAL_TDX_TSM_REPORT_ROOT", DEFAULT_TSM_REPORT_ROOT)
    )
    return TdxEnvironment(
        tdx_guest=any(marker.exists() for marker in _TDX_GUEST_MARKERS),
        tsm_report_root=root,
        tsm_report_root_present=root.exists(),
    )


def measurement_of(quote: bytes) -> str:
    """Derive the Cathedral launch measurement exactly as the verifier does."""

    return parse_tdx_quote(quote).measurement


def registry_allowlist(
    registry_bytes: bytes,
    trusted_keys: Mapping[str, bytes],
    *,
    max_age_seconds: int = 86400,
) -> tuple[tuple[str, ...], str]:
    """The approved list from a signed policy registry, the only authority."""

    from cathedral.policy_registry import verify_registry

    snapshot = verify_registry(registry_bytes, trusted_keys, max_age_seconds=max_age_seconds)
    policy = snapshot.to_policy()
    source = f"signed policy registry release {snapshot.release} ({snapshot.digest})"
    return tuple(sorted(policy.allowed_measurements)), source


def file_allowlist(path: Path) -> tuple[tuple[str, ...], str]:
    """An approved list as an operator hands one out: one measurement per line."""

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SelfCheckError(f"unable to read the approved list: {exc}") from exc
    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not lines:
        raise SelfCheckError(f"approved list is empty: {path}")
    return normalize_measurements(lines), f"operator list {path}"


def normalize_measurements(values: Iterable[str]) -> tuple[str, ...]:
    """Accept the measurement strings an operator hands out, reject anything else."""

    approved: list[str] = []
    for value in values:
        candidate = value.strip()
        if not candidate.startswith(MEASUREMENT_PREFIX):
            raise SelfCheckError(f"measurement must start with {MEASUREMENT_PREFIX!r}: {value!r}")
        digest = candidate[len(MEASUREMENT_PREFIX) :]
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise SelfCheckError(
                f"measurement digest must be 64 lowercase hex characters: {value!r}"
            )
        approved.append(candidate)
    return tuple(approved)


def run_verifier(
    verifier: Sequence[str],
    quote: bytes,
    expected_report_data: bytes,
    *,
    timeout: float = _DEFAULT_VERIFIER_TIMEOUT,
    quote_dir: Path | None = None,
) -> VerifierOutcome:
    """Run a TDX verifier over the quote the way the validator parent does.

    The production contract is ``<verifier> <absolute-quote-path>
    <expected-report-data-hex>``, and the binary fails closed with a nonzero
    exit for any quote whose Intel collateral, revocation, or TCB evaluation is
    not current. That failure is exactly the signal a miner needs, so a nonzero
    exit is captured and classified rather than raised.
    """

    printable = " ".join(verifier)
    with tempfile.TemporaryDirectory(dir=quote_dir) as workdir:
        quote_path = Path(workdir) / "self-check-quote.bin"
        quote_path.write_bytes(quote)
        command = [*verifier, str(quote_path), expected_report_data.hex()]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            return VerifierOutcome(printable, False, None, None, "verifier binary not found")
        except PermissionError:
            return VerifierOutcome(
                printable, False, None, None, "verifier binary is not executable"
            )
        except subprocess.TimeoutExpired:
            return VerifierOutcome(
                printable, False, None, None, f"verifier did not finish within {timeout:.0f}s"
            )
        except OSError as exc:
            return VerifierOutcome(printable, False, None, None, f"verifier could not run: {exc}")

    stderr = completed.stderr[:_MAX_REPORTED_STDERR].decode("utf-8", "replace").strip()
    claims: Mapping[str, object] | None = None
    stdout = completed.stdout[:_MAX_VERIFIER_OUTPUT]
    if stdout.strip():
        try:
            parsed = json.loads(stdout.decode("utf-8"))
            if isinstance(parsed, dict):
                claims = parsed
        except (UnicodeDecodeError, ValueError):
            claims = None
    return VerifierOutcome(printable, True, completed.returncode, claims, stderr)


def run_self_check(
    *,
    approved_measurements: Sequence[str] = (),
    allowlist_source: str = "none supplied",
    hotkey: str = SELF_CHECK_HOTKEY,
    tsm_report_root: Path | None = None,
    quote: bytes | None = None,
    verifier: Sequence[str] | None = None,
    verifier_timeout: float = _DEFAULT_VERIFIER_TIMEOUT,
) -> SelfCheckResult:
    """Collect (or accept) one quote, derive its measurement, and classify it.

    An empty ``approved_measurements`` is a supported case, not an error: the
    measurement is still reported, and the verdict says the question was never
    asked rather than answering it from an assumption.
    """

    approved = tuple(approved_measurements)
    base = {
        "approved_measurements": approved,
        "allowlist_source": allowlist_source,
    }

    environment = detect_tdx(tsm_report_root)
    expected_report_data: bytes | None = None
    quote_source = "collected"

    if quote is None:
        if not environment.ready:
            return SelfCheckResult(
                verdict=VERDICT_NO_TDX,
                environment=environment,
                error="; ".join(environment.reasons()),
                **base,
            )
        nonce = secrets.token_bytes(_NONCE_BYTES)
        try:
            evidence = collect_tdx(nonce, hotkey)
        except (OSError, RuntimeError, ValueError) as exc:
            return SelfCheckResult(
                verdict=VERDICT_COLLECTION_FAILED,
                environment=environment,
                error=f"{type(exc).__name__}: {exc}",
                **base,
            )
        quote = evidence.quote
        expected_report_data = evidence_report_data(evidence, nonce)
    else:
        quote_source = "file"

    try:
        parsed = parse_tdx_quote(quote)
    except TdxQuoteParseError as exc:
        return SelfCheckResult(
            verdict=VERDICT_COLLECTION_FAILED,
            quote_bytes=len(quote),
            quote_source=quote_source,
            environment=environment,
            error=f"quote did not parse as an Intel TDX quote v4: {exc}",
            **base,
        )

    measurement = parsed.measurement
    if expected_report_data is None:
        # A quote read from a file carries its own REPORT_DATA. Echoing it keeps
        # the verifier contract satisfiable, and the caller is told that this
        # proves nothing about freshness or hotkey ownership.
        expected_report_data = parsed.report_data

    observed = {
        "measurement": measurement,
        "tcb_svn": parsed.tcb_svn,
        "debug_enabled": parsed.debug_enabled,
        "quote_bytes": len(quote),
        "quote_source": quote_source,
        "environment": environment,
    }

    outcome: VerifierOutcome | None = None
    tcb_status: str | None = None
    if verifier:
        outcome = run_verifier(
            verifier,
            quote,
            expected_report_data,
            timeout=verifier_timeout,
        )
        if outcome.ran and outcome.claims is not None and outcome.measurement:
            if outcome.measurement != measurement:
                # Nothing downstream is trustworthy if these two disagree.
                return SelfCheckResult(
                    verdict=VERDICT_DERIVATION_MISMATCH,
                    tcb_status=outcome.tcb_status,
                    verifier=outcome,
                    error=(
                        f"verifier reported {outcome.measurement} but this build derives "
                        f"{measurement} from the same quote bytes"
                    ),
                    **observed,
                    **base,
                )
            if not outcome.intel_verified or outcome.claims.get("report_data_match") is not True:
                # The same two flags the validator parent demands as exact JSON
                # booleans. Without both, a TCB status claim is just a string.
                return SelfCheckResult(
                    verdict=VERDICT_VERIFIER_FAILED,
                    verifier=outcome,
                    error=(
                        "verifier returned claims without intel_verified and "
                        "report_data_match both true, so its TCB status means nothing"
                    ),
                    **observed,
                    **base,
                )
            tcb_status = outcome.tcb_status
        elif outcome.ran and outcome.exit_code != 0:
            # The pinned verifier fails closed and does not name the failing
            # component. Measurement classification still stands on its own,
            # where an allowlist exists to classify it against.
            if not approved:
                verdict = VERDICT_NO_ALLOWLIST
            elif measurement in approved:
                verdict = VERDICT_TCB_NOT_CURRENT
            else:
                verdict = VERDICT_NOT_APPROVED
            return SelfCheckResult(
                verdict=verdict,
                verifier=outcome,
                error=outcome.stderr or f"verifier exited {outcome.exit_code}",
                **observed,
                **base,
            )
        else:
            return SelfCheckResult(
                verdict=VERDICT_VERIFIER_FAILED,
                verifier=outcome,
                error=outcome.stderr or "verifier produced no JSON claims",
                **observed,
                **base,
            )

    if not approved:
        # Never guess. Without a supplied list there is no approved set to
        # compare against, and inventing one would be worse than saying so.
        return SelfCheckResult(
            verdict=VERDICT_NO_ALLOWLIST,
            tcb_status=tcb_status,
            verifier=outcome,
            **observed,
            **base,
        )
    if measurement not in approved:
        return SelfCheckResult(
            verdict=VERDICT_NOT_APPROVED,
            tcb_status=tcb_status,
            verifier=outcome,
            **observed,
            **base,
        )
    if tcb_status is not None and tcb_status != "UpToDate":
        return SelfCheckResult(
            verdict=VERDICT_TCB_NOT_CURRENT,
            tcb_status=tcb_status,
            verifier=outcome,
            **observed,
            **base,
        )
    verdict = VERDICT_APPROVED if tcb_status == "UpToDate" else VERDICT_APPROVED_TCB_UNCHECKED
    return SelfCheckResult(
        verdict=verdict,
        tcb_status=tcb_status,
        verifier=outcome,
        **observed,
        **base,
    )


def render(result: SelfCheckResult) -> str:
    """Human-readable report. One headline, then what to do about it."""

    lines: list[str] = []
    if result.measurement:
        lines.append(f"measurement : {result.measurement}")
    if result.tcb_svn:
        lines.append(f"tcb svn     : {result.tcb_svn}")
    if result.measurement:
        lines.append(f"tcb status  : {result.tcb_status or 'not checked locally'}")
    if result.debug_enabled is not None:
        lines.append(f"td debug    : {'ENABLED' if result.debug_enabled else 'disabled'}")
    if result.quote_bytes is not None:
        lines.append(f"quote       : {result.quote_bytes} bytes ({result.quote_source})")
    lines.append(f"allowlist   : {result.allowlist_source}")
    lines.append("")

    if result.verdict == VERDICT_APPROVED:
        lines.append("RESULT: this machine passes the measurement and TCB gates.")
        lines.append("")
        lines.append(
            "Your measurement is on the approved list and a verifier confirmed TCB status "
            "UpToDate against Intel collateral. Admission still requires the remaining gates "
            "in MINING.md section 8: registration, an approved coldkey, the HTTPS channel "
            "binding, enrollment, and verified work. Nothing here promises weight or earnings."
        )
    elif result.verdict == VERDICT_APPROVED_TCB_UNCHECKED:
        lines.append("RESULT: your measurement is approved. TCB status was not checked here.")
        lines.append("")
        lines.append(
            "The measurement gate passes. TCB status is decided by Intel collateral, not by "
            "the quote alone, so this run cannot report it. Pass --verifier "
            "/path/to/cathedral-tdx-verifier to have it evaluated, or expect the operator to "
            "evaluate it during enrollment."
        )
    elif result.verdict == VERDICT_NO_ALLOWLIST:
        lines.append("RESULT: this is your measurement. Whether it is approved was not checked.")
        lines.append("")
        lines.append(
            "No approved list was supplied, so this run has nothing to compare against and "
            "will not guess. Cathedral ships no built-in list on purpose: the signed policy "
            "registry is the only authority and it changes independently of this release."
        )
        lines.append("")
        lines.append(f"    {result.measurement}")
        lines.append("")
        lines.append("To get an answer, re-run with the operator's list:")
        lines.append("")
        lines.append("    --policy-registry <file> --trusted-keys <file>   (the signed registry)")
        lines.append("    --allowlist-file <file>                          (one measurement/line)")
        lines.append("    --approved-measurement <value>                   (repeat per value)")
        lines.append("")
        lines.append(
            "If you have no list yet, send the line above to the operator on your miner beta "
            "issue and ask whether it is approved. See MINING.md, 'Getting a new measurement "
            "approved'."
        )
    elif result.verdict == VERDICT_TCB_NOT_CURRENT:
        lines.append("RESULT: your platform TCB is not current. Fix this before enrolling.")
        lines.append("")
        lines.append(
            "Cathedral requires TCB status UpToDate. The failing component is the host "
            "platform, the TDX module, or the quoting enclave, and on a cloud TDX VM none of "
            "those are yours to patch directly. In order:"
        )
        lines.append(
            "  1. Fully stop and start the VM (not reboot). A cold start lands the guest on "
            "current host firmware and is what usually clears this. Expect the measurement "
            "to change, so re-run this check afterwards."
        )
        lines.append(
            "  2. If it persists, your host has not received the TDX TCB recovery yet. Wait "
            "for the provider rollout or move the VM to another zone, then re-check."
        )
        lines.append(
            "  3. Report the tcb svn above to the operator so they can confirm which "
            "recovery you are missing."
        )
    elif result.verdict == VERDICT_NOT_APPROVED:
        lines.append("RESULT: your measurement is NOT approved. You would be scored zero.")
        lines.append("")
        lines.append(
            "Every quote your machine produces carries this value, and the verifier rejects "
            "any measurement that is not on the signed list. Send exactly this line to the "
            "operator on your miner beta issue:"
        )
        lines.append("")
        lines.append(f"    {result.measurement}")
        lines.append("")
        lines.append(
            "Adding it is a human step: the operator captures the measurement live from your "
            "worker through the pinned verifier and publishes a new signed policy release. "
            "It is not automatic and it is not instant. See MINING.md, 'Getting a new "
            "measurement approved'."
        )
        lines.append(
            "If you have not yet built the machine from the documented recipe, do that first: "
            "docs/TDX_LAUNCH.md 'Reproducing an approved miner image' gives the exact instance "
            "definition that produces an approved measurement today."
        )
        if result.debug_enabled:
            lines.append("")
            lines.append(
                "Note: this TD has the debug attribute set. Cathedral rejects debug TDs outright, "
                "and the attribute is one of the fields inside the measurement, so this value can "
                "never be approved. Relaunch without debug before asking for anything else."
            )
    elif result.verdict == VERDICT_NO_TDX:
        lines.append("RESULT: this machine cannot produce a TDX quote. Nothing was checked.")
        lines.append("")
        for reason in (result.environment.reasons() if result.environment else ()):
            lines.append(f"  - {reason}")
        lines.append("")
        lines.append(
            "This is a real answer, not a failure of the tool: a machine that cannot produce "
            "a quote can never be admitted. Rebuild on an Intel TDX confidential VM using the "
            "recipe in docs/TDX_LAUNCH.md."
        )
    elif result.verdict == VERDICT_COLLECTION_FAILED:
        lines.append("RESULT: quote collection failed. No conclusion was reached.")
        lines.append("")
        lines.append(f"  {result.error}")
        lines.append("")
        lines.append(
            "configfs-tsm needs write access to create a report directory. Re-run under sudo "
            "if this was a permission error."
        )
    elif result.verdict == VERDICT_VERIFIER_FAILED:
        lines.append("RESULT: the verifier did not produce a usable answer.")
        lines.append("")
        lines.append(f"  {result.error}")
        lines.append("")
        lines.append(
            "The measurement above was derived locally and is still correct. Only the TCB "
            "verdict is missing."
        )
    elif result.verdict == VERDICT_DERIVATION_MISMATCH:
        lines.append("RESULT: STOP. The verifier and this build disagree about the measurement.")
        lines.append("")
        lines.append(f"  {result.error}")
        lines.append("")
        lines.append(
            "Do not enrol on this result. You are running a verifier and a Cathedral release "
            "whose measurement contracts differ. Report both values to the operator."
        )

    approved_verdicts = (VERDICT_APPROVED, VERDICT_APPROVED_TCB_UNCHECKED)
    if result.verdict in approved_verdicts and not result.allowlist_source.startswith(
        "signed policy registry"
    ):
        lines.append("")
        lines.append(
            "This answer is only as good as the list you supplied. The signed policy registry "
            "is what admission actually consults, so confirm with the operator before relying "
            "on a hand-copied list."
        )
    return "\n".join(lines)


def _claim_str(claims: Mapping[str, object] | None, key: str) -> str | None:
    if not claims:
        return None
    value = claims.get(key)
    return value if isinstance(value, str) and value else None
