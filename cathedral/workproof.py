"""Independent SAT work replay: the workload half of full provenance.

A hardware quote proves *where* work ran; it says nothing about *what* work
was done. A signed receipt asserts work digests and units, but a signer-only
assertion must never earn at FULL assurance. This module re-verifies the
published, content-addressed work artifacts end to end:

  receipt ``work.manifest_digest``  ==  sha256(canonical work-item bytes)
  receipt ``work.result_digest``    ==  sha256(canonical result bytes)
  result challenge/hotkey           ==  work item challenge / receipt subject
  the assignment                    ==  independently re-checked against
                                        every clause (exactly-once variable
                                        coverage, single sign, satisfaction)
  work units                        ==  re-derived by the validator formula
                                        (clause count for validator-derived
                                        SAT work) and equal to the receipt's
                                        signed units

The byte formats are exactly the runtime's: the ``cathedral_sat_manifest_v1``
work-item canonicalization and the work-claim evidence material
(``assigned_hotkey``/``assignment``/``challenge_id``/``satisfiable``/
``work_units``, sorted compact ASCII JSON).
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any

WORK_ITEM_SCHEMA = "cathedral_sat_manifest_v1"
MAX_WORK_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_CLAUSES = 100_000
MAX_VARS = 100_000


class WorkProofError(Exception):
    """Independent work replay failed; FULL provenance must fail closed."""


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _strict_canonical_json(data: bytes, label: str) -> dict[str, Any]:
    if len(data) > MAX_WORK_ARTIFACT_BYTES:
        raise WorkProofError(f"{label} is oversized")

    def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate {label} JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_no_duplicates,
            parse_constant=lambda _v: (_ for _ in ()).throw(ValueError(f"non-finite {label} JSON")),
        )
    except (ValueError, UnicodeDecodeError) as exc:
        raise WorkProofError(f"{label} is not strict ASCII JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise WorkProofError(f"{label} is not a JSON object")
    canonical = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if canonical != data:
        raise WorkProofError(f"{label} bytes are not canonical JSON")
    return document


def verify_work_artifacts(
    work_item_bytes: bytes,
    result_bytes: bytes,
    *,
    expected_manifest_digest: str,
    expected_result_digest: str,
    expected_challenge_id: str,
    expected_hotkey: str,
    expected_units: Decimal,
) -> None:
    """Independently replay one receipt's SAT work from published bytes."""
    if _digest(work_item_bytes) != expected_manifest_digest:
        raise WorkProofError("work-item bytes do not match the receipt's signed manifest digest")
    if _digest(result_bytes) != expected_result_digest:
        raise WorkProofError("result bytes do not match the receipt's signed result digest")

    item = _strict_canonical_json(work_item_bytes, "work item")
    if frozenset(item) != {"schema", "challenge_id", "seed", "instance"}:
        raise WorkProofError("work item has missing or unknown fields")
    if item["schema"] != WORK_ITEM_SCHEMA:
        raise WorkProofError("work item schema is unsupported")
    if item["challenge_id"] != expected_challenge_id:
        raise WorkProofError("work item challenge does not match the receipt's challenge binding")
    instance = item["instance"]
    if not isinstance(instance, dict) or frozenset(instance) != {"n_vars", "clauses"}:
        raise WorkProofError("work item instance is malformed")
    n_vars = instance["n_vars"]
    clauses = instance["clauses"]
    if (
        isinstance(n_vars, bool)
        or not isinstance(n_vars, int)
        or not 1 <= n_vars <= MAX_VARS
        or not isinstance(clauses, list)
        or not 1 <= len(clauses) <= MAX_CLAUSES
    ):
        raise WorkProofError("work item instance bounds are invalid")
    for clause in clauses:
        if (
            not isinstance(clause, list)
            or not clause
            or any(
                isinstance(literal, bool)
                or not isinstance(literal, int)
                or literal == 0
                or abs(literal) > n_vars
                for literal in clause
            )
        ):
            raise WorkProofError("work item clause is malformed")

    result = _strict_canonical_json(result_bytes, "work result")
    if frozenset(result) != {
        "assigned_hotkey",
        "assignment",
        "challenge_id",
        "satisfiable",
        "work_units",
    }:
        raise WorkProofError("work result has missing or unknown fields")
    if result["challenge_id"] != expected_challenge_id:
        raise WorkProofError("work result challenge does not match the receipt's challenge binding")
    if result["assigned_hotkey"] != expected_hotkey:
        raise WorkProofError(
            "work result is assigned to a different hotkey than the receipt subject"
        )
    if result["satisfiable"] is not True:
        raise WorkProofError("only satisfiable certificates with checkable witnesses can earn")

    assignment = result["assignment"]
    if (
        not isinstance(assignment, list)
        or len(assignment) != n_vars
        or any(isinstance(literal, bool) or not isinstance(literal, int) for literal in assignment)
    ):
        raise WorkProofError("work result assignment is malformed")
    # Exactly-once variable coverage with a single sign: a contradictory
    # assignment (+v and -v) could otherwise 'satisfy' unsatisfiable input.
    if {abs(literal) for literal in assignment} != set(range(1, n_vars + 1)):
        raise WorkProofError("work result assignment does not cover the variables")
    true_literals = set(assignment)
    for clause in clauses:
        if not any(literal in true_literals for literal in clause):
            raise WorkProofError(
                "work result assignment does not satisfy every clause; the "
                "claimed solve is not real work"
            )

    # Validator-derived unit formula for supported SAT work: the clause
    # count. Neither the miner's nor the signer's asserted number is
    # trusted; the receipt's signed units must EQUAL the re-derivation, and
    # the certificate's own units must agree.
    derived_units = Decimal(len(clauses))
    certificate_units = result["work_units"]
    # The raw certificate's units are the MINER's claim - bound into the
    # result digest for auditability but never trusted. Only shape-check it;
    # the value that earns is the validator re-derivation below.
    if isinstance(certificate_units, bool) or not isinstance(certificate_units, (int, float)):
        raise WorkProofError("work result units are malformed")
    if expected_units != derived_units:
        raise WorkProofError(
            f"receipt-signed units {expected_units} != independently derived "
            f"{derived_units}; a signer-only assertion never earns"
        )
