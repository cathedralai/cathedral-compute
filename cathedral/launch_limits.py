"""Frozen SN39 Intel TDX launch cardinality contract.

These limits are shared by the score producer, evidence exporter, and
independent verifier. A report that the producer can publish must remain
exportable and verifiable under the same launch grammar.
"""

MAX_LAUNCH_CANDIDATES = 4096
MAX_LAUNCH_VERIFIED_CANDIDATES = 28
# This is the exact upper bound accepted by the SN39 confidential-score
# intake. Keeping it here prevents the producer from publishing an identity
# that the public publisher must later reject.
MAX_LAUNCH_HOTKEY_BYTES = 128
# Exact authenticated intake ceiling on the subnet publisher. The
# confidential producer checks this on the canonical body before freezing
# and again before posting.
MAX_LAUNCH_WIRE_REPORT_BYTES = 1024 * 1024
# The public evidence verifier already fetches score reports under this
# 2 MiB ceiling. A maximal 4,096-candidate report at the launch hotkey bound
# fits beneath it; the former 1 MiB score-class-only cap did not.
MAX_LAUNCH_SCORE_REPORT_BYTES = 2 * 1024 * 1024
MAX_LAUNCH_EVIDENCE_BASE_URI_BYTES = 2048


def is_launch_hotkey(value: object) -> bool:
    """Return whether an identity is stable across JSON and subnet intake.

    SN39 identities are SS58 text. Requiring non-whitespace printable ASCII
    prevents JSON escape amplification and normalization drift while retaining
    the subnet's deliberately generous 128-character launch bound.
    """

    return (
        isinstance(value, str)
        and 1 <= len(value) <= MAX_LAUNCH_HOTKEY_BYTES
        and value.strip() == value
        and value.isascii()
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )
