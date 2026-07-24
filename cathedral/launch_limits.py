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
# The public evidence verifier already fetches score reports under this
# 2 MiB ceiling. A maximal 4,096-candidate report at the launch hotkey bound
# fits beneath it; the former 1 MiB score-class-only cap did not.
MAX_LAUNCH_SCORE_REPORT_BYTES = 2 * 1024 * 1024
