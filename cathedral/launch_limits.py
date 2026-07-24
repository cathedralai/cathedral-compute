"""Frozen SN39 Intel TDX launch cardinality contract.

These limits are shared by the score producer, evidence exporter, and
independent verifier. A report that the producer can publish must remain
exportable and verifiable under the same launch grammar.
"""

MAX_LAUNCH_CANDIDATES = 4096
MAX_LAUNCH_VERIFIED_CANDIDATES = 28
