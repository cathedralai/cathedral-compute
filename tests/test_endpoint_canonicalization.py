"""Contract: enrollment and the runtime must agree on what one machine is.

Two implementations decide whether two endpoint strings name the same machine:

* ``enroll.canonical_endpoint_key`` gates enrollment uniqueness and the
  per-coldkey cap;
* ``runtime._canonical_endpoint`` dedups probe targets at epoch time.

They are deliberately separate (enrollment must not import the runtime), and
``canonical_endpoint_key``'s own docstring says it "must agree with
``runtime._canonical_endpoint``". Nothing held that until this file: neither
name appeared in any test.

Why the agreement is load-bearing, not tidiness. The runtime excludes **every**
claimant of a duplicate, not just the later one. So if enrollment considers two
spellings different while the runtime considers them the same:

1. an attacker with one registered hotkey enrolls a cosmetic variant of a
   victim's endpoint (``:443`` made explicit, an expanded IPv6 form, a trailing
   dot);
2. enrollment sees a different key, so ``endpoint_claimed`` never fires and the
   row is accepted;
3. at epoch time the runtime collapses both to one target, finds a duplicate,
   and drops **both** before attestation;
4. the victim earns nothing, repeatably, for the price of one registration.

The same gap inflates one machine into N slots against the per-coldkey cap, so
"N machines per coldkey" silently becomes "N spellings of one machine".

The corpus below is only endpoints the runtime accepts: https, no credentials,
no query or fragment, and an empty or bare-slash path. Divergent handling of
INVALID input is fine and intended (enrollment returns a conservative fallback
key, the runtime raises), so it is out of scope here.
"""

from __future__ import annotations

import pytest

from cathedral.enroll import canonical_endpoint_key
from cathedral.runtime import RuntimeConfig, _canonical_endpoint

# Each group is one machine written several ways. Every member must produce the
# same key, under BOTH implementations, and the two must produce the same key
# as each other.
EQUIVALENT_SPELLINGS = [
    pytest.param(
        ["https://miner.example", "https://miner.example:443", "https://miner.example/"],
        id="https-default-port-and-bare-path",
    ),
    pytest.param(
        ["https://MINER.example", "https://miner.EXAMPLE", "https://miner.example"],
        id="host-case",
    ),
    pytest.param(
        ["https://miner.example.", "https://miner.example"],
        id="trailing-dot",
    ),
    pytest.param(
        ["https://8.8.8.8", "https://8.8.8.8:443", "https://8.8.8.8/"],
        id="ipv4-default-port",
    ),
    pytest.param(
        [
            "https://[2001:db8::1]",
            "https://[2001:0db8:0000:0000:0000:0000:0000:0001]",
            "https://[2001:DB8::1]",
        ],
        id="ipv6-compression-and-case",
    ),
    pytest.param(
        ["https://miner.example:8443", "https://MINER.example:8443/"],
        id="explicit-non-default-port",
    ),
]

# Endpoints that name genuinely different machines. Without these the test
# above could pass by mapping everything to one constant.
DISTINCT = [
    "https://miner-a.example",
    "https://miner-b.example",
    "https://miner.example:8443",
    "https://8.8.8.8",
    "https://8.8.4.4",
    "https://[2001:db8::1]",
    "https://[2001:db8::2]",
]


def _config() -> RuntimeConfig:
    return RuntimeConfig(production_mode=False)


@pytest.mark.parametrize("spellings", EQUIVALENT_SPELLINGS)
def test_both_implementations_collapse_equivalent_spellings(spellings: list[str]):
    enroll_keys = {canonical_endpoint_key(url) for url in spellings}
    runtime_keys = {_canonical_endpoint(url, _config()) for url in spellings}
    assert len(enroll_keys) == 1, f"enrollment split one machine into {enroll_keys}"
    assert len(runtime_keys) == 1, f"the runtime split one machine into {runtime_keys}"


@pytest.mark.parametrize("spellings", EQUIVALENT_SPELLINGS)
def test_the_two_implementations_agree_with_each_other(spellings: list[str]):
    """The load-bearing one: a disagreement is the victim-zeroing bug."""
    for url in spellings:
        assert canonical_endpoint_key(url) == _canonical_endpoint(url, _config()), (
            f"enrollment and the runtime disagree on {url!r}; the runtime drops "
            "every claimant of a duplicate, so a disagreement lets an attacker "
            "zero a victim by enrolling an equivalent spelling"
        )


def test_distinct_machines_keep_distinct_keys():
    """Both directions, so agreement cannot be reached by collapsing everything."""
    enroll_keys = [canonical_endpoint_key(url) for url in DISTINCT]
    runtime_keys = [_canonical_endpoint(url, _config()) for url in DISTINCT]
    assert len(set(enroll_keys)) == len(DISTINCT), f"enrollment merged: {enroll_keys}"
    assert len(set(runtime_keys)) == len(DISTINCT), f"the runtime merged: {runtime_keys}"


def test_an_attacker_spelling_collides_at_enrollment_not_at_epoch_time():
    """The specific attack, stated as an assertion.

    A victim enrolled at the implicit-port form. The attacker submits the
    explicit-port form of the same address. Enrollment must already see that as
    the same machine, because by the time the runtime notices it is too late:
    it drops both.
    """
    victim = "https://8.8.8.8"
    attacker = "https://8.8.8.8:443"
    assert canonical_endpoint_key(victim) == canonical_endpoint_key(attacker)
    cfg = _config()
    assert _canonical_endpoint(victim, cfg) == _canonical_endpoint(attacker, cfg)
