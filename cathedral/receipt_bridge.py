"""Authenticated key resolution for cross-repo receipt verification.

A receipt verifier in another repository (cathedral-distill's compute lane, and
the validator seam that drives it) resolves a receipt's `signing_key_id` through
an injected registry object with one method::

    registry.resolve(key_id, at=<aware UTC datetime>) -> Ed25519PublicKey

This repository anchors receipt keys differently: in the signed policy registry,
reached through `PolicyRegistrySnapshot.receipt_key()`, with per-key status,
transition time, and validity window. The two shapes are compatible in content
but not in interface, so a genuine Cathedral-issued receipt could not be handed
to those verifiers at all.

`AnchoredReceiptKeyResolver` is that adapter, and it is deliberately an
ANCHORED one: it resolves only from a signature-verified policy registry
snapshot, applies the same trust rules `receipt.verify_receipt` applies, and
never accepts a caller-supplied public key. Adapting the interface must not
widen the trust model, so this class enforces, in order:

  * both snapshots carry a verified registry signature;
  * the newest key registry does not predate the policy registry;
  * the key id exists in both and carries identical public-key bytes across
    them, so a key cannot be swapped by publishing a newer registry;
  * the key may verify at the receipt's issue time (a revoked key never can,
    and a retired key only before its retirement).

Legacy behavior is explicit and unchanged: this adapter resolves keys only. It
does not add, require, or emit the optional `platform` extension block, and a
platform-less Cathedral receipt remains exactly as (in)admissible in another
lane as that lane's own schema makes it. Compute in cathedral-distill requires
`platform`, so a platform-less receipt is refused there on schema grounds, not
on key grounds.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cathedral.policy_registry import PolicyRegistrySnapshot
from cathedral.receipt import ReceiptError


class AnchoredReceiptKeyResolver:
    """Resolve a receipt `signing_key_id` from signed Cathedral registries."""

    def __init__(
        self,
        policy_registry: PolicyRegistrySnapshot,
        *,
        key_registry: PolicyRegistrySnapshot | None = None,
    ) -> None:
        if not isinstance(policy_registry, PolicyRegistrySnapshot):
            raise ReceiptError("key", "receipt policy registry snapshot is invalid")
        if key_registry is not None and not isinstance(
            key_registry, PolicyRegistrySnapshot
        ):
            raise ReceiptError("key", "receipt key registry snapshot is invalid")
        trust_registry = key_registry or policy_registry
        # An unauthenticated snapshot resolves nothing: adapting the interface
        # must not become a way to bypass the registry signature.
        if not policy_registry.signature_verified or not trust_registry.signature_verified:
            raise ReceiptError("key", "receipt key registry signature is not verified")
        if trust_registry.release < policy_registry.release:
            raise ReceiptError("key", "receipt key registry predates its policy registry")
        self._policy_registry = policy_registry
        self._trust_registry = trust_registry

    @property
    def release(self) -> int:
        return self._policy_registry.release

    def resolve(self, key_id: object, *, at: datetime) -> Ed25519PublicKey:
        if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() != timedelta(0):
            raise ReceiptError("key", "receipt key resolution time must be UTC")
        if not isinstance(key_id, str) or not key_id:
            raise ReceiptError("key", "receipt signing key id is invalid")
        policy_key = self._policy_registry.receipt_key(key_id)
        trust_key = self._trust_registry.receipt_key(key_id)
        if (
            policy_key is None
            or trust_key is None
            or policy_key.public_key != trust_key.public_key
        ):
            raise ReceiptError("key", "receipt signing key is not consistently anchored")
        if not trust_key.can_verify_at(at.astimezone(UTC)):
            raise ReceiptError(
                "key", "receipt signing key is retired, revoked, or out of window"
            )
        return Ed25519PublicKey.from_public_bytes(trust_key.public_key)


__all__ = ["AnchoredReceiptKeyResolver"]
