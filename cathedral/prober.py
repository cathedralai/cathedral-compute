"""Attestation probe loop for enrolled Cathedral miners."""

from __future__ import annotations

import argparse
import base64
import http.client
import ipaddress
import json
import logging
import math
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from http.client import HTTPResponse
from typing import Any, Callable
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

import cathedral.verify as verifier
from cathedral.assurance import ATTESTATION_ADMISSION_POLICY, with_verified_channel
from cathedral.common import (
    Attested,
    Evidence,
    EvidenceKind,
    MAX_EVIDENCE_RESPONSE_BODY,
    MAX_GPU_EVIDENCE_CONCURRENCY,
    Policy,
    Tier,
    issue_nonce,
    is_globally_routable,
)
from cathedral.enroll import RegistryStore
from cathedral.lifecycle import (
    LifecycleError,
    LifecycleReason,
    WorkerLifecycleState,
)
from cathedral.remote import RemoteMiner, _deadline_response_class


MAX_EVIDENCE_BYTES = 64 * 1024
TIMEOUT_SECONDS = 5
LOGGER = logging.getLogger(__name__)


class _PreResolvedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that uses a pre-resolved IP address.

    Stores the original hostname for the Host header and the resolved IP
    for the socket connection. This prevents a second DNS lookup that could
    be hijacked by DNS rebinding after enrollment-time validation.
    """

    def __init__(
        self,
        host: str,
        *,
        resolved_addr: str,
        deadline: float | None = None,
        **kwargs: Any,
    ) -> None:
        self._resolved_addr = resolved_addr
        super().__init__(host, **kwargs)
        if deadline is not None:
            self.response_class = _deadline_response_class(deadline)

    def connect(self) -> None:
        """Override socket connection to use the pre-resolved IP."""
        self.sock = socket.create_connection(
            (self._resolved_addr, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()


class _PreResolvedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that uses a pre-resolved IP address.

    Stores the original hostname for SNI and the resolved IP for the socket.
    """

    def __init__(
        self,
        host: str,
        *,
        resolved_addr: str,
        deadline: float | None = None,
        **kwargs: Any,
    ) -> None:
        self._resolved_addr = resolved_addr
        super().__init__(host, **kwargs)
        if deadline is not None:
            self.response_class = _deadline_response_class(deadline)

    def connect(self) -> None:
        """Override socket connection to use the pre-resolved IP."""
        sock = socket.create_connection(
            (self._resolved_addr, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )
        self.sock = sock
        if self._tunnel_host:
            self._tunnel()
            server_hostname = self._tunnel_host
        else:
            server_hostname = self.host
        self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)


def _resolve_endpoint(
    url: str, *, resolver: Any = None, production_mode: bool = False
) -> str | None:
    """Resolve the endpoint URL's hostname and verify every resolved address is
    a public/global unicast destination.  Runs before any network call to
    prevent SSRF to loopback, link-local, or RFC-1918 targets via DNS rebinding.

    IP literals are validated for globality here. At enrollment time,
    ``validate_endpoint_url`` enforces this in production_mode=True only. At
    probe time, this function ensures preexisting/migrated/hand-inserted rows
    cannot use local IP literals in production mode.

    :param resolver: optional ``callable(host: str, port: int) -> list[str]``
        injected by tests.  When None the default system resolver is used.
    :param production_mode: when True, both hostname and non-global IP-literal
        endpoints are rejected outright, before any network access. This
        closes two SSRF gaps: (1) DNS rebinding (hostname → non-global via
        re-resolution), and (2) stale enrollments (preexisting local IP
        literals that bypassed production enrollment checks). A public IP
        literal has neither gap because nothing is re-resolved and the literal
        is validated to be global at this point. Non-production callers accept
        local IP literals for testing; that residual SSRF window is accepted
        outside production.

    :return: the first validated global address (for use in pre-resolved
        connection classes), or None if the URL uses a global IP literal.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if host is None:
        raise ValueError("endpoint_url has no hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # IP literals: validate globality; in production mode, reject all non-global.
    try:
        ip = ipaddress.ip_address(host)
        if production_mode and not is_globally_routable(ip):
            raise ValueError(
                f"endpoint IP literal {host!r} rejected in production mode: "
                "must be a public/global address"
            )
        return None  # IP literal (validated as global in production); no resolution needed
    except ValueError as exc:
        # Re-raise validation errors; let hostname parsing continue.
        if "rejected" in str(exc):
            raise
        pass  # Not an IP literal — fall through.

    if production_mode:
        raise ValueError(
            f"endpoint hostname {host!r} rejected in production mode: "
            "production endpoints must be a public IP literal"
        )

    if resolver is not None:
        addrs = resolver(host, port)
    else:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ValueError(f"cannot resolve endpoint hostname {host!r}: {exc}") from exc
        addrs = [info[4][0] for info in infos]

    if not addrs:
        raise ValueError(f"endpoint hostname {host!r} resolved to no addresses")

    resolved_addr = None
    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if not is_globally_routable(ip):
            raise ValueError(
                f"endpoint resolves to non-global address {addr!r} for hostname {host!r}"
            )
        if resolved_addr is None:
            resolved_addr = addr
    return resolved_addr


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class _PreResolvedHTTPHandler(http.client.HTTPConnection):
    """urllib handler that uses pre-resolved HTTP connections."""

    def __init__(self, resolved_addr: str) -> None:
        self.resolved_addr = resolved_addr


class _PreResolvedHTTPSHandler(http.client.HTTPSConnection):
    """urllib handler that uses pre-resolved HTTPS connections."""

    def __init__(self, resolved_addr: str) -> None:
        self.resolved_addr = resolved_addr


def _build_pre_resolved_opener(
    resolved_addr: str,
    *,
    deadline: float | None = None,
) -> Any:
    """Build an opener that uses pre-resolved connection classes.

    The opener will instantiate _PreResolvedHTTPConnection and
    _PreResolvedHTTPSConnection with the validated resolved address,
    preventing any secondary DNS lookup that could be hijacked.
    """
    from urllib.request import HTTPHandler, HTTPSHandler

    class _ResolvedHTTPHandler(HTTPHandler):
        def http_open(self, req: Any) -> Any:
            return self.do_open(
                lambda h, **kw: _PreResolvedHTTPConnection(
                    h,
                    resolved_addr=resolved_addr,
                    deadline=deadline,
                    **kw,
                ),
                req,
            )

    class _ResolvedHTTPSHandler(HTTPSHandler):
        def https_open(self, req: Any) -> Any:
            return self.do_open(
                lambda h, **kw: _PreResolvedHTTPSConnection(
                    h,
                    resolved_addr=resolved_addr,
                    deadline=deadline,
                    **kw,
                ),
                req,
            )

    return build_opener(NoRedirect, _ResolvedHTTPHandler(), _ResolvedHTTPSHandler())


def _remaining_evidence_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("evidence request exceeded its total deadline")
    return remaining


def _read_capped(response: HTTPResponse, cap: int = MAX_EVIDENCE_BYTES) -> bytes:
    body = response.read(cap + 1)
    if len(body) > cap:
        raise ValueError("evidence response too large")
    return body


def _parse_evidence_item(raw: Any, hotkey: str, nonce: bytes) -> Evidence:
    if not isinstance(raw, dict):
        raise ValueError("evidence item must be an object")
    kind = EvidenceKind(raw["kind"])
    quote = base64.b64decode(raw["quote_b64"], validate=True)
    if len(quote) > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence quote too large")
    evidence_nonce = bytes.fromhex(raw["nonce_hex"])
    if evidence_nonce != nonce:
        raise ValueError("evidence nonce mismatch")
    miner_hotkey = raw.get("miner_hotkey")
    if miner_hotkey != hotkey:
        raise ValueError("evidence hotkey mismatch")
    cert_chain = [base64.b64decode(item, validate=True) for item in raw.get("cert_chain_b64", [])]
    ssh_host_key = None
    if raw.get("ssh_host_key_b64"):
        ssh_host_key = base64.b64decode(raw["ssh_host_key_b64"], validate=True)
    return Evidence(
        kind=kind,
        quote=quote,
        nonce=evidence_nonce,
        miner_hotkey=miner_hotkey,
        cert_chain=cert_chain,
        ssh_host_key=ssh_host_key,
        composite_jwt=raw.get("composite_jwt"),
    )


def _request_evidence(
    endpoint_url: str,
    hotkey: str,
    nonce: bytes,
    *,
    resolver: Any = None,
    opener: Any = None,
    production_mode: bool = False,
) -> list[Evidence]:
    """Fetch attestation evidence from a miner endpoint.

    :param resolver: injected DNS resolver ``(host, port) -> list[str]`` for
        tests; None uses the system resolver.  See ``_resolve_endpoint``.
    :param opener: injected ``urllib`` opener for tests; None creates the
        default no-redirect opener with pre-resolved connection classes.
        The resolution check always runs first, before ``opener.open`` is
        ever called.
    :param production_mode: forwarded to ``_resolve_endpoint``; rejects
        hostname endpoints before any network access. See ``probe_once``.
    """
    # Resolve the hostname and reject non-global destinations before making
    # any network connection.  Prevents SSRF via DNS rebinding, and in
    # production mode rejects hostnames outright (see _resolve_endpoint).
    resolved_addr = _resolve_endpoint(
        endpoint_url, resolver=resolver, production_mode=production_mode
    )
    # Synchronous name resolution has no safe stdlib cancellation primitive.
    # The request deadline starts after resolution. Production endpoints are
    # IP literals, so production probing has no resolver step here.
    deadline = time.monotonic() + TIMEOUT_SECONDS

    url = urljoin(endpoint_url.rstrip("/") + "/", "v1/evidence")
    payload = json.dumps({"nonce_hex": nonce.hex(), "hotkey": hotkey}).encode("utf-8")
    req = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    if opener is None:
        # Build a custom opener that uses pre-resolved connections to prevent
        # a second (rebindable) DNS lookup.  When resolved_addr is None
        # (IP literal endpoint), the standard connection classes are used.
        parsed_host = urlparse(endpoint_url).hostname
        if parsed_host is None:
            raise ValueError("endpoint_url has no hostname")
        opener = _build_pre_resolved_opener(
            resolved_addr or parsed_host,
            deadline=deadline,
        )
    with opener.open(req, timeout=_remaining_evidence_seconds(deadline)) as response:
        body = _read_capped(response)
    raw = json.loads(body.decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("evidence response must be an object")
    if isinstance(raw.get("evidence"), list):
        items = raw["evidence"]
    elif isinstance(raw.get("evidence_items"), list):
        items = raw["evidence_items"]
    else:
        items = [raw]
    if not items or len(items) > 8:
        raise ValueError("evidence bundle size invalid")
    return [_parse_evidence_item(item, hotkey, nonce) for item in items]


def policy_from_args(args: argparse.Namespace) -> Policy:
    measurements = set(args.allow_measurement or [])
    if args.allow_measurements_file:
        with open(args.allow_measurements_file) as fh:
            measurements.update(line.strip() for line in fh if line.strip())
    return Policy(
        allowed_measurements=measurements,
        min_tcb=args.min_tcb,
        tdx_strict=getattr(args, "tdx_strict", False),
        tdx_allowed_tcb_statuses=set(getattr(args, "allow_tdx_tcb_status", None) or ["UpToDate"]),
        tdx_allowed_advisories=set(getattr(args, "allow_tdx_advisory", None) or []),
    )


def _verify_tdx_evidence(
    evidences: list[Evidence],
    nonce: bytes,
    policy: Policy,
) -> Attested | None:
    """TDX-CPU launch path: a single verified TDX evidence is sufficient.

    Returns an ``Attested(CC_CPU_TDX)`` verdict only when the verifier returns
    an ``Attested`` with ``verification_status == "VERIFIED"`` and
    ``tier == Tier.CC_CPU_TDX``.  Any other outcome (None, wrong status, wrong
    tier) rejects.
    """
    tdx = next((e for e in evidences if e.kind is EvidenceKind.TDX), None)
    if tdx is None:
        return None

    attested = verifier.verify(tdx, nonce, policy)
    if (
        attested is None
        or attested.verification_status != "VERIFIED"
        or attested.tier is not Tier.CC_CPU_TDX
        or not ATTESTATION_ADMISSION_POLICY.allows(attested.assurance)
    ):
        return None
    return attested


def verify_cc_evidence_bundle(
    evidences: list[Evidence],
    nonce: bytes,
    policy: Policy,
    *,
    gpu_profile=None,
    gpu_verifier=None,
    gpu_identity_registry=None,
    expected_tier: Tier = Tier.CC_CPU_TDX,
) -> Attested | None:
    """Verify the CPU evidence bundle and return an admission verdict.

    GPU verification is deliberately completed inside ``probe_once`` so the
    component result cannot escape without live-channel confirmation and the
    durable identity claim at the lifecycle admission boundary.

    Returns ``None`` (reject) when no path produces a verdict.
    """

    if expected_tier not in {Tier.CC_CPU_TDX, Tier.CC_GPU}:
        return None
    gpu_configuration = (gpu_profile, gpu_verifier, gpu_identity_registry)
    if expected_tier is Tier.CC_GPU:
        return None
    if any(item is not None for item in gpu_configuration):
        # CPU and GPU participation use separate validator-owned requests.
        return None

    gpu_components = [e for e in evidences if e.kind is EvidenceKind.GPU_CC]
    if gpu_components:
        return None

    tdx_result = _verify_tdx_evidence(evidences, nonce, policy)
    if tdx_result is not None:
        return tdx_result

    return None


DEFAULT_NEW_WORKER_SHARE = 0.25


def select_probe_targets(
    due: list[tuple[Any, Any]],
    *,
    max_probes: int | None,
    new_worker_share: float = DEFAULT_NEW_WORKER_SHARE,
    deadline_active: bool = False,
) -> tuple[list[tuple[Any, Any]], list[tuple[Any, Any]]]:
    """Split the due set into this pass's targets and the deferred remainder.

    A budget without an ordering is a starvation bug. ``due_refreshes``
    returns rows ordered by hotkey, so truncating that list would probe the
    same lexicographically smallest hotkeys every pass and never reach the
    tail. Targets are therefore ordered **most overdue first**, which is both
    fair and the order that minimises time spent outside a verdict.

    The budget is also split across two classes, because a single queue lets
    either class starve the other:

    - workers with no verified evidence yet (a first probe), and
    - workers with evidence due for refresh.

    Open mode makes this load-bearing. If new workers always won, anyone
    could enroll continuously and push already-attested miners past their
    evidence expiry, turning an admission gate into a way to zero honest
    supply. If refreshes always won, a full subnet would never admit anyone
    new. An interior share reserves both classes and unused capacity spills to
    the other, so the budget is never wasted on an empty class. The 0.0 and 1.0
    endpoints are explicit single-class-priority modes.

    Deferral is not failure. A deferred target keeps its verdict, its
    lifecycle state, and its retry counter untouched; it is simply probed on
    a later pass.

    The ordering applies even when everything fits inside the budget, because
    the pass deadline still decides who starts, and a set that fits in the
    budget can still exceed the clock.
    """
    if not 0.0 <= new_worker_share <= 1.0:
        raise ValueError("new_worker_share must be between 0.0 and 1.0")
    if max_probes is None and not deadline_active:
        return list(due), []
    if max_probes is not None and max_probes < 1:
        raise ValueError(f"max_probes must be at least 1, got {max_probes}")
    if max_probes is not None and max_probes < 2 and 0.0 < new_worker_share < 1.0:
        raise ValueError(
            "max_probes must be at least 2 when new_worker_share reserves "
            "capacity for both first probes and refreshes"
        )

    # A deadline can defer targets even without a count budget. In that mode
    # every due target remains selected, but it must still use the fair order
    # below. Otherwise the database's hotkey order lets the same low-sorting
    # workers start first on every pass and starves the tail indefinitely.
    if max_probes is None:
        max_probes = len(due)
        if max_probes == 0:
            return [], []

    def _epoch_seconds(value: Any) -> float | None:
        try:
            return value.timestamp()
        except AttributeError:
            return None

    def overdue_key(target: tuple[Any, Any]) -> tuple[Any, ...]:
        _enrollment, lifecycle = target
        expires = _epoch_seconds(getattr(lifecycle, "evidence_expires_at", None))
        verified = _epoch_seconds(getattr(lifecycle, "evidence_verified_at", None))
        # A worker awaiting its first probe has neither timestamp, so without
        # a third key the whole fresh class would collapse onto the hotkey
        # tie-break — and an attacker who grinds a low-sorting ss58 would take
        # the reserved share every pass, which is the starvation this ordering
        # exists to prevent. state_changed_at makes the fresh class
        # first-come-first-served, which key choice cannot influence.
        waiting_since = _epoch_seconds(getattr(lifecycle, "state_changed_at", None))
        return (
            expires is not None,
            expires if expires is not None else 0.0,
            verified is not None,
            verified if verified is not None else 0.0,
            waiting_since is not None,
            waiting_since if waiting_since is not None else 0.0,
            lifecycle.hotkey,
        )

    fresh = sorted(
        (t for t in due if getattr(t[1], "evidence_verified_at", None) is None),
        key=overdue_key,
    )
    refresh = sorted(
        (t for t in due if getattr(t[1], "evidence_verified_at", None) is not None),
        key=overdue_key,
    )

    fresh_budget = min(len(fresh), int(max_probes * new_worker_share))
    if fresh and fresh_budget == 0 and new_worker_share > 0:
        # A share small enough to round to zero would silently mean "never
        # admit anyone". An explicit 0.0 still means zero: that is a
        # deliberate posture where newcomers get only leftover capacity.
        fresh_budget = 1
    refresh_budget = max_probes - fresh_budget
    # Spill unused capacity both ways so a budget is never lost to an empty
    # or short class.
    if len(refresh) < refresh_budget:
        fresh_budget = min(len(fresh), fresh_budget + (refresh_budget - len(refresh)))
        refresh_budget = len(refresh)
    elif len(fresh) < fresh_budget:
        refresh_budget = min(len(refresh), refresh_budget + (fresh_budget - len(fresh)))
        fresh_budget = len(fresh)

    # Preserve refresh urgency in the selection result. When a deadline is
    # active, probe_once separately makes the executor's first wave fair across
    # both classes. Selection order alone cannot do that: a slow first class
    # can occupy every worker until the deadline expires.
    selected = refresh[:refresh_budget] + fresh[:fresh_budget]
    chosen = {id(target) for target in selected}
    return selected, [target for target in due if id(target) not in chosen]


def _deadline_fair_dispatch_order(
    targets: list[tuple[Any, Any]],
    *,
    worker_count: int,
    new_worker_share: float,
) -> list[tuple[Any, Any]]:
    """Place both reserved classes in the executor's first worker wave.

    A deadline is checked when a queued target starts. If every refresh is
    queued before every first probe, slow refreshes occupy the whole pool and
    the deadline discards the reserved first-probe capacity on every pass.
    The first wave therefore contains at least one target from each nonempty
    class and otherwise follows the selected class proportions.

    The explicit 0.0 and 1.0 share endpoints keep their single-class priority.
    One worker cannot provide two-class deadline fairness for an interior
    share, so callers reject that configuration before reaching this helper.
    """
    if worker_count < 1:
        raise ValueError("worker_count must be at least 1")
    refresh = [
        target for target in targets if getattr(target[1], "evidence_verified_at", None) is not None
    ]
    fresh = [
        target for target in targets if getattr(target[1], "evidence_verified_at", None) is None
    ]
    if new_worker_share == 0.0:
        return refresh + fresh
    if new_worker_share == 1.0:
        return fresh + refresh
    if not refresh or not fresh:
        return list(targets)
    if worker_count < 2:
        raise ValueError(
            "deadline probing requires at least 2 effective workers when "
            "capacity is reserved for first probes and refreshes"
        )

    first_wave_size = min(worker_count, len(targets))
    proportional_fresh = int(first_wave_size * len(fresh) / len(targets))
    fresh_slots = min(
        len(fresh),
        first_wave_size - 1,
        max(1, proportional_fresh),
    )
    refresh_slots = min(len(refresh), first_wave_size - fresh_slots)

    # Fill short-class capacity without losing the one-slot guarantee for
    # either class.
    unfilled = first_wave_size - fresh_slots - refresh_slots
    if unfilled:
        extra_fresh = min(len(fresh) - fresh_slots, unfilled)
        fresh_slots += extra_fresh
        unfilled -= extra_fresh
    if unfilled:
        refresh_slots += min(len(refresh) - refresh_slots, unfilled)

    # Put one target from each class first. This minimises thread-start timing
    # skew before the rest of the first wave is submitted.
    first_wave = [refresh[0], fresh[0]]
    first_wave.extend(refresh[1:refresh_slots])
    first_wave.extend(fresh[1:fresh_slots])
    remainder = refresh[refresh_slots:] + fresh[fresh_slots:]
    return first_wave + remainder


def probe_once(
    store: RegistryStore,
    policy: Policy,
    *,
    max_workers: int = 4,
    max_probes: int | None = None,
    new_worker_share: float = DEFAULT_NEW_WORKER_SHARE,
    deadline_seconds: float | None = None,
    resolver: Any = None,
    opener: Any = None,
    production_mode: bool = False,
    policy_refresher: Callable[[], Policy] | None = None,
    gpu_profile=None,
    gpu_verifier=None,
    gpu_identity_registry=None,
    expected_tier: Tier = Tier.CC_CPU_TDX,
) -> bool:
    """Probe all enrolled miners concurrently, bounded to *max_workers* threads.

    Each enrollment is isolated: a timeout or transport error in one probe
    records a failed public verdict plus a bounded lifecycle retry and does not
    prevent remaining enrollments from being probed in the same pass.
    Concurrency prevents one slow miner from serialising the entire pass.

    :param production_mode: when True, any enrollment whose endpoint_url host
        is not a public IP literal is rejected before any network access
        (recorded as a FAILED verdict for that hotkey, isolated from the
        rest of the pass). Matches the production enrollment-time policy in
        ``cathedral.enroll.validate_endpoint_url``.
    :param max_probes: cap on targets probed in one pass. ``None`` (the
        default) preserves the historical unbounded behaviour. Under open
        enrollment this is what stops a large population from making a pass
        unbounded in cost; see ``select_probe_targets`` for the fair
        two-class ordering that keeps a cap from starving either class.
    :param new_worker_share: fraction of *max_probes* reserved for workers
        with no verified evidence yet.
    :param deadline_seconds: wall-clock budget for the pass. Once it elapses,
        targets that have not started are deferred rather than dispatched.
        Probes already in flight are allowed to finish; their own transport
        timeouts bound them. An interior two-class share requires at least two
        effective workers so both classes enter the first dispatch wave.
    :raises ValueError: when *max_workers* is less than 1.
    """
    if max_workers < 1:
        raise ValueError(f"max_workers must be at least 1, got {max_workers}")
    if deadline_seconds is not None and (
        not math.isfinite(deadline_seconds) or deadline_seconds <= 0
    ):
        raise ValueError("deadline_seconds must be finite and positive")
    gpu_configuration = (gpu_profile, gpu_verifier, gpu_identity_registry)
    if expected_tier is Tier.CC_GPU and any(item is None for item in gpu_configuration):
        raise ValueError("GPU probing requires profile, verifier, and identity registry")
    if expected_tier is Tier.CC_CPU_TDX and any(item is not None for item in gpu_configuration):
        raise ValueError("CPU probing cannot carry GPU verifier configuration")
    if expected_tier not in {Tier.CC_CPU_TDX, Tier.CC_GPU}:
        raise ValueError("unsupported expected attestation tier")
    if expected_tier is Tier.CC_GPU:
        from cathedral.gpu import (
            ExternalGpuVerifier,
            GpuIdentityRegistry,
            GpuProfile,
        )

        if not isinstance(gpu_profile, GpuProfile) or not isinstance(
            gpu_identity_registry, GpuIdentityRegistry
        ):
            raise ValueError("GPU probe profile or identity registry is invalid")
    if production_mode:
        if not policy.production_ready_for_tdx:
            raise ValueError(
                "production probing requires strict signed CPU policy registry authority"
            )
        if policy_refresher is None:
            raise ValueError("production probing requires a live policy registry refresher")
        verifier.preflight_tdx_verifier(policy)

    captured_policy_authority = policy.registry_authority_identity

    def _require_current_policy() -> Policy:
        if not production_mode:
            return policy
        assert policy_refresher is not None
        refreshed = policy_refresher()
        if not isinstance(refreshed, Policy) or not refreshed.production_ready_for_tdx:
            raise ValueError("production CPU policy registry authority is not live")
        if refreshed.registry_authority_identity != captured_policy_authority:
            raise ValueError("production CPU policy changed during the probe")
        return refreshed

    _require_current_policy()
    if expected_tier is Tier.CC_GPU:
        if production_mode:
            if not gpu_profile.production_ready_for(policy):
                raise ValueError(
                    "production GPU probe requires a live profile from its CPU policy registry"
                )
            if not gpu_identity_registry.production_ready:
                raise ValueError("production GPU probe requires a protected identity registry")
            if not isinstance(gpu_verifier, ExternalGpuVerifier):
                raise ValueError("production GPU probe requires the pinned external verifier")
            if not gpu_verifier.production_ready:
                raise ValueError("production GPU probe requires a static verifier executable")
            gpu_verifier.preflight(gpu_profile)
    effective_workers = (
        min(max_workers, MAX_GPU_EVIDENCE_CONCURRENCY)
        if expected_tier is Tier.CC_GPU
        else max_workers
    )
    if deadline_seconds is not None and 0.0 < new_worker_share < 1.0 and effective_workers < 2:
        raise ValueError(
            "deadline probing requires at least 2 effective workers when "
            "new_worker_share reserves first probes and refreshes"
        )
    due_snapshots = {
        snapshot.hotkey: snapshot
        for snapshot in store.due_refreshes(refresh_ahead_seconds=store.verification_ttl_seconds)
    }
    all_due = [
        (enrollment, due_snapshots[enrollment.hotkey])
        for enrollment in store.enrollments()
        if enrollment.hotkey in due_snapshots
    ]
    probe_targets, deferred = select_probe_targets(
        all_due,
        max_probes=max_probes,
        new_worker_share=new_worker_share,
        deadline_active=deadline_seconds is not None,
    )
    if deadline_seconds is not None:
        probe_targets = _deadline_fair_dispatch_order(
            probe_targets,
            worker_count=effective_workers,
            new_worker_share=new_worker_share,
        )
    all_reached = True
    if deferred:
        LOGGER.info(
            "probe budget %d reached: %d target(s) deferred to the next pass",
            max_probes,
            len(deferred),
        )
        # A pass that did not reach every due target has not verified every
        # due target. Reporting success here would let `--once --max-probes N`
        # tell a health check the fleet is fine after contacting N of M.
        all_reached = False
    gpu_evidence_slots = threading.BoundedSemaphore(MAX_GPU_EVIDENCE_CONCURRENCY)

    def _probe_one(target: tuple[Any, Any]) -> bool:
        enrollment, lifecycle = target
        nonce = issue_nonce()
        try:
            if production_mode:
                _resolve_endpoint(
                    enrollment.endpoint_url,
                    resolver=resolver,
                    production_mode=True,
                )
                if urlparse(enrollment.endpoint_url).scheme != "https":
                    raise ValueError("production probing requires HTTPS")
                remote_options = {"timeout": TIMEOUT_SECONDS}
                if expected_tier is Tier.CC_GPU:
                    remote_options["max_response_body"] = MAX_EVIDENCE_RESPONSE_BODY
                client = RemoteMiner(
                    enrollment.endpoint_url,
                    enrollment.hotkey,
                    **remote_options,
                )
                if expected_tier is Tier.CC_GPU:
                    with gpu_evidence_slots:
                        evidences = list(client.fetch_evidence_bundle(nonce))
                    channel_evidence = next(
                        item for item in evidences if item.kind is EvidenceKind.TDX
                    )
                else:
                    channel_evidence = client.fetch_evidence(nonce)
                    evidences = [channel_evidence]
            else:
                client = None
                evidences = _request_evidence(
                    enrollment.endpoint_url,
                    enrollment.hotkey,
                    nonce,
                    resolver=resolver,
                    opener=opener,
                    production_mode=False,
                )
            composite = None
            if expected_tier is Tier.CC_GPU:
                from cathedral.gpu import (
                    GpuAttestationError,
                    gpu_error_is_evidence_denial,
                    verify_composite_gpu,
                )

                if production_mode and not gpu_profile.production_ready_for(policy):
                    raise ValueError("production GPU profile expired during probe")
                tdx_components = [item for item in evidences if item.kind is EvidenceKind.TDX]
                gpu_components = [item for item in evidences if item.kind is EvidenceKind.GPU_CC]
                if len(evidences) != 2 or len(tdx_components) != 1 or len(gpu_components) != 1:
                    attested = None
                else:
                    try:
                        composite = verify_composite_gpu(
                            tdx_components[0],
                            gpu_components[0],
                            nonce,
                            policy,
                            gpu_profile,
                            gpu_verifier,
                        )
                        if production_mode and not gpu_profile.production_ready_for(policy):
                            raise ValueError("production GPU profile expired during probe")
                        attested = composite.attested
                    except GpuAttestationError as exc:
                        if not gpu_error_is_evidence_denial(exc):
                            raise
                        LOGGER.info("GPU composite rejected: %s", exc.category)
                        attested = None
            else:
                attested = verify_cc_evidence_bundle(evidences, nonce, policy)
            if attested is None:
                _require_current_policy()
                store.record_verdict(
                    enrollment.hotkey,
                    None,
                    error="verification failed",
                    expected_generation=lifecycle.generation,
                    expected_revision=lifecycle.revision,
                    policy_registry_release=policy.registry_release,
                    policy_registry_digest=policy.registry_digest,
                )
                return False
            else:
                if client is not None:
                    binding = client.confirm_channel_binding(channel_evidence)
                    if (
                        any(item.channel_binding != binding for item in evidences)
                        or attested.assurance is None
                    ):
                        raise ValueError("attested channel binding mismatch")
                    attested = replace(
                        attested,
                        assurance=with_verified_channel(
                            attested.assurance, binding.canonical_bytes()
                        ),
                    )
                pending_gpu_claim = None
                if composite is not None:
                    if production_mode and not gpu_profile.production_ready_for(policy):
                        raise ValueError("production GPU profile expired before admission")
                    try:
                        pending_gpu_claim = gpu_identity_registry.begin_claim(
                            enrollment.hotkey,
                            composite.gpu_component,
                        )
                    except GpuAttestationError as exc:
                        if exc.category != "identity_conflict":
                            raise
                        store.transition_lifecycle(
                            enrollment.hotkey,
                            WorkerLifecycleState.REVOKED,
                            LifecycleReason.IDENTITY_CONFLICT,
                            expected_generation=lifecycle.generation,
                            expected_revision=lifecycle.revision,
                            operator_detail="GPU identity already backs another worker",
                        )
                        return False
                try:
                    _require_current_policy()
                    gpu_commit_authority = {}
                    if composite is not None and production_mode:
                        gpu_commit_authority = {
                            "gpu_profile_valid_from": gpu_profile.registry_valid_from,
                            "gpu_profile_valid_until": gpu_profile.registry_valid_until,
                            "gpu_profile_registry_release": gpu_profile.registry_release,
                            "gpu_profile_registry_digest": gpu_profile.registry_digest,
                        }
                    store.record_verdict(
                        enrollment.hotkey,
                        attested,
                        expected_generation=lifecycle.generation,
                        expected_revision=lifecycle.revision,
                        policy_registry_release=policy.registry_release,
                        policy_registry_digest=policy.registry_digest,
                        **gpu_commit_authority,
                    )
                except BaseException:
                    if pending_gpu_claim is not None:
                        gpu_identity_registry.rollback_claim(pending_gpu_claim)
                    raise
                if pending_gpu_claim is not None:
                    gpu_identity_registry.commit_claim(pending_gpu_claim)
                return True
        except LifecycleError:
            # The endpoint or lifecycle changed while evidence was in flight.
            # The lifecycle CAS rejected the stale result, so do not mutate the
            # replacement generation or schedule a retry against it.
            return False
        except Exception as exc:
            try:
                store.record_probe_failure(
                    enrollment.hotkey,
                    error=type(exc).__name__,
                    expected_generation=lifecycle.generation,
                    expected_revision=lifecycle.revision,
                )
            except LifecycleError:
                return False
            except Exception:
                LOGGER.exception("failed to record probe failure for hotkey %s", enrollment.hotkey)
            return False

    all_succeeded = all_reached
    expires_at = time.monotonic() + deadline_seconds if deadline_seconds is not None else None

    def _probe_within_deadline(
        target: tuple[Any, Any],
        admitted_first_wave: bool,
    ) -> bool:
        # Checked inside the worker, not at submit time: with a bounded pool
        # the queue drains over the whole pass, so a target that would start
        # after the deadline must be dropped when its turn comes rather than
        # when it was queued. The first wave is admitted atomically into the
        # available worker slots before this check. Treating those targets as
        # in flight keeps thread-start jitter from defeating either class's
        # reserved slot. Deferral leaves verdict and retry state untouched.
        if not admitted_first_wave and expires_at is not None and time.monotonic() >= expires_at:
            enrollment, _lifecycle = target
            LOGGER.info(
                "probe deadline reached; deferring hotkey=%s to the next pass",
                enrollment.hotkey,
            )
            # Not a failure for the worker, but not a success for the pass:
            # nothing was verified, so the pass must not claim it was.
            return False
        return _probe_one(target)

    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        first_wave_size = min(effective_workers, len(probe_targets))
        futures = [
            executor.submit(
                _probe_within_deadline,
                target,
                index < first_wave_size,
            )
            for index, target in enumerate(probe_targets)
        ]
        for future in as_completed(futures):
            try:
                if not future.result():
                    all_succeeded = False
            except Exception:
                LOGGER.exception("unexpected error in probe worker")
                all_succeeded = False
    return all_succeeded


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Probe enrolled Cathedral miners for TEE evidence")
    parser.add_argument("--db", default="cathedral-enroll.sqlite")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--allow-measurement", action="append", default=[])
    parser.add_argument("--allow-measurements-file")
    parser.add_argument("--min-tcb", type=int, default=0)
    parser.add_argument("--tdx-strict", action="store_true")
    parser.add_argument("--allow-tdx-tcb-status", action="append", default=[])
    parser.add_argument("--allow-tdx-advisory", action="append", default=[])
    parser.add_argument("--policy-registry")
    parser.add_argument("--policy-registry-keys")
    parser.add_argument(
        "--policy-registry-keys-digest",
        help="independently configured sha256 digest of the trusted-key file",
    )
    parser.add_argument("--policy-registry-state")
    parser.add_argument("--policy-registry-min-release", type=int)
    parser.add_argument("--policy-registry-pinned-release", type=int)
    parser.add_argument("--policy-registry-pinned-digest")
    parser.add_argument("--policy-registry-max-age-seconds", type=int, default=86400)
    parser.add_argument(
        "--gpu-profile-id",
        help="active gpu_cc profile id from the verified policy registry",
    )
    parser.add_argument(
        "--gpu-identity-db",
        help="durable pseudonymous GPU identity-claim database",
    )
    parser.add_argument(
        "--gpu-identity-key-file",
        help="owner-only file containing a 32-byte base64 identity key",
    )
    parser.add_argument(
        "--gpu-identity-anchor-file",
        help="external protected monotonic generation anchor",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help=(
            "concurrent probe workers per pass (default: 4, must be ≥ 1; "
            "a two-class deadline share requires ≥ 2 effective workers)"
        ),
    )
    parser.add_argument(
        "--max-probes",
        type=int,
        default=None,
        metavar="N",
        help=(
            "cap targets probed per pass; the rest are deferred to the next "
            "pass with their verdicts and retry counters untouched. Required "
            "sizing under open enrollment (default: unbounded)"
        ),
    )
    parser.add_argument(
        "--new-worker-share",
        type=float,
        default=DEFAULT_NEW_WORKER_SHARE,
        metavar="F",
        help=(
            "fraction of --max-probes reserved for workers with no verified "
            "evidence yet; interior values reserve both classes, while 0 and "
            "1 are explicit single-class-priority overrides (default: 0.25)"
        ),
    )
    parser.add_argument(
        "--pass-deadline-seconds",
        type=float,
        default=None,
        metavar="S",
        help=(
            "finite positive wall-clock budget for one pass; targets that "
            "have not started when it elapses are deferred (default: unbounded)"
        ),
    )
    parser.add_argument(
        "--production-mode",
        action="store_true",
        help=(
            "launch policy: reject enrollments whose endpoint host is not a "
            "public IP literal, before any network access (no DNS check/use gap)"
        ),
    )
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.production_mode and args.policy_registry is None:
        parser.error("--production-mode requires --policy-registry authority")

    store = RegistryStore(args.db)
    gpu_values = (
        args.gpu_profile_id,
        args.gpu_identity_db,
        args.gpu_identity_key_file,
        args.gpu_identity_anchor_file,
    )
    if any(value is not None for value in gpu_values) and any(
        value is None for value in gpu_values
    ):
        parser.error(
            "--gpu-profile-id, --gpu-identity-db, --gpu-identity-key-file, and "
            "--gpu-identity-anchor-file are required together"
        )
    if args.policy_registry is not None:
        if args.allow_measurement or args.allow_measurements_file:
            parser.error("legacy measurement flags and --policy-registry are mutually exclusive")
        for name in ("policy_registry_keys", "policy_registry_state"):
            if getattr(args, name) is None:
                parser.error(f"--{name.replace('_', '-')} is required with --policy-registry")
        from cathedral.cli import _verified_registry_snapshot_and_policy

        registry_refresh_lock = threading.Lock()

        def refresh_registry_authority():
            with registry_refresh_lock:
                return _verified_registry_snapshot_and_policy(
                    args.policy_registry,
                    args.policy_registry_keys,
                    state_path=args.policy_registry_state,
                    minimum_release=args.policy_registry_min_release,
                    max_age_seconds=args.policy_registry_max_age_seconds,
                    production_mode=args.production_mode,
                    trusted_keys_digest=args.policy_registry_keys_digest,
                    pinned_release=args.policy_registry_pinned_release,
                    pinned_digest=args.policy_registry_pinned_digest,
                )

        policy, policy_snapshot = refresh_registry_authority()
    else:
        policy = policy_from_args(args)
        policy_snapshot = None
        refresh_registry_authority = None
    gpu_profile = None
    gpu_verifier = None
    gpu_identity_registry = None
    expected_tier = Tier.CC_CPU_TDX
    if args.gpu_profile_id is not None:
        if policy_snapshot is None:
            parser.error("GPU probing requires --policy-registry authority")
        from cathedral.cli import _load_gpu_identity_key
        from cathedral.gpu import (
            GpuIdentityRegistry,
            gpu_profile_from_registry,
            gpu_verifier_from_env,
        )

        gpu_profile = gpu_profile_from_registry(policy_snapshot, args.gpu_profile_id)
        gpu_verifier = gpu_verifier_from_env(production_mode=args.production_mode)
        gpu_identity_registry = GpuIdentityRegistry(
            args.gpu_identity_db,
            identity_digest_key=_load_gpu_identity_key(
                args.gpu_identity_key_file,
                production_mode=args.production_mode,
            ),
            production_mode=args.production_mode,
            generation_anchor_path=args.gpu_identity_anchor_file,
        )
        expected_tier = Tier.CC_GPU

    # Validated at startup, not on the first pass. probe_once raises for a bad
    # budget, and the pass loop below swallows every exception and sleeps, so
    # a typo would otherwise turn the prober into a silent no-op that logs
    # once per interval while every worker's evidence quietly expires.
    if args.max_probes is not None and args.max_probes < 1:
        parser.error("--max-probes must be at least 1")
    if not 0.0 <= args.new_worker_share <= 1.0:
        parser.error("--new-worker-share must be between 0.0 and 1.0")
    if args.max_probes is not None and args.max_probes < 2 and 0.0 < args.new_worker_share < 1.0:
        parser.error(
            "--max-probes must be at least 2 when --new-worker-share "
            "reserves capacity for both first probes and refreshes"
        )
    if args.pass_deadline_seconds is not None and (
        not math.isfinite(args.pass_deadline_seconds) or args.pass_deadline_seconds <= 0
    ):
        parser.error("--pass-deadline-seconds must be finite and positive")
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    configured_effective_workers = (
        min(args.workers, MAX_GPU_EVIDENCE_CONCURRENCY)
        if args.gpu_profile_id is not None
        else args.workers
    )
    if (
        args.pass_deadline_seconds is not None
        and 0.0 < args.new_worker_share < 1.0
        and configured_effective_workers < 2
    ):
        parser.error(
            "--pass-deadline-seconds with a two-class --new-worker-share "
            "requires at least 2 effective --workers"
        )

    while True:
        try:
            if args.policy_registry is not None:
                assert refresh_registry_authority is not None
                policy, policy_snapshot = refresh_registry_authority()
                if args.gpu_profile_id is not None:
                    gpu_profile = gpu_profile_from_registry(policy_snapshot, args.gpu_profile_id)
            all_succeeded = probe_once(
                store,
                policy,
                max_workers=args.workers,
                max_probes=args.max_probes,
                new_worker_share=args.new_worker_share,
                deadline_seconds=args.pass_deadline_seconds,
                production_mode=args.production_mode,
                policy_refresher=(
                    (lambda: refresh_registry_authority()[0])
                    if refresh_registry_authority is not None
                    else None
                ),
                gpu_profile=gpu_profile,
                gpu_verifier=gpu_verifier,
                gpu_identity_registry=gpu_identity_registry,
                expected_tier=expected_tier,
            )
            if args.once and not all_succeeded:
                raise RuntimeError("one-shot probe did not verify every due target")
        except Exception:
            LOGGER.exception("probe pass failed")
            if args.once:
                raise
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
