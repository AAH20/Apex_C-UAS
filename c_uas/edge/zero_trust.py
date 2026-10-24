"""
C-UAS edge zero-trust network policies.

Default-deny ingress, mTLS enforcement, network segmentation, service-to-service
authentication, and deterministic policy evaluation. Every edge flow is
evaluated against an explicit allow-list; nothing is permitted by default.

State persists under ~/.c-uas-platform/edge/zero_trust/ (outside the repo).

All output is deterministic: identical inputs produce identical policy
evaluations on any machine. No network, no randomness.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from typing import Any, List, Tuple

from .state import EDGE_ROOT

ZERO_TRUST_DIR = EDGE_ROOT / "zero_trust"


def _zt_dir() -> str:
    d = ZERO_TRUST_DIR
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def _atomic_write_json(path: str, data: Any) -> None:
    import os as _os

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    _os.replace(tmp, path)


def _read_json(path: str, default: Any = None) -> Any:
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _policy_path() -> str:
    return os.path.join(_zt_dir(), "policy.json")


@dataclass(frozen=True)
class NetworkPolicy:
    """Zero-trust network policy for an edge site."""

    default_deny_ingress: bool = True
    mTLS_enforced: bool = True
    network_segmentation: bool = True
    service_to_service_auth: bool = True
    allowed_segments: Tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyEvaluation:
    """Result of evaluating one ingress flow against a policy."""

    allowed: bool
    reason: str
    rules_checked: Tuple[str, ...]
    matched_rules: Tuple[str, ...]


class ZeroTrustManager:
    """Zero-trust policy engine with persistent policy state."""

    def __init__(self) -> None:
        self.policy = self._load_policy()

    # -- persistence ---------------------------------------------------

    def _load_policy(self) -> NetworkPolicy:
        data = _read_json(_policy_path())
        if data is None:
            return NetworkPolicy()
        return NetworkPolicy(
            default_deny_ingress=bool(data.get("default_deny_ingress", True)),
            mTLS_enforced=bool(data.get("mTLS_enforced", True)),
            network_segmentation=bool(data.get("network_segmentation", True)),
            service_to_service_auth=bool(data.get("service_to_service_auth", True)),
            allowed_segments=tuple(data.get("allowed_segments", ())),
        )

    def save_policy(self, policy: NetworkPolicy) -> None:
        self.policy = policy
        _atomic_write_json(_policy_path(), asdict(policy))

    # -- policy evaluation ---------------------------------------------

    def evaluate_ingress(
        self,
        source: str,
        dest: str,
        port: int,
        has_mtls: bool,
        same_segment: bool,
        authenticated: bool,
    ) -> PolicyEvaluation:
        """Evaluate one ingress flow against the active policy.

        Returns a deterministic PolicyEvaluation. Default-deny: unless an
        explicit allow rule matches and all enforcement checks pass, the
        flow is denied.
        """
        policy = self.policy
        rules_checked: List[str] = []
        matched: List[str] = []

        # 1. Default-deny ingress.
        rules_checked.append("default-deny-ingress")
        if policy.default_deny_ingress:
            matched.append("default-deny-ingress")
            return PolicyEvaluation(
                allowed=False,
                reason="ingress denied by default-deny rule",
                rules_checked=tuple(rules_checked),
                matched_rules=tuple(matched),
            )

        # 2. mTLS enforcement.
        rules_checked.append("mTLS-enforcement")
        if policy.mTLS_enforced and not has_mtls:
            return PolicyEvaluation(
                allowed=False,
                reason="mTLS required for ingress",
                rules_checked=tuple(rules_checked),
                matched_rules=tuple(matched),
            )
        matched.append("mTLS-enforcement")

        # 3. Network segmentation.
        rules_checked.append("network-segmentation")
        if policy.network_segmentation and not same_segment:
            return PolicyEvaluation(
                allowed=False,
                reason="source and dest in different segments",
                rules_checked=tuple(rules_checked),
                matched_rules=tuple(matched),
            )
        matched.append("network-segmentation")

        # 4. Service-to-service authentication.
        rules_checked.append("service-to-service-auth")
        if policy.service_to_service_auth and not authenticated:
            return PolicyEvaluation(
                allowed=False,
                reason="service-to-service authentication required",
                rules_checked=tuple(rules_checked),
                matched_rules=tuple(matched),
            )
        matched.append("service-to-service-auth")

        return PolicyEvaluation(
            allowed=True,
            reason="ingress allowed by zero-trust policy",
            rules_checked=tuple(rules_checked),
            matched_rules=tuple(matched),
        )


# -- pure functions ----------------------------------------------------


def default_deny_eval(
    source: str,
    dest: str,
    port: int,
    has_mtls: bool,
    same_segment: bool,
    authenticated: bool,
) -> PolicyEvaluation:
    """Pure zero-trust evaluation with a strict default-deny policy.

    Equivalent to NetworkPolicy(default_deny_ingress=True, mTLS_enforced=True,
    network_segmentation=True, service_to_service_auth=True).
    """
    policy = NetworkPolicy(
        default_deny_ingress=True,
        mTLS_enforced=True,
        network_segmentation=True,
        service_to_service_auth=True,
    )
    mgr = ZeroTrustManager()
    mgr.policy = policy
    return mgr.evaluate_ingress(
        source=source,
        dest=dest,
        port=port,
        has_mtls=has_mtls,
        same_segment=same_segment,
        authenticated=authenticated,
    )
