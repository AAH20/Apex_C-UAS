"""
CLI for the API Gateway: status / route / health.

Usage:
  c-uas gateway --status
  c-uas gateway --route [--backend <role|id>] [--strategy X] [--seed N]
  c-uas gateway --health --backend <id>
"""

from __future__ import annotations

import os
import sys
from typing import Optional

from .config import ROLES, STRATEGIES, GatewayConfig
from .gateway import Gateway


def _build_config(strategy: Optional[str], seed: Optional[int]) -> GatewayConfig:
    config = GatewayConfig()  # loads persisted defaults
    if strategy is not None and strategy not in STRATEGIES:
        print(
            "[C-UAS] Unknown strategy %r (expected one of %s)" % (strategy, STRATEGIES)
        )
        sys.exit(1)
    return GatewayConfig(
        backends=config.backends,
        strategy=strategy if strategy is not None else config.strategy,
        failure_threshold=config.failure_threshold,
        recovery_timeout_s=config.recovery_timeout_s,
        health_interval_s=config.health_interval_s,
        seed=seed if seed is not None else config.seed,
        state_dir=os.environ.get("C_UAS_GATEWAY_STATE_DIR", config.state_dir),
    )


def main(args) -> int:
    gateway = Gateway(config=_build_config(args.strategy, args.seed))

    if args.status:
        status = gateway.status()
        print("[C-UAS] API Gateway status")
        print("  Strategy      : %s" % status["strategy"])
        print("  Seed          : %s" % status["seed"])
        print("  State dir     : %s" % status["state_dir"])
        print("  Backends (%d):" % len(status["backends"]))
        for b in status["backends"]:
            print(
                "  - %-14s %-22s %-12s healthy=%s circuit=%s latency=%s fails=%d"
                % (
                    b["backend_id"],
                    b["endpoint"],
                    b["role"],
                    b["healthy"],
                    b["circuit"],
                    b["last_latency_ms"],
                    b["failure_count"],
                )
            )
        return 0

    if args.health:
        if not args.backend:
            print("[C-UAS] --backend <id> required for --health")
            return 1
        try:
            result = gateway.probe(args.backend)
        except ValueError as exc:
            print("[C-UAS] %s" % exc)
            return 1
        gateway.save()
        print(
            "[C-UAS] Health probe %s: healthy=%s latency_ms=%s error=%s"
            % (result.backend_id, result.healthy, result.latency_ms, result.error)
        )
        return 0

    if args.route:
        decision = gateway.route(role=args.backend, backend_id=None)
        gateway.save()
        if decision.backend is None:
            print(
                "[C-UAS] No route (%s): %s (candidates=%d, seed=%d)"
                % (decision.strategy, decision.reason, decision.candidates, decision.seed)
            )
            return 1
        print(
            "[C-UAS] Route %s -> %s (%s) reason=%s candidates=%d seed=%d"
            % (
                decision.strategy,
                decision.backend.backend_id,
                decision.backend.role,
                decision.reason,
                decision.candidates,
                decision.seed,
            )
        )
        return 0

    print("[C-UAS] gateway: specify --status, --route, or --health")
    print("  c-uas gateway --status")
    print("  c-uas gateway --route --backend detection")
    print("  c-uas gateway --health --backend detection-1")
    return 1
