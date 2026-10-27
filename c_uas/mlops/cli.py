"""``c-uas mlops`` subcommand: model registry, drift detection, A/B testing.

Usage:
    c-uas mlops --register --name rf_clf --version 1.0.0 --artifact m.joblib
        --metrics-hash <sha256>
    c-uas mlops --list
    c-uas mlops --promote --name rf_clf --version 1.0.0 --stage production
    c-uas mlops --drift --baseline baseline.json --current inference.json
    c-uas mlops --ab --ab-action route --experiment-id rf-ab-1 --user-id user-42

All output is deterministic. State persists under
~/.c-uas-platform/mlops/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, List, Optional, Sequence

from . import ab_test, registry
from . import drift as drift_mod
from .ab_test import ABTestError, Variant
from .drift import FeatureDriftResult
from .registry import ModelRecord


def build_subparser(subparsers: Any) -> Any:
    """Register the ``mlops`` subcommand on a parent parser."""
    parser = subparsers.add_parser(
        "mlops",
        help="MLOps: model registry, drift detection, A/B testing",
    )

    g = parser.add_argument_group("registry actions")
    g.add_argument("--register", action="store_true", help="Register a model version")
    g.add_argument("--list", action="store_true", help="List registered models")
    g.add_argument("--get", action="store_true", help="Show one registered model")
    g.add_argument("--promote", action="store_true", help="Promote a model to a stage")
    g.add_argument("--demote", action="store_true", help="Demote a model to staging/archived")
    g.add_argument("--archive", action="store_true", help="Archive a model")
    g.add_argument("--delete", action="store_true", help="Delete a model registration")
    g.add_argument("--name", type=str, default=None, help="Model name")
    g.add_argument("--version", type=str, default=None, help="Model version")
    g.add_argument("--artifact", type=str, default=None, help="Artifact path (for --register)")
    g.add_argument("--metrics-hash", type=str, default=None, help="Metrics sha256 (for --register)")
    g.add_argument(
        "--stage",
        type=str,
        default=None,
        help="Target stage: staging|production|archived (register: staging, "
        "promote: production, demote: staging; --list shows all stages when omitted)",
    )
    g.add_argument(
        "--state-dir",
        type=str,
        default=None,
        help="MLOps state dir (default: ~/.c-uas-platform/mlops)",
    )

    g = parser.add_argument_group("drift detection")
    g.add_argument("--drift", action="store_true", help="Run drift detection")
    g.add_argument(
        "--baseline", type=str, default=None, help="Baseline JSON: {feature: [values] | {cat: n}}"
    )
    g.add_argument(
        "--current", type=str, default=None, help="Inference JSON: same shape as --baseline"
    )
    g.add_argument(
        "--threshold", type=float, default=0.2, help="Drift score threshold (default: 0.2)"
    )

    g = parser.add_argument_group("A/B testing")
    g.add_argument("--ab", action="store_true", help="Run an A/B testing action")
    g.add_argument(
        "--ab-action",
        type=str,
        default=None,
        help="create|route|record|metrics|winner|complete|list",
    )
    g.add_argument("--experiment-id", type=str, default=None, help="Experiment id")
    g.add_argument(
        "--experiment-name",
        type=str,
        default=None,
        help="Experiment name (for create)",
    )
    g.add_argument(
        "--variant",
        type=str,
        default=None,
        action="append",
        help="Variant as id:name:weight (repeatable, for create)",
    )
    g.add_argument("--user-id", type=str, default=None, help="Routing key (for route)")
    g.add_argument("--variant-id", type=str, default=None, help="Variant id (for record/metrics)")
    g.add_argument("--pk", type=float, default=None, help="Probability of kill 0..1 (for record)")
    g.add_argument("--converted", action="store_true", help="Mark trial as converted (for record)")
    g.add_argument("--min-trials", type=int, default=10, help="Min trials per variant (for winner)")
    return parser


# --------------------------------------------------------------------------- #
# renderers (deterministic, no wall-clock in output except persisted state)
# --------------------------------------------------------------------------- #


def _render_record(record: ModelRecord) -> List[str]:
    return [
        f"Model        : {record.name}@{record.version}",
        f"Stage        : {record.stage}",
        f"Artifact     : {record.artifact_path}",
        f"Metrics hash : {record.metrics_hash}",
        f"Created      : {record.created_at}",
        f"Updated      : {record.updated_at}",
    ]


def _render_drift_result(result: FeatureDriftResult) -> List[str]:
    lines = [
        f"  {result.feature}:",
        f"    test        : {result.test}",
        f"    score       : {result.drift_score:.6f}",
        f"    p_value     : {result.p_value:.6f}",
        f"    threshold   : {result.threshold}",
        f"    drifted     : {result.drifted}",
        f"    baseline_n  : {result.baseline_size}",
        f"    current_n   : {result.current_size}",
    ]
    detail = result.detail
    if result.test == "ks_2samp":
        lines.append(f"    statistic   : {detail.get('statistic')}")
    elif result.test == "chisq":
        lines.append(f"    statistic   : {detail.get('statistic')}")
        categories = detail.get("categories", [])
        df = len(categories) - 1 if categories else 0
        lines.append(f"    df          : {df}")
        lines.append(f"    categories  : {', '.join(categories)}")
    return lines


def _render_variant_metrics(m: ab_test.VariantMetrics, variants: List[Variant]) -> List[str]:
    name = next((v.name for v in variants if v.variant_id == m.variant_id), m.variant_id)
    weight = next((v.traffic_weight for v in variants if v.variant_id == m.variant_id), 0.0)
    return [
        f"  {m.variant_id} ({name}, weight={weight}):",
        f"    trials        : {m.trials}",
        f"    conversions   : {m.conversions}",
        f"    conversion_rate: {m.conversion_rate:.6f}",
        f"    mean_pk       : {m.mean_pk:.6f}",
    ]


# --------------------------------------------------------------------------- #
# action handlers
# --------------------------------------------------------------------------- #


def _cmd_register(args: argparse.Namespace) -> int:
    if not args.name or not args.version or not args.artifact:
        print("[C-UAS] mlops --register requires --name, --version, --artifact")
        return 1
    if not args.metrics_hash:
        print("[C-UAS] mlops --register requires --metrics-hash")
        return 1
    stage = args.stage or "staging"
    record = registry.register_model(
        name=args.name,
        version=args.version,
        artifact_path=args.artifact,
        metrics_hash=args.metrics_hash,
        stage=stage,
        state_dir=args.state_dir,
    )
    print("[C-UAS] Model registered")
    for line in _render_record(record):
        print("  " + line)
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    records = registry.list_models(state_dir=args.state_dir, name=args.name, stage=args.stage)
    print(f"[C-UAS] Registered models ({len(records)}):")
    for record in records:
        print(
            "  " + " | ".join([record.name, record.version, record.stage, record.metrics_hash[:12]])
        )
    return 0


def _cmd_get(args: argparse.Namespace) -> int:
    if not args.name or not args.version:
        print("[C-UAS] mlops --get requires --name and --version")
        return 1
    record = registry.get_model(args.name, args.version, state_dir=args.state_dir)
    if record is None:
        print(f"[C-UAS] Model not registered: {args.name}@{args.version}")
        return 1
    for line in _render_record(record):
        print(line)
    return 0


def _cmd_stage(args: argparse.Namespace, action: str) -> int:
    if not args.name or not args.version:
        print(f"[C-UAS] mlops --{action} requires --name and --version")
        return 1
    if args.stage not in ("staging", "production", "archived"):
        if args.stage is not None:
            print(f"[C-UAS] unknown stage: {args.stage!r}")
            return 1
        if action == "promote":
            args.stage = "production"
        elif action == "demote":
            args.stage = "staging"
        else:
            args.stage = "archived"
    if action == "promote":
        record = registry.promote_model(args.name, args.version, state_dir=args.state_dir)
    elif action == "demote":
        if args.stage == "production":
            print("[C-UAS] --demote target must be staging or archived")
            return 1
        record = registry.demote_model(
            args.name, args.version, stage=args.stage, state_dir=args.state_dir
        )
    else:  # archive
        record = registry.archive_model(args.name, args.version, state_dir=args.state_dir)
    print(f"[C-UAS] Model {action}d: {args.name}@{args.version} -> {record.stage}")
    return 0


def _cmd_delete(args: argparse.Namespace) -> int:
    if not args.name or not args.version:
        print("[C-UAS] mlops --delete requires --name and --version")
        return 1
    removed = registry.remove_model(args.name, args.version, state_dir=args.state_dir)
    if not removed:
        print(f"[C-UAS] Model not registered: {args.name}@{args.version}")
        return 1
    print(f"[C-UAS] Model deleted: {args.name}@{args.version}")
    return 0


def _cmd_drift(args: argparse.Namespace) -> int:
    if not args.baseline or not args.current:
        print("[C-UAS] mlops --drift requires --baseline and --current")
        return 1
    try:
        with open(args.baseline, "r", encoding="utf-8") as fh:
            baseline = json.load(fh)
        with open(args.current, "r", encoding="utf-8") as fh:
            current = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"[C-UAS] mlops --drift: failed to read input: {exc}")
        return 1
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        print("[C-UAS] mlops --drift: baseline/current must be JSON objects")
        return 1

    report = drift_mod.detect_drift(baseline, current, threshold=args.threshold)
    print("[C-UAS] Drift Detection Report")
    print(f"  threshold      : {report.threshold}")
    print(f"  features       : {len(report.results)}")
    print(f"  drifted        : {len(report.drifted_features)}")
    print(f"  any_drifted    : {report.any_drifted}")
    for result in report.results:
        for line in _render_drift_result(result):
            print(line)
    return 0


def _parse_variant(spec: Optional[str]) -> Variant:
    if spec is None:
        raise ABTestError("variant spec required as id:name:weight")
    parts = spec.split(":")
    if len(parts) != 3:
        raise ABTestError(f"invalid variant spec: {spec!r} (expected id:name:weight)")
    variant_id, name, weight_s = parts
    try:
        weight = float(weight_s)
    except ValueError:
        raise ABTestError(f"invalid weight: {weight_s!r}") from None
    return Variant(
        variant_id=variant_id,
        name=name,
        model_name="",
        model_version="",
        traffic_weight=weight,
    )


def _cmd_ab(args: argparse.Namespace) -> int:
    action = args.ab_action or "list"
    if action == "create":
        if not args.experiment_id or not args.experiment_name or not args.variant:
            print(
                "[C-UAS] mlops --ab --ab-action create requires "
                "--experiment-id, --experiment-name, --variant"
            )
            return 1
        variants = [_parse_variant(spec) for spec in args.variant]
        experiment = ab_test.create_experiment(
            args.experiment_id, args.experiment_name, variants, state_dir=args.state_dir
        )
        print(f"[C-UAS] Experiment created: {experiment.experiment_id} ({experiment.status})")
        for variant in experiment.variants:
            print(f"  {variant.variant_id} ({variant.name}): weight={variant.traffic_weight}")
        return 0

    if action == "list":
        experiments = ab_test.list_experiments(state_dir=args.state_dir)
        print(f"[C-UAS] Experiments ({len(experiments)}):")
        for experiment in experiments:
            print(
                f"  {experiment.experiment_id}  {experiment.name}  {experiment.status}  "
                f"variants={len(experiment.variants)}"
            )
        return 0

    if not args.experiment_id:
        print("[C-UAS] mlops --ab requires --experiment-id")
        return 1

    if action == "route":
        if not args.user_id:
            print("[C-UAS] mlops --ab --ab-action route requires --user-id")
            return 1
        variant = ab_test.route_variant(args.experiment_id, args.user_id, state_dir=args.state_dir)
        print("[C-UAS] A/B route")
        print(f"  experiment   : {args.experiment_id}")
        print(f"  key          : {args.user_id}")
        print(f"  variant_id   : {variant.variant_id}")
        print(f"  variant_name : {variant.name}")
        return 0

    if action == "record":
        if not args.variant_id or args.pk is None:
            print("[C-UAS] mlops --ab --ab-action record requires --variant-id and --pk")
            return 1
        trial = ab_test.record_trial(
            args.experiment_id,
            args.variant_id,
            args.pk,
            converted=args.converted,
            state_dir=args.state_dir,
        )
        print("[C-UAS] Trial recorded")
        print(f"  variant_id  : {trial.variant_id}")
        print(f"  pk          : {trial.pk}")
        print(f"  converted   : {trial.converted}")
        return 0

    if action == "metrics":
        exp = ab_test.get_experiment(args.experiment_id, state_dir=args.state_dir)
        if exp is None:
            print(f"[C-UAS] unknown experiment: {args.experiment_id}")
            return 1
        variants = list(exp.variants)
        print(f"[C-UAS] A/B metrics: {args.experiment_id}")
        for m in ab_test.all_variant_metrics(args.experiment_id, state_dir=args.state_dir):
            for line in _render_variant_metrics(m, variants):
                print(line)
        return 0

    if action == "winner":
        winner = ab_test.determine_winner(
            args.experiment_id, min_trials=args.min_trials, state_dir=args.state_dir
        )
        print(f"[C-UAS] A/B winner: {args.experiment_id}")
        if winner is None:
            print("  winner : none (insufficient trials)")
        else:
            print(f"  winner : {winner.variant_id} ({winner.name})")
        return 0

    if action == "complete":
        experiment = ab_test.complete_experiment(args.experiment_id, state_dir=args.state_dir)
        print(f"[C-UAS] Experiment completed: {experiment.experiment_id}")
        return 0

    print(f"[C-UAS] unknown --ab-action: {action!r}")
    return 1


def mlops_main(args: argparse.Namespace) -> int:
    """Handle the ``mlops`` subcommand from a parsed namespace."""

    if args.register:
        return _cmd_register(args)
    if args.list:
        return _cmd_list(args)
    if args.get:
        return _cmd_get(args)
    if args.promote:
        return _cmd_stage(args, "promote")
    if args.demote:
        return _cmd_stage(args, "demote")
    if args.archive:
        return _cmd_stage(args, "archive")
    if args.delete:
        return _cmd_delete(args)
    if args.drift:
        return _cmd_drift(args)
    if args.ab:
        return _cmd_ab(args)

    print(
        "[C-UAS] mlops: specify one of --register/--list/--get/--promote/"
        "--demote/--archive/--delete/--drift/--ab"
    )
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Standalone entry point: ``python -m c_uas.mlops.cli``."""
    parser = argparse.ArgumentParser(prog="c-uas mlops")
    build_subparser(parser.add_subparsers(dest="command"))
    args = parser.parse_args(argv)
    return mlops_main(args)


if __name__ == "__main__":
    sys.exit(main())
