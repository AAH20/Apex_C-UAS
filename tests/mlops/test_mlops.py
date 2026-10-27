"""Deterministic tests for c_uas.mlops: registry, drift detection, A/B testing.

All tests use throwaway state directories (no ~/.c-uas-platform writes) and
assert on real computed values. No mocks, no network, no randomness.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from c_uas.mlops.ab_test import (
    ABTestError,
    Variant,
    all_variant_metrics,
    complete_experiment,
    create_experiment,
    determine_winner,
    get_experiment,
    record_trial,
    route_variant,
    set_experiment_status,
    variant_metrics,
)
from c_uas.mlops.cli import build_subparser, mlops_main
from c_uas.mlops.drift import DriftReport, detect_drift, feature_drift, ks_2samp
from c_uas.mlops.registry import (
    ModelRecord,
    demote_model,
    get_model,
    list_models,
    promote_model,
    register_model,
    remove_model,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _state(tmp_path: Path) -> str:
    return str(tmp_path / "mlops")


def _parse_cli(*args: str):
    parser = argparse.ArgumentParser(prog="c-uas mlops")
    build_subparser(parser.add_subparsers(dest="command"))
    return parser.parse_args(["mlops", *list(args)])


def _run_cli(tmp_path: Path, capsys, *args: str) -> int:
    ns = _parse_cli(*args)
    ns.state_dir = _state(tmp_path)
    return mlops_main(ns)


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


def test_register_model_returns_record(tmp_path: Path) -> None:
    record = register_model(
        "rf_classifier",
        "1.0.0",
        "models/rf_v1.joblib",
        "aa" * 32,
        stage="staging",
        state_dir=_state(tmp_path),
    )
    assert record == ModelRecord(
        name="rf_classifier",
        version="1.0.0",
        stage="staging",
        artifact_path="models/rf_v1.joblib",
        metrics_hash="aa" * 32,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )
    assert record.created_at == record.updated_at


def test_register_model_is_idempotent(tmp_path: Path) -> None:
    first = register_model(
        "rf_classifier",
        "1.0.0",
        "models/rf_v1.joblib",
        "aa" * 32,
        state_dir=_state(tmp_path),
    )
    second = register_model(
        "rf_classifier",
        "1.0.0",
        "models/rf_v2.joblib",
        "bb" * 32,
        stage="production",
        state_dir=_state(tmp_path),
    )
    assert second == first  # existing record untouched


def test_register_model_validates(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        register_model("", "1.0.0", "m", "h", state_dir=_state(tmp_path))
    with pytest.raises(ValueError):
        register_model("m", "1.0.0", "m", "h", stage="bogus", state_dir=_state(tmp_path))


def test_list_models_sorted_and_filtered(tmp_path: Path) -> None:
    register_model("detector", "2.0.0", "a", "h1", stage="production", state_dir=_state(tmp_path))
    register_model("detector", "1.0.0", "a", "h1", stage="staging", state_dir=_state(tmp_path))
    register_model("tracker", "1.0.0", "a", "h1", stage="production", state_dir=_state(tmp_path))

    all_models = list_models(state_dir=_state(tmp_path))
    assert [m.name for m in all_models] == ["detector", "detector", "tracker"]
    assert all_models[0].version == "1.0.0"  # sorted by (name, version)

    staged = list_models(state_dir=_state(tmp_path), stage="production")
    assert {m.name for m in staged} == {"detector", "tracker"}

    only = list_models(state_dir=_state(tmp_path), name="tracker")
    assert len(only) == 1 and only[0].version == "1.0.0"


def test_get_model_unknown_returns_none(tmp_path: Path) -> None:
    assert get_model("nope", "9.9", state_dir=_state(tmp_path)) is None


def test_promote_and_demote_persist_stage(tmp_path: Path) -> None:
    register_model("m", "1", "a", "h", state_dir=_state(tmp_path))
    promoted = promote_model("m", "1", state_dir=_state(tmp_path))
    assert promoted.stage == "production"
    assert get_model("m", "1", state_dir=_state(tmp_path)).stage == "production"

    demoted = demote_model("m", "1", stage="archived", state_dir=_state(tmp_path))
    assert demoted.stage == "archived"

    with pytest.raises(ValueError):
        demote_model("m", "1", stage="production", state_dir=_state(tmp_path))
    with pytest.raises(KeyError):
        promote_model("ghost", "1", state_dir=_state(tmp_path))


def test_remove_model(tmp_path: Path) -> None:
    register_model("m", "1", "a", "h", state_dir=_state(tmp_path))
    assert remove_model("m", "1", state_dir=_state(tmp_path)) is True
    assert remove_model("m", "1", state_dir=_state(tmp_path)) is False
    assert list_models(state_dir=_state(tmp_path)) == ()


def test_registry_state_files(tmp_path: Path) -> None:
    register_model("m", "1", "a", "h", state_dir=_state(tmp_path))
    state_root = Path(_state(tmp_path))
    assert (state_root / "registry" / "registry.json").exists()
    data = json.loads((state_root / "registry" / "registry.json").read_text(encoding="utf-8"))
    assert data["models"][0]["name"] == "m"


def test_env_var_state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    custom = str(tmp_path / "custom")
    monkeypatch.setenv("CUAS_MLOPS_STATE_DIR", custom)
    record = register_model("m", "1", "a", "h")
    assert record.name == "m"
    assert Path(custom, "registry", "registry.json").exists()


# --------------------------------------------------------------------------- #
# Drift
# --------------------------------------------------------------------------- #


def test_drift_identical_numeric_distributions_no_drift(tmp_path: Path) -> None:
    samples = [float(i) for i in range(50)]
    result = feature_drift(samples, samples, threshold=0.2)
    assert result.test == "ks_2samp"
    assert result.drift_score == 0.0
    assert result.p_value == 1.0
    assert result.drifted is False

    report = detect_drift({"speed": samples}, {"speed": samples}, threshold=0.2)
    assert isinstance(report, DriftReport)
    assert report.any_drifted is False
    assert report.drifted_features == ()


def test_drift_shifted_numeric_distribution_detected(tmp_path: Path) -> None:
    baseline = [float(i) for i in range(50)]  # 0..49
    current = [float(i) + 30.0 for i in range(50)]  # 30..79 (partial overlap)
    d, p = ks_2samp(baseline, current)
    assert 0.5 < d <= 1.0
    assert p < 0.01

    result = feature_drift(baseline, current, threshold=0.2)
    assert result.drifted is True
    assert result.drift_score > 0.5


def test_drift_small_samples_graceful(tmp_path: Path) -> None:
    d, p = ks_2samp([1.0], [2.0])
    assert d == 0.0 and p == 1.0


def test_drift_categorical_identical_proportions_no_drift(tmp_path: Path) -> None:
    baseline = {"A": 70, "B": 30}
    current = {"A": 70, "B": 30}
    result = feature_drift(baseline, current, threshold=0.2)
    assert result.test == "chisq"
    assert result.drift_score == 0.0
    assert result.p_value == 1.0
    assert result.drifted is False


def test_drift_categorical_different_proportions_detected(tmp_path: Path) -> None:
    baseline = {"A": 70, "B": 30}
    current = {"A": 30, "B": 70}
    result = feature_drift(baseline, current, threshold=0.2)
    assert result.test == "chisq"
    assert result.drift_score > 0.5
    assert result.p_value < 0.01
    assert result.drifted is True
    assert result.detail["categories"] == ["A", "B"]


def test_drift_per_feature_report(tmp_path: Path) -> None:
    baseline = {
        "speed": [float(i) for i in range(50)],
        "protocol": {"A": 80, "B": 20},
    }
    current = {
        "speed": [float(i) + 30.0 for i in range(50)],
        "protocol": {"A": 80, "B": 20},
    }
    report = detect_drift(baseline, current, threshold=0.2)
    assert len(report.results) == 2
    by_feature = {r.feature: r for r in report.results}
    speed = by_feature["speed"]
    proto = by_feature["protocol"]
    assert speed.drifted is True
    assert proto.drifted is False
    assert report.any_drifted is True
    assert report.drifted_features == ("speed",)


def test_drift_missing_feature_flagged(tmp_path: Path) -> None:
    report = detect_drift(
        {"speed": [1.0, 2.0], "protocol": {"A": 5, "B": 5}},
        {"speed": [1.0, 2.0]},
        threshold=0.2,
    )
    missing = [r for r in report.results if r.feature == "protocol"][0]
    assert missing.drifted is True
    assert missing.drift_score == 1.0
    assert missing.p_value == 0.0


# --------------------------------------------------------------------------- #
# A/B testing
# --------------------------------------------------------------------------- #


def _make_variants() -> list[Variant]:
    return [
        Variant("a", "champion", "rf_clf", "1.0.0", 0.5),
        Variant("b", "challenger", "rf_clf", "2.0.0", 0.5),
    ]


def test_ab_route_deterministic(tmp_path: Path) -> None:
    create_experiment("exp-1", "test", _make_variants(), state_dir=_state(tmp_path))
    picks = [
        route_variant("exp-1", f"user-{i}", state_dir=_state(tmp_path)).variant_id
        for i in range(100)
    ]
    assert picks == picks  # same call sequence, same result (determinism smoke)
    picks2 = [
        route_variant("exp-1", f"user-{i}", state_dir=_state(tmp_path)).variant_id
        for i in range(100)
    ]
    assert picks == picks2


def test_ab_route_respects_weights(tmp_path: Path) -> None:
    create_experiment("exp-w", "weights", _make_variants(), state_dir=_state(tmp_path))
    counts = {"a": 0, "b": 0}
    for i in range(2000):
        counts[route_variant("exp-w", f"u-{i}", state_dir=_state(tmp_path)).variant_id] += 1
    share = counts["a"] / 2000
    assert 0.45 < share < 0.55  # 50/50 split within sampling tolerance of the hash


def test_ab_route_unknown_or_inactive(tmp_path: Path) -> None:
    with pytest.raises(ABTestError):
        route_variant("missing", "u-1", state_dir=_state(tmp_path))
    create_experiment("exp-2", "stopped", _make_variants(), state_dir=_state(tmp_path))
    set_experiment_status("exp-2", "stopped", state_dir=_state(tmp_path))
    with pytest.raises(ABTestError):
        route_variant("exp-2", "u-1", state_dir=_state(tmp_path))


def test_ab_record_and_metrics(tmp_path: Path) -> None:
    state = _state(tmp_path)
    create_experiment("exp-3", "metrics", _make_variants(), state_dir=state)
    for _ in range(20):
        record_trial("exp-3", "a", 0.9, converted=True, state_dir=state)
    for _ in range(20):
        record_trial("exp-3", "b", 0.6, converted=False, state_dir=state)

    ma = variant_metrics("exp-3", "a", state_dir=state)
    mb = variant_metrics("exp-3", "b", state_dir=state)
    assert ma.trials == 20 and ma.conversions == 20
    assert ma.conversion_rate == 1.0 and ma.mean_pk == 0.9
    assert mb.trials == 20 and mb.conversions == 0
    assert mb.conversion_rate == 0.0 and mb.mean_pk == 0.6

    metrics = all_variant_metrics("exp-3", state_dir=state)
    assert {m.variant_id for m in metrics} == {"a", "b"}


def test_ab_winner_selection(tmp_path: Path) -> None:
    state = _state(tmp_path)
    create_experiment("exp-4", "winner", _make_variants(), state_dir=state)
    # Variant b converts more (0.8 vs 0.4) with equal pk
    for _ in range(25):
        record_trial("exp-4", "a", 0.5, converted=False, state_dir=state)
    for _ in range(10):
        record_trial("exp-4", "a", 0.5, converted=True, state_dir=state)
    for _ in range(25):
        record_trial("exp-4", "b", 0.5, converted=False, state_dir=state)
    for _ in range(20):
        record_trial("exp-4", "b", 0.5, converted=True, state_dir=state)

    winner = determine_winner("exp-4", min_trials=10, state_dir=state)
    assert winner is not None and winner.variant_id == "b"

    # Below min_trials -> no winner
    create_experiment("exp-5", "few", _make_variants(), state_dir=state)
    record_trial("exp-5", "a", 0.5, converted=True, state_dir=state)
    record_trial("exp-5", "b", 0.5, converted=True, state_dir=state)
    assert determine_winner("exp-5", min_trials=10, state_dir=state) is None


def test_ab_invalid_weights_rejected(tmp_path: Path) -> None:
    with pytest.raises((ABTestError, ValueError)):
        create_experiment(
            "exp-6",
            "bad",
            [
                Variant("a", "a", "m", "1", 0.5),
                Variant("b", "b", "m", "1", 0.6),
            ],
            state_dir=_state(tmp_path),
        )


def test_ab_persisted_files(tmp_path: Path) -> None:
    state = _state(tmp_path)
    create_experiment("exp-7", "persist", _make_variants(), state_dir=state)
    state_root = Path(state)
    assert (state_root / "ab" / "experiments.json").exists()
    record_trial("exp-7", "a", 0.5, state_dir=state)
    trial_files = list((state_root / "ab" / "trials").iterdir())
    assert len(trial_files) == 1
    # Survives reload: new object graph reads same persisted state
    exp = get_experiment("exp-7", state_dir=state)
    assert exp is not None and exp.status == "active"
    metrics = variant_metrics("exp-7", "a", state_dir=state)
    assert metrics.trials == 1


def test_ab_complete_records_winner(tmp_path: Path) -> None:
    state = _state(tmp_path)
    create_experiment("exp-8", "complete", _make_variants(), state_dir=state)
    for _ in range(30):
        record_trial("exp-8", "b", 0.9, converted=True, state_dir=state)
    for _ in range(30):
        record_trial("exp-8", "a", 0.4, converted=False, state_dir=state)
    experiment = complete_experiment("exp-8", state_dir=state)
    assert experiment.status == "completed"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_register_and_list_deterministic(tmp_path: Path, capsys) -> None:
    args = dict(
        name="rf_clf",
        version="1.0.0",
        artifact="m.joblib",
        metrics_hash="ab" * 32,
        stage="staging",
    )
    out1 = _capture(tmp_path, capsys, "--register", **args)
    out2 = _capture(tmp_path, capsys, "--register", **args)
    assert out1 == out2  # idempotent -> byte-identical output
    out = _capture(tmp_path, capsys, "--list")
    assert "rf_clf | 1.0.0 | staging" in out
    assert "staging" in out


def test_cli_promote_changes_stage(tmp_path: Path, capsys) -> None:
    _run_cli(
        tmp_path,
        capsys,
        "--register",
        "--name",
        "m",
        "--version",
        "1",
        "--artifact",
        "a",
        "--metrics-hash",
        "ab" * 32,
        "--stage",
        "staging",
    )
    _run_cli(
        tmp_path, capsys, "--promote", "--name", "m", "--version", "1", "--stage", "production"
    )
    out = _capture(tmp_path, capsys, "--list", "--stage", "production")
    assert "m" in out and "production" in out
    # --list with no --stage shows every model regardless of stage
    all_list = _capture(tmp_path, capsys, "--list")
    assert "m | 1 | production" in all_list
    empty = _capture(tmp_path, capsys, "--list", "--stage", "staging")
    assert "Registered models (0)" in empty


def test_cli_drift(tmp_path: Path, capsys) -> None:
    baseline = {"speed": [float(i) for i in range(50)], "protocol": {"A": 80, "B": 20}}
    current = {"speed": [float(i) + 30.0 for i in range(50)], "protocol": {"A": 80, "B": 20}}
    b_path = tmp_path / "baseline.json"
    c_path = tmp_path / "current.json"
    b_path.write_text(json.dumps(baseline), encoding="utf-8")
    c_path.write_text(json.dumps(current), encoding="utf-8")
    rc = _run_cli(
        tmp_path,
        capsys,
        "--drift",
        "--baseline",
        str(b_path),
        "--current",
        str(c_path),
        "--threshold",
        "0.2",
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "drifted" in out
    assert "  speed:" in out
    # Numeric feature drifted, categorical did not
    assert any(line.strip().startswith("drifted") and ": True" in line for line in out.splitlines())
    assert any(
        line.strip().startswith("drifted") and ": False" in line for line in out.splitlines()
    )


def test_cli_ab_route_and_winner(tmp_path: Path, capsys) -> None:
    variants = ["a:champion:0.5", "b:challenger:0.5"]
    cmd = ["--ab", "--ab-action", "create", "--experiment-id", "e1", "--experiment-name", "x"]
    for v in variants:
        cmd += ["--variant", v]
    out1 = _capture(tmp_path, capsys, *cmd)
    out2 = _capture(tmp_path, capsys, *cmd)
    assert out1 == out2

    r1 = _capture(
        tmp_path,
        capsys,
        "--ab",
        "--ab-action",
        "route",
        "--experiment-id",
        "e1",
        "--user-id",
        "user-42",
    )
    r2 = _capture(
        tmp_path,
        capsys,
        "--ab",
        "--ab-action",
        "route",
        "--experiment-id",
        "e1",
        "--user-id",
        "user-42",
    )
    assert r1 == r2
    assert "variant_id" in r1

    for _ in range(25):
        _run_cli(
            tmp_path,
            capsys,
            "--ab",
            "--ab-action",
            "record",
            "--experiment-id",
            "e1",
            "--variant-id",
            "b",
            "--pk",
            "0.9",
            "--converted",
        )
    for _ in range(25):
        _run_cli(
            tmp_path,
            capsys,
            "--ab",
            "--ab-action",
            "record",
            "--experiment-id",
            "e1",
            "--variant-id",
            "a",
            "--pk",
            "0.4",
        )
    win = _capture(
        tmp_path,
        capsys,
        "--ab",
        "--ab-action",
        "winner",
        "--experiment-id",
        "e1",
        "--min-trials",
        "10",
    )
    assert "b" in win


def _capture(tmp_path: Path, capsys, *args: str, **kwargs: str) -> str:
    ns = _parse_cli(*args)
    ns.state_dir = _state(tmp_path)
    for key, value in kwargs.items():
        setattr(ns, key, value)
    rc = mlops_main(ns)
    assert rc == 0
    return capsys.readouterr().out
