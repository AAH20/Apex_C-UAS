"""
Tests for the Contract Readiness Engine (c_uas.contract_readiness).

Deterministic: same inputs, same assertions every run. No network, no
randomness. Legacy burn-rate / CAC-LTV / MVP-scope tests are preserved
because c_uas.contract_readiness is now a package that re-exports that API.
"""

import argparse
import json
from dataclasses import asdict

import yaml

# ---------------------------------------------------------------------------
# Legacy contract readiness model (burn rate / CAC-LTV / MVP scope)
# ---------------------------------------------------------------------------
from c_uas.contract_readiness import (  # noqa: E402
    DEFAULT_STATE_DIR,
    BurnRateInput,
    CACLTVInput,
    ContractReadinessModel,
    GateResult,
    RouteEntry,
    contract_main,
    detect_breaking_changes_from_files,
    extract_app_routes,
    extract_spec_routes,
    load_app_routes,
    load_spec,
    run_gate,
    verify_contract,
)


class TestBurnRate:
    def test_default_burn_rate(self):
        model = ContractReadinessModel()
        result = model.burn_rate()
        assert result.monthly_burn_usd == 15_500.0  # 15k + 500 free-tier infra
        assert result.annual_burn_usd == result.monthly_burn_usd * 12
        assert result.runway_months == 12

    def test_custom_burn_rate(self):
        model = ContractReadinessModel()
        result = model.burn_rate(
            BurnRateInput(
                monthly_engineer_cost_usd=20_000,
                num_engineers=2,
                months_of_runway=6,
            )
        )
        assert result.monthly_burn_usd == 40_500.0  # 20k*2 + 500
        assert result.runway_months == 6
        assert result.total_runway_usd == 40_500.0 * 6


class TestCACLTV:
    def test_default_cac_ltv(self):
        result = ContractReadinessModel().cac_ltv()
        assert result.ltv_usd > 0.0
        assert result.cac_usd > 0.0
        assert result.cac_ltv_ratio > 0.0
        assert isinstance(result.viable, bool)

    def test_healthy_ratio_viable(self):
        result = ContractReadinessModel().cac_ltv(
            CACLTVInput(
                avg_contract_value_usd=100_000,
                gross_margin=0.9,
                customer_lifespan_years=5.0,
                marketing_spend_usd=1_000,
                contracts_won_per_year=10,
            )
        )
        assert result.viable
        assert result.cac_ltv_ratio < 0.33


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SPEC_PATH = "/openapi.yaml"


def write_spec(tmp_path, spec, name="openapi.yaml", kind="yaml"):
    path = tmp_path / name
    if kind == "json":
        path.write_text(json.dumps(spec), encoding="utf-8")
    else:
        path.write_text(yaml.safe_dump(spec, sort_keys=True), encoding="utf-8")
    return str(path)


BASE_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0.0"},
    "paths": {
        "/users": {"get": {}, "post": {}},
        "/users/{userId}": {"get": {}, "delete": {}},
        "/health": {"get": {}},
    },
}

APP_ROUTES = [
    RouteEntry(method="GET", path="/users"),
    RouteEntry(method="POST", path="/users"),
    RouteEntry(method="GET", path="/users/{userId}"),
    RouteEntry(method="DELETE", path="/users/{userId}"),
    RouteEntry(method="GET", path="/health"),
]


class FakeRoute:
    def __init__(self, methods, path):
        self.methods = set(methods)
        self.path = path


class FakeRouter:
    def __init__(self, routes):
        self.routes = routes


class FakeApp:
    def __init__(self, routes):
        self.router = FakeRouter(routes)


# ---------------------------------------------------------------------------
# contract.py
# ---------------------------------------------------------------------------


class TestLoadSpec:
    def test_load_spec_yaml(self, tmp_path):
        path = write_spec(tmp_path, BASE_SPEC, "api.yaml", "yaml")
        spec = load_spec(path)
        assert spec["info"]["title"] == "Test API"
        assert set(spec["paths"]) == {"/users", "/users/{userId}", "/health"}

    def test_load_spec_json(self, tmp_path):
        path = write_spec(tmp_path, BASE_SPEC, "api.json", "json")
        spec = load_spec(path)
        assert spec["openapi"] == "3.0.0"
        assert len(spec["paths"]) == 3


class TestExtractSpecRoutes:
    def test_extract_all_routes(self):
        routes = extract_spec_routes(BASE_SPEC)
        assert routes == [
            RouteEntry("GET", "/health"),
            RouteEntry("GET", "/users"),
            RouteEntry("POST", "/users"),
            RouteEntry("DELETE", "/users/{userId}"),
            RouteEntry("GET", "/users/{userId}"),
        ]

    def test_empty_spec(self):
        assert extract_spec_routes({}) == []
        assert extract_spec_routes({"paths": {}}) == []

    def test_non_dict_path_item_ignored(self):
        spec = {"paths": {"/users": "not-a-dict"}}
        assert extract_spec_routes(spec) == []


class TestContractVerifier:
    def test_missing_route(self, tmp_path):
        spec_path = write_spec(tmp_path, BASE_SPEC, kind="yaml")
        app_routes = [RouteEntry("GET", "/users")]  # app lacks most spec routes
        report = verify_contract(spec_path, app_routes)
        assert not report.ok
        assert RouteEntry("GET", "/health") in report.missing
        assert RouteEntry("POST", "/users") in report.missing
        assert RouteEntry("DELETE", "/users/{userId}") in report.missing
        assert report.extra == ()

    def test_extra_route(self, tmp_path):
        spec_path = write_spec(
            tmp_path,
            {
                "openapi": "3.0.0",
                "info": {"title": "T", "version": "1"},
                "paths": {"/users": {"get": {}}},
            },
        )
        report = verify_contract(spec_path, APP_ROUTES)
        assert not report.ok
        assert report.missing == ()
        assert RouteEntry("POST", "/users") in report.extra
        assert RouteEntry("GET", "/health") in report.extra

    def test_mismatched_methods(self, tmp_path):
        spec_path = write_spec(
            tmp_path,
            {
                "openapi": "3.0.0",
                "info": {"title": "T", "version": "1"},
                "paths": {"/users": {"post": {}}},
            },
        )
        app_routes = [RouteEntry("GET", "/users")]
        report = verify_contract(spec_path, app_routes)
        assert not report.ok
        assert len(report.mismatched) == 1
        path, spec_methods, app_methods = report.mismatched[0]
        assert path == "/users"
        assert spec_methods == ("POST",)
        assert app_methods == ("GET",)
        # at route-entry level the method change shows as missing + extra
        assert report.missing == (RouteEntry("POST", "/users"),)
        assert report.extra == (RouteEntry("GET", "/users"),)

    def test_ok_when_spec_matches_app(self, tmp_path):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/users": {"get": {}, "post": {}},
                "/health": {"get": {}},
            },
        }
        spec_path = write_spec(tmp_path, spec)
        app_routes = [
            RouteEntry("GET", "/users"),
            RouteEntry("POST", "/users"),
            RouteEntry("GET", "/health"),
        ]
        report = verify_contract(spec_path, app_routes)
        assert report.ok
        assert report.missing == ()
        assert report.extra == ()
        assert report.mismatched == ()

    def test_deterministic_output(self, tmp_path):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/users": {"get": {}, "post": {}},
                "/widgets": {"get": {}},  # not in APP_ROUTES -> not ok
            },
        }
        spec_path = write_spec(tmp_path, spec)
        first = verify_contract(spec_path, APP_ROUTES)
        second = verify_contract(spec_path, APP_ROUTES)
        assert asdict(first) == asdict(second)
        assert first.ok is False
        assert first == second

    def test_real_app_routes(self):
        routes = load_app_routes()
        assert len(routes) > 0
        assert RouteEntry("GET", "/status") in routes
        assert RouteEntry("POST", "/detection/scan-rf") in routes
        # no infrastructure methods leaked in
        assert all(r.method not in ("HEAD", "OPTIONS") for r in routes)

    def test_route_entry_equality_and_hash(self):
        assert RouteEntry("GET", "/x") == RouteEntry("GET", "/x")
        assert RouteEntry("GET", "/x") != RouteEntry("POST", "/x")
        assert {RouteEntry("GET", "/x"), RouteEntry("GET", "/x")} == {RouteEntry("GET", "/x")}


# ---------------------------------------------------------------------------
# breaking.py
# ---------------------------------------------------------------------------


OLD_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "T", "version": "1"},
    "paths": {
        "/pets": {
            "get": {
                "parameters": [
                    {
                        "in": "query",
                        "name": "limit",
                        "required": False,
                        "schema": {"type": "integer", "default": 10},
                    },
                    {
                        "in": "query",
                        "name": "kind",
                        "required": True,
                        "schema": {"type": "string", "enum": ["cat", "dog"]},
                    },
                ]
            }
        },
        "/pets/{petId}": {
            "get": {
                "parameters": [
                    {
                        "in": "path",
                        "name": "petId",
                        "required": True,
                        "schema": {"type": "number"},
                    }
                ]
            }
        },
    },
}

NEW_SPEC_CLEAN = {
    "openapi": "3.0.0",
    "info": {"title": "T", "version": "2"},
    "paths": {
        "/pets": {
            "get": {
                "parameters": [
                    {
                        "in": "query",
                        "name": "limit",
                        "required": False,
                        "schema": {"type": "integer", "default": 10},
                    },
                    {
                        "in": "query",
                        "name": "kind",
                        "required": True,
                        "schema": {"type": "string", "enum": ["cat", "dog"]},
                    },
                ]
            }
        },
        "/pets/{petId}": {
            "get": {
                "parameters": [
                    {
                        "in": "path",
                        "name": "petId",
                        "required": True,
                        "schema": {"type": "number"},
                    }
                ]
            }
        },
    },
}


class TestBreakingChangeDetector:
    def test_removed_parameter(self, tmp_path):
        new_spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "2"},
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": [
                            {
                                "in": "query",
                                "name": "limit",
                                "required": False,
                                "schema": {"type": "integer", "default": 10},
                            }
                        ]
                    }
                }
            },
        }
        old_path = write_spec(tmp_path, OLD_SPEC, "old.yaml")
        new_path = write_spec(tmp_path, new_spec, "new.yaml")
        report = detect_breaking_changes_from_files(old_path, new_path)
        assert report.breaking
        kinds = [c.kind for c in report.changes]
        assert "removed_parameter" in kinds
        removed = [c for c in report.changes if c.kind == "removed_parameter"][0]
        assert "kind" in removed.location

    def test_changed_required_field(self, tmp_path):
        new_spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "2"},
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": [
                            {
                                "in": "query",
                                "name": "limit",
                                "required": True,  # was optional
                                "schema": {"type": "integer", "default": 10},
                            },
                            {
                                "in": "query",
                                "name": "kind",
                                "required": True,
                                "schema": {"type": "string", "enum": ["cat", "dog"]},
                            },
                        ]
                    }
                },
                "/pets/{petId}": {
                    "get": {
                        "parameters": [
                            {
                                "in": "path",
                                "name": "petId",
                                "required": True,
                                "schema": {"type": "number"},
                            }
                        ]
                    }
                },
            },
        }
        old_path = write_spec(tmp_path, OLD_SPEC, "old.yaml")
        new_path = write_spec(tmp_path, new_spec, "new.yaml")
        report = detect_breaking_changes_from_files(old_path, new_path)
        required_changes = [c for c in report.changes if c.kind == "changed_required_field"]
        assert len(required_changes) == 1
        assert required_changes[0].old_value == "False"
        assert required_changes[0].new_value == "True"

    def test_type_narrowing(self, tmp_path):
        new_spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "2"},
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": [
                            {
                                "in": "query",
                                "name": "limit",
                                "required": False,
                                "schema": {"type": "integer"},
                            },
                            {
                                "in": "query",
                                "name": "kind",
                                "required": True,
                                "schema": {"type": "string", "enum": ["cat", "dog"]},
                            },
                        ]
                    }
                },
                "/pets/{petId}": {
                    "get": {
                        "parameters": [
                            {
                                "in": "path",
                                "name": "petId",
                                "required": True,
                                "schema": {"type": "integer"},  # was number
                            }
                        ]
                    }
                },
            },
        }
        old_path = write_spec(tmp_path, OLD_SPEC, "old.yaml")
        new_path = write_spec(tmp_path, new_spec, "new.yaml")
        report = detect_breaking_changes_from_files(old_path, new_path)
        narrowing = [c for c in report.changes if c.kind == "type_narrowing"]
        assert len(narrowing) == 1
        assert narrowing[0].old_value == "number"
        assert narrowing[0].new_value == "integer"

    def test_enum_removal(self, tmp_path):
        new_spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "2"},
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": [
                            {
                                "in": "query",
                                "name": "limit",
                                "required": False,
                                "schema": {"type": "integer", "default": 10},
                            },
                            {
                                "in": "query",
                                "name": "kind",
                                "required": True,
                                "schema": {"type": "string", "enum": ["cat"]},  # dog removed
                            },
                        ]
                    }
                },
                "/pets/{petId}": {
                    "get": {
                        "parameters": [
                            {
                                "in": "path",
                                "name": "petId",
                                "required": True,
                                "schema": {"type": "number"},
                            }
                        ]
                    }
                },
            },
        }
        old_path = write_spec(tmp_path, OLD_SPEC, "old.yaml")
        new_path = write_spec(tmp_path, new_spec, "new.yaml")
        report = detect_breaking_changes_from_files(old_path, new_path)
        enum_changes = [c for c in report.changes if c.kind == "enum_removal"]
        assert len(enum_changes) == 1
        assert "dog" in enum_changes[0].detail

    def test_default_removal(self, tmp_path):
        new_spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "2"},
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": [
                            {
                                "in": "query",
                                "name": "limit",
                                "required": False,
                                "schema": {"type": "integer"},  # default removed
                            },
                            {
                                "in": "query",
                                "name": "kind",
                                "required": True,
                                "schema": {"type": "string", "enum": ["cat", "dog"]},
                            },
                        ]
                    }
                },
                "/pets/{petId}": {
                    "get": {
                        "parameters": [
                            {
                                "in": "path",
                                "name": "petId",
                                "required": True,
                                "schema": {"type": "number"},
                            }
                        ]
                    }
                },
            },
        }
        old_path = write_spec(tmp_path, OLD_SPEC, "old.yaml")
        new_path = write_spec(tmp_path, new_spec, "new.yaml")
        report = detect_breaking_changes_from_files(old_path, new_path)
        default_changes = [c for c in report.changes if c.kind == "default_removal"]
        assert len(default_changes) == 1
        assert default_changes[0].old_value == "10"
        assert default_changes[0].new_value is None

    def test_clean_specs_not_breaking(self, tmp_path):
        old_path = write_spec(tmp_path, OLD_SPEC, "old.yaml")
        new_path = write_spec(tmp_path, NEW_SPEC_CLEAN, "new.yaml")
        report = detect_breaking_changes_from_files(old_path, new_path)
        assert not report.breaking
        assert report.changes == ()

    def test_body_newly_required_field(self, tmp_path):
        old_spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/orders": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "sku": {"type": "string"},
                                            "qty": {"type": "integer"},
                                        },
                                        "required": ["sku"],
                                    }
                                }
                            }
                        }
                    }
                }
            },
        }
        new_spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "2"},
            "paths": {
                "/orders": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "sku": {"type": "string"},
                                            "qty": {"type": "integer"},
                                        },
                                        "required": ["sku", "qty"],  # qty newly required
                                    }
                                }
                            }
                        }
                    }
                }
            },
        }
        old_path = write_spec(tmp_path, old_spec, "old.yaml")
        new_path = write_spec(tmp_path, new_spec, "new.yaml")
        report = detect_breaking_changes_from_files(old_path, new_path)
        assert report.breaking
        required_changes = [c for c in report.changes if c.kind == "changed_required_field"]
        assert len(required_changes) == 1
        assert "qty" in required_changes[0].detail

    def test_deterministic_order(self, tmp_path):
        new_spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "2"},
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": [
                            {
                                "in": "query",
                                "name": "limit",
                                "required": False,
                                "schema": {"type": "integer"},
                            }
                        ]
                    }
                }
            },
        }
        old_path = write_spec(tmp_path, OLD_SPEC, "old.yaml")
        new_path = write_spec(tmp_path, new_spec, "new.yaml")
        first = detect_breaking_changes_from_files(old_path, new_path)
        second = detect_breaking_changes_from_files(old_path, new_path)
        assert asdict(first) == asdict(second)


# ---------------------------------------------------------------------------
# ci_gate.py
# ---------------------------------------------------------------------------


class TestCIGate:
    def test_gate_passes_and_persists_state(self, tmp_path):
        spec_path = write_spec(
            tmp_path,
            {
                "openapi": "3.0.0",
                "info": {"title": "T", "version": "1"},
                "paths": {"/users": {"get": {}}},
            },
        )
        app_routes = [RouteEntry("GET", "/users")]
        result = run_gate(spec_path=spec_path, state_dir=tmp_path, app_routes=app_routes)
        assert isinstance(result, GateResult)
        assert result.exit_code == 0
        assert result.ok
        assert "PASSED" in result.reason
        state_file = tmp_path / "gate_state.json"
        assert state_file.exists()
        state = json.loads(state_file.read_text(encoding="utf-8"))
        assert state["exit_code"] == 0
        assert state["ok"] is True

    def test_gate_fails_on_missing_route(self, tmp_path):
        spec_path = write_spec(
            tmp_path,
            {
                "openapi": "3.0.0",
                "info": {"title": "T", "version": "1"},
                "paths": {"/missing": {"get": {}}},
            },
        )
        result = run_gate(
            spec_path=spec_path,
            state_dir=tmp_path,
            app_routes=[RouteEntry("GET", "/users")],
        )
        assert result.exit_code == 1
        assert not result.ok
        assert "missing" in result.reason

    def test_gate_fails_on_breaking_change(self, tmp_path):
        breaking_new = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "2"},
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": [
                            {
                                "in": "query",
                                "name": "limit",
                                "required": False,
                                "schema": {"type": "integer", "default": 10},
                            }
                        ]
                    }
                },
                "/pets/{petId}": {
                    "get": {
                        "parameters": [
                            {
                                "in": "path",
                                "name": "petId",
                                "required": True,
                                "schema": {"type": "number"},
                            }
                        ]
                    }
                },
            },
        }
        spec_path = write_spec(tmp_path, breaking_new, "new.yaml")
        old_path = write_spec(tmp_path, OLD_SPEC, "old.yaml")
        result = run_gate(
            spec_path=spec_path,
            old_spec_path=old_path,
            state_dir=tmp_path,
            app_routes=[
                RouteEntry("GET", "/pets"),
                RouteEntry("GET", "/pets/{petId}"),
            ],
        )
        assert result.exit_code == 1
        assert not result.ok
        assert "breaking" in result.reason

    def test_gate_state_is_deterministic(self, tmp_path):
        spec_path = write_spec(
            tmp_path,
            {
                "openapi": "3.0.0",
                "info": {"title": "T", "version": "1"},
                "paths": {"/users": {"get": {}}},
            },
        )
        app_routes = [RouteEntry("GET", "/users")]
        first = run_gate(spec_path=spec_path, state_dir=tmp_path, app_routes=app_routes)
        second = run_gate(spec_path=spec_path, state_dir=tmp_path, app_routes=app_routes)
        first_bytes = tmp_path.joinpath("gate_state.json").read_bytes()
        second_bytes = tmp_path.joinpath("gate_state.json").read_bytes()
        assert first_bytes == second_bytes
        assert first.state_path == second.state_path

    def test_default_state_dir(self):
        from pathlib import Path

        assert DEFAULT_STATE_DIR == Path.home() / ".c-uas-platform" / "contract_readiness"


# ---------------------------------------------------------------------------
# cli.py
# ---------------------------------------------------------------------------


def _namespace(**kwargs):
    defaults = {
        "command": "contract",
        "verify": False,
        "breaking": False,
        "gate": False,
        "spec": None,
        "old_spec": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestContractCLI:
    def test_verify_missing_spec_returns_one(self):
        assert contract_main(_namespace(verify=True)) == 1

    def test_breaking_missing_specs_returns_one(self):
        assert contract_main(_namespace(breaking=True)) == 1
        assert contract_main(_namespace(breaking=True, spec="x.yaml")) == 1

    def test_no_flags_returns_one(self):
        assert contract_main(_namespace()) == 1

    def test_verify_ok_with_real_app(self, tmp_path):
        from c_uas.api.server import app

        routes = extract_app_routes(app)
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "C-UAS", "version": "0.1.0"},
            "paths": {},
        }
        for route in routes:
            spec["paths"].setdefault(route.path, {})[route.method.lower()] = {}
        spec_path = write_spec(tmp_path, spec)
        result = contract_main(_namespace(verify=True, spec=spec_path))
        assert result == 0

    def test_verify_missing_route_returns_one(self, tmp_path):
        spec_path = write_spec(
            tmp_path,
            {
                "openapi": "3.0.0",
                "info": {"title": "T", "version": "1"},
                "paths": {"/nope": {"get": {}}},
            },
        )
        result = contract_main(_namespace(verify=True, spec=spec_path))
        assert result == 1

    def test_breaking_clean_returns_zero(self, tmp_path):
        old_path = write_spec(tmp_path, OLD_SPEC, "old.yaml")
        new_path = write_spec(tmp_path, NEW_SPEC_CLEAN, "new.yaml")
        result = contract_main(_namespace(breaking=True, spec=new_path, old_spec=old_path))
        assert result == 0

    def test_breaking_violation_returns_one(self, tmp_path):
        new_spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "2"},
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": [
                            {
                                "in": "query",
                                "name": "limit",
                                "required": False,
                                "schema": {"type": "integer"},
                            }
                        ]
                    }
                }
            },
        }
        old_path = write_spec(tmp_path, OLD_SPEC, "old.yaml")
        new_path = write_spec(tmp_path, new_spec, "new.yaml")
        result = contract_main(_namespace(breaking=True, spec=new_path, old_spec=old_path))
        assert result == 1
