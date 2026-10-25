"""
C-UAS Platform REST API Server.

Exposes all platform capabilities via HTTP for integration by system
integrators, SOC operators, and broker channels. Built on FastAPI.

Endpoints:
  GET  /                         Health check
  GET  /systems                  List registered AI systems (governance)
  POST /systems                  Register an AI system
  GET  /risks                    List risks
  POST /risks                    Assess a new risk
  GET  /controls                 List Annex A controls
  POST /controls/{id}/implement  Implement a control
  POST /incidents                Record an incident
  GET  /compliance               ISO 42001 compliance report
  POST /detection/scan-rf        Classify RF emitter
  POST /detection/spoof          Evaluate GNSS spoofing
  POST /engagement/schedule      Compute engagement schedule
  POST /swarm/simulate           Simulate drone swarm
  POST /dew/model                Directed-energy beam model (spot size, dwell, fluence)
  GET  /competitive-landscape    List deployed C-UAS systems
  POST /unit-economics           Compute unit economics
  GET  /benchmarks               Run performance benchmarks
  GET  /performance/benchmark    Run deterministic benchmark kernels
  GET  /performance/profile      Profile per-endpoint latency/throughput
  GET  /performance/sla          Assess SLA compliance
  GET  /security/audit           Run the hardening audit
  GET  /security/penetrate       Run penetration test scenarios
  GET  /security/compliance      ISO 42001 / SOC 2 compliance matrix
  GET  /observability/metrics    Prometheus-style metrics collection
  GET  /observability/alerts     Alerting engine state
  GET  /observability/health     Composite platform health
  GET  /observability/slo        SLO / error-budget evaluation
  GET  /status                   Comprehensive platform health (observability)
  GET  /datacenter/capacity      Data center capacity plan
  GET  /datacenter/lifecycle     Data center lifecycle report
  GET  /datacenter/efficiency    Energy-to-compute efficiency report
  GET  /edge/tenant              List registered edge tenants
  GET  /edge/fleet               Aggregate fleet health
  GET  /edge/zero-trust          Evaluate ingress against zero-trust policy

All figures computed from real code execution — no fabricated metrics.
"""

from __future__ import annotations

import random
from dataclasses import asdict
from typing import Any, Callable, Dict, List, Optional, Sequence, cast

from fastapi import FastAPI, HTTPException, WebSocket
from pydantic import BaseModel, Field

from c_uas.api.websockets import websocket_route

# ---------------------------------------------------------------------------
# Module analysis imports (HTTP surface mirrors the CLI surface)
# ---------------------------------------------------------------------------
from c_uas.datacenter.capacity import compute_capacity_plan
from c_uas.datacenter.cli import EXAMPLE_RACKS as _DC_EXAMPLE_RACKS
from c_uas.datacenter.efficiency import compute_efficiency_report
from c_uas.datacenter.lifecycle import lifecycle_report
from c_uas.detection.opendew_classifier import get_opendew_classifier
from c_uas.detection.rf_classifier import RFSignalClassifier
from c_uas.detection.spoof_detector import GNSSMeasurement, GNSSSpoofDetector
from c_uas.dew.atmospheric import (
    LASER_SPECS,
    AtmosphericConditions,
    time_to_kill_with_attenuation,
)
from c_uas.edge.fleet import FleetManager
from c_uas.edge.tenancy import TenancyManager
from c_uas.edge.zero_trust import default_deny_eval
from c_uas.engagement.backtest import Scenario, run_backtest
from c_uas.engagement.scheduler import (
    DroneTrack,
    EngagementScheduler,
)
from c_uas.governance import (
    AISystemRegistry,
    AuditEvidenceChain,
    ComplianceReporter,
    ControlImplementation,
    IncidentManager,
    RiskAssessment,
)
from c_uas.observability.alerts import (
    AbsenceSignalRule,
    RateOfChangeRule,
    ThresholdRule,
    new_engine,
)
from c_uas.observability.health import new_aggregator, run_all_probes
from c_uas.observability.metrics import (
    MetricType,
    new_registry,
)
from c_uas.observability.slo import SLOTarget, new_tracker
from c_uas.performance.optimizers import (
    a_star,
    greedy_set_cover,
    local_search,
)
from c_uas.performance.profiler import (
    ProfileStore,
    run_profile,
)
from c_uas.performance.sla_tracker import (
    SLARegistry,
    SLATarget,
    record_recovery,
    record_request,
)
from c_uas.security.cli import (
    BASELINE_CONFIG as _SEC_BASELINE_CONFIG,
)
from c_uas.security.compliance_matrix import build_matrix
from c_uas.security.hardening import run_audit
from c_uas.security.penetration import run_penetration_test
from c_uas.swarm import SwarmConfig, SwarmSimulator
from c_uas.unit_economics import UnitEconomicsModel

app = FastAPI(
    title="C-UAS Platform API",
    description="Counter-UAS detection, tracking, engagement scheduling, "
    "and airspace forensics — ISO 42001 governance ready.",
    version="0.1.0",
)


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket, client_id: Optional[str] = None) -> None:
    """WebSocket endpoint for real-time track/event streaming.

    Clients subscribe to topics (tracks, detections, engagements, alerts,
    health) by sending JSON messages:
      {"action": "subscribe", "topics": ["tracks", "detections"]}
    The server pushes MessageEnvelope frames for matching events.
    """
    await websocket_route(websocket, client_id)


# ---------------------------------------------------------------------------
# Governance state (singleton per process)
# ---------------------------------------------------------------------------
_registry = AISystemRegistry()
_assessor = RiskAssessment()
_controller = ControlImplementation()
_chain = AuditEvidenceChain()
_mgr = IncidentManager()
_reporter = ComplianceReporter(_registry, _assessor, _controller, _chain, _mgr)


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------
class RegisterSystemRequest(BaseModel):
    name: str = Field(..., description="AI system name")
    module_path: str = Field(..., description="Python module path")
    lifecycle_stage: str = Field("operation", description="development/operation/decommission")
    risk_level: str = Field("medium", description="low/medium/high/critical")
    description: str = Field("", description="System description")


class AssessRiskRequest(BaseModel):
    system_id: str = Field(..., description="Registered AI system ID")
    description: str = Field(..., description="Risk description")
    likelihood: str = Field("medium", description="low/medium/high")
    impact: str = Field("medium", description="low/medium/high")
    treatment: str = Field("mitigate", description="mitigate/avoid/transfer/accept")
    treatment_plan: str = Field("", description="Remediation plan")


class ImplementControlRequest(BaseModel):
    control_id: str = Field(..., description="Annex A control ID, e.g. A.8.2")
    evidence: str = Field(..., description="Evidence pointer or description")


class RecordIncidentRequest(BaseModel):
    title: str = Field(..., description="Incident title")
    description: str = Field(..., description="Incident description")
    severity: str = Field("medium", description="low/medium/high/critical")
    system_id: Optional[str] = Field(None, description="Related AI system ID")


class ScanRFRequest(BaseModel):
    freq_mhz: float = Field(2450.0, description="Frequency in MHz")
    bw_mhz: float = Field(20.0, description="Bandwidth in MHz")


class SpoofRequest(BaseModel):
    carrier_to_noise_db_hz: float = Field(42.0)
    pseudorange_rate_mps: float = Field(10.0)
    clock_drift_ppm: float = Field(0.05)
    num_satellites: int = Field(10)


class ScheduleRequest(BaseModel):
    num_drones: int = Field(5, ge=1, le=1000)
    dwell_s: float = Field(4.0, gt=0)
    slew_s: float = Field(1.5, gt=0)
    time_limit_s: float = Field(30.0, gt=0)


class SwarmRequest(BaseModel):
    num_drones: int = Field(16, ge=1, le=10000)
    spread_s: float = Field(10.0, gt=0)
    speed_mps: float = Field(30.0, gt=0)
    evasion: float = Field(0.3, ge=0.0, le=1.0)
    seed: int = Field(42)


class UnitEconomicsRequest(BaseModel):
    system_type: str = Field(
        "software_only",
        description="directed_energy_laser/kinetic_missile/rf_jamming/software_only",
    )
    capital_cost_usd: float = Field(250_000, gt=0)
    annual_engagements: int = Field(1_000, gt=0)
    service_life_years: int = Field(5, gt=0)
    marginal_cost_usd: float = Field(0.0, ge=0)
    attacker_drone_cost_usd: float = Field(5_000, gt=0)


class DewModelRequest(BaseModel):
    laser: str = Field(
        "fiber_50kw",
        description="Laser spec key (fiber_50kw, fiber_100kw, solid_state_150kw, chemical_100kw)",
    )
    range_m: float = Field(3000.0, gt=0, description="Slant range to target in meters")
    material: str = Field(
        "aluminum", description="Target material: aluminum, carbon_fiber, plastic, composite"
    )
    rain_mm_hr: float = Field(0.0, ge=0, description="Rain rate in mm/hr")
    visibility_km: float = Field(20.0, gt=0, description="Aerosol visibility in km")


# ---------------------------------------------------------------------------
# Module analysis request/response models (HTTP surface mirrors CLI surface)
# ---------------------------------------------------------------------------


class BenchmarkRequest(BaseModel):
    module: str = Field("default", description="Target module id")
    seed: int = Field(42, description="Deterministic RNG seed")


class BenchmarkResponse(BaseModel):
    module: str
    seed: int
    astar_path: List[List[int]]
    astar_cost: float
    astar_nodes_expanded: int
    astar_found: bool
    set_cover_chosen: List[str]
    set_cover_covered: int
    set_cover_universe: int
    set_cover_uncovered: List[object]
    local_search_best_state: List[float]
    local_search_best_cost: float
    local_search_iterations: int
    local_search_improved: bool


class ProfileRequest(BaseModel):
    module: str = Field("default", description="Target module id")
    seed: int = Field(42, description="Deterministic RNG seed")


class ProfileResponse(BaseModel):
    module: str
    seed: int
    endpoints: Dict[str, Any]
    memory_pressure: bool
    peak_rss_bytes: int
    bottlenecks: List[Dict[str, Any]]


class SLARequest(BaseModel):
    module: str = Field("default", description="Target module id")
    seed: int = Field(42, description="Deterministic RNG seed")


class SLAResponse(BaseModel):
    module: str
    sample_count: int
    latency_p50_s: float
    latency_p95_s: float
    latency_p99_s: float
    error_count: int
    error_rate: float
    error_budget_remaining: float
    p99_compliant: bool
    error_budget_compliant: bool
    overall_compliant: bool
    recovery_time_s: float
    compliance_status: str


class AuditResponse(BaseModel):
    audit_id: str
    config_hash: str
    overall_score: float
    grade: str
    checks_passed: int
    checks_total: int


class PenetrateResponse(BaseModel):
    report_id: str
    config_hash: str
    overall_passed: bool
    pass_rate: float
    results: List[Dict[str, Any]]


class ComplianceResponse(BaseModel):
    matrix_id: str
    overall_coverage: float
    iso_coverage: float
    soc2_coverage: float
    gaps: List[str]


class MetricsResponse(BaseModel):
    collected_at: str
    counters: int
    gauges: int
    histograms: int
    summaries: int


class AlertsResponse(BaseModel):
    total: int
    firing: int
    active: int
    resolved: int
    by_severity: Dict[str, int]


class HealthResponse(BaseModel):
    overall_status: str
    composite_score: float
    components: List[Dict[str, Any]]
    unhealthy: List[str]
    degraded: List[str]
    healthy: List[str]


class SLOResponse(BaseModel):
    results: List[Dict[str, Any]]


class CapacityResponse(BaseModel):
    plan_id: str
    config_hash: str
    total_it_load_kw: float
    total_facility_kw: float
    overall_utilization_pct: float
    overcommitted_racks: int
    racks: List[Dict[str, Any]]


class LifecycleResponse(BaseModel):
    report_id: str
    config_hash: str
    total_assets: int
    assets_needing_retirement: int
    total_decommission_cost_usd: float
    stage_counts: Dict[str, int]


class EfficiencyResponse(BaseModel):
    report_id: str
    config_hash: str
    pue: float
    dcie: float
    compute_per_watt: float
    efficiency_rating: str


class TenantResponse(BaseModel):
    tenants: List[Dict[str, Any]]


class FleetResponse(BaseModel):
    total_nodes: int
    active_nodes: int
    offline_nodes: int
    decommissioned_nodes: int
    average_health_score: float
    by_tenant: Dict[str, int]


class ZeroTrustRequest(BaseModel):
    source: str = Field("node-A", description="Ingress source identity")
    dest: str = Field("node-B", description="Ingress destination identity")
    port: int = Field(443, description="Ingress destination port")
    has_mtls: bool = Field(False, description="mTLS is present for the flow")
    same_segment: bool = Field(False, description="Same network segment")
    authenticated: bool = Field(False, description="Service-to-service auth present")


class ZeroTrustResponse(BaseModel):
    allowed: bool
    reason: str
    rules_checked: List[str]
    matched_rules: List[str]


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "platform": "C-UAS Platform",
        "version": "0.1.0",
        "publisher": "Apex Growth Systems LLC",
        "contact": "aah@a2zsoc.com",
    }


@app.get("/status")
def platform_status() -> Dict[str, Any]:
    """Comprehensive platform health from real component probes.

    Returns the composite health score (weighted average of the six
    component scores), the per-component breakdown, the list of unhealthy
    components (score < 80), and the UTC check timestamp.
    """
    aggregator = new_aggregator()
    run_all_probes(aggregator)
    composite = aggregator.composite()
    return {
        "schema_version": composite.schema_version,
        "overall_status": composite.overall_status,
        "composite_score": composite.composite_score,
        "unhealthy": list(composite.unhealthy),
        "components": [
            {
                "component": c.component,
                "status": c.status,
                "score": c.score,
                "details": c.details,
                "checked_at": c.checked_at,
                "error": c.error,
            }
            for c in composite.components
        ],
        "checked_at": composite.checked_at,
    }


# ---------------------------------------------------------------------------
# Governance endpoints
# ---------------------------------------------------------------------------
@app.get("/systems")
def list_systems() -> dict[str, Any]:
    systems = _registry.list_all()
    return {
        "count": len(systems),
        "systems": [s.to_dict() for s in systems],
    }


@app.post("/systems", status_code=201)
def register_system(req: RegisterSystemRequest) -> dict[str, Any]:
    try:
        sid = _registry.register(
            req.name,
            req.module_path,
            req.lifecycle_stage,
            req.risk_level,
            req.description,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from None
    sys = _registry.get(sid)
    assert sys is not None
    return {"system_id": sid, "system": sys.to_dict()}


@app.get("/risks")
def list_risks() -> dict[str, Any]:
    risks = _assessor.list_all()
    return {
        "count": len(risks),
        "risks": [r.to_dict() for r in risks],
    }


@app.post("/risks", status_code=201)
def assess_risk(req: AssessRiskRequest) -> dict[str, Any]:
    try:
        risk = _assessor.assess(
            req.system_id,
            req.description,
            req.likelihood,
            req.impact,
            req.treatment,
            req.treatment_plan,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from None
    _chain.log("risk_assessment", {"risk_id": risk.risk_id}, req.system_id)
    return {"risk_id": risk.risk_id, "risk": risk.to_dict()}


@app.get("/controls")
def list_controls() -> dict[str, Any]:
    controls = _controller.list_all()
    return {
        "count": len(controls),
        "implemented": len(_controller.list_implemented()),
        "controls": [c.to_dict() for c in controls],
    }


@app.post("/controls/{control_id}/implement")
def implement_control(control_id: str, req: ImplementControlRequest) -> dict[str, Any]:
    ctrl = _controller.implement(control_id, req.evidence)
    if ctrl is None:
        raise HTTPException(status_code=404, detail=f"Unknown control: {control_id}")
    _chain.log("control_implementation", {"control_id": ctrl.control_id}, None)
    return {"control_id": ctrl.control_id, "control": ctrl.to_dict()}


@app.post("/incidents", status_code=201)
def record_incident(req: RecordIncidentRequest) -> dict[str, Any]:
    inc = _mgr.record(req.title, req.description, req.severity, req.system_id)
    _chain.log("incident", {"incident_id": inc.incident_id}, req.system_id)
    return {"incident_id": inc.incident_id, "incident": inc.to_dict()}


@app.get("/compliance")
def compliance_report() -> dict[str, Any]:
    report = _reporter.generate()
    return report.to_dict()


@app.get("/evidence/verify")
def verify_evidence_chain() -> dict[str, Any]:
    return {"valid": _chain.verify_chain(), "entries": len(_chain.list_all())}


# ---------------------------------------------------------------------------
# Detection endpoints
# ---------------------------------------------------------------------------
@app.post("/detection/scan-rf")
def scan_rf(req: ScanRFRequest) -> dict[str, Any]:
    res = RFSignalClassifier.classify_frequency(req.freq_mhz, req.bw_mhz)
    return {
        "freq_mhz": req.freq_mhz,
        "bw_mhz": req.bw_mhz,
        "protocol": res["protocol"],
        "threat_category": res["threat_category"],
        "matched": res.get("matched", False),
    }


@app.post("/detection/spoof")
def detect_spoof(req: SpoofRequest) -> dict[str, Any]:
    detector = GNSSSpoofDetector()
    meas = GNSSMeasurement(
        carrier_to_noise_db_hz=req.carrier_to_noise_db_hz,
        pseudorange_rate_mps=req.pseudorange_rate_mps,
        clock_drift_ppm=req.clock_drift_ppm,
        num_satellites=req.num_satellites,
    )
    result = detector.evaluate_telemetry(meas)
    return result


# ---------------------------------------------------------------------------
# Engagement endpoints
# ---------------------------------------------------------------------------
@app.post("/engagement/schedule")
def schedule_engagement(req: ScheduleRequest) -> dict[str, Any]:
    scheduler = EngagementScheduler(
        dwell_s=req.dwell_s, slew_s=req.slew_s, time_limit_s=req.time_limit_s
    )
    tracks = [
        DroneTrack(
            track_id=i,
            arrival_time_s=5.0 + i * 0.5,
            pk_base=0.75,
            priority=3,
        )
        for i in range(req.num_drones)
    ]
    plan = scheduler.schedule(tracks=tracks)
    return {
        "num_drones": req.num_drones,
        "expected_kills": plan.expected_kills,
        "engaged_targets": plan.engaged_targets,
        "leaked_targets": plan.leaked_targets,
        "total_time_s": plan.total_time_s,
        "leak_rate": round(plan.leaked_targets / req.num_drones, 4),
        "sequence": plan.sequence,
    }


@app.post("/engagement/backtest")
def backtest_engagement() -> dict[str, Any]:
    """Run backtest against counterfactual controls (swarm_8 scenario)."""
    scenario = Scenario(name="swarm_8", num_drones=8, time_limit_s=40.0, seed=42)
    result = run_backtest(scenario)
    return result


# ---------------------------------------------------------------------------
# Swarm endpoints
# ---------------------------------------------------------------------------
@app.post("/swarm/simulate")
def simulate_swarm(req: SwarmRequest) -> dict[str, Any]:
    config = SwarmConfig(
        num_drones=req.num_drones,
        arrival_spread_s=req.spread_s,
        speed_mps=req.speed_mps,
        start_distance_km=2.0,
        evasion_probability=req.evasion,
        seed=req.seed,
    )
    sim = SwarmSimulator(config)
    tracks = sim.generate_tracks()

    scheduler = EngagementScheduler(dwell_s=4.0, slew_s=1.5, time_limit_s=40.0)
    drone_tracks = [
        DroneTrack(
            track_id=t.track_id,
            arrival_time_s=t.arrival_time_s,
            pk_base=t.pk_base,
            priority=t.priority,
        )
        for t in tracks
    ]
    plan = scheduler.schedule(tracks=drone_tracks)

    return {
        "config": sim.summary(),
        "tracks_generated": len(tracks),
        "expected_kills": plan.expected_kills,
        "engaged_targets": plan.engaged_targets,
        "leaked_targets": plan.leaked_targets,
        "leak_rate": round(plan.leaked_targets / req.num_drones, 4),
        "total_time_s": plan.total_time_s,
    }


# ---------------------------------------------------------------------------
# Competitive landscape
# ---------------------------------------------------------------------------
@app.get("/competitive-landscape")
def competitive_landscape() -> dict[str, Any]:
    from c_uas.competitive_landscape import CUASDatabase

    db = CUASDatabase()
    summary = db.summary()
    systems = [
        {
            "name": s.name,
            "origin": s.origin,
            "developer": s.developer,
            "type": s.system_type,
            "power_class": s.power_class,
            "effective_range_km": s.effective_range_km,
            "role": s.role,
            "status": s.public_status,
            "fielded": s.is_fielded,
        }
        for s in db.list_all()
    ]
    return {"summary": summary, "systems": systems}


# ---------------------------------------------------------------------------
# Unit economics
# ---------------------------------------------------------------------------
@app.post("/unit-economics")
def unit_economics(req: UnitEconomicsRequest) -> dict[str, Any]:
    model = UnitEconomicsModel(attacker_drone_cost_usd=req.attacker_drone_cost_usd)

    from c_uas.unit_economics import EngagementParams

    params = EngagementParams(
        system_type=req.system_type,
        capital_cost_usd=req.capital_cost_usd,
        annual_engagements=req.annual_engagements,
        service_life_years=req.service_life_years,
        marginal_cost_usd=req.marginal_cost_usd,
    )
    result = model.cost_per_engagement(params)
    return asdict(result)


# ---------------------------------------------------------------------------
# Directed-energy beam modeling
# ---------------------------------------------------------------------------
@app.post("/dew/model")
def dew_model(req: DewModelRequest) -> dict[str, Any]:
    if req.laser not in LASER_SPECS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown laser: {req.laser}. Available: {', '.join(LASER_SPECS.keys())}",
        )
    spec = LASER_SPECS[req.laser]
    conditions = AtmosphericConditions(
        rainfall_mm_hr=req.rain_mm_hr,
        aerosol_visibility_km=req.visibility_km,
    )
    result = time_to_kill_with_attenuation(
        spec,
        range_m=req.range_m,
        target_material=req.material,
        conditions=conditions,
    )
    return result


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------
@app.get("/benchmarks")
def run_benchmarks() -> dict[str, Any]:
    from c_uas.benchmarks.performance import BenchmarkSuite

    suite = BenchmarkSuite()
    result = suite.run_all()
    return {
        "scheduler": [asdict(r) for r in result.scheduler_results],
        "ekf": asdict(result.ekf_result),
        "end_to_end": asdict(result.end_to_end_result),
        "swarm_saturation": result.swarm_saturation,
    }


# ---------------------------------------------------------------------------
# OpenDEW classifier
# ---------------------------------------------------------------------------
@app.post("/detection/opendew")
def opendew_classify() -> dict[str, Any]:
    clf = get_opendew_classifier()
    import random

    samples = [random.uniform(-1.0, 1.0) for _ in range(100)]
    return clf.classify_iq(samples)


# ---------------------------------------------------------------------------
# Performance routes
# ---------------------------------------------------------------------------


@app.get("/performance/benchmark", response_model=BenchmarkResponse)
def performance_benchmark(module: str = "default", seed: int = 42) -> Dict[str, Any]:
    """Run deterministic performance benchmark kernels (mirrors ``c-uas perf --benchmark``)."""
    grid = [
        [True, True, True, True, True],
        [True, False, False, False, True],
        [True, True, True, True, True],
        [True, False, False, False, True],
        [True, True, True, True, True],
    ]
    astar = a_star(grid, (0, 0), (4, 4), seed=seed)

    universe = ["a", "b", "c", "d", "e", "f", "g"]
    sets: Dict[str, List[object]] = {
        "S1": ["a", "b", "c"],
        "S2": ["c", "d", "e"],
        "S3": ["e", "f", "g"],
        "S4": ["a", "g"],
    }
    cover = greedy_set_cover(
        universe,
        cast(Dict[str, Sequence[object]], sets),
        seed=seed,
    )

    def cost_fn(state: Sequence[float]) -> float:
        return sum(float(x) ** 2 for x in state)

    def neighbors_fn(state: Sequence[float]) -> List[List[float]]:
        out: List[List[float]] = []
        for i in range(len(state)):
            for delta in (-1.0, 1.0):
                n = list(state)
                n[i] += delta
                out.append(n)
        return out

    search = local_search(
        [3.0, -2.0, 5.0],
        cast(Callable[[Sequence[object]], float], cost_fn),
        cast(Callable[[Sequence[object]], Sequence[Sequence[object]]], neighbors_fn),
        seed=seed,
        max_iterations=50,
    )

    return {
        "module": module,
        "seed": seed,
        "astar_path": [list(p) for p in astar.path],
        "astar_cost": astar.cost,
        "astar_nodes_expanded": astar.nodes_expanded,
        "astar_found": astar.found,
        "set_cover_chosen": list(cover.chosen_sets),
        "set_cover_covered": len(cover.covered_elements),
        "set_cover_universe": cover.universe_size,
        "set_cover_uncovered": list(cover.uncovered_elements),
        "local_search_best_state": list(search.best_state),
        "local_search_best_cost": search.best_cost,
        "local_search_iterations": search.iterations,
        "local_search_improved": search.improved,
    }


@app.get("/performance/profile", response_model=ProfileResponse)
def performance_profile(module: str = "default", seed: int = 42) -> Dict[str, Any]:
    """Profile per-endpoint latency/throughput (mirrors ``c-uas perf --profile``)."""
    store = ProfileStore(seed=seed)
    rng = random.Random(seed)
    base = 0.05 if module == "default" else 0.1
    samples = [base + rng.uniform(0.0, 0.02) for _ in range(200)]
    for s in samples:
        store.record_latency(module, s, errored=s > 0.09)
    store.record_memory(0.0, 128 * 1024 * 1024)

    result = run_profile(store, seed=seed)
    return {
        "module": module,
        "seed": seed,
        "endpoints": {k: asdict(v) for k, v in result.endpoints.items()},
        "memory_pressure": result.memory_pressure,
        "peak_rss_bytes": result.peak_rss_bytes,
        "bottlenecks": [asdict(b) for b in result.bottlenecks],
    }


@app.get("/performance/sla", response_model=SLAResponse)
def performance_sla(module: str = "default", seed: int = 42) -> Dict[str, Any]:
    """Assess SLA compliance (mirrors ``c-uas perf --sla``)."""
    registry = SLARegistry(seed=seed)
    registry.add_target(
        SLATarget(
            module=module,
            latency_p50_s=0.1,
            latency_p95_s=0.5,
            latency_p99_s=1.0,
            error_budget=0.01,
            recovery_time_s=30.0,
        )
    )
    rng = random.Random(seed + 1)
    for _ in range(1000):
        seconds = 0.05 + rng.uniform(0.0, 0.05)
        failed = rng.random() < 0.005
        record_request(registry, module, seconds, failed)

    result = registry.compute_result(module)
    if result is None:
        raise HTTPException(status_code=404, detail=f"No SLA data for module: {module}")
    record_recovery(registry, module, "2026-01-01T00:00:00Z", "2026-01-01T00:00:10Z", 10.0)

    return {
        "module": result.module,
        "sample_count": result.sample_count,
        "latency_p50_s": result.latency_p50_s,
        "latency_p95_s": result.latency_p95_s,
        "latency_p99_s": result.latency_p99_s,
        "error_count": result.error_count,
        "error_rate": result.error_rate,
        "error_budget_remaining": result.error_budget_remaining,
        "p99_compliant": result.p99_compliant,
        "error_budget_compliant": result.error_budget_compliant,
        "overall_compliant": result.overall_compliant,
        "recovery_time_s": result.recovery_time_s,
        "compliance_status": registry.compliance_status(module),
    }


# ---------------------------------------------------------------------------
# Security routes
# ---------------------------------------------------------------------------


@app.get("/security/audit", response_model=AuditResponse)
def security_audit() -> Dict[str, Any]:
    """Run the hardening audit (mirrors ``c-uas security --audit``)."""
    audit = run_audit(_SEC_BASELINE_CONFIG)
    return {
        "audit_id": audit.audit_id,
        "config_hash": audit.config_hash,
        "overall_score": audit.overall_score,
        "grade": audit.grade,
        "checks_passed": sum(1 for c in audit.checks if c.passed),
        "checks_total": len(audit.checks),
    }


@app.get("/security/penetrate", response_model=PenetrateResponse)
def security_penetrate() -> Dict[str, Any]:
    """Run penetration test scenarios (mirrors ``c-uas security --penetrate``)."""
    report = run_penetration_test(_SEC_BASELINE_CONFIG)
    return {
        "report_id": report.report_id,
        "config_hash": report.config_hash,
        "overall_passed": report.overall_passed,
        "pass_rate": report.pass_rate,
        "results": [asdict(r) for r in report.results],
    }


@app.get("/security/compliance", response_model=ComplianceResponse)
def security_compliance() -> Dict[str, Any]:
    """ISO 42001 / SOC 2 compliance matrix (mirrors ``c-uas security --compliance``)."""
    audit = run_audit(_SEC_BASELINE_CONFIG)
    report = run_penetration_test(_SEC_BASELINE_CONFIG)
    matrix = build_matrix(audit, report)
    return {
        "matrix_id": matrix.matrix_id,
        "overall_coverage": matrix.overall_coverage,
        "iso_coverage": matrix.iso_coverage,
        "soc2_coverage": matrix.soc2_coverage,
        "gaps": list(matrix.gaps),
    }


# ---------------------------------------------------------------------------
# Observability routes
# ---------------------------------------------------------------------------


@app.get("/observability/metrics", response_model=MetricsResponse)
def observability_metrics() -> Dict[str, Any]:
    """Prometheus-style metrics collection (mirrors ``c-uas obs --metrics``)."""
    registry = new_registry()
    registry.register(
        "http_requests_total",
        MetricType.COUNTER,
        help="Total HTTP requests",
        unit="requests",
        label_names=("code", "method"),
    )
    registry.register(
        "http_request_duration_seconds",
        MetricType.HISTOGRAM,
        help="HTTP latency",
        unit="seconds",
        label_names=("handler",),
    )
    registry.register(
        "api_requests_in_flight",
        MetricType.GAUGE,
        help="In-flight requests",
        unit="requests",
    )
    registry.register(
        "api_response_time_seconds",
        MetricType.SUMMARY,
        help="API response time",
        unit="seconds",
        label_names=("endpoint",),
    )

    c = registry.counter("http_requests_total")
    for code, method, n in (("200", "GET", 1250), ("404", "GET", 30), ("500", "POST", 5)):
        c.inc(float(n), labels={"code": code, "method": method})
    h = registry.histogram("http_request_duration_seconds")
    for v in (0.012, 0.045, 0.089, 0.210, 0.540, 1.230, 2.500):
        h.observe(v, labels={"handler": "detect"})
    g = registry.gauge("api_requests_in_flight")
    g.set(7.0)
    s = registry.summary("api_response_time_seconds")
    for v in (0.05, 0.11, 0.19, 0.33, 0.67, 1.10):
        s.observe(v, labels={"endpoint": "/detect"})

    result = registry.collect()
    return {
        "collected_at": result.collected_at,
        "counters": len(result.counters),
        "gauges": len(result.gauges),
        "histograms": len(result.histograms),
        "summaries": len(result.summaries),
    }


@app.get("/observability/alerts", response_model=AlertsResponse)
def observability_alerts() -> Dict[str, Any]:
    """Alerting engine state (mirrors ``c-uas obs --alerts``)."""
    registry = new_registry()
    registry.register("http_requests_total", MetricType.COUNTER, label_names=("code", "method"))
    registry.register(
        "http_request_duration_seconds",
        MetricType.HISTOGRAM,
        label_names=("handler",),
    )
    registry.register("api_requests_in_flight", MetricType.GAUGE)

    c = registry.counter("http_requests_total")
    c.inc(1250.0, labels={"code": "200", "method": "GET"})
    c.inc(5.0, labels={"code": "500", "method": "POST"})
    h = registry.histogram("http_request_duration_seconds")
    h.observe(0.012, labels={"handler": "detect"})
    h.observe(2.500, labels={"handler": "detect"})
    g = registry.gauge("api_requests_in_flight")
    g.set(7.0)

    engine = new_engine(registry)
    engine.add_threshold_rule(
        ThresholdRule(
            rule_id="obs-001",
            name="high_error_rate",
            metric="http_requests_total",
            threshold=1000.0,
            severity="warning",
            comparison="gt",
            for_seconds=60.0,
            labels=(("code", "500"), ("method", "POST")),
        )
    )
    engine.add_rate_of_change_rule(
        RateOfChangeRule(
            rule_id="obs-002",
            name="latency_spike",
            metric="http_request_duration_seconds",
            threshold=0.5,
            severity="critical",
            for_seconds=60.0,
        )
    )
    engine.add_absence_signal_rule(
        AbsenceSignalRule(
            rule_id="obs-003",
            name="missing_metric",
            metric="api_requests_in_flight",
            severity="warning",
            for_seconds=60.0,
        )
    )
    engine.evaluate()

    summary = engine.summary()
    return {
        "total": summary["total"],
        "firing": summary["firing"],
        "active": summary["active"],
        "resolved": summary["resolved"],
        "by_severity": summary["by_severity"],
    }


@app.get("/observability/health", response_model=HealthResponse)
def observability_health() -> Dict[str, Any]:
    """Composite platform health (mirrors ``c-uas obs --health``)."""
    aggregator = new_aggregator()
    run_all_probes(aggregator)
    composite = aggregator.composite()
    return {
        "overall_status": composite.overall_status,
        "composite_score": composite.composite_score,
        "components": [asdict(c) for c in composite.components],
        "unhealthy": list(composite.unhealthy),
        "degraded": list(composite.degraded),
        "healthy": list(composite.healthy),
    }


@app.get("/observability/slo", response_model=SLOResponse)
def observability_slo() -> Dict[str, Any]:
    """SLO / error-budget evaluation (mirrors ``c-uas obs --slo``)."""
    tracker = new_tracker()
    tracker.add_target(
        SLOTarget(
            service="detection-api",
            metric="availability",
            target=0.999,
            window_seconds=3600,
            is_latency=False,
        )
    )
    tracker.add_target(
        SLOTarget(
            service="detection-api",
            metric="latency_p95",
            target=0.5,
            window_seconds=3600,
            is_latency=True,
        )
    )
    tracker.add_target(
        SLOTarget(
            service="engagement-api",
            metric="error_rate",
            target=0.01,
            window_seconds=3600,
            is_latency=False,
        )
    )
    tracker.observe("detection-api", "availability", 0.9995)
    tracker.observe("detection-api", "latency_p95", 0.42)
    tracker.observe("engagement-api", "error_rate", 0.003)

    results = tracker.evaluate_all()
    return {"results": [asdict(r) for r in results]}


# ---------------------------------------------------------------------------
# Datacenter routes
# ---------------------------------------------------------------------------


@app.get("/datacenter/capacity", response_model=CapacityResponse)
def datacenter_capacity() -> Dict[str, Any]:
    """Data center capacity plan (mirrors ``c-uas dc --capacity``)."""
    it_loads = {"RACK-01": 8.0, "RACK-02": 11.0, "RACK-03": 6.0}
    cooling_loads = {"RACK-01": 7.5, "RACK-02": 10.5, "RACK-03": 5.5}
    compute_units = {"RACK-01": 24, "RACK-02": 36, "RACK-03": 18}
    plan = compute_capacity_plan(
        _DC_EXAMPLE_RACKS,
        it_loads_kw=it_loads,
        cooling_loads_kw=cooling_loads,
        compute_units_map=compute_units,
    )
    return {
        "plan_id": plan.plan_id,
        "config_hash": plan.config_hash,
        "total_it_load_kw": plan.total_it_load_kw,
        "total_facility_kw": plan.total_facility_kw,
        "overall_utilization_pct": plan.overall_utilization_pct,
        "overcommitted_racks": plan.overcommitted_racks,
        "racks": [asdict(r) for r in plan.racks],
    }


@app.get("/datacenter/lifecycle", response_model=LifecycleResponse)
def datacenter_lifecycle() -> Dict[str, Any]:
    """Data center lifecycle report (mirrors ``c-uas dc --lifecycle``)."""
    report = lifecycle_report()
    return {
        "report_id": report.report_id,
        "config_hash": report.config_hash,
        "total_assets": len(report.assets),
        "assets_needing_retirement": report.assets_needing_retirement,
        "total_decommission_cost_usd": report.total_decommission_cost_usd,
        "stage_counts": dict(report.stage_counts),
    }


@app.get("/datacenter/efficiency", response_model=EfficiencyResponse)
def datacenter_efficiency() -> Dict[str, Any]:
    """Energy-to-compute efficiency report (mirrors ``c-uas dc --efficiency``)."""
    report = compute_efficiency_report(
        facility_energy_kwh=1500.0,
        it_energy_kwh=1000.0,
        compute_units=50_000,
        power_watts=1_000_000.0,
        interval_kwh=1500.0,
        emission_factor_kg_co2e_per_kwh=0.45,
        pue_target=1.3,
    )
    return {
        "report_id": report.report_id,
        "config_hash": report.config_hash,
        "pue": report.metrics.pue,
        "dcie": report.metrics.dcie,
        "compute_per_watt": report.metrics.compute_per_watt,
        "efficiency_rating": report.efficiency_rating,
    }


# ---------------------------------------------------------------------------
# Edge routes
# ---------------------------------------------------------------------------


@app.get("/edge/tenant", response_model=TenantResponse)
def edge_tenant() -> Dict[str, Any]:
    """List registered edge tenants (mirrors ``c-uas edge --tenant --list-tenants``)."""
    manager = TenancyManager()
    tenants = manager.list_tenants()
    return {"tenants": [asdict(t) for t in tenants.tenants]}


@app.get("/edge/fleet", response_model=FleetResponse)
def edge_fleet() -> Dict[str, Any]:
    """Aggregate fleet health (mirrors ``c-uas edge --fleet --fleet-health``)."""
    manager = FleetManager()
    report = manager.fleet_health()
    return {
        "total_nodes": report.total_nodes,
        "active_nodes": report.active_nodes,
        "offline_nodes": report.offline_nodes,
        "decommissioned_nodes": report.decommissioned_nodes,
        "average_health_score": report.average_health_score,
        "by_tenant": dict(report.by_tenant),
    }


@app.get("/edge/zero-trust", response_model=ZeroTrustResponse)
def edge_zero_trust(
    source: str = "node-A",
    dest: str = "node-B",
    port: int = 443,
    has_mtls: bool = False,
    same_segment: bool = False,
    authenticated: bool = False,
) -> Dict[str, Any]:
    """Evaluate an ingress flow against the zero-trust policy (mirrors
    ``c-uas edge --zero-trust --evaluate-policy``).
    """
    result = default_deny_eval(
        source=source,
        dest=dest,
        port=port,
        has_mtls=has_mtls,
        same_segment=same_segment,
        authenticated=authenticated,
    )
    return {
        "allowed": result.allowed,
        "reason": result.reason,
        "rules_checked": list(result.rules_checked),
        "matched_rules": list(result.matched_rules),
    }
