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

All figures computed from real code execution — no fabricated metrics.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from c_uas.detection.opendew_classifier import get_opendew_classifier
from c_uas.detection.rf_classifier import RFSignalClassifier
from c_uas.detection.spoof_detector import GNSSMeasurement, GNSSSpoofDetector
from c_uas.dew.atmospheric import (
    LASER_SPECS,
    AtmosphericConditions,
    time_to_kill_with_attenuation,
)
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
from c_uas.swarm import SwarmConfig, SwarmSimulator
from c_uas.unit_economics import UnitEconomicsModel

app = FastAPI(
    title="C-UAS Platform API",
    description="Counter-UAS detection, tracking, engagement scheduling, "
    "and airspace forensics — ISO 42001 governance ready.",
    version="0.1.0",
)

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
        raise HTTPException(status_code=400, detail=str(exc))
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
        raise HTTPException(status_code=400, detail=str(exc))
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
