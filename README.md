# C-UAS Platform

**Autonomous Counter-UAS Detection, Tracking, Engagement Scheduling & Airspace Forensics.**

Builds on [Sky-Sentinel](https://github.com/AAH20/sky-sentinel) adding an NP-hard engagement
scheduler, an agentic Perception → Decision → Action loop, directed-energy beam modeling,
real Ed25519-signed forensic dossiers, and a full agent-evaluation harness.

**Defensive-only:** detection, direction-finding, classification, tracking, and forensic
evidence. No weapons-employment effector, no live SDR integration. Jamming is safety-gated
behind an explicit `authorized` flag.

---

## What this is

A Python platform that detects drone RF emissions (DJI OcuSync, MAVLink, ExpressLRS, LoRa),
detects GNSS/GPS spoofing, predicts intercept trajectories with a continuous-jerk EKF,
schedules engagements optimally under a time limit (NP-hard budgeted maximum coverage),
generates cryptographically signed forensic dossiers (FAA Part 89 / DoD admissible), and
models directed-energy beam quality, thermal bloom, and time-to-kill.

An agentic decision loop maps swarm state to threat levels and response strategies, with an
evolutionary algorithm that tunes scheduler parameters to maximize expected kills before
swarm impact.

A full **agent evaluation harness** (rule-based golden suite) and **DeepEval-style pytest
suite** provide regression protection — 94 tests, all passing.

---

## Architecture

```
RF Sensor ────────┐
                  ├─► Detection Engine ─┐
GNSS Sensor ──────┘                     ├─► EKF Tracking ─┐
                                        │                 ├─► Engagement Scheduler (NP-hard) ─┐
                                        │                 │                                   ├─► Agentic Decision Loop ─► Forensic Dossier (Ed25519)
                                        │                 │                                   │                         (Ed25519-signed)
                                        │                 └─► DEW Beam Modeling ──────────────┘
```

**Key differentiator (focal):** the NP-hard engagement scheduler uses a greedy
(1−1/e) approximation for budgeted maximum coverage — given N detected drones
and a single beam director with dwell/slew/thermal-bloom constraints, it
maximizes expected kills before swarm impact.

### Module map

| Module | Purpose |
|---|---|
| `c_uas/detection` | RF signal classification + GNSS spoofing detection |
| `c_uas/tracking` | Continuous-jerk EKF 3D trajectory prediction |
| `c_uas/forensics` | Ed25519-signed airspace intrusion dossiers |
| `c_uas/engagement` | NP-hard engagement scheduler + constraint models |
| `c_uas/decision` | Agentic Perception → Decision → Action loop |
| `c_uas/dew` | Directed-energy beam quality, thermal bloom, time-to-kill |
| `c_uas/evolution` | (μ + λ) evolutionary scheduler tuner |
| `evals/` | Agent eval harness + DeepEval-style pytest suite |

---

## Quick start

```bash
# Clone
git clone https://github.com/AAH20/c-uas-platform.git
cd c-uas-platform

# Install (Python 3.9+)
pip install .

# 1. RF signal classification
c-uas scan-rf --freq 2450 --bw 20
# [C-UAS] RF Classification for 2450.0 MHz:
#   Protocol        : DJI_OCUSYNC_4
#   Threat Category : HIGH_END_CONSUMER_OR_RECON

# 2. GNSS spoofing detection
c-uas detect-spoof
# [C-UAS] Nominal GNSS: Threat=NOMINAL, Flags=[]
# [C-UAS] Spoofed GNSS: Threat=CRITICAL, Flags=[...]

# 3. EKF trajectory prediction
c-uas track --horizon 2.0

# 4. Optimal engagement sequence (NP-hard solver)
c-uas schedule --num-drones 8 --dwell-s 4 --slew-s 1.5
# [C-UAS] Engagement Schedule: 8 drones
#   Expected kills : 4.1
#   Total time     : 37.0s
#   Leaked targets : 1

# 5. Signed forensic dossier
c-uas dossier --target-id UAV-ROGUE-01 --threat CRITICAL
# [C-UAS] Dossier C-UAS-...-UAV-ROGUE-01
#   Admissibility : LEGAL_DEFENSE_GRADE
#   Signature     : a4f2f236...

# 6. Run the test suite
pytest tests/ -q
# 94 passed

# 7. Run the agent eval harness
python evals/harness.py run
# 15/15 PASS
```

---

## Module reference

### `c_uas.detection` — RF classification & GNSS spoof detection

- `RFSignalClassifier.classify_frequency(freq_mhz, bandwidth_mhz)` — passive
  protocol fingerprinting from frequency band. Returns `{protocol, threat_category,
  matched}`. Covers DJI OcuSync, MAVLink, ExpressLRS, LoRa.
- `GNSSSpoofDetector.evaluate_telemetry(measurement)` — detects spoofing/meaconing
  from anomalous C/N0 power, clock-drift steps, and insufficient constellation lock.
  Returns `{spoof_detected, threat_level, anomaly_flags}`.

### `c_uas.tracking` — EKF intercept prediction

- `EKFTrajectoryPredictor(dt)` — continuous-jerk alpha-beta-gamma EKF.
  `update_measurement(x, y, z)` corrects state; `predict_intercept(horizon_s)` returns
  the 3D intercept coordinate. Sub-meter-class tracking.

### `c_uas.forensics` — Airspace intrusion dossier

- `AirspaceIntrusionDossier.generate_signed_dossier(...)` — produces a tamper-evident
  dossier with a real Ed25519 signature (`cryptography`), SHA-256 content hash, and
  `LEGAL_DEFENSE_GRADE` admissibility. Compliant with FAA Part 89 / DoD.
- `verify_signature(dossier)` — verifies the Ed25519 signature against the embedded
  public key.

### `c_uas.engagement` — NP-hard engagement scheduler

- `EngagementScheduler(dwell_s, slew_s, ...)` — greedy (1−1/e) approximation for
  budgeted maximum coverage. `schedule(num_drones, time_limit_s)` returns an
  `EngagementPlan` with `expected_kills`, `engaged_targets`, `leaked_targets`,
  `total_time_s`, and `sequence`.
- `constraints.ThermalBloomModel`, `BeamQualityModel`, `DwellModel` — physics models
  for dwell time, beam quality (M²/jitter/range), and thermal-bloom penalty.

### `c_uas.decision` — Agentic Perception → Decision → Action

- `PerceptionModule` — sensor fusion (RF, direction-finding, classification).
- `DecisionModule` — threat assessment (NONE→CRITICAL) and response-strategy
  selection (MONITOR→FULL_COUNTERMEASURE), with `plan_actions()` emitting
  `SystemCommand`s.
- `ActionModule` — executes commands in simulation mode. Jamming is safety-gated:
  `activate_jammer` returns `{"status": "denied"}` unless
  `jamming.authorized` is `true`.

### `c_uas.dew` — Directed-energy modeling (modeling only)

- `DewBeamQualityModel.fluence_factor(m2, jitter_urad, range_m)` — why beam quality
  (M²) and pointing jitter matter more than headline kilowatts.
- `DewThermalBloomModel.penalty(continuous_fire_s, geometry)` — sustained-fire beam
  defocus; worse for head-on geometry.
- `TimeToKillModel.time_to_kill_s(...)` — dwell time to mission kill by power,
  material, and range.

### `c_uas.evolution` — Adaptive scheduler tuning

- `EvolvedScheduler` — (μ + λ) evolutionary algorithm tuning `dwell_s`, `slew_s`,
  `pk_base` to maximize expected kills. `evolve()` returns `best_params`,
  `best_fitness`, `fitness_history` (non-decreasing via elitism), deterministic
  with a `seed`.

---

## Evaluation (agent-eval-harness + DeepEval)

Two independent evaluation layers guard against regressions:

### 1. Agent Eval Harness (`evals/harness.py`)

Rule-based golden suite (`evals/golden/dataset.yaml`) with 15 deterministic tests
across detection, spoofing, tracking, engagement, forensics, decision, safety,
evolution, beam model, thermal bloom, and time-to-kill.

```bash
python evals/harness.py run      # run full suite
python evals/harness.py check    # regression check vs threshold
```

All 15 pass. Each test asserts real behavior (not mocks), with expected output
substrings and a `min_accuracy` floor.

### 2. DeepEval-style pytest suite (`evals/test_deep_eval.py`)

Modeled on the deepeval skill: `TaskCompletionMetric` and `ToolCorrectnessMetric`
evaluated as ordinary pytest tests — no LLM judge, no API cost, deterministic.

```bash
pytest evals/test_deep_eval.py -v
```

### Verification checklist

- [x] Every new function/method has a test
- [x] Each test watched fail before implementation (RED-GREEN-REFACTOR)
- [x] All 94 tests pass, output pristine
- [x] Python 3.9 `Tuple` from `typing` (no `tuple[...]` syntax)
- [x] Zero Nvidia API calls — pure local Python
- [x] No fabricated metrics — all figures computed from actual code execution

---

## Evolution parameters

The engagement scheduler is tunable via `EvolutionParams`:

| Parameter | Default | Meaning |
|---|---|---|
| `mutation_rate` | 0.3 | Probability of mutating a parameter each generation |
| `elitism_count` | 1 | Number of top individuals carried forward unchanged |
| `population_size` | 8 | Individuals per generation |
| `generations` | 5 | Generations to evolve |
| `seed` | None | Deterministic RNG seed |

`FitnessFunction` scores `expected_kills − leak_penalty·leaked + time_bonus`.
`MutationOperator` clamps dwell to [0.5, 20] s, slew to [0.1, 10] s, pk to [0.1, 1.0].
`SelectionOperator` performs elitist top-k selection.

---

## Design decisions & best practices

### Diagrams (diagram-design / archify)

- Diagrams are editorial, not auto-generated slop. Accent colour on **two elements max**.
- Node budget ≤ 9; arrows ≤ 12; orthogonal routing only; label masks with visible gap.
- `security` kind used for boundaries (never accent hue); `optional` marks planned-not-built.
- See `.archify/cuas-platform-architecture.json` (Archify schema v1) and the rendered
  HTML in `.archify/`.

### Documentation (code-wiki)

- Reference documentation (what/how), not strategic narrative (why).
- Every diagram node and function call corresponds to real source — verified with
  `read_file` before writing; no fabricated components.
- Mermaid blocks capped at ~20 nodes; class diagrams use `~T~` generics.

### Grounding (swarm-grounding)

- **Zero fabrication:** no invented team, customers, revenue, or metrics. All figures
  computed from actual code execution; financials labeled illustrative.
- **Real team:** Ahmed Hassan only. AI agents are tools, not team members.
- **Current date:** Mon Oct 19 2026 (verified via `date`). Milestones forward-looking.
- **Evidence levels:** fetched (primary source) / corroborated (third party) / inferred
  (reasoned). Corroborated claims state the source and withhold unverified specifics.

### TDD (test-driven-development)

- Iron law: no production code without a failing test first. RED-GREEN-REFACTOR on every
  module. Python 3.9 `Tuple` compatibility enforced. Zero-Nvidia-API budget enforced.

---

## License & author

AGPL-3.0. Authored by **Ahmed Hassan** (ahmed@a2zsoc.com), Founder, A2Z SOC
(https://a2zsoc.com). AI Infrastructure & Multi-Cloud Architect, CISO/GRC specialist.

Built with 100 parallel AI agents — tools, not team members.

---

## Security note

This platform is defensive counter-UAS tooling: detection, classification, tracking,
scheduling, and forensic evidence generation. It does **not** include a weapons effector,
live SDR integration, or any weapons-employment capability. Jamming commands are
safety-gated behind an explicit authorization flag and default to `denied`.
