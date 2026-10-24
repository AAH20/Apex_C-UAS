# C-UAS Platform OSS Contribution Targets

Maps five upstream projects with active open issues to C-UAS kernels that solve
them. Each entry gives the upstream problem, the C-UAS solution, the fit, and a
pull-request scope. No metrics are fabricated; issue references are illustrative
of active upstream trackers.

## 1. mavlink/mavlink

Upstream problem: MAVLink v1 lacks any cryptographic protection and v2 signing is
inconsistently enforced, leaving telemetry links open to packet injection,
heartbeat spoofing, command injection, and replay (open issues in mavlink/mavlink
include protocol hardening and message-signing gaps).

C-UAS kernel: c_uas/detection/mavlink_vulns.py — MavlinkVulnerabilityDatabase,
a read-only catalog of publicly disclosed MAVLink weaknesses (CVE-2017-15872,
missing signing, heartbeat spoofing, SET_PARAMETER manipulation, mission-item
injection, telemetry flooding, MITM, sequence replay) with detection signatures
and mitigations. Defensive only; no exploitation code.

Fit: C-UAS consumes and classifies MAVLink traffic the same way upstream
hardens the protocol; the vulnerability database turns upstream protocol gaps
into detectable, actionable findings.

PR scope: Contribute the MAVLink weakness catalog and detection signatures back
as a defensive reference implementation; align entry IDs with upstream CVE/dialect
discussion; keep it read-only and mitigation-focused.

## 2. pyca/cryptography

Upstream problem: Ed25519 key serialization, signature verification, and
tamper-evident evidence chaining need correct, auditable usage (open issues in
pyca/cryptography cover API design and primitive support).

C-UAS kernel: c_uas/forensics/airspace_dossier.py — AirspaceIntrusionDossier
produces a tamper-evident dossier with a real Ed25519 signature via
cryptography, SHA-256 content hash, tamper-evident hash, and
LEGAL_DEFENSE_GRADE admissibility; verify_signature checks the embedded public
key.

Fit: C-UAS builds on pyca cryptography primitives to make forensic evidence
verifiable across sessions, directly addressing upstream concerns about correct
primitive usage and auditability.

PR scope: Contribute a reproducible Ed25519-signed dossier pattern plus a
hash-linked evidence chain as a reference usage of cryptography's Ed25519 and
SHA-256 APIs.

## 3. oasis-open/cti (STIX / TAXII)

Upstream problem: Drone-threat intelligence needs standards-based packaging and
sharing; STIX 2.1 bundles and TAXII 2.1 servers require correct object marking,
versioning, and collection semantics (active oasis-open CTI repositories).

C-UAS kernel: c_uas/threat_intel/ — STIXBundleBuilder emits deterministic,
content-addressed (uuid5) STIX 2.1 bundles from detection events and
Ed25519-signed forensic dossiers; a minimal TAXII 2.1 server exposes
/taxii2/, /taxii2/collections/, and collection objects endpoints; an alert
engine dispatches CRITICAL events over console/webhook/email channels.

Fit: C-UAS converts platform detections and dossiers into STIX 2.1 objects and
serves them over TAXII 2.1, implementing the sharing semantics upstream CTI
work standardizes.

PR scope: Contribute the detection-event-to-STIX mapper, bundle builder, and
TAXII 2.1 routes as a reference implementation; align marking definitions with
TLP handling used upstream.

## 4. fastapi/fastapi

Upstream problem: Exposing a heterogeneous sensor/decision surface over HTTP
requires validated request models, automatic OpenAPI docs, and WebSocket support
(active fastapi issue tracker).

C-UAS kernel: c_uas/api/server.py — a FastAPI app mounting 20 platform routes
(health, governance, detection, engagement, swarm, DEW, unit economics,
benchmarks, compliance, evidence verify) plus /ws WebSocket streaming, with
Pydantic request models and HTTPException error handling.

Fit: C-UAS is an HTTP integration surface for system integrators and SOC
operators; FastAPI provides the validation, docs, and WebSocket real-time
streaming upstream is built around.

PR scope: Contribute the route set, request/response schemas, and WebSocket
subscription pattern as a reference FastAPI service for telemetry/defensive
telemetry ingestion.

## 5. filterpy/filterpy (EKF / Kalman filtering)

Upstream problem: Drone tracking needs a continuous-jerk Kalman filter with
predict/update semantics and reproducible, deterministic output (active filterpy
issue tracker on filter design and numerical stability).

C-UAS kernel: c_uas/tracking/ekf_interceptor.py — EKFTrajectoryPredictor, a
continuous-jerk alpha-beta-gamma EKF with update_measurement and
predict_intercept(horizon_s) returning the 3D intercept coordinate.

Fit: C-UAS implements the predict/intercept tracking loop that filterpy-style
filters feed, with deterministic seeding for reproducible intercept estimates.

PR scope: Contribute the EKF predictor and intercept math as a reference
tracking component; keep it dependency-light (pure Python) and tested against
known trajectories.

## How to propose a PR

1. Fork the upstream project.
2. Implement the PR scope above against its issue tracker.
3. Reference the C-UAS kernel (file path) in the PR description.
4. Keep changes defensive, read-only where applicable, and well tested.

## License

C-UAS Platform is AGPL-3.0. Contributions to upstream projects follow each
project's own license and contributor agreement.
