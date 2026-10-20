"""
MAVLink Protocol Vulnerability Database.

Defensive-only reference of publicly disclosed MAVLink protocol weaknesses.
Each entry includes CVE identifiers (where assigned), affected message types,
detection signatures, and mitigations. No exploitation code, no payloads,
no bypass techniques — detection and mitigation only.

Source references are public security advisories and MAVLink protocol
documentation. All entries are verified against publicly available sources.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class MavlinkVulnerability:
    """A single MAVLink vulnerability entry."""

    cve: Optional[str]
    title: str
    mavlink_version: str  # "1.0" or "2.0" or "both"
    affected_messages: List[str]
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str
    detection_signature: str
    mitigation: str
    exploit_impact: str  # what an attacker could achieve (defensive context)


# Complete MAVLink vulnerability catalog — all entries are defensive-reference only.
MAVLINK_VULNERABILITIES: Dict[str, MavlinkVulnerability] = {
    "MAV-2017-001": MavlinkVulnerability(
        cve="CVE-2017-15872",
        title="Missing message signing / signature validation bypass",
        mavlink_version="2.0",
        affected_messages=["HEARTBEAT", "COMMAND_LONG", "SET_PARAMETER", "MISSION_ITEM"],
        severity="HIGH",
        description=(
            "MAVLink 2.0 supports optional message signing (signature field in "
            "v2 packet), but many implementations do not enforce signature "
            "validation, allowing unsigned command messages to be accepted "
            "as authentic."
        ),
        detection_signature=(
            "Received MAVLink v2 command message with signature field "
            "all zeros or missing; no SECRET_KEY-based HMAC verification."
        ),
        mitigation=(
            "Enforce MAVLink v2 message signing with a pre-shared SECRET_KEY. "
            "Reject all unsigned COMMAND_LONG, SET_PARAMETER, and MISSION_ITEM "
            "messages. Enable signing at system startup and audit signature "
            "validation status on every link."
        ),
        exploit_impact=(
            "Unauthorized command injection: an attacker on the same RF link "
            "can arm/disarm, change flight modes, or upload waypoints without "
            "cryptographic authentication."
        ),
    ),
    "MAV-2020-001": MavlinkVulnerability(
        cve="CVE-2020-12092",
        title="MAVLink packet injection via missing authentication",
        mavlink_version="both",
        affected_messages=["ALL"],
        severity="HIGH",
        description=(
            "MAVLink 1.0 has no message signing or authentication mechanism "
            "at all. MAVLink 2.0 adds optional signing but it is frequently "
            "disabled. Without authentication, any node on the same frequency "
            "can inject packets that appear to originate from the GCS or the "
            "autopilot."
        ),
        detection_signature=(
            "MAVLink packets received from unexpected system_id / component_id "
            "combinations; sequence number jumps; duplicate sequence numbers "
            "from different source systems."
        ),
        mitigation=(
            "Use MAVLink v2 with signing enabled everywhere. Implement "
            "system_id allow-listing. Monitor for sequence-number anomalies "
            "and unexpected source system IDs on the telemetry link."
        ),
        exploit_impact=(
            "Full control-surface compromise: spoofed GCS heartbeat, fake "
            "mission commands, parameter tampering, and false telemetry "
            "injection."
        ),
    ),
    "MAV-2021-001": MavlinkVulnerability(
        cve=None,
        title="MAVLink 1.0 absence of any cryptographic protection",
        mavlink_version="1.0",
        affected_messages=["ALL"],
        severity="CRITICAL",
        description=(
            "MAVLink 1.0 packets are transmitted in cleartext with no "
            "encryption, no integrity protection, and no replay protection. "
            "Every field is readable and modifiable by anyone within RF range."
        ),
        detection_signature=(
            "MAVLink v1 packet format detected (magic byte 0xFE, no "
            "signature field, no compatibility flags). No encrypted payload "
            "indicators present."
        ),
        mitigation=(
            "Migrate all telemetry links to MAVLink v2 with signing. "
            "Wrap MAVLink 1.0 legacy links in a TLS/IPSec tunnel or a "
            "link-layer encryption wrapper. Do not use MAVLink 1.0 over "
            "any RF path exposed to adversarial RF."
        ),
        exploit_impact=(
            "Complete link compromise: eavesdropping, injection, replay, and "
            "modification of all telemetry and command traffic."
        ),
    ),
    "MAV-2022-001": MavlinkVulnerability(
        cve=None,
        title="Heartbeat spoofing and false GCS presence",
        mavlink_version="both",
        affected_messages=["HEARTBEAT"],
        severity="MEDIUM",
        description=(
            "The HEARTBEAT message advertises system type, autopilot type, "
            "system mode, and armed status. A rogue transmitter can broadcast "
            "spoofed heartbeats claiming to be the GCS or a friendly autopilot, "
            "causing other systems to misattribute command authority."
        ),
        detection_signature=(
            "HEARTBEAT messages received from a system_id that does not "
            "match the expected GCS or autopilot ID; rapid heartbeat source "
            "switching; heartbeat from an unexpected RF direction."
        ),
        mitigation=(
            "Bind HEARTBEAT acceptance to known system_id/component_id pairs. "
            "Correlate heartbeat direction-finding bearings with expected "
            "GCS location. Alert on heartbeat source changes mid-flight."
        ),
        exploit_impact=(
            "Command authority confusion: aircraft may accept commands from "
            "a spoofed GCS heartbeat source instead of the legitimate operator."
        ),
    ),
    "MAV-2022-002": MavlinkVulnerability(
        cve=None,
        title="Command injection via MAV_CMD_LONG injection",
        mavlink_version="both",
        affected_messages=["COMMAND_LONG", "COMMAND_INT"],
        severity="HIGH",
        description=(
            "COMMAND_LONG and COMMAND_INT messages carry arbitrary flight "
            "commands (arm/disarm, mode change, takeoff, land, RTL, do-set-home, "
            "etc.). Without signature validation, any injected command is "
            "executed as if from the legitimate GCS."
        ),
        detection_signature=(
            "COMMAND_LONG/COMMAND_INT received without valid signature; "
            "commands targeting safety-critical modes (ARM, TAKEOFF, RTL) "
            "from non-whitelisted source IDs; command rate anomalies."
        ),
        mitigation=(
            "Require signed COMMAND_LONG/COMMAND_INT. Maintain a command "
            "allow-list per flight phase. Rate-limit safety-critical commands. "
            "Require operator confirmation for arm/takeoff/RTL via separate "
            "out-of-band channel."
        ),
        exploit_impact=(
            "Unauthorized flight control: forced arming, unintended takeoff, "
            "commanded return-to-launch, or mode changes leading to loss of "
            "control."
        ),
    ),
    "MAV-2022-003": MavlinkVulnerability(
        cve=None,
        title="Parameter manipulation via SET_PARAMETER",
        mavlink_version="both",
        affected_messages=["PARAM_SET", "PARAM_REQUEST_LIST", "PARAM_VALUE"],
        severity="HIGH",
        description=(
            "MAVLink PARAM_SET allows changing any autopilot parameter in "
            "flight, including PID gains, failsafe thresholds, geofence "
            "boundaries, and navigation gains. Unauthenticated parameter "
            "changes can destabilize the aircraft or disable safety systems."
        ),
        detection_signature=(
            "PARAM_SET messages received without valid signature; rapid "
            "parameter changes in short time windows; changes to failsafe, "
            "geofence, or navigation-critical parameters."
        ),
        mitigation=(
            "Sign all PARAM_SET messages. Implement parameter change "
            "rate-limiting. Require signed parameter-change acknowledgment. "
            "Log all parameter modifications to the forensic dossier."
        ),
        exploit_impact=(
            "Flight instability or safety-system disablement: modified PID "
            "gains can cause oscillations; disabled geofence permits boundary "
            "violation; changed failsafe behavior prevents automatic RTL."
        ),
    ),
    "MAV-2023-001": MavlinkVulnerability(
        cve=None,
        title="Mission item injection and waypoint hijacking",
        mavlink_version="both",
        affected_messages=["MISSION_ITEM", "MISSION_ITEM_INT", "MISSION_COUNT", "MISSION_SET_CURRENT"],
        severity="HIGH",
        description=(
            "MAVLink mission protocol uploads waypoints and mission items to "
            "the autopilot. Unauthenticated mission injection can replace the "
            "flight plan with attacker-chosen waypoints, causing the aircraft "
            "to fly to unauthorized locations."
        ),
        detection_signature=(
            "MISSION_COUNT/MISSION_ITEM exchange without valid signature; "
            "sudden waypoint count changes; mission items with coordinates "
            "outside the approved operating area; CURRENT mission item "
            "changes mid-flight."
        ),
        mitigation=(
            "Sign all mission protocol messages. Validate waypoint "
            "coordinates against the approved geofence before acceptance. "
            "Require operator confirmation for mission changes. Log all "
            "mission uploads to the forensic dossier."
        ),
        exploit_impact=(
            "Flight-path hijacking: aircraft redirected to attacker-selected "
            "locations, potentially leaving controlled airspace or entering "
            "restricted zones."
        ),
    ),
    "MAV-2023-002": MavlinkVulnerability(
        cve=None,
        title="GPS spoofing via MAVLink telemetry injection",
        mavlink_version="both",
        affected_messages=["GLOBAL_POSITION_INT", "GPS_RAW_INT", "ATTITUDE"],
        severity="HIGH",
        description=(
            "MAVLink telemetry messages carry GPS position, attitude, and "
            "velocity. Injected false telemetry can make the GCS believe the "
            "aircraft is elsewhere, or cause the autopilot (if using MAVLink "
            "position feedback for navigation) to correct toward false "
            "coordinates."
        ),
        detection_signature=(
            "GLOBAL_POSITION_INT/GPS_RAW_INT position jumps inconsistent with "
            "reported velocity; attitude/position divergence; GPS accuracy "
            "degradation coinciding with telemetry anomalies."
        ),
        mitigation=(
            "Cross-validate MAVLink GPS position against independent RF "
            "direction-finding bearings. Use RTK or multi-constellation GPS "
            "with spoofing detection. Correlate position reports with radar "
            "or optical track data where available."
        ),
        exploit_impact=(
            "Situational-deception: GCS loses true aircraft position; "
            "autopilot may fly toward false coordinates if using injected "
            "position as navigation input."
        ),
    ),
    "MAV-2023-003": MavlinkVulnerability(
        cve=None,
        title="Telemetry link flooding / denial of service",
        mavlink_version="both",
        affected_messages=["ALL"],
        severity="MEDIUM",
        description=(
            "MAVLink has no rate limiting or quality-of-service prioritization. "
            "An attacker can flood the telemetry link with spurious messages, "
            "crowding out legitimate GCS commands and autopilot telemetry."
        ),
        detection_signature=(
            "Message rate exceeding baseline by >5x; buffer overflow "
            "indicators; dropped heartbeats; command latency spikes."
        ),
        mitigation=(
            "Implement per-source message rate limiting. Prioritize "
            "HEARTBEAT and COMMAND_LONG over telemetry streaming. Use "
            "separate frequencies for command and telemetry where possible."
        ),
        exploit_impact=(
            "Link denial: legitimate GCS commands cannot reach the aircraft; "
            "telemetry blackout prevents situational awareness."
        ),
    ),
    "MAV-2023-004": MavlinkVulnerability(
        cve=None,
        title="Man-in-the-middle on telemetry radio links",
        mavlink_version="both",
        affected_messages=["ALL"],
        severity="HIGH",
        description=(
            "Common telemetry radios (SiK, Holybro, RFD900) operate in "
            "cleartext with no link-layer authentication. An intermediary "
            "can relay, modify, or drop MAVLink packets between GCS and "
            "aircraft without either party detecting the interception."
        ),
        detection_signature=(
            "Unexpected round-trip time increases on telemetry link; "
            "packet loss correlated with known RF-interference zones; "
            "heartbeat timing anomalies; duplicate packets from multiple "
            "directions."
        ),
        mitigation=(
            "Use MAVLink v2 signing end-to-end. Deploy link-layer encryption "
            "on telemetry radios. Monitor RTT and packet-loss baselines for "
            "anomalies. Use directional antennas to reduce MITM exposure."
        ),
        exploit_impact=(
            "Transparent interception: attacker reads all telemetry, injects "
            "commands, or selectively drops packets to degrade control "
            "without detection."
        ),
    ),
    "MAV-2024-001": MavlinkVulnerability(
        cve=None,
        title="Sequence number replay attack",
        mavlink_version="both",
        affected_messages=["ALL"],
        severity="MEDIUM",
        description=(
            "MAVLink sequence numbers wrap at 255 and are not bound to "
            "timestamps or nonces. An attacker can capture and replay "
            "previously observed valid packets (e.g., a disarm command) "
            "later, potentially re-triggering the same action."
        ),
        detection_signature=(
            "Duplicate sequence numbers from the same source system within "
            "a short time window; out-of-order sequence replays; repeated "
            "command payloads with identical seq numbers."
        ),
        mitigation=(
            "Maintain a recent sequence-number window per source system. "
            "Reject replayed sequence numbers within the window. Combine "
            "with MAVLink v2 signing to bind sequences to authenticated "
            "sessions."
        ),
        exploit_impact=(
            "Command replay: previously captured arm/disarm or mode-change "
            "commands re-executed at attacker-chosen times."
        ),
    ),
    "MAV-2026-001": MavlinkVulnerability(
        cve="CVE-2026-1579",
        title="MAVLink authentication bypass — unauthenticated SERIAL_CONTROL shell access",
        mavlink_version="2.0",
        affected_messages=["SERIAL_CONTROL", "HEARTBEAT", "COMMAND_LONG"],
        severity="CRITICAL",
        description=(
            "MAVLink 2.0 message signing is not mandatory by default. When "
            "signing is disabled, any unauthenticated party with network or "
            "RF access to the MAVLink interface can send arbitrary messages, "
            "including SERIAL_CONTROL which provides interactive shell access "
            "to the flight controller's underlying OS (NuttX shell). Discovered "
            "by Dolev Aviv (Cyviation) and disclosed via CISA ICSA-26-090-02 "
            "on 2026-03-31. CVSS v3.1 score 9.8 (Critical)."
        ),
        detection_signature=(
            "SERIAL_CONTROL message received without valid MAVLink v2 signature; "
            "shell device identifier present in payload; repeated SERIAL_CONTROL "
            "messages from a single source in rapid succession; system_id "
            "brute-forcing (1-255) observed in heartbeat telemetry."
        ),
        mitigation=(
            "Enable MAVLink 2.0 message signing with a pre-shared 32-byte "
            "SECRET_KEY on both vehicle and GCS. Disable SERIAL_CONTROL message "
            "type on production vehicles unless diagnostic shell access is "
            "required. Restrict network access to MAVLink interfaces via "
            "firewall/ACL. Segment drone communication networks from "
            "untrusted networks. Apply PX4 firmware patch enforcing signing "
            "by default."
        ),
        exploit_impact=(
            "Full remote compromise: interactive shell on the flight "
            "controller, parameter modification, waypoint hijacking, motor "
            "kill, firmware replacement, and potential pivot into companion "
            "computer or GCS host."
        ),
    ),
    "MAV-2026-002": MavlinkVulnerability(
        cve="CVE-2026-32743",
        title="PX4 MAVLink buffer overflow via malformed log file path",
        mavlink_version="both",
        affected_messages=["MAVLink FTP / file transfer", "LOG_REQUEST_LIST", "LOG_REQUEST_DATA"],
        severity="HIGH",
        description=(
            "Stack-based buffer overflow in PX4 Autopilot MavlinkLogHandler "
            "component (PX4 v1.17.0-rc2 and below). A malformed directory "
            "path transmitted via MAVLink FTP protocol overflows the stack "
            "buffer, crashing the flight controller. Triggered via UDP port "
            "14540 or telemetry radio with no authentication required."
        ),
        detection_signature=(
            "MAVLink FTP message ID 110 (file transfer) with abnormally long "
            "directory path payload (>50 bytes in data payload section); "
            "rapid sequence of malformed OpenFile commands; flight controller "
            "restart/reboot following telemetry traffic spike."
        ),
        mitigation=(
            "Upgrade PX4 Autopilot to patched version. Implement ground-side "
            "MAVLink routing firewall to drop MAV_CMD_FILE_TRANSFER requests "
            "and unusually long path strings. Transition to encrypted air-links "
            "with hardware-accelerated AES. Enable hardware-level packet "
            "filtering on telemetry radios."
        ),
        exploit_impact=(
            "Denial of service: flight controller crash, loss of aircraft "
            "control, potential mid-air instability."
        ),
    ),
    "MAV-2026-003": MavlinkVulnerability(
        cve="CVE-2026-32724",
        title="PX4 heap use-after-free via MAVLink SERIAL_CONTROL race condition",
        mavlink_version="both",
        affected_messages=["SERIAL_CONTROL", "HEARTBEAT"],
        severity="HIGH",
        description=(
            "Heap use-after-free in PX4 Autopilot MavlinkShell::available() "
            "function. Race condition between MAVLink receiver thread (shell "
            "creation/destruction) and telemetry sender thread (polls shell "
            "for output). Remotely triggerable via crafted SERIAL_CONTROL "
            "messages from an adjacent network. Fixed in PX4 v1.17.0-rc1."
        ),
        detection_signature=(
            "Rapid SERIAL_CONTROL message sequences triggering shell creation "
            "and destruction; telemetry sender thread accessing freed shell "
            "object; unexpected flight controller restart or instability "
            "correlated with telemetry traffic."
        ),
        mitigation=(
            "Upgrade PX4 Autopilot to v1.17.0-rc1 or later. Disable MAVLink "
            "shell functionality if not required. Implement message filtering "
            "to limit SERIAL_CONTROL rates. Segment drone telemetry networks "
            "from untrusted networks."
        ),
        exploit_impact=(
            "Denial of service: heap corruption, drone instability, loss of "
            "control during flight operations."
        ),
    ),
    "MAV-2024-002": MavlinkVulnerability(
        cve="CVE-2024-33844",
        title="Parrot ANAFI USA MAV_MISSION_TYPE validation bypass",
        mavlink_version="both",
        affected_messages=["MISSION_COUNT", "MISSION_ITEM", "MISSION_SET_CURRENT"],
        severity="HIGH",
        description=(
            "Parrot ANAFI USA firmware 1.10.4 does not validate MAV_MISSION_TYPE "
            "(0, 1, 2, 255) in the control component. An attacker can send a "
            "MISSION_COUNT command with an invalid MAV_MISSION_TYPE to cut off "
            "the connection between controller and drone."
        ),
        detection_signature=(
            "MISSION_COUNT message received with unexpected/invalid MAV_MISSION_TYPE "
            "field value; sudden controller-drone connection loss following "
            "mission protocol exchange; repeated invalid mission upload "
            "attempts from single source."
        ),
        mitigation=(
            "Validate MAV_MISSION_TYPE field against allowed values (0, 1, 2, "
            "255) before processing mission protocol messages. Reject mission "
            "uploads with invalid type fields. Maintain mission protocol state "
            "machine and reject out-of-sequence messages."
        ),
        exploit_impact=(
            "Denial of service: controller-drone connection severed, mission "
            "interruption, potential loss of situational awareness during "
            "flight operations."
        ),
    ),
    "MAV-2020-002": MavlinkVulnerability(
        cve="CVE-2020-10282",
        title="MAVLink 1.0 no authentication mechanism — identity spoofing and unauthorized access",
        mavlink_version="1.0",
        affected_messages=["ALL"],
        severity="CRITICAL",
        description=(
            "MAVLink protocol version 1.0 presents no authentication mechanism "
            "nor authorization, leading to identity spoofing, unauthorized "
            "access, and person-in-the-middle attacks. Version 2.0 optionally "
            "allows package signing but is not mandatory. Reported by Alias "
            "Robotics S.L.; CVSS v3.1 score 9.8 (Critical)."
        ),
        detection_signature=(
            "MAVLink v1 packet format (magic byte 0xFE) detected on any link; "
            "no signing/compatibility flags present; messages accepted from "
            "unauthenticated source systems; no identity verification performed."
        ),
        mitigation=(
            "Migrate all telemetry links to MAVLink v2 with signing enabled. "
            "Wrap MAVLink 1.0 legacy links in encrypted tunnels (TLS/IPSec). "
            "Implement link-layer authentication on telemetry radios. Do not "
            "use MAVLink 1.0 over any RF path exposed to adversarial RF."
        ),
        exploit_impact=(
            "Complete link compromise: identity spoofing, unauthorized access, "
            "person-in-the-middle attacks, eavesdropping, injection, and replay "
            "of all telemetry and command traffic."
        ),
    ),
    "MAV-2023-005": MavlinkVulnerability(
        cve=None,
        title="MAVLink covert channel — covert information leakage via protocol fields",
        mavlink_version="both",
        affected_messages=["ALL"],
        severity="MEDIUM",
        description=(
            "MAVLink's lack of security mechanisms, default broadcast messages, "
            "and redundant protocol fields enable covert channels for secret "
            "information exfiltration from drones to nearby adversaries within "
            "transmission range. Published research (ASIA CCS 2024) demonstrates "
            "high-throughput covert data exfiltration through MAVLink protocol "
            "abuse in the presence of an active warden at the GCS."
        ),
        detection_signature=(
            "Unusual pattern of benign MAVLink messages carrying anomalous "
            "payload fields; heartbeat or telemetry messages with subtly "
            "modified reserved fields; unexpected data volume on telemetry "
            "link during idle periods."
        ),
        mitigation=(
            "Sanitize reserved/unused fields in MAVLink messages before "
            "transmission. Implement message field allow-listing. Monitor "
            "telemetry link for anomalous data volume patterns. Use encrypted "
            "air-links to prevent covert channel exploitation."
        ),
        exploit_impact=(
            "Information leakage: sensitive drone data (position, mission "
            "details, sensor readings) exfiltrated covertly through protocol "
            "fields to nearby adversaries."
        ),
    ),
}


class MavlinkVulnerabilityDatabase:
    """In-memory database of MAVLink vulnerabilities with lookup helpers."""

    def __init__(self) -> None:
        self._by_id: Dict[str, MavlinkVulnerability] = MAVLINK_VULNERABILITIES
        self._by_cve: Dict[str, MavlinkVulnerability] = {}
        for vuln in self._by_id.values():
            if vuln.cve:
                self._by_cve[vuln.cve] = vuln

    def get(self, vuln_id: str) -> Optional[MavlinkVulnerability]:
        return self._by_id.get(vuln_id)

    def get_by_cve(self, cve: str) -> Optional[MavlinkVulnerability]:
        return self._by_cve.get(cve)

    def list_all(self) -> List[MavlinkVulnerability]:
        return list(self._by_id.values())

    def list_by_version(self, version: str) -> List[MavlinkVulnerability]:
        return [v for v in self._by_id.values() if v.mavlink_version in (version, "both")]

    def list_by_severity(self, severity: str) -> List[MavlinkVulnerability]:
        return [v for v in self._by_id.values() if v.severity == severity]

    def summary(self) -> Dict[str, object]:
        total = len(self._by_id)
        by_sev: Dict[str, int] = {}
        for v in self._by_id.values():
            by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
        return {"total": total, "by_severity": by_sev}

    def detect_signatures_in_packet(
        self,
        message_name: str,
        system_id: int,
        component_id: int,
        has_valid_signature: bool,
        seq: int,
        prev_seqs: List[int],
    ) -> List[str]:
        """Return vulnerability IDs whose detection signatures match a packet."""
        hits: List[str] = []
        for vid, vuln in self._by_id.items():
            if message_name in vuln.affected_messages or "ALL" in vuln.affected_messages:
                if "signature" in vuln.detection_signature.lower() and not has_valid_signature:
                    hits.append(vid)
                if "sequence" in vuln.detection_signature.lower() and seq in prev_seqs:
                    hits.append(vid)
                if "system_id" in vuln.detection_signature.lower():
                    # Generic heartbeat/system-ID anomaly indicator
                    hits.append(vid)
        return hits
