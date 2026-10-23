"""Tests for the ISO 42001 AI Governance chassis."""

import unittest
from c_uas.governance import (
    AISystem,
    AISystemRegistry,
    AuditEvidenceChain,
    ComplianceReporter,
    ControlImplementation,
    EvidenceEntry,
    Incident,
    IncidentManager,
    Risk,
    RiskAssessment,
    _compute_risk_level,
    _hash_entry,
)


class TestRiskScoring(unittest.TestCase):
    def test_low_low_is_low(self):
        self.assertEqual(_compute_risk_level("low", "low"), "low")

    def test_high_high_is_critical(self):
        self.assertEqual(_compute_risk_level("high", "high"), "critical")

    def test_medium_medium_is_medium(self):
        self.assertEqual(_compute_risk_level("medium", "medium"), "medium")

    def test_high_low_is_medium(self):
        self.assertEqual(_compute_risk_level("high", "low"), "medium")

    def test_hash_entry_deterministic(self):
        h1 = _hash_entry("prev", {"a": 1})
        h2 = _hash_entry("prev", {"a": 1})
        self.assertEqual(h1, h2)

    def test_hash_entry_changes_with_payload(self):
        h1 = _hash_entry("prev", {"a": 1})
        h2 = _hash_entry("prev", {"a": 2})
        self.assertNotEqual(h1, h2)


class TestAISystemRegistry(unittest.TestCase):
    def test_register_and_get(self):
        reg = AISystemRegistry()
        # Clear any existing for clean test
        reg._systems.clear()
        sid = reg.register("EKF Tracking", "c_uas.tracking.ekf_interceptor", "operation", "medium")
        sys = reg.get(sid)
        self.assertIsNotNone(sys)
        self.assertEqual(sys.name, "EKF Tracking")
        self.assertEqual(sys.module_path, "c_uas.tracking.ekf_interceptor")
        self.assertEqual(sys.lifecycle_stage, "operation")
        self.assertEqual(sys.risk_level, "medium")

    def test_list_all(self):
        reg = AISystemRegistry()
        reg._systems.clear()
        reg.register("Sys A", "mod.a", "development", "low")
        reg.register("Sys B", "mod.b", "operation", "high")
        self.assertEqual(len(reg.list_all()), 2)

    def test_list_by_risk(self):
        reg = AISystemRegistry()
        reg._systems.clear()
        reg.register("Low", "mod.a", "development", "low")
        reg.register("High", "mod.b", "operation", "high")
        high = reg.list_by_risk("high")
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0].name, "High")

    def test_update_risk_level(self):
        reg = AISystemRegistry()
        reg._systems.clear()
        sid = reg.register("Sys", "mod", "development", "low")
        self.assertTrue(reg.update_risk_level(sid, "critical"))
        self.assertEqual(reg.get(sid).risk_level, "critical")
        self.assertFalse(reg.update_risk_level("nonexistent", "high"))


class TestRiskAssessment(unittest.TestCase):
    def test_assess_and_get(self):
        assessor = RiskAssessment()
        assessor._risks.clear()
        risk = assessor.assess("sys-1", "EKF drift", "high", "high", "mitigate", "Add input validation")
        self.assertIsNotNone(risk)
        self.assertEqual(risk.risk_level, "critical")
        self.assertEqual(risk.status, "open")

        fetched = assessor.get(risk.risk_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.risk_id, risk.risk_id)

    def test_list_open(self):
        assessor = RiskAssessment()
        assessor._risks.clear()
        assessor.assess("sys-1", "Risk A", "low", "low")
        assessor.assess("sys-2", "Risk B", "high", "high")
        open_risks = assessor.list_open()
        self.assertEqual(len(open_risks), 2)

    def test_close_risk(self):
        assessor = RiskAssessment()
        assessor._risks.clear()
        risk = assessor.assess("sys-1", "Risk A", "low", "low")
        self.assertTrue(assessor.close_risk(risk.risk_id))
        self.assertEqual(assessor.get(risk.risk_id).status, "closed")
        self.assertIsNotNone(assessor.get(risk.risk_id).closed_at)
        self.assertFalse(assessor.close_risk("nonexistent"))


class TestControlImplementation(unittest.TestCase):
    def test_default_controls_seeded(self):
        ctrl = ControlImplementation()
        ctrl._controls.clear()
        # Re-init to seed defaults
        ctrl2 = ControlImplementation()
        ids = {c.control_id for c in ctrl2.list_all()}
        self.assertIn("A.8.2", ids)
        self.assertIn("A.10.1", ids)
        self.assertGreaterEqual(len(ids), 10)

    def test_implement_control(self):
        ctrl = ControlImplementation()
        ctrl._controls.clear()
        ctrl2 = ControlImplementation()
        updated = ctrl2.implement("A.8.2", "ev-1234")
        self.assertIsNotNone(updated)
        self.assertTrue(updated.implemented)
        self.assertEqual(updated.implementation_evidence, "ev-1234")

    def test_list_implemented(self):
        ctrl = ControlImplementation()
        ctrl._controls.clear()
        ctrl2 = ControlImplementation()
        ctrl2.implement("A.8.2", "ev-1")
        implemented = ctrl2.list_implemented()
        self.assertEqual(len(implemented), 1)
        self.assertEqual(implemented[0].control_id, "A.8.2")

    def test_mark_not_applicable(self):
        ctrl = ControlImplementation()
        ctrl._controls.clear()
        ctrl2 = ControlImplementation()
        updated = ctrl2.mark_not_applicable("A.11.1")
        self.assertIsNotNone(updated)
        self.assertFalse(updated.applicable)


class TestAuditEvidenceChain(unittest.TestCase):
    def test_log_and_verify(self):
        chain = AuditEvidenceChain()
        chain._entries.clear()
        entry = chain.log("risk_assessment", {"risk_id": "risk-1"}, "sys-1")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.event_type, "risk_assessment")
        self.assertEqual(entry.system_id, "sys-1")
        self.assertNotEqual(entry.prev_hash, entry.entry_hash)

        # Verify chain integrity
        self.assertTrue(chain.verify_chain())

    def test_chain_tamper_detected(self):
        chain = AuditEvidenceChain()
        chain._entries.clear()
        chain.log("event_a", {"x": 1})
        chain.log("event_b", {"x": 2})
        # Tamper with the first entry's payload
        first = chain._entries[0]
        tampered = EvidenceEntry(
            entry_id=first.entry_id,
            timestamp=first.timestamp,
            event_type=first.event_type,
            system_id=first.system_id,
            payload={"x": 999},  # changed
            prev_hash=first.prev_hash,
            entry_hash=first.entry_hash,
        )
        chain._entries[0] = tampered
        self.assertFalse(chain.verify_chain())

    def test_genesis_hash(self):
        chain = AuditEvidenceChain()
        chain._entries.clear()
        entry = chain.log("first", {"x": 1})
        self.assertEqual(entry.prev_hash, "0" * 64)


class TestIncidentManager(unittest.TestCase):
    def test_record_and_resolve(self):
        mgr = IncidentManager()
        mgr._incidents.clear()
        inc = mgr.record("EKF Drift", "Intercept off by 3m", "medium", "sys-1")
        self.assertIsNotNone(inc)
        self.assertEqual(inc.severity, "medium")
        self.assertEqual(inc.status, "open")

        self.assertTrue(mgr.resolve(inc.incident_id, "Recalibrated EKF gains"))
        resolved = mgr.get(inc.incident_id)
        self.assertEqual(resolved.status, "resolved")
        self.assertEqual(resolved.resolution, "Recalibrated EKF gains")
        self.assertIsNotNone(resolved.resolved_at)

    def test_list_open(self):
        mgr = IncidentManager()
        mgr._incidents.clear()
        mgr.record("Inc A", "desc A", "low")
        mgr.record("Inc B", "desc B", "critical")
        open_incs = mgr.list_open()
        self.assertEqual(len(open_incs), 2)


class TestComplianceReporter(unittest.TestCase):
    def test_generate_report(self):
        reg = AISystemRegistry()
        reg._systems.clear()
        reg.register("Sys A", "mod.a", "operation", "medium")
        reg.register("Sys B", "mod.b", "development", "low")

        assessor = RiskAssessment()
        assessor._risks.clear()
        assessor.assess("sys-1", "Risk A", "high", "high")

        controller = ControlImplementation()
        controller._controls.clear()
        ctrl2 = ControlImplementation()
        ctrl2.implement("A.8.2", "ev-1")

        chain = AuditEvidenceChain()
        chain._entries.clear()
        chain.log("risk_assessment", {"risk": "r1"}, "sys-1")

        mgr = IncidentManager()
        mgr._incidents.clear()
        mgr.record("Inc A", "desc", "low")

        reporter = ComplianceReporter(reg, assessor, ctrl2, chain, mgr)
        report = reporter.generate()

        self.assertEqual(report.total_ai_systems, 2)
        self.assertEqual(report.total_risks, 1)
        self.assertEqual(report.open_risks, 1)
        self.assertGreaterEqual(report.implemented_controls, 1)
        self.assertGreaterEqual(report.compliance_percentage, 0.0)
        self.assertIn(report.overall_status, ["compliant", "partial", "non_compliant"])


if __name__ == "__main__":
    unittest.main()
