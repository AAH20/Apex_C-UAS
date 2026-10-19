"""Tests for agentic decision loop modules."""

import unittest
from c_uas.decision.perception import PerceptionModule
from c_uas.decision.decision_engine import (
    DecisionModule,
    ThreatLevel,
    ResponseStrategy,
)
from c_uas.decision.action_module import ActionModule, SystemCommand


class TestPerceptionModule(unittest.TestCase):
    def test_update_and_summary(self):
        p = PerceptionModule()
        p.update_rf([{"freq": 2450.0, "power": -55}])
        p.update_df([{"bearing": 45.0, "confidence": 0.8}])
        p.update_classification([{"class": "DJI_Mavic", "confidence": 0.9}])
        summary = p.get_situation_summary()
        self.assertEqual(summary["num_rf_detections"], 1)
        self.assertEqual(summary["num_df_results"], 1)
        self.assertEqual(summary["num_drones_classified"], 1)
        self.assertIn("timestamp", summary)


class TestDecisionModule(unittest.TestCase):
    def test_threat_level_none(self):
        dm = DecisionModule({})
        # Create a mock swarm state with 0 drones
        class SwarmState:
            num_drones = 0
            controller_location = None
        threat = dm.assess_threat(SwarmState())
        self.assertEqual(threat, ThreatLevel.NONE)

    def test_threat_level_critical(self):
        dm = DecisionModule({})
        class SwarmState:
            num_drones = 25
            controller_location = None
        threat = dm.assess_threat(SwarmState())
        self.assertEqual(threat, ThreatLevel.CRITICAL)

    def test_select_strategy_monitor(self):
        dm = DecisionModule({})
        strategy = dm.select_strategy(ThreatLevel.NONE, None)
        self.assertEqual(strategy, ResponseStrategy.MONITOR)

    def test_select_strategy_full_countermeasure(self):
        dm = DecisionModule({})
        strategy = dm.select_strategy(ThreatLevel.CRITICAL, None)
        self.assertEqual(strategy, ResponseStrategy.FULL_COUNTERMEASURE)

    def test_plan_actions_monitor(self):
        dm = DecisionModule({})
        actions = dm.plan_actions(ResponseStrategy.MONITOR, None)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].action, "scan_rf")

    def test_plan_actions_full_countermeasure(self):
        dm = DecisionModule({})
        actions = dm.plan_actions(ResponseStrategy.FULL_COUNTERMEASURE, None)
        self.assertGreaterEqual(len(actions), 2)
        jam_actions = [a for a in actions if a.action == "activate_jammer"]
        self.assertGreaterEqual(len(jam_actions), 1)


class TestActionModule(unittest.TestCase):
    def test_execute_scan_rf_simulation(self):
        am = ActionModule({}, simulation_mode=True)
        import asyncio
        result = asyncio.run(am.execute(SystemCommand(
            action="scan_rf", params={"duration_s": 1.0},
            timestamp=0.0, priority=1
        )))
        self.assertEqual(result["status"], "executed")

    def test_execute_jammer_denied_when_unauthorized(self):
        am = ActionModule({"jamming": {"authorized": False}}, simulation_mode=True)
        import asyncio
        result = asyncio.run(am.execute(SystemCommand(
            action="activate_jammer",
            params={"bands": [2.44e9], "power_dBm": 20},
            timestamp=0.0, priority=3
        )))
        self.assertEqual(result["status"], "denied")
        self.assertIn("reason", result["details"])

    def test_system_command_creation(self):
        cmd = SystemCommand(
            action="direction_find",
            params={"frequency": 2.44e9},
            timestamp=1234567890.0,
            priority=2,
        )
        self.assertEqual(cmd.action, "direction_find")
        self.assertEqual(cmd.params["frequency"], 2.44e9)
        self.assertEqual(cmd.priority, 2)


if __name__ == "__main__":
    unittest.main()
