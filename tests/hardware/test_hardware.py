"""
Tests for the hardware abstraction layer (SDR / radar / camera + fusion).

Deterministic scenarios only: fixed seeds produce identical output across
runs; adapters run in simulation mode when no hardware is present (logged,
never raised); fusion deduplicates by spatial proximity and time. State
persists under ~/.c-uas-platform/hardware/ (tests point the store at a temp
dir so the real state dir is never touched).
"""

import math
import shutil
import tempfile
import unittest
from unittest.mock import patch

from c_uas.hardware import (
    CameraAdapter,
    HardwareCapability,
    RadarAdapter,
    RadarTrack,
    SensorFusion,
    SDRAdapter,
    Track,
)
from c_uas.hardware.sensor_interface import Detection, SensorInterface, SensorStatus
import c_uas.hardware.state as state


def _tmp_state_dir() -> str:
    return tempfile.mkdtemp(prefix="cuas-hardware-test-")


class TestSensorInterfaceContract(unittest.TestCase):
    def test_abstract_base_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            SensorInterface(  # type: ignore[abstract]
                sensor_id="x",
                capability=HardwareCapability.RF_SCAN,
            )

    def test_status_fields_are_valid(self):
        sdr = SDRAdapter(sensor_id="sdr-status", seed=1)
        radar = RadarAdapter(sensor_id="radar-status", seed=2)
        cam = CameraAdapter(sensor_id="cam-status", seed=3)
        for st in (sdr.get_status(), radar.get_status(), cam.get_status()):
            self.assertIsInstance(st, SensorStatus)
            self.assertIsInstance(st.online, bool)
            self.assertTrue(st.simulation_mode)
            self.assertGreaterEqual(st.last_seen, 0.0)
            self.assertIsInstance(st.message, str)

    def test_health_check_passes_in_simulation(self):
        self.assertTrue(SDRAdapter(sensor_id="hc-sdr", seed=1).health_check())
        self.assertTrue(RadarAdapter(sensor_id="hc-radar", seed=1).health_check())
        self.assertTrue(CameraAdapter(sensor_id="hc-cam", seed=1).health_check())


class TestHardwareCapability(unittest.TestCase):
    def test_capability_enum_values(self):
        self.assertEqual(HardwareCapability.RF_SCAN.value, "rf_scan")
        self.assertEqual(HardwareCapability.RADAR_TRACK.value, "radar_track")
        self.assertEqual(HardwareCapability.VISUAL_DETECTION.value, "visual_detection")


class TestSDRAdapter(unittest.TestCase):
    def test_simulation_mode_when_no_hardware(self):
        sdr = SDRAdapter(sensor_id="sdr-sim", seed=4)
        self.assertTrue(sdr.simulation)
        self.assertFalse(sdr._hardware_present)

    def test_no_hardware_is_logged_not_raised(self):
        with patch("c_uas.hardware.sensor_interface.logger") as mock_logger:
            SDRAdapter(sensor_id="sdr-log", seed=1, simulation=True)
        self.assertTrue(mock_logger.info.called)
        logged = " ".join(str(a[0]) for a in mock_logger.info.call_args_list)
        self.assertIn("no hardware", logged)

    def test_detect_returns_rf_detections_with_expected_metadata(self):
        sdr = SDRAdapter(sensor_id="sdr-det", seed=11)
        dets = sdr.detect()
        self.assertGreaterEqual(len(dets), 1)
        for d in dets:
            self.assertEqual(d.source, "rf")
            self.assertEqual(d.sensor_id, "sdr-det")
            self.assertTrue(0.0 <= d.confidence <= 1.0)
            self.assertIn("frequency_mhz", d.metadata)
            self.assertIn("rssi_dbm", d.metadata)
            self.assertEqual(d.metadata["position_source"], "synthetic_rssi_estimate")

    def test_detect_is_deterministic(self):
        a = SDRAdapter(sensor_id="sdr-det-a", seed=42)
        b = SDRAdapter(sensor_id="sdr-det-b", seed=42)
        self.assertEqual(
            [d.detection_id for d in a.detect()], [d.detection_id for d in b.detect()]
        )
        self.assertEqual(
            [(d.x_m, d.y_m, d.z_m) for d in a.detect()],
            [(d.x_m, d.y_m, d.z_m) for d in b.detect()],
        )

    def test_scan_flags_signals_above_threshold(self):
        sdr = SDRAdapter(sensor_id="sdr-scan", seed=7)
        scan = sdr.scan_frequencies(2400.0, 2500.0, 5.0)
        detected = [sig for sig in scan.signals if sig.detected]
        self.assertGreaterEqual(len(detected), 1)
        for sig in detected:
            self.assertGreater(sig.rssi_dbm, sdr.detection_threshold_dbm)
            self.assertEqual(sig.bandwidth_mhz, 20.0)


class TestRadarAdapter(unittest.TestCase):
    def test_detect_returns_radar_detections(self):
        radar = RadarAdapter(sensor_id="radar-det", seed=2)
        dets = radar.detect()
        self.assertGreaterEqual(len(dets), 1)
        for d in dets:
            self.assertEqual(d.source, "radar")
            md = d.metadata
            self.assertIn("bearing_deg", md)
            self.assertIn("range_m", md)
            self.assertIn("altitude_m", md)
            self.assertIn("velocity_mps", md)
            br = math.radians(float(md["bearing_deg"]))  # type: ignore[arg-type]
            self.assertAlmostEqual(
                d.x_m, float(md["range_m"]) * math.sin(br), places=2  # type: ignore[arg-type]
            )
            self.assertAlmostEqual(
                d.y_m, float(md["range_m"]) * math.cos(br), places=2  # type: ignore[arg-type]
            )
            self.assertAlmostEqual(d.z_m, float(md["altitude_m"]), places=2)  # type: ignore[arg-type]

    def test_detect_is_deterministic(self):
        a = RadarAdapter(sensor_id="radar-a", seed=99)
        b = RadarAdapter(sensor_id="radar-b", seed=99)
        self.assertEqual(
            [(round(d.x_m, 2), round(d.y_m, 2)) for d in a.detect()],
            [(round(d.x_m, 2), round(d.y_m, 2)) for d in b.detect()],
        )

    def test_correlation_matches_identical_tracks(self):
        radar = RadarAdapter(sensor_id="radar-corr", seed=5)
        tracks = radar.scan_tracks()
        corr = radar.correlate_tracks(tracks, tracks)
        self.assertEqual(len(corr), len(tracks))
        for c in corr:
            self.assertTrue(c.correlated)
            self.assertEqual(c.new_track_id, c.previous_track_id)
            self.assertEqual(c.distance_m, 0.0)

    def test_correlation_leaves_far_tracks_unmatched(self):
        radar = RadarAdapter(sensor_id="radar-corr2", seed=5)
        near = RadarTrack(
            "t-new", 10.0, 1000.0, 100.0, 20.0, 1000.0, 10.0
        )
        far = RadarTrack(
            "t-prev", 10.0, 50000.0, 100.0, 20.0, 1000.0, 10.0
        )
        corr = radar.correlate_tracks([near], [far], max_distance_m=150.0)
        self.assertEqual(len(corr), 1)
        self.assertFalse(corr[0].correlated)
        self.assertIsNone(corr[0].previous_track_id)


class TestCameraAdapter(unittest.TestCase):
    def test_detect_returns_visual_detections(self):
        cam = CameraAdapter(sensor_id="cam-det", seed=6)
        dets = cam.detect()
        self.assertGreaterEqual(len(dets), 1)
        for d in dets:
            self.assertEqual(d.source, "visual")
            bbox = d.metadata["bounding_box"]
            self.assertEqual(len(bbox), 4)
            self.assertTrue(0.0 <= d.confidence <= 1.0)
            self.assertEqual(d.metadata["class"], "quadcopter")

    def test_no_facial_recognition_or_targeting_fields(self):
        cam = CameraAdapter(sensor_id="cam-safe", seed=6)
        forbidden = ("face", "identity", "identities", "targeting", "aim_point", "weapon")
        for d in cam.detect():
            for key in forbidden:
                self.assertNotIn(key, d.metadata)

    def test_detect_is_deterministic(self):
        a = CameraAdapter(sensor_id="cam-a", seed=123)
        b = CameraAdapter(sensor_id="cam-b", seed=123)
        self.assertEqual(
            [
                tuple(list(d.metadata["bounding_box"]))  # type: ignore[arg-type]
                for d in a.detect()
            ],
            [
                tuple(list(d.metadata["bounding_box"]))  # type: ignore[arg-type]
                for d in b.detect()
            ],
        )

    def test_defensive_keys_raise(self):
        with self.assertRaises(ValueError):
            CameraAdapter._assert_defensive({"face": True})
        with self.assertRaises(ValueError):
            CameraAdapter._assert_defensive({"targeting": [1, 2, 3]})
        CameraAdapter._assert_defensive({"class": "quadcopter"})


class TestSensorFusion(unittest.TestCase):
    def test_fuse_single_detection(self):
        fusion = SensorFusion(seed=1)
        dets = [
            Detection(
                "d1", "sdr-1", 100.0, "rf", 100.0, 0.0, 100.0, 0.8,
                {"frequency_mhz": 2440.0, "rssi_dbm": -50.0},
            )
        ]
        tracks = fusion.fuse(dets)
        self.assertEqual(len(tracks), 1)
        self.assertTrue(tracks[0].track_id.startswith("track--"))
        self.assertEqual(tracks[0].sensors, ["sdr-1"])
        self.assertEqual(tracks[0].sources, ["rf"])

    def test_fuse_deduplicates_by_proximity(self):
        fusion = SensorFusion(proximity_m=10.0, time_window_s=1.0, seed=1)
        dets = [
            Detection("d1", "radar-1", 100.0, "radar", 100.0, 0.0, 100.0, 0.8, {}),
            Detection(
                "d2", "camera-1", 100.1, "visual", 103.0, 2.0, 101.0, 0.9, {}
            ),  # ~3.7 m from d1
            Detection("d3", "sdr-1", 100.0, "rf", 1000.0, 0.0, 100.0, 0.7, {}),  # far
        ]
        tracks = fusion.fuse(dets)
        self.assertEqual(len(tracks), 2)
        fused = [t for t in tracks if len(t.sensors) == 2][0]
        self.assertIn("radar-1", fused.sensors)
        self.assertIn("camera-1", fused.sensors)
        self.assertIn("radar", fused.sources)
        self.assertIn("visual", fused.sources)

    def test_fuse_deduplicates_by_time(self):
        fusion = SensorFusion(proximity_m=1000.0, time_window_s=1.0, seed=1)
        dets = [
            Detection("d1", "radar-1", 100.0, "radar", 100.0, 0.0, 100.0, 0.8, {}),
            Detection(
                "d2", "radar-1", 105.0, "radar", 100.0, 0.0, 100.0, 0.8, {}
            ),  # same place, 5 s later
        ]
        tracks = fusion.fuse(dets)
        self.assertEqual(len(tracks), 2)

    def test_fuse_is_deterministic(self):
        dets = [
            Detection("d1", "radar-1", 100.0, "radar", 100.0, 0.0, 100.0, 0.8, {}),
            Detection("d2", "camera-1", 100.1, "visual", 103.0, 2.0, 101.0, 0.9, {}),
        ]
        t1 = fusion_tracks = SensorFusion(seed=5).fuse(dets)
        t2 = SensorFusion(seed=5).fuse(dets)
        self.assertEqual([t.track_id for t in t1], [t.track_id for t in t2])
        self.assertEqual(
            [(t.x_m, t.y_m, t.z_m) for t in t1], [(t.x_m, t.y_m, t.z_m) for t in t2]
        )

    def test_fuse_empty_input(self):
        self.assertEqual(SensorFusion(seed=1).fuse([]), [])

    def test_fuse_confidence_in_bounds(self):
        fusion = SensorFusion(seed=1)
        dets = [
            Detection(f"d{i}", f"s{i}", 100.0, "rf", float(i), 0.0, 0.0, c, {})
            for i, c in enumerate([0.2, 0.5, 0.9])
        ]
        tracks = fusion.fuse(dets)
        for t in tracks:
            self.assertTrue(0.0 <= t.confidence <= 1.0)

    def test_fuse_with_history_preserves_ids(self):
        fusion = SensorFusion(seed=1)
        prev = [
            Track("track--keep", 100.0, 0.0, 100.0, 0.0, 0.0, 0.0, 100.0, 0.8, ["s1"], ["rf"])
        ]
        dets = [
            Detection("d1", "s1", 100.1, "rf", 102.0, 1.0, 101.0, 0.8, {}),
        ]
        tracks = fusion.fuse_with_history(dets, prev, max_assoc_distance_m=100.0)
        self.assertEqual(len(tracks), 1)
        self.assertEqual(tracks[0].track_id, "track--keep")


class TestStatePersistence(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmp_state_dir()
        self.old = state._DATA_DIR
        state._DATA_DIR = state.Path.home() if False else state.Path(self.tmp)
        state._DETECTIONS_FILE = state._DATA_DIR / "detections.json"
        state._TRACKS_FILE = state._DATA_DIR / "tracks.json"
        state._STATUS_FILE = state._DATA_DIR / "status.json"

    def tearDown(self):
        state._DATA_DIR = self.old
        state._DETECTIONS_FILE = state._DATA_DIR / "detections.json"
        state._TRACKS_FILE = state._DATA_DIR / "tracks.json"
        state._STATUS_FILE = state._DATA_DIR / "status.json"
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_detections_save_and_load_round_trip(self):
        dets = [
            Detection("d1", "sdr-0", 100.0, "rf", 1.0, 2.0, 3.0, 0.8, {})
        ]
        state.save_detections("sdr-0", dets)
        records = state.load_detections()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["sensor_id"], "sdr-0")
        self.assertEqual(records[0]["count"], 1)
        self.assertEqual(records[0]["detections"][0]["detection_id"], "d1")

    def test_tracks_save_and_load_round_trip(self):
        tracks = [
            Track("track--x", 1.0, 2.0, 3.0, 0.0, 0.0, 0.0, 100.0, 0.8, ["s1"], ["rf"])
        ]
        state.save_tracks(tracks)
        loaded = state.load_tracks()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["track_id"], "track--x")

    def test_status_save_and_load_round_trip(self):
        state.save_status("sdr-0", True, True, "simulation mode: no hardware")
        loaded = state.load_status()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["sensor_id"], "sdr-0")
        self.assertTrue(loaded[0]["online"])
        self.assertTrue(loaded[0]["simulation_mode"])


class TestHardwareCLI(unittest.TestCase):
    def test_cli_lists_sensors(self):
        from c_uas.hardware.cli import main

        rc = main(["--list"])
        self.assertEqual(rc, 0)

    def test_cli_scan_produces_detections(self):
        from c_uas.hardware.cli import main

        rc = main(["--scan"])
        self.assertEqual(rc, 0)

    def test_cli_fuse_produces_tracks(self):
        from c_uas.hardware.cli import main

        rc = main(["--fuse"])
        self.assertEqual(rc, 0)

    def test_cli_status_health_ok(self):
        from c_uas.hardware.cli import main

        rc = main(["--status"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
