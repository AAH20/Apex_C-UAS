"""Tests for the C-UAS SOC dashboard static file server."""

import unittest
from http.client import HTTPConnection

from c_uas.dashboard import DASHBOARD_DIR, dashboard_dir
from c_uas.dashboard.server import serve_dashboard


class TestDashboardFiles(unittest.TestCase):
    def test_dashboard_directory_exists(self):
        self.assertTrue(DASHBOARD_DIR.is_dir())
        self.assertEqual(dashboard_dir(), DASHBOARD_DIR)

    def test_index_html_exists(self):
        self.assertTrue((DASHBOARD_DIR / "index.html").exists())

    def test_assets_exist(self):
        for name in ("app.js", "style.css", "vendor/chart.js"):
            self.assertTrue((DASHBOARD_DIR / name).exists(), f"missing asset {name}")


class TestDashboardServer(unittest.TestCase):
    def setUp(self):
        self.server = serve_dashboard("127.0.0.1", 0)  # port 0: ephemeral
        self.port = self.server.server_address[1]
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

    def test_serve_index_html(self):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/index.html")
            resp = conn.getresponse()
            body = resp.read()
        finally:
            conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn(b"C-UAS Platform", body)
        self.assertIn(b"Drone tracks", body)
        self.assertIn(b"Engagement schedule", body)
        self.assertIn(b"Swarm saturation", body)
        self.assertIn(b"Governance compliance", body)
        self.assertIn(b"DEW beam", body)

    def test_serve_app_js(self):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/app.js")
            resp = conn.getresponse()
            body = resp.read()
        finally:
            conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn(b"/dew/model", body)
        self.assertIn(b"/swarm/simulate", body)
        self.assertIn(b"/engagement/schedule", body)
        self.assertIn(b"/compliance", body)
        self.assertIn(b"/benchmarks", body)

    def test_no_cache_headers(self):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/index.html")
            resp = conn.getresponse()
            resp.read()
        finally:
            conn.close()
        self.assertEqual(resp.getheader("Cache-Control"), "no-cache, no-store, must-revalidate")

    def test_missing_file_404(self):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/does-not-exist.html")
            resp = conn.getresponse()
            resp.read()
        finally:
            conn.close()
        self.assertEqual(resp.status, 404)
