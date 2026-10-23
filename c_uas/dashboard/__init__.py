"""
C-UAS Platform SOC Dashboard.

Static frontend (HTML/JS/CSS, no build step) that connects to the FastAPI
REST API at http://127.0.0.1:8000 and visualizes drone tracks, engagement
schedules, swarm saturation, governance compliance, and DEW beam modeling
in real time via polling.

Serving is stdlib-only (http.server) so the dashboard has no extra
Python dependencies beyond the platform itself.
"""

from __future__ import annotations

from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parent


def dashboard_dir() -> Path:
    """Return the directory containing the static dashboard files."""
    return DASHBOARD_DIR
