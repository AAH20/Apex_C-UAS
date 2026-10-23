"""
Serve the C-UAS SOC dashboard static files.

Uses only the Python standard library (http.server) so there is no build
step and no extra dependency. Intended for `c-uas dashboard`, which binds
http://127.0.0.1:8080 by default and opens the browser.
"""

from __future__ import annotations

import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from . import DASHBOARD_DIR


class _DashboardHandler(SimpleHTTPRequestHandler):
    """Handler that serves dashboard files from DASHBOARD_DIR without cache."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    def end_headers(self) -> None:
        # The dashboard polls a live API; never cache the static files.
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def log_message(self, format: str, *args) -> None:
        # Silence per-request log lines; the CLI prints the URL once.
        return None


def serve_dashboard(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    """Bind and serve the dashboard on host:port.

    The server runs on a daemon thread so the caller can keep the main
    thread open (e.g. to wait for KeyboardInterrupt in the CLI).
    """
    server = ThreadingHTTPServer((host, port), _DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def open_dashboard(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Convenience: serve then block on the main thread (CLI entry point)."""
    import webbrowser

    server = serve_dashboard(host, port)
    url = f"http://{host}:{port}/"
    print(f"[C-UAS] Dashboard serving on {url}")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()
