"""
C-UAS Platform API package.

Exposes platform capabilities via FastAPI REST API.
"""

from .server import app

__all__ = ["app"]
