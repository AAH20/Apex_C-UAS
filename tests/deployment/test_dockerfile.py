"""Deterministic checks on the production Dockerfile (text parsing only; no daemon required)."""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "c_uas" / "deployment" / "Dockerfile"


def _from_stages(text: str) -> list:
    return [line for line in text.splitlines() if line.lstrip().startswith("FROM")]


def test_dockerfile_exists():
    assert DOCKERFILE.exists()


def test_dockerfile_is_multi_stage():
    stages = _from_stages(DOCKERFILE.read_text())
    assert len(stages) >= 2, f"expected multiple build stages, got: {stages}"
    assert any(" AS " in stage.upper() for stage in stages), "expected a named build stage"


def test_dockerfile_runs_as_non_root():
    text = DOCKERFILE.read_text()
    user_lines = [line for line in text.splitlines() if line.lstrip().startswith("USER")]
    assert user_lines, "Dockerfile must declare a USER directive"
    last_user = user_lines[-1].split(None, 1)[1].strip()
    assert last_user != "root", f"Dockerfile must not run as root, got USER {last_user}"


def test_dockerfile_exposes_platform_port():
    text = DOCKERFILE.read_text()
    assert re.search(r"^EXPOSE\s+8000\b", text, re.MULTILINE)


def test_dockerfile_has_entrypoint_cmd():
    text = DOCKERFILE.read_text()
    assert re.search(r"^CMD\s+\[", text, re.MULTILINE), "Dockerfile must define a CMD"


def test_dockerfile_uses_builder_venv():
    text = DOCKERFILE.read_text()
    assert "COPY --from=builder /opt/venv" in text


def test_dockerfile_has_healthcheck():
    assert "HEALTHCHECK" in DOCKERFILE.read_text()
