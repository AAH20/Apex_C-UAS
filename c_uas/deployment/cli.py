"""
``c-uas deploy`` subcommand.

Modes:
  --config-check   validate deployment configuration and artifact presence
  --docker         build and start the API with Docker Compose
  --k8s            print Kubernetes deployment guidance
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_DOCKERFILE = REPO_ROOT / "c_uas" / "deployment" / "Dockerfile"
_COMPOSE = REPO_ROOT / "c_uas" / "deployment" / "docker-compose.yml"


def _check(name: str, ok: bool, detail: str = "") -> bool:
    status = "PASS" if ok else "FAIL"
    message = f"[config-check] {status} {name}"
    if detail:
        message += f" — {detail}"
    print(message)
    return ok


def config_check() -> int:
    """Validate deployment configuration without deploying anything."""
    from .config import load_config

    ok = True
    config = load_config()
    ok = (
        _check(
            "configuration",
            True,
            f"host={config.host} port={config.port} rate_limit={config.rate_limit_rps}rps "
            f"burst={config.rate_limit_burst} auth={'on' if config.auth_required else 'off (dev)'}",
        )
        and ok
    )
    ok = _check("dockerfile", _DOCKERFILE.exists(), str(_DOCKERFILE)) and ok
    ok = _check("docker-compose", _COMPOSE.exists(), str(_COMPOSE)) and ok
    ok = (
        _check(
            "api_keys",
            bool(config.api_keys),
            "loaded from CUAS_API_KEYS or ~/.c-uas-platform/api_keys.json",
        )
        and ok
    )
    return 0 if ok else 1


def deploy_docker() -> int:
    """Build and run the API image via Docker Compose."""
    if config_check() != 0:
        return 1
    if shutil.which("docker") is None:
        print("[deploy] docker not found in PATH — install Docker, then run:")
        print("  docker build -t c-uas-platform -f c_uas/deployment/Dockerfile .")
        print("  docker compose -f c_uas/deployment/docker-compose.yml up -d")
        return 1
    command = ["docker", "compose", "-f", str(_COMPOSE), "up", "-d", "--build"]
    print(f"[deploy] {' '.join(command)}")
    return subprocess.call(command)


def deploy_k8s() -> int:
    """Print Kubernetes deployment guidance (manifests are cluster-specific)."""
    print("[deploy] --k8s: apply Kubernetes manifests to the target cluster")
    print("  kubectl apply -f deploy/k8s/")
    print("  Inject CUAS_API_KEYS as a Kubernetes Secret — never as plaintext.")
    return 0


def deploy(*, docker: bool = False, k8s: bool = False, check_config: bool = False) -> int:
    """Entry point used by c_uas.cli; returns a process exit code."""
    if docker:
        return deploy_docker()
    if k8s:
        return deploy_k8s()
    # Default: validate configuration without deploying.
    return config_check()
