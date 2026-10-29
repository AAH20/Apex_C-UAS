"""
External anchoring for the evidence ledger: git commits, IPFS-style content hash,
and JSON manifest for third-party verification.

All anchors are deterministic: same root hash -> same anchor record. No network
access is required; anchoring is purely local content addressing.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from c_uas.evidence_ledger.ledger import LedgerEntry

GIT_ANCHOR_NAMESPACE = "c-uas-evidence-ledger"


@dataclass(frozen=True)
class Anchor:
    """An immutable external anchor record for a ledger root hash."""

    anchor_type: str  # "git" | "ipfs" | "manifest"
    root_hash: str
    content_hash: str
    created_at: float
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def anchor_to_git(
    root_hash: str,
    created_at: Optional[float] = None,
    repo_path: Optional[str] = None,
) -> Anchor:
    """Anchor a ledger root hash to a deterministic Git commit.

    Builds a deterministic commit message from the root hash. If ``repo_path``
    (or CWD) points at a git repository, attempts a real commit with a fixed
    author/committer date so the commit id is deterministic; otherwise returns
    the planned anchor record without mutating the filesystem.
    """
    ts = time.time() if created_at is None else float(created_at)
    message = f"c-uas evidence ledger anchor: {root_hash}"
    details: Dict[str, Any] = {
        "anchor_type": "git",
        "root_hash": root_hash,
        "commit_message": message,
        "namespace": GIT_ANCHOR_NAMESPACE,
        "created_at": ts,
    }
    content_hash = hashlib.sha256(json.dumps(details, sort_keys=True).encode("utf-8")).hexdigest()
    anchor = Anchor(
        anchor_type="git",
        root_hash=root_hash,
        content_hash=content_hash,
        created_at=ts,
        details=details,
    )
    _try_git_commit(anchor, repo_path)
    return anchor


def _try_git_commit(anchor: Anchor, repo_path: Optional[str]) -> None:
    """Best-effort deterministic git commit; never raises on failure."""
    try:
        cwd = repo_path if repo_path else str(Path.cwd())
        if not Path(cwd, ".git").exists():
            return
        env = dict(os.environ)
        env.update(
            {
                "GIT_AUTHOR_NAME": "C-UAS Evidence Ledger",
                "GIT_AUTHOR_EMAIL": "ledger@c-uas-platform.internal",
                "GIT_COMMITTER_NAME": "C-UAS Evidence Ledger",
                "GIT_COMMITTER_EMAIL": "ledger@c-uas-platform.internal",
                "GIT_AUTHOR_DATE": f"{int(anchor.created_at)} +0000",
                "GIT_COMMITTER_DATE": f"{int(anchor.created_at)} +0000",
            }
        )
        anchor_file = Path(cwd) / "c-uas-evidence-anchor.json"
        anchor_file.write_text(json.dumps(anchor.to_dict(), indent=2) + "\n")
        subprocess.run(
            ["git", "add", "c-uas-evidence-anchor.json"],
            cwd=cwd,
            env=env,
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["git", "commit", "-m", anchor.details["commit_message"]],
            cwd=cwd,
            env=env,
            capture_output=True,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return


def anchor_ipfs(root_hash: str, created_at: Optional[float] = None) -> Anchor:
    """IPFS-style content-addressed anchor.

    content_hash = "sha256:" + sha256(canonical payload of the root hash).
    Purely local content addressing; no network access.
    """
    ts = time.time() if created_at is None else float(created_at)
    payload: Dict[str, Any] = {
        "root_hash": root_hash,
        "anchor_type": "ipfs",
        "created_at": ts,
    }
    content_hash = (
        "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    )
    return Anchor(
        anchor_type="ipfs",
        root_hash=root_hash,
        content_hash=content_hash,
        created_at=ts,
        details={"payload": payload, "multihash": content_hash},
    )


def anchor_manifest(
    root_hash: str,
    entries: List[LedgerEntry],
    manifest_path: Optional[str] = None,
    created_at: Optional[float] = None,
) -> Anchor:
    """Write a JSON manifest anchoring the root hash and full entry list.

    The Anchor's content_hash is the sha256 of the manifest bytes. The manifest
    is written to ``manifest_path`` (default under the ledger dir).
    """
    ts = time.time() if created_at is None else float(created_at)
    path = (
        Path(manifest_path)
        if manifest_path
        else Path.home() / ".c-uas-platform" / "evidence_ledger" / "anchor_manifest.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest: Dict[str, Any] = {
        "anchor_type": "manifest",
        "root_hash": root_hash,
        "entry_count": len(entries),
        "created_at": ts,
        "entries": [e.to_dict() for e in entries],
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")
    path.write_bytes(manifest_bytes)
    content_hash = hashlib.sha256(manifest_bytes).hexdigest()
    return Anchor(
        anchor_type="manifest",
        root_hash=root_hash,
        content_hash=content_hash,
        created_at=ts,
        details={
            "manifest_path": str(path),
            "entry_count": len(entries),
            "content_hash": content_hash,
        },
    )


def write_anchor(anchor: Anchor, path: str) -> Path:
    """Persist an Anchor record as JSON; returns the path written."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(anchor.to_dict(), indent=2) + "\n")
    return out


def load_anchor(path: str) -> Anchor:
    """Load an Anchor record from JSON."""
    data = json.loads(Path(path).read_text())
    return Anchor(**data)
