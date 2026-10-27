"""Disaster recovery backup manager.

Snapshots every module state directory under the platform state root
(``~/.c-uas-platform/*/``) into a deterministic, uncompressed tar archive,
records backup metadata (timestamp, files, checksums), and persists archives
and metadata under ``<state_dir>/backups/``.

The archive is byte-for-byte deterministic for identical inputs: members are
sorted, every member uses a fixed mtime (epoch 0), uid/gid 0, and fixed
modes, so re-running a backup against unchanged state reproduces the exact
same archive bytes and backup id.

Nothing here mutates the scanned state trees -- this is a read-only snapshot.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "disaster_recovery")
BACKUP_SUBDIR = "backups"
REGISTRY_FILENAME = "registry.json"

# Fixed mtime for every archive member -> byte-identical archives for
# identical inputs (tar otherwise embeds mtime/uid/gid/uname/gname).
ARCHIVE_MTIME = 0
ARCHIVE_DIR_MODE = 0o755
ARCHIVE_FILE_MODE = 0o644

# Never back up the disaster recovery directory itself (it would recurse into
# its own backups), and drop transient platform noise.
EXCLUDED_MODULES = {"disaster_recovery"}
SKIP_ENTRY_NAMES = {".DS_Store"}
SKIP_ENTRY_SUFFIXES = (".pyc",)
SKIP_DIR_NAMES = {"__pycache__", ".git"}


@dataclass(frozen=True)
class FileEntry:
    """One file captured in a backup: module-relative path plus checksum."""

    module: str
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class BackupMetadata:
    """Full record of one backup: what was captured and where it lives."""

    backup_id: str
    timestamp: str
    modules: Tuple[str, ...]
    files: Tuple[FileEntry, ...]
    total_files: int
    total_size: int
    archive_path: str
    archive_sha256: str


@dataclass(frozen=True)
class BackupResult:
    """Result of ``create_backup``."""

    backup_id: str
    timestamp: str
    archive_path: str
    archive_sha256: str
    modules: Tuple[str, ...]
    files: Tuple[FileEntry, ...]
    total_files: int
    total_size: int


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string (real wall-clock time)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def platform_root(state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR) -> Path:
    """Platform state root: the parent of the disaster recovery state dir."""
    return Path(state_dir).resolve().parent


def _is_excluded_dir(name: str) -> bool:
    return name in SKIP_DIR_NAMES or name.startswith(".")


def _is_excluded_entry(name: str) -> bool:
    if name in SKIP_ENTRY_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in SKIP_ENTRY_SUFFIXES)


def list_modules(state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR) -> Tuple[str, ...]:
    """Sorted module state dirs under the platform root (excl. disaster_recovery)."""
    root = platform_root(state_dir)
    if not root.exists():
        return ()
    modules = sorted(
        entry.name
        for entry in root.iterdir()
        if entry.is_dir() and entry.name not in EXCLUDED_MODULES and not entry.name.startswith(".")
    )
    return tuple(modules)


def snapshot_files(state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR) -> Tuple[FileEntry, ...]:
    """Snapshot every file under each module state dir, in deterministic order.

    Returns ``FileEntry`` records sorted by ``(module, path)`` with real
    sizes and SHA-256 checksums computed from disk.
    """
    root = platform_root(state_dir)
    entries: List[FileEntry] = []
    for module in list_modules(state_dir):
        module_dir = root / module
        for dirpath, dirnames, filenames in os.walk(module_dir):
            dirnames[:] = sorted(name for name in dirnames if not _is_excluded_dir(name))
            for fname in sorted(filenames):
                if _is_excluded_entry(fname):
                    continue
                file_path = Path(dirpath) / fname
                relative = file_path.relative_to(module_dir)
                entries.append(
                    FileEntry(
                        module=module,
                        path=str(relative),
                        size=file_path.stat().st_size,
                        sha256=_sha256_file(file_path),
                    )
                )
    entries.sort(key=lambda entry: (entry.module, entry.path))
    return tuple(entries)


def compute_backup_id(entries: Sequence[FileEntry], total_size: int) -> str:
    """Content-derived backup id: identical inputs always yield the same id."""
    payload = {
        "modules": sorted({entry.module for entry in entries}),
        "files": [asdict(entry) for entry in entries],
        "total_size": total_size,
    }
    canonical = json.dumps(payload, indent=2, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _archive_name(backup_id: str) -> str:
    return f"{backup_id}.tar"


def _metadata_name(backup_id: str) -> str:
    return f"{backup_id}.meta.json"


def _write_archive(entries: Sequence[FileEntry], root: Path, archive_path: Path) -> None:
    """Write a deterministic tar archive of ``entries`` rooted at ``root``."""
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    dirs: Dict[Tuple[str, str], None] = {}
    for entry in entries:
        parts = entry.path.split("/")
        for index in range(len(parts) - 1):
            dirs[(entry.module, "/".join(parts[: index + 1]))] = None
    with tarfile.open(archive_path, "w") as tar:
        for module, dir_rel in sorted(dirs):
            info = tarfile.TarInfo(name=f"{module}/{dir_rel}/")
            info.type = tarfile.DIRTYPE
            info.mode = ARCHIVE_DIR_MODE
            info.mtime = ARCHIVE_MTIME
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tar.addfile(info)
        for entry in entries:
            data = (root / entry.module / entry.path).read_bytes()
            info = tarfile.TarInfo(name=f"{entry.module}/{entry.path}")
            info.type = tarfile.REGTYPE
            info.size = len(data)
            info.mode = ARCHIVE_FILE_MODE
            info.mtime = ARCHIVE_MTIME
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tar.addfile(info, io.BytesIO(data))


def _save_metadata(metadata: BackupMetadata, backup_dir: Path) -> None:
    backup_dir.mkdir(parents=True, exist_ok=True)
    payload = asdict(metadata)
    (backup_dir / _metadata_name(metadata.backup_id)).write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )


def _load_registry(state_dir: str | os.PathLike[str]) -> Dict:
    registry_path = Path(state_dir) / REGISTRY_FILENAME
    if not registry_path.exists():
        return {"backups": [], "last_backup_per_module": {}}
    return json.loads(registry_path.read_text(encoding="utf-8"))


def _save_registry(state_dir: str | os.PathLike[str], registry: Dict) -> None:
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    (Path(state_dir) / REGISTRY_FILENAME).write_text(
        json.dumps(registry, indent=2, sort_keys=True), encoding="utf-8"
    )


def _update_registry(metadata: BackupMetadata, state_dir: str | os.PathLike[str]) -> None:
    registry = _load_registry(state_dir)
    entry = {
        "backup_id": metadata.backup_id,
        "timestamp": metadata.timestamp,
        "modules": list(metadata.modules),
        "total_files": metadata.total_files,
        "total_size": metadata.total_size,
        "archive_sha256": metadata.archive_sha256,
    }
    backups = [
        item for item in registry.get("backups", []) if item["backup_id"] != metadata.backup_id
    ]
    backups.insert(0, entry)
    backups.sort(key=lambda item: item["timestamp"], reverse=True)
    registry["backups"] = backups
    last_per_module = registry.setdefault("last_backup_per_module", {})
    for module in metadata.modules:
        last_per_module[module] = {
            "timestamp": metadata.timestamp,
            "backup_id": metadata.backup_id,
            "archive_size": metadata.total_size,
            "archive_sha256": metadata.archive_sha256,
        }
    _save_registry(state_dir, registry)


def load_metadata(
    backup_id: str, state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR
) -> Optional[BackupMetadata]:
    """Load the metadata record for ``backup_id``, or None if not present."""
    meta_path = Path(state_dir) / BACKUP_SUBDIR / _metadata_name(backup_id)
    if not meta_path.exists():
        return None
    data = json.loads(meta_path.read_text(encoding="utf-8"))
    files = tuple(
        FileEntry(
            module=item["module"],
            path=item["path"],
            size=item["size"],
            sha256=item["sha256"],
        )
        for item in data.get("files", [])
    )
    return BackupMetadata(
        backup_id=data["backup_id"],
        timestamp=data["timestamp"],
        modules=tuple(data["modules"]),
        files=files,
        total_files=data["total_files"],
        total_size=data["total_size"],
        archive_path=data["archive_path"],
        archive_sha256=data["archive_sha256"],
    )


def list_backups(
    state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR,
) -> Tuple[BackupMetadata, ...]:
    """All known backups, newest first (metadata may be missing -> skipped)."""
    registry = _load_registry(state_dir)
    backups: List[BackupMetadata] = []
    for item in registry.get("backups", []):
        metadata = load_metadata(item["backup_id"], state_dir)
        if metadata is not None:
            backups.append(metadata)
    backups.sort(key=lambda metadata: metadata.timestamp, reverse=True)
    return tuple(backups)


def create_backup(
    state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR,
) -> BackupResult:
    """Snapshot all module state dirs into a deterministic backup archive.

    Idempotent: re-running against unchanged state reproduces the same
    archive bytes and returns the same ``backup_id``.
    """
    root = platform_root(state_dir)
    entries = snapshot_files(state_dir)
    total_size = sum(entry.size for entry in entries)
    backup_id = compute_backup_id(entries, total_size)
    backup_dir = Path(state_dir) / BACKUP_SUBDIR
    archive_path = backup_dir / _archive_name(backup_id)
    if not archive_path.exists():
        _write_archive(entries, root, archive_path)
    archive_sha256 = _sha256_file(archive_path)
    timestamp = utc_now_iso()
    metadata = BackupMetadata(
        backup_id=backup_id,
        timestamp=timestamp,
        modules=tuple(sorted({entry.module for entry in entries})),
        files=entries,
        total_files=len(entries),
        total_size=total_size,
        archive_path=str(archive_path),
        archive_sha256=archive_sha256,
    )
    _save_metadata(metadata, backup_dir)
    _update_registry(metadata, state_dir)
    return BackupResult(
        backup_id=backup_id,
        timestamp=timestamp,
        archive_path=str(archive_path),
        archive_sha256=archive_sha256,
        modules=metadata.modules,
        files=entries,
        total_files=len(entries),
        total_size=total_size,
    )
