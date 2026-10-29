"""
TAXII 2.1 server for C-UAS threat intelligence sharing collections.

Endpoints (TAXII 2.1):

* GET  /taxii2/                          -- discovery (API root)
* GET  /taxii2/collections/              -- list collections
* GET  /taxii2/collections/{id}/         -- collection detail
* GET  /taxii2/collections/{id}/manifest/ -- STIX object manifest
* GET  /taxii2/collections/{id}/objects/ -- get STIX objects (filtered)
* POST /taxii2/collections/{id}/objects/ -- add STIX objects

Pure FastAPI + stdlib. Serves STIX 2.1 bundles produced by
``c_uas.threat_intel.STIXBundleBuilder`` and persisted under
``~/.c-uas-platform/threat_sharing/``.

Run standalone:
    python -m c_uas.threat_sharing.taxii_server --host 127.0.0.1 --port 8002
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query

from c_uas.threat_intel.store import ThreatIntelStore

DATA_DIR = Path.home() / ".c-uas-platform" / "threat_sharing"
_COLLECTIONS_FILE = DATA_DIR / "collections.json"
_OBJECTS_FILE = DATA_DIR / "objects.json"

API_ROOT_ID = "cuas-platform"
TITLE = "C-UAS Platform Threat Sharing"
COLLECTION_ID = "cuas-indicators"
COLLECTION_TITLE = "C-UAS Community Threat Indicators"


def _ensure_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _load_json(path: Path) -> List[Dict[str, Any]]:
    _ensure_dir()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        if isinstance(data, list):
            return data
        return []
    except (json.JSONDecodeError, OSError):
        return []


def _save_json(path: Path, data: List[Dict[str, Any]]) -> None:
    _ensure_dir()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    tmp.replace(path)


@dataclass(frozen=True)
class TAXIICollection:
    """A TAXII 2.1 collection of STIX objects."""

    id: str
    title: str
    description: str
    can_read: bool = True
    can_write: bool = True
    media_types: List[str] = field(default_factory=lambda: ["application/stix+json;version=2.1"])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "can_read": self.can_read,
            "can_write": self.can_write,
            "media_types": list(self.media_types),
        }


@dataclass(frozen=True)
class TAXIIManifestEntry:
    """A single entry in a TAXII 2.1 collection manifest."""

    id: str  # STIX object id
    type: str
    version: str
    date_added: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "version": self.version,
            "date_added": self.date_added,
        }


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _default_collection() -> TAXIICollection:
    return TAXIICollection(
        id=COLLECTION_ID,
        title=COLLECTION_TITLE,
        description=(
            "Community-shared C-UAS threat indicators (STIX 2.1) contributed "
            "by partner organisations via TAXII 2.1."
        ),
    )


def _collection_envelope() -> Dict[str, Any]:
    return _default_collection().to_dict()


def _api_root_envelope() -> Dict[str, Any]:
    return {
        "api_root": API_ROOT_ID,
        "title": TITLE,
        "description": ("STIX 2.1 threat intelligence shared across the C-UAS operator community."),
        "versions": ["2.1"],
        "max_page_size": 1000,
    }


def _load_collections() -> List[TAXIICollection]:
    return [TAXIICollection(**c) for c in _load_json(_COLLECTIONS_FILE)]


def _save_collections(collections: List[TAXIICollection]) -> None:
    _save_json(_COLLECTIONS_FILE, [c.to_dict() for c in collections])


def _load_objects() -> List[Dict[str, Any]]:
    return _load_json(_OBJECTS_FILE)


def _save_objects(objects: List[Dict[str, Any]]) -> None:
    _save_json(_OBJECTS_FILE, objects)


def _ensure_default_collection() -> None:
    collections = _load_collections()
    if not any(c.id == COLLECTION_ID for c in collections):
        collections.append(_default_collection())
        _save_collections(collections)


def app_factory(
    store: Optional[ThreatIntelStore] = None,
) -> FastAPI:
    _store = store or ThreatIntelStore()
    _ensure_default_collection()
    app = FastAPI(title="C-UAS TAXII 2.1 Sharing Server", version="2.1")

    @app.get("/taxii2/")
    def discovery() -> Dict[str, Any]:
        return {
            "type": "discovery",
            "id": "discovery--" + str(uuid.uuid4()),
            "spec_version": "2.1",
            "title": TITLE,
            "api_roots": [
                {
                    "id": API_ROOT_ID,
                    "title": TITLE,
                    "description": _api_root_envelope()["description"],
                    "versions": ["2.1"],
                    "max_page_size": 1000,
                    "collections": [
                        f"/taxii2/collections/{c.id}/"
                        for c in sorted(_load_collections(), key=lambda c: c.id)
                    ],
                }
            ],
        }

    @app.get("/taxii2/collections/")
    def list_collections() -> Dict[str, Any]:
        collections = sorted(_load_collections(), key=lambda c: c.id)
        return {
            "type": "collection-collection",
            "id": "collection-collection--" + str(uuid.uuid4()),
            "spec_version": "2.1",
            "title": "Collections",
            "collections": [c.to_dict() for c in collections],
        }

    @app.get("/taxii2/collections/{collection_id}/")
    def collection_detail(collection_id: str) -> Dict[str, Any]:
        collection = next((c for c in _load_collections() if c.id == collection_id), None)
        if collection is None:
            raise HTTPException(status_code=404, detail="Collection not found")
        return {
            "type": "collection",
            "spec_version": "2.1",
            **collection.to_dict(),
        }

    @app.get("/taxii2/collections/{collection_id}/manifest/")
    def manifest(
        collection_id: str,
    ) -> Dict[str, Any]:
        collection = next((c for c in _load_collections() if c.id == collection_id), None)
        if collection is None:
            raise HTTPException(status_code=404, detail="Collection not found")

        objects = _load_objects()
        entries: List[TAXIIManifestEntry] = []
        seen: Dict[str, str] = {}
        for obj in objects:
            oid = obj.get("id")
            otype = obj.get("type")
            if not oid or not otype:
                continue
            # Keep the most recent version per STIX id.
            version = obj.get("version", "1")
            if oid in seen and seen[oid] >= version:
                continue
            seen[oid] = version
            entries.append(
                TAXIIManifestEntry(
                    id=oid,
                    type=otype,
                    version=version,
                    date_added=obj.get("date_added", _now()),
                )
            )
        entries.sort(key=lambda e: e.id)

        return {
            "type": "manifest",
            "id": "manifest--" + str(uuid.uuid4()),
            "spec_version": "2.1",
            "collection_id": collection_id,
            "objects": [e.to_dict() for e in entries],
        }

    @app.get("/taxii2/collections/{collection_id}/objects/")
    def get_objects(
        collection_id: str,
        type: Optional[str] = Query(default=None, alias="type"),
        id: Optional[str] = Query(default=None, alias="id"),
        match: Optional[str] = Query(default=None),
    ) -> Dict[str, Any]:
        collection = next((c for c in _load_collections() if c.id == collection_id), None)
        if collection is None:
            raise HTTPException(status_code=404, detail="Collection not found")

        objects: List[Dict[str, Any]] = []
        for obj in _load_objects():
            if type and obj.get("type") != type:
                continue
            if id and obj.get("id") != id:
                continue
            if match:
                haystack = json.dumps(obj).lower()
                if match.lower() not in haystack:
                    continue
            objects.append(obj)
        objects.sort(key=lambda o: o.get("id", ""))

        return {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "spec_version": "2.1",
            "objects": objects,
        }

    @app.post("/taxii2/collections/{collection_id}/objects/")
    def add_objects(collection_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        collection = next((c for c in _load_collections() if c.id == collection_id), None)
        if collection is None:
            raise HTTPException(status_code=404, detail="Collection not found")

        obj_type = payload.get("type")
        if obj_type == "bundle":
            new_objects = list(payload.get("objects", []))
        elif obj_type in (
            "indicator",
            "observed-data",
            "attack-pattern",
            "intrusion-set",
            "marking-definition",
        ):
            new_objects = [payload]
        else:
            raise HTTPException(status_code=400, detail="Unsupported STIX object type")

        now = _now()
        for obj in new_objects:
            if "id" not in obj:
                raise HTTPException(status_code=400, detail="STIX object missing id")
            obj.setdefault("date_added", now)

        existing = _load_objects()
        existing_ids = {o.get("id") for o in existing}
        merged = list(existing)
        for obj in new_objects:
            if obj.get("id") in existing_ids:
                # Replace with the newest version deterministically.
                merged = [o for o in merged if o.get("id") != obj.get("id")]
                existing_ids.discard(obj.get("id"))
            merged.append(obj)
            existing_ids.add(obj.get("id"))
        merged.sort(key=lambda o: o.get("id", ""))
        _save_objects(merged)

        # Also persist to the threat-intel store for cross-module reuse.
        if obj_type == "bundle":
            _store.save_bundle(payload)

        return {
            "type": "status",
            "id": "status--" + str(uuid.uuid4()),
            "spec_version": "2.1",
            "status": "complete",
            "timestamp": now,
        }

    return app


app = app_factory()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="c-uas taxii-share-server",
        description="Run the C-UAS TAXII 2.1 threat sharing server.",
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8002, help="Bind port")
    args = parser.parse_args()

    import uvicorn  # type: ignore

    print(f"[C-UAS] TAXII 2.1 sharing server on {args.host}:{args.port}")
    print(f"  Discovery: http://{args.host}:{args.port}/taxii2/")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
