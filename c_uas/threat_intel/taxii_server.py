"""
Minimal TAXII 2.1 server for sharing C-UAS threat intelligence collections.

Endpoints (TAXII 2.1):

* GET  /taxii2/                          -- discovery (API root)
* GET  /taxii2/collections/              -- list collections
* GET  /taxii2/collections/{id}/         -- collection detail
* GET  /taxii2/collections/{id}/objects/ -- get STIX objects (filtered)
* POST /taxii2/collections/{id}/objects/ -- add STIX objects

Pure FastAPI + stdlib. Serves STIX 2.1 bundles produced by
STIXBundleBuilder and persisted in ThreatIntelStore.

Run standalone:
    python -m c_uas.threat_intel.taxii_server --host 127.0.0.1 --port 8001
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from .models import ChannelConfig
from .store import ThreatIntelStore
from .stix_builder import STIXBundleBuilder, bundle_hash

API_ROOT_ID = "cuas-platform"
TITLE = "C-UAS Platform Threat Intelligence"
COLLECTION_ID = "cuas-detections"
COLLECTION_TITLE = "C-UAS Detections & Forensic Evidence"


def _api_root_envelope() -> Dict[str, Any]:
    return {
        "api_root": API_ROOT_ID,
        "title": TITLE,
        "description": "STIX 2.1 threat intelligence from the C-UAS platform "
        "(detection events, forensic dossiers, competitive intel).",
        "versions": ["2.1"],
        "max_page_size": 1000,
    }


def _collection_envelope() -> Dict[str, Any]:
    return {
        "id": COLLECTION_ID,
        "title": COLLECTION_TITLE,
        "description": "C-UAS detection events, Ed25519-signed forensic "
        "dossiers, and competitive-landscape intel as STIX 2.1 objects.",
        "can_read": True,
        "can_write": True,
        "media_types": ["application/stix+json;version=2.1"],
    }


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def app_factory(store: Optional[ThreatIntelStore] = None) -> FastAPI:
    store = store or ThreatIntelStore()
    app = FastAPI(title="C-UAS TAXII 2.1 Server", version="2.1")

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
                        f"/taxii2/collections/{COLLECTION_ID}/"
                    ],
                }
            ],
        }

    @app.get("/taxii2/collections/")
    def list_collections() -> Dict[str, Any]:
        return {
            "type": "collection-collection",
            "id": "collection-collection--" + str(uuid.uuid4()),
            "spec_version": "2.1",
            "title": "Collections",
            "collections": [_collection_envelope()],
        }

    @app.get("/taxii2/collections/{collection_id}/")
    def collection_detail(collection_id: str) -> Dict[str, Any]:
        if collection_id != COLLECTION_ID:
            raise HTTPException(status_code=404, detail="Collection not found")
        return {
            "type": "collection",
            "spec_version": "2.1",
            "id": COLLECTION_ID,
            "title": COLLECTION_TITLE,
            "description": _collection_envelope()["description"],
            "can_read": True,
            "can_write": True,
            "media_types": ["application/stix+json;version=2.1"],
        }

    @app.get("/taxii2/collections/{collection_id}/objects/")
    def get_objects(
        collection_id: str,
        type: Optional[str] = Query(default=None, alias="type"),
        id: Optional[str] = Query(default=None, alias="id"),
        match: Optional[str] = Query(default=None),
    ) -> Dict[str, Any]:
        if collection_id != COLLECTION_ID:
            raise HTTPException(status_code=404, detail="Collection not found")

        objects: List[Dict[str, Any]] = []
        for bundle in store.list_bundles():
            for obj in bundle.get("objects", []):
                if type and obj.get("type") != type:
                    continue
                if id and obj.get("id") != id:
                    continue
                if match:
                    # Very small substring match on name/display fields.
                    haystack = json.dumps(obj).lower()
                    if match.lower() not in haystack:
                        continue
                objects.append(obj)

        return {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "spec_version": "2.1",
            "objects": objects,
        }

    @app.post("/taxii2/collections/{collection_id}/objects/")
    def add_objects(collection_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if collection_id != COLLECTION_ID:
            raise HTTPException(status_code=404, detail="Collection not found")

        obj_type = payload.get("type")
        if obj_type == "bundle":
            store.save_bundle(payload)
        elif obj_type in ("indicator", "observed-data", "attack-pattern",
                          "intrusion-set", "marking-definition"):
            # Wrap a single STIX object in a bundle for persistence.
            bundle = {
                "type": "bundle",
                "id": "bundle--" + str(uuid.uuid4()),
                "spec_version": "2.1",
                "objects": [payload],
            }
            store.save_bundle(bundle)
        else:
            raise HTTPException(status_code=400, detail="Unsupported STIX object type")

        return {
            "type": "status",
            "id": "status--" + str(uuid.uuid4()),
            "spec_version": "2.1",
            "status": "complete",
            "timestamp": _now(),
        }

    return app


app = app_factory()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="c-uas taxii-server",
        description="Run the C-UAS TAXII 2.1 threat intelligence server.",
    )
    parser.add_argument("--host", type=str, default="127.0.0.1",
                        help="Bind host")
    parser.add_argument("--port", type=int, default=8001,
                        help="Bind port")
    args = parser.parse_args()

    import uvicorn  # type: ignore
    print(f"[C-UAS] TAXII 2.1 server on {args.host}:{args.port}")
    print(f"  Discovery: http://{args.host}:{args.port}/taxii2/")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
