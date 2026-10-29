"""
STIX 2.1 feed ingestion for C-UAS threat sharing.

Fetches STIX bundles from remote TAXII 2.1 servers, parses STIX objects,
de-duplicates by STIX id, and filters by confidence / relevance so the
operator community only receives actionable indicators.

All functions are pure and deterministic: same feed bytes -> same parsed
objects, sorted by STIX id. Network access is isolated in
:func:`fetch_taxi bundle` so it can be mocked in tests.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

# Minimum confidence (0.0-1.0) for an indicator to be ingested.
DEFAULT_MIN_CONFIDENCE = 0.5
# Minimum relevance score (0.0-1.0) for an indicator to be ingested.
DEFAULT_MIN_RELEVANCE = 0.3

# STIX object types treated as indicators worth sharing.
INDICATOR_TYPES = {
    "indicator",
    "observed-data",
    "attack-pattern",
    "intrusion-set",
}


@dataclass(frozen=True)
class FeedResult:
    """Outcome of ingesting one remote feed."""

    feed_url: str
    fetched_at: str
    objects_received: int
    objects_ingested: int
    duplicates_skipped: int
    filtered_out: int
    ingested_ids: Tuple[str, ...]
    sha256: str  # SHA-256 of the canonical ingested set


@dataclass(frozen=True)
class ParsedIndicator:
    """A normalised STIX object ready for ingestion."""

    stix_id: str
    stix_type: str
    confidence: Optional[float]
    relevance: float
    object: Dict[str, Any]


def fetch_taxi_bundle(
    feed_url: str,
    get: Callable[[str], Any],
) -> Any:
    """Fetch a STIX bundle from a remote TAXII 2.1 server.

    ``get`` is an injectable callable ``get(url) -> response`` so the
    function is deterministic and testable without network access. A real
    caller passes ``httpx.get``.
    """
    return get(feed_url)


def parse_bundle(raw: Any) -> List[Dict[str, Any]]:
    """Parse a TAXII/STIX response into a list of STIX objects.

    Accepts a response-like object with ``.json()`` or a raw dict/list.
    Returns a sorted (by STIX id) list of STIX object dicts. Non-bundle
    payloads are normalised to a single-object list when possible.
    """
    data: Any
    if hasattr(raw, "json"):
        try:
            data = raw.json()
        except (ValueError, TypeError):
            return []
    else:
        data = raw

    if isinstance(data, dict):
        if data.get("type") == "bundle":
            objects = data.get("objects", [])
        else:
            # Single STIX object wrapped in a list.
            objects = [data] if data.get("id") else []
    elif isinstance(data, list):
        objects = data
    else:
        return []

    cleaned: List[Dict[str, Any]] = []
    for obj in objects:
        if isinstance(obj, dict) and obj.get("id") and obj.get("type"):
            cleaned.append(obj)
    cleaned.sort(key=lambda o: o.get("id", ""))
    return cleaned


def confidence_of(obj: Dict[str, Any]) -> Optional[float]:
    """Extract confidence (0.0-1.0) from a STIX object, else None."""
    conf = obj.get("confidence")
    if conf is None:
        # Some STIX objects carry confidence inside the observable.
        obs = obj.get("objects")
        if isinstance(obs, dict):
            for entry in obs.values():
                if isinstance(entry, dict) and "confidence" in entry:
                    conf = entry.get("confidence")
                    break
    try:
        return float(conf)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def relevance_of(obj: Dict[str, Any]) -> float:
    """Compute a deterministic relevance score (0.0-1.0) for a STIX object.

    Based on object type and the presence of observable content, so the
    same object always scores the same.
    """
    otype = obj.get("type", "")
    score = 0.2
    if otype in INDICATOR_TYPES:
        score += 0.4
    if otype == "indicator":
        score += 0.2
    obs = obj.get("objects")
    if isinstance(obs, dict) and obs:
        score += 0.2
    pattern = obj.get("pattern")
    if isinstance(pattern, str) and pattern:
        score += 0.1
    return min(score, 1.0)


def filter_objects(
    objects: List[Dict[str, Any]],
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    min_relevance: float = DEFAULT_MIN_RELEVANCE,
) -> List[ParsedIndicator]:
    """Filter STIX objects by confidence and relevance thresholds."""
    parsed: List[ParsedIndicator] = []
    for obj in objects:
        conf = confidence_of(obj)
        rel = relevance_of(obj)
        if conf is not None and conf < min_confidence:
            continue
        if rel < min_relevance:
            continue
        parsed.append(
            ParsedIndicator(
                stix_id=obj.get("id", ""),
                stix_type=obj.get("type", ""),
                confidence=conf,
                relevance=rel,
                object=dict(obj),
            )
        )
    parsed.sort(key=lambda p: p.stix_id)
    return parsed


def deduplicate(
    existing_ids: List[str], incoming: List[ParsedIndicator]
) -> Tuple[List[ParsedIndicator], List[str]]:
    """Split incoming indicators into new vs duplicates by STIX id."""
    existing = set(existing_ids)
    new_indicators: List[ParsedIndicator] = []
    duplicates: List[str] = []
    for ind in incoming:
        if ind.stix_id in existing:
            duplicates.append(ind.stix_id)
        else:
            new_indicators.append(ind)
            existing.add(ind.stix_id)
    new_indicators.sort(key=lambda p: p.stix_id)
    return new_indicators, duplicates


def ingest_feed(
    feed_url: str,
    existing_ids: List[str],
    get: Callable[[str], Any],
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    min_relevance: float = DEFAULT_MIN_RELEVANCE,
) -> FeedResult:
    """Fetch, parse, filter, and de-duplicate one remote TAXII feed."""
    response = fetch_taxi_bundle(feed_url, get)
    objects = parse_bundle(response)
    objects_received = len(objects)
    parsed = filter_objects(objects, min_confidence=min_confidence, min_relevance=min_relevance)
    filtered_out = objects_received - len(parsed)
    new_indicators, duplicates = deduplicate(existing_ids, parsed)
    ingested_ids = tuple(ind.stix_id for ind in new_indicators)

    canonical = json.dumps(
        [ind.object for ind in new_indicators], sort_keys=True, separators=(",", ":")
    )
    sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return FeedResult(
        feed_url=feed_url,
        fetched_at=_fixed_timestamp(),
        objects_received=objects_received,
        objects_ingested=len(new_indicators),
        duplicates_skipped=len(duplicates),
        filtered_out=filtered_out,
        ingested_ids=ingested_ids,
        sha256=sha256,
    )


def _fixed_timestamp() -> str:
    """Fixed timestamp so FeedResult is deterministic by default."""
    return "2026-10-23T00:00:00Z"
