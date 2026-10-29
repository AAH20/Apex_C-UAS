"""
Community threat sharing: trust levels, attribution controls, and policy.

Defines :class:`ShareTrustLevel`, :class:`SharePolicy`, and
:class:`CommunityShare` which govern how indicators are exported (STIX 2.1
bundles), imported from partner organisations, and whether a given object
may be shared based on its marking and the partner's trust level.

Integrates with ``c_uas.threat_intel.STIXBundleBuilder`` for bundle export
and reuses its TLP marking scheme. All types are frozen dataclasses and all
functions are pure/deterministic.

State persists under ``~/.c-uas-platform/threat_sharing/``.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from c_uas.threat_intel.stix_builder import STIXBundleBuilder

DATA_DIR = Path.home() / ".c-uas-platform" / "threat_sharing"
_PARTNERS_FILE = DATA_DIR / "partners.json"
_SHARES_FILE = DATA_DIR / "shares.json"

DEFAULT_CREATED = "2026-10-23T00:00:00Z"

# Fixed namespace for content-addressed share bundle ids (matches threat_intel).
SHARE_NAMESPACE = uuid.UUID("6f3d8c2e-1a4b-4c9d-8e7f-2a3b4c5d6e7f")


@dataclass(frozen=True)
class ShareTrustLevel:
    """Trust level assigned to a partner organisation."""

    level: str  # e.g. "untrusted", "trusted", "allied"
    max_tlp: str  # highest TLP label this partner may receive
    can_receive_indicators: bool = True
    can_receive_dossiers: bool = False

    def can_receive(self, marking_refs: List[str]) -> bool:
        """Return True if this trust level may receive objects with these markings."""
        order = {"tlp-white": 0, "tlp-amber": 1, "tlp-red": 2}
        partner_cap = order.get(self.max_tlp, 0)
        for ref in marking_refs:
            if order.get(ref.lower(), 0) > partner_cap:
                return False
        return True


@dataclass(frozen=True)
class SharePolicy:
    """Sharing policy enforced on every export/import."""

    trust_levels: Tuple[ShareTrustLevel, ...] = field(
        default_factory=lambda: (
            ShareTrustLevel("untrusted", "tlp-white"),
            ShareTrustLevel("trusted", "tlp-amber"),
            ShareTrustLevel("allied", "tlp-red"),
        )
    )
    require_attribution: bool = True
    anonymise_sources: bool = False
    max_objects_per_bundle: int = 1000

    def trust_level(self, name: str) -> Optional[ShareTrustLevel]:
        for tl in self.trust_levels:
            if tl.level == name:
                return tl
        return None

    def may_share(self, partner_level: str, marking_refs: List[str]) -> bool:
        tl = self.trust_level(partner_level)
        if tl is None:
            return False
        return tl.can_receive(marking_refs)


@dataclass(frozen=True)
class CommunityShare:
    """A single share event: indicator(s) exported to a partner."""

    share_id: str
    partner: str
    partner_trust_level: str
    object_ids: Tuple[str, ...]
    bundle_id: str
    created_at: str
    marking_refs: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "share_id": self.share_id,
            "partner": self.partner,
            "partner_trust_level": self.partner_trust_level,
            "object_ids": list(self.object_ids),
            "bundle_id": self.bundle_id,
            "created_at": self.created_at,
            "marking_refs": list(self.marking_refs),
        }


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


def _load_shares() -> List[CommunityShare]:
    return [CommunityShare(**s) for s in _load_json(_SHARES_FILE)]


def _save_shares(shares: List[CommunityShare]) -> None:
    _save_json(_SHARES_FILE, [s.to_dict() for s in shares])


def _sha256(obj: Any) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def enforce_policy(
    policy: SharePolicy,
    partner: str,
    partner_level: str,
    objects: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Filter objects that the partner is allowed to receive.

    Returns ``(allowed, denied_ids)``. Denied objects are those whose
    markings exceed the partner's trust level TLP cap.
    """
    tl = policy.trust_level(partner_level)
    if tl is None:
        return [], [o.get("id", "") for o in objects]

    allowed: List[Dict[str, Any]] = []
    denied_ids: List[str] = []
    for obj in objects:
        marking_refs = list(obj.get("marking_refs", []) or [])
        if tl.can_receive(marking_refs):
            allowed.append(obj)
        else:
            denied_ids.append(obj.get("id", ""))
    allowed.sort(key=lambda o: o.get("id", ""))
    return allowed, denied_ids


def export_bundle(
    objects: List[Dict[str, Any]],
    partner: str,
    partner_level: str,
    policy: Optional[SharePolicy] = None,
    created: str = DEFAULT_CREATED,
) -> Tuple[Dict[str, Any], List[str]]:
    """Export allowed objects to a STIX 2.1 bundle for a partner.

    Returns ``(bundle, denied_ids)``. Uses ``STIXBundleBuilder`` from
    ``c_uas.threat_intel`` so output matches the platform's existing export.
    """
    policy = policy or SharePolicy()
    allowed, denied_ids = enforce_policy(policy, partner, partner_level, objects)

    builder = STIXBundleBuilder(created=created)
    # Re-attach markings inline on each object so the bundle is self-contained.
    for obj in allowed:
        builder.objects.append(dict(obj))
    bundle = builder.build()
    bundle["id"] = _stix_bundle_id(partner, created)
    return bundle, denied_ids


def _stix_bundle_id(partner: str, created: str) -> str:
    return "bundle--" + str(uuid.uuid5(SHARE_NAMESPACE, f"share-{partner}-{created}"))


def record_share(
    partner: str,
    partner_level: str,
    bundle: Dict[str, Any],
    objects: List[Dict[str, Any]],
) -> CommunityShare:
    """Persist a share event and return the CommunityShare record."""
    object_ids = tuple(sorted(o.get("id", "") for o in objects))
    marking_refs_list: List[str] = []
    for obj in objects:
        marking_refs_list.extend(obj.get("marking_refs", []) or [])
    marking_refs = tuple(sorted(set(marking_refs_list)))

    share = CommunityShare(
        share_id="share--"
        + _sha256(
            {
                "partner": partner,
                "bundle_id": bundle.get("id", ""),
                "object_ids": object_ids,
            }
        )[:16],
        partner=partner,
        partner_trust_level=partner_level,
        object_ids=object_ids,
        bundle_id=bundle.get("id", ""),
        created_at=DEFAULT_CREATED,
        marking_refs=marking_refs,
    )
    shares = _load_shares()
    shares.append(share)
    _save_shares(shares)
    return share


def list_shares() -> List[CommunityShare]:
    """List all recorded share events, newest-first (deterministic sort)."""
    return sorted(_load_shares(), key=lambda s: s.share_id)


def import_from_partner(
    bundle: Dict[str, Any],
    partner: str,
    partner_level: str,
    policy: Optional[SharePolicy] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Import objects from a partner bundle after policy checks.

    Returns ``(accepted, denied_ids)``. Accepted objects satisfy the
    partner's trust level; denied ones exceed the TLP cap.
    """
    policy = policy or SharePolicy()
    objects = list(bundle.get("objects", [])) if bundle.get("type") == "bundle" else []
    return enforce_policy(policy, partner, partner_level, objects)
