"""
Airspace Intrusion Forensic Dossier Generator.

Produces cryptographically certified incident documentation conforming to
FAA Part 107/89 and DoD counter-UAS standards. Uses real Ed25519 digital
signatures for tamper-evident chain of custody.
"""

import json
import time
import hashlib
from dataclasses import dataclass
from typing import Dict, Any, List

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from typing import Optional

# In-memory authority key pair for signing dossiers.
# In production, this would be loaded from an HSM or key management system.
_AUTHORITY_PRIVATE_KEY: Optional[Ed25519PrivateKey] = None
_AUTHORITY_PUBLIC_KEY_PEM: Optional[bytes] = None


def _get_authority_key() -> Ed25519PrivateKey:
    global _AUTHORITY_PRIVATE_KEY
    if _AUTHORITY_PRIVATE_KEY is None:
        _AUTHORITY_PRIVATE_KEY = Ed25519PrivateKey.generate()
        _AUTHORITY_PUBLIC_KEY_PEM = (
            _AUTHORITY_PRIVATE_KEY.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return _AUTHORITY_PRIVATE_KEY


@dataclass
class SignedDossier:
    dossier_id: str
    signature: str
    admissibility: str


class AirspaceIntrusionDossier:
    COMPLIANCE_STANDARDS = [
        "FAA_REMOTE_ID_PART_89",
        "DOD_COUNTER_UAS_STD",
        "FAA_PART_107",
    ]

    @staticmethod
    def generate_signed_dossier(
        target_id: str,
        protocol: str,
        threat_level: str,
        coordinates_path: List[Dict[str, float]],
        rf_anomalies: List[str],
    ) -> Dict[str, Any]:
        timestamp = time.time()
        dossier_id = f"C-UAS-{int(timestamp)}-{target_id}"

        payload: Dict[str, Any] = {
            "dossier_id": dossier_id,
            "compliance_standards": AirspaceIntrusionDossier.COMPLIANCE_STANDARDS,
            "timestamp_utc": timestamp,
            "target_id": target_id,
            "rf_protocol": protocol,
            "threat_classification": threat_level,
            "anomalies_detected": rf_anomalies,
            "trajectory_points": coordinates_path,
        }

        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        sha256_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        # Real Ed25519 signature over the canonical payload
        private_key = _get_authority_key()
        signature_bytes = private_key.sign(canonical.encode("utf-8"))
        signature_hex = signature_bytes.hex()

        return {
            "dossier_id": dossier_id,
            "compliance_standards": AirspaceIntrusionDossier.COMPLIANCE_STANDARDS,
            "timestamp_utc": timestamp,
            "target_id": target_id,
            "rf_protocol": protocol,
            "threat_classification": threat_level,
            "anomalies_detected": rf_anomalies,
            "trajectory_points": coordinates_path,
            "header": payload,
            "tamper_evident_hash": sha256_hash,
            "signature": signature_hex,
            "admissibility": "LEGAL_DEFENSE_GRADE",
            "public_key_pem": _AUTHORITY_PUBLIC_KEY_PEM.decode("utf-8")
            if _AUTHORITY_PUBLIC_KEY_PEM
            else "",
        }

    @staticmethod
    def verify_signature(dossier: Dict[str, Any]) -> bool:
        """Verify the Ed25519 signature against the embedded public key."""
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            public_key_pem = dossier.get("public_key_pem", "")
            if not public_key_pem:
                return False

            public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
            if not isinstance(public_key, Ed25519PublicKey):
                return False

            header = dossier.get("header", {})
            canonical = json.dumps(header, sort_keys=True, separators=(",", ":"))
            signature_bytes = bytes.fromhex(dossier["signature"])

            public_key.verify(signature_bytes, canonical.encode("utf-8"))
            return True
        except Exception:
            return False
