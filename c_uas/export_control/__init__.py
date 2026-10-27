"""Export Control Compliance Scanner.

Audits repo descriptions, code comments, and READMEs for §120.41
''specially designed'' exposure via weapons-employment framing.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from .audit import AuditTrail, diff_audits, load_prior
from .ci_gate import GateResult, evaluate_gate, run_gate
from .scanner import Finding, ScanReport, load_latest_scan, save_scan, scan_directory

__all__ = [
    "scan_directory",
    "ScanReport",
    "Finding",
    "save_scan",
    "load_latest_scan",
    "evaluate_gate",
    "AuditTrail",
    "load_prior",
    "diff_audits",
    "run_gate",
    "GateResult",
]
