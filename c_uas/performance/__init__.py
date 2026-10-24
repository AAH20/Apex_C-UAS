"""Performance optimization, profiling, and SLA tracking for the C-UAS platform.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from c_uas.performance.optimizers import (
    AStarResult,
    LocalSearchResult,
    SetCoverResult,
    a_star,
    greedy_set_cover,
    local_search,
)
from c_uas.performance.profiler import (
    Bottleneck,
    EndpointTiming,
    MemorySample,
    ProfileResult,
    ProfileStore,
    detect_bottlenecks,
    detect_memory_pressure,
    percentile,
    profile_endpoint,
    throughput_rps,
)
from c_uas.performance.sla_tracker import (
    ErrorBudget,
    RecoveryRecord,
    SLARegistry,
    SLAResult,
    SLATarget,
    compliance_status,
    compute_percentiles,
    error_budget_remaining,
    record_recovery,
    record_request,
)

__all__ = [
    "AStarResult",
    "LocalSearchResult",
    "SetCoverResult",
    "a_star",
    "greedy_set_cover",
    "local_search",
    "Bottleneck",
    "EndpointTiming",
    "MemorySample",
    "ProfileResult",
    "ProfileStore",
    "detect_bottlenecks",
    "detect_memory_pressure",
    "percentile",
    "profile_endpoint",
    "throughput_rps",
    "ErrorBudget",
    "RecoveryRecord",
    "SLARegistry",
    "SLATarget",
    "SLAResult",
    "compliance_status",
    "compute_percentiles",
    "error_budget_remaining",
    "record_request",
    "record_recovery",
]
