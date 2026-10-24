"""
Per-backend circuit breaker: closed / open / half_open states.

A backend starts closed. Each recorded failure increments the failure count;
once it reaches the failure threshold the circuit opens and rejects requests.
After the recovery timeout elapses, the circuit moves to half_open and admits a
single trial request. A successful trial closes the circuit; a failed trial
re-opens it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"


@dataclass
class CircuitState:
    backend_id: str
    state: str = CLOSED
    failure_count: int = 0
    opened_at: Optional[float] = None
    half_open_at: Optional[float] = None


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int,
        recovery_timeout_s: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout_s = recovery_timeout_s
        self.clock = clock
        self._states: Dict[str, CircuitState] = {}

    def state_for(self, backend_id: str) -> CircuitState:
        st = self._states.get(backend_id)
        if st is None:
            st = CircuitState(backend_id=backend_id)
            self._states[backend_id] = st
        return st

    def all_states(self) -> Dict[str, CircuitState]:
        return dict(self._states)

    def replace_states(self, states: Dict[str, CircuitState]) -> None:
        self._states = dict(states)

    def allow_request(self, backend_id: str) -> bool:
        """Return whether a request may be sent to backend_id (with transitions)."""
        st = self.state_for(backend_id)
        now = self.clock()
        if st.state == CLOSED:
            return True
        if st.state == OPEN:
            if st.opened_at is not None and now - st.opened_at >= self.recovery_timeout_s:
                st.state = HALF_OPEN
                st.half_open_at = now
                return True
            return False
        # half_open: admit a single trial request
        return True

    def record_success(self, backend_id: str) -> None:
        st = self.state_for(backend_id)
        if st.state == HALF_OPEN:
            st.state = CLOSED
            st.failure_count = 0
            st.opened_at = None
            st.half_open_at = None
        elif st.state == CLOSED:
            st.failure_count = 0

    def record_failure(self, backend_id: str) -> None:
        st = self.state_for(backend_id)
        st.failure_count += 1
        now = self.clock()
        if st.state == HALF_OPEN:
            st.state = OPEN
            st.opened_at = now
            st.half_open_at = None
        elif st.state == CLOSED and st.failure_count >= self.failure_threshold:
            st.state = OPEN
            st.opened_at = now
