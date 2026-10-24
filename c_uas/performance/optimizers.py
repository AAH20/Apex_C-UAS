"""
Deterministic optimization kernels for the C-UAS performance module.

Kernels:
  - A* pathfinding over a grid graph (deterministic tie-breaking).
  - Greedy set cover (deterministic ordering, seed-keyed tie-breaks).
  - Local search / hill-climb with fixed seed.

All functions are pure: same input yields same output. No external randomness
without an explicit seed. Results persist under
~/.c-uas-platform/performance/optimizers/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import heapq
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

DEFAULT_SEED = 42
SCHEMA_VERSION = "1.0.0"


def _optimizer_dir() -> Path:
    return Path(
        os.environ.get(
            "C_UAS_PERFORMANCE_DIR",
            str(Path.home() / ".c-uas-platform" / "performance" / "optimizers"),
        )
    )


def _write_json(name: str, obj: object) -> Path:
    path = _optimizer_dir() / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(obj, "__dataclass_fields__"):
        payload = asdict(obj)  # type: ignore[call-overload]
    else:
        payload = obj
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return path


def _seed_key(seed: int, label: str) -> int:
    """Deterministic seed-keyed integer used for reproducible tie-breaking."""
    return int(hashlib_sha256(f"{seed}:{label}")[:8], 16)


def hashlib_sha256(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# A* pathfinding
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AStarResult:
    """Result of a deterministic A* pathfinding run."""

    schema_version: str
    seed: int
    start: Tuple[int, int]
    goal: Tuple[int, int]
    path: Tuple[Tuple[int, int], ...]
    cost: float
    nodes_expanded: int
    found: bool


def _heuristic(a: Tuple[int, int], b: Tuple[int, int]) -> float:
    return abs(a[0] - b[0]) + abs(a[1] - b[1])


def a_star(
    grid: Sequence[Sequence[bool]],
    start: Tuple[int, int],
    goal: Tuple[int, int],
    seed: int = DEFAULT_SEED,
) -> AStarResult:
    """Find a shortest path on a walkable grid using A*.

    ``grid[y][x]`` is True when the cell is walkable. Ties in the open set are
    broken deterministically using a seed-keyed counter so the same input always
    yields the same path.
    """
    rows = len(grid)
    cols = len(grid[0]) if rows else 0

    def in_bounds(cell: Tuple[int, int]) -> bool:
        x, y = cell
        return 0 <= x < cols and 0 <= y < rows

    def walkable(cell: Tuple[int, int]) -> bool:
        x, y = cell
        return in_bounds(cell) and grid[y][x]

    if not walkable(start) or not walkable(goal):
        return AStarResult(
            schema_version=SCHEMA_VERSION,
            seed=seed,
            start=start,
            goal=goal,
            path=(),
            cost=float("inf"),
            nodes_expanded=0,
            found=False,
        )

    if start == goal:
        return AStarResult(
            schema_version=SCHEMA_VERSION,
            seed=seed,
            start=start,
            goal=goal,
            path=(start,),
            cost=0.0,
            nodes_expanded=1,
            found=True,
        )

    # Neighbour order is fixed (up, right, down, left) for determinism.
    neighbours: Tuple[Tuple[int, int], ...] = ((0, -1), (1, 0), (0, 1), (-1, 0))

    open_set: List[Tuple[float, int, Tuple[int, int]]] = []
    counter = 0
    heapq.heappush(open_set, (0.0, counter, start))
    counter += 1

    came_from: Dict[Tuple[int, int], Tuple[int, int]] = {}
    g_score: Dict[Tuple[int, int], float] = {start: 0.0}
    f_score: Dict[Tuple[int, int], float] = {start: _heuristic(start, goal)}
    in_open: Set[Tuple[int, int]] = {start}

    nodes_expanded = 0
    found = False
    goal_cell: Optional[Tuple[int, int]] = None

    while open_set:
        _, _, current = heapq.heappop(open_set)
        in_open.discard(current)
        nodes_expanded += 1

        if current == goal:
            found = True
            goal_cell = current
            break

        for dx, dy in neighbours:
            neighbour = (current[0] + dx, current[1] + dy)
            if not walkable(neighbour):
                continue
            tentative_g = g_score[current] + 1.0
            if tentative_g < g_score.get(neighbour, float("inf")):
                came_from[neighbour] = current
                g_score[neighbour] = tentative_g
                f = tentative_g + _heuristic(neighbour, goal)
                f_score[neighbour] = f
                # Seed-keyed tie-break: equal f values order by a deterministic
                # key derived from the seed and the cell coordinates.
                tie = _seed_key(seed, f"{neighbour[0]},{neighbour[1]}")
                if neighbour not in in_open:
                    heapq.heappush(open_set, (f, tie, neighbour))
                    counter += 1
                    in_open.add(neighbour)

    path: List[Tuple[int, int]] = []
    if found and goal_cell is not None:
        cell: Optional[Tuple[int, int]] = goal_cell
        while cell is not None:
            path.append(cell)
            cell = came_from.get(cell)
        path.reverse()

    result = AStarResult(
        schema_version=SCHEMA_VERSION,
        seed=seed,
        start=start,
        goal=goal,
        path=tuple(path),
        cost=float(len(path) - 1) if found else float("inf"),
        nodes_expanded=nodes_expanded,
        found=found,
    )
    _write_json("astar", result)
    return result


# --------------------------------------------------------------------------- #
# Greedy set cover
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SetCoverResult:
    """Result of a deterministic greedy set cover."""

    schema_version: str
    seed: int
    universe_size: int
    chosen_sets: Tuple[str, ...]
    covered_elements: Tuple[object, ...]
    uncovered_elements: Tuple[object, ...]
    set_count: int


def greedy_set_cover(
    universe: Sequence[object],
    sets: Dict[str, Sequence[object]],
    seed: int = DEFAULT_SEED,
) -> SetCoverResult:
    """Greedy minimum set cover with deterministic tie-breaking.

    Repeatedly picks the set covering the most uncovered elements. Ties are
    broken by set id then by a seed-keyed hash, so the same input always yields
    the same cover.
    """
    uncovered: Set[object] = set(universe)
    chosen: List[str] = []
    remaining = dict(sets)

    while uncovered and remaining:
        best_id: Optional[str] = None
        best_count = -1
        for set_id in sorted(remaining):
            cover = remaining[set_id]
            count = len(set(cover) & uncovered)
            if count > best_count:
                best_count = count
                best_id = set_id
            elif count == best_count and best_id is not None and count > 0:
                # Deterministic seed-keyed tie-break on set id.
                if _seed_key(seed, set_id) < _seed_key(seed, best_id):
                    best_id = set_id
        if best_id is None or best_count <= 0:
            break
        chosen.append(best_id)
        uncovered -= set(remaining[best_id])
        del remaining[best_id]

    covered = sorted(set(universe) - uncovered, key=lambda e: str(e))
    uncovered_sorted = sorted(uncovered, key=lambda e: str(e))

    result = SetCoverResult(
        schema_version=SCHEMA_VERSION,
        seed=seed,
        universe_size=len(set(universe)),
        chosen_sets=tuple(chosen),
        covered_elements=tuple(covered),
        uncovered_elements=tuple(uncovered_sorted),
        set_count=len(chosen),
    )
    _write_json("set_cover", result)
    return result


# --------------------------------------------------------------------------- #
# Local search (hill climb)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LocalSearchResult:
    """Result of a deterministic local search / hill-climb run."""

    schema_version: str
    seed: int
    best_state: Tuple[object, ...]
    best_cost: float
    iterations: int
    improved: bool


def local_search(
    initial_state: Sequence[object],
    cost_fn: Callable[[Sequence[object]], float],
    neighbors_fn: Callable[[Sequence[object]], Sequence[Sequence[object]]],
    seed: int = DEFAULT_SEED,
    max_iterations: int = 100,
) -> LocalSearchResult:
    """First-improvement hill climb with deterministic neighbour ordering.

    Starting from ``initial_state``, repeatedly moves to the first neighbour
    (sorted for determinism, seed-keyed as final tie-break) whose cost is
    strictly lower. Stops at a local optimum or after ``max_iterations``.
    """
    current = tuple(initial_state)
    current_cost = cost_fn(current)
    iterations = 0
    improved = False

    for _ in range(max_iterations):
        iterations += 1
        neighbours = sorted(
            (tuple(n) for n in neighbors_fn(current)),
            key=lambda s: (str(s), _seed_key(seed, str(s))),
        )
        moved = False
        for neighbour in neighbours:
            neighbour_cost = cost_fn(neighbour)
            if neighbour_cost < current_cost:
                current = neighbour
                current_cost = neighbour_cost
                improved = True
                moved = True
                break
        if not moved:
            break

    result = LocalSearchResult(
        schema_version=SCHEMA_VERSION,
        seed=seed,
        best_state=current,
        best_cost=current_cost,
        iterations=iterations,
        improved=improved,
    )
    _write_json("local_search", result)
    return result
