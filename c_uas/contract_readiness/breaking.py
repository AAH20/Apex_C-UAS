"""
Breaking change detector: compare two OpenAPI specs and flag breaking
changes between the old (previous) spec and the new (current) spec:

- removed parameters (path / query / header / cookie or body property)
- changed required fields (optional -> required or required -> optional)
- type narrowing (for example number -> integer)
- enum removals (values present in the old spec but missing in the new)
- default value removals (a default present in the old spec but missing in the new)

All functions are pure: identical inputs produce an identical report.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from .contract import load_spec

# Pairs (old_type, new_type) where the new type is a strict narrowing of the old.
_TYPE_NARROWING = {("number", "integer")}

HTTP_METHODS = ("get", "head", "post", "put", "delete", "options", "patch", "trace")
_PARAM_LOCATIONS = frozenset({"path", "query", "header", "cookie"})


@dataclass(frozen=True)
class BreakingChange:
    """A single breaking change between two OpenAPI specs."""

    kind: str
    location: str
    detail: str
    old_value: Optional[str]
    new_value: Optional[str]


@dataclass(frozen=True)
class BreakingReport:
    """Deterministic comparison of two OpenAPI specs."""

    old_spec_path: str
    new_spec_path: str
    changes: Tuple[BreakingChange, ...]
    breaking: bool


def _operations(spec: Dict[str, Any]) -> List[Tuple[str, str, Dict[str, Any]]]:
    """All (method, path, operation) entries in an OpenAPI spec."""
    found: List[Tuple[str, str, Dict[str, Any]]] = []
    paths = spec.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            operation = item.get(method)
            if isinstance(operation, dict):
                found.append((method.upper(), path, operation))
    return found


def _param_map(
    item: Dict[str, Any], operation: Dict[str, Any]
) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Parameters keyed by (in, name); operation-level overrides path-level."""
    params: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for param in item.get("parameters") or []:
        if isinstance(param, dict) and "in" in param and "name" in param:
            params[(str(param["in"]), str(param["name"]))] = param
    for param in operation.get("parameters") or []:
        if isinstance(param, dict) and "in" in param and "name" in param:
            params[(str(param["in"]), str(param["name"]))] = param
    return params


def _schema_of(param: Dict[str, Any]) -> Dict[str, Any]:
    """Schema dict for a parameter (OpenAPI 3.0 schema or inline fields)."""
    schema = param.get("schema")
    if isinstance(schema, dict):
        return schema
    return {key: param[key] for key in ("type", "format", "enum", "default") if key in param}


def _body_schemas(operation: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Request body schemas for an operation (all media types)."""
    schemas: List[Dict[str, Any]] = []
    body = operation.get("requestBody")
    if not isinstance(body, dict):
        return schemas
    content = body.get("content") or {}
    for _media_type, media_obj in content.items():
        if isinstance(media_obj, dict) and isinstance(media_obj.get("schema"), dict):
            schemas.append(media_obj["schema"])
    return schemas


def _prop_map(schema: Any) -> Dict[str, Dict[str, Any]]:
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    if not isinstance(props, dict):
        return {}
    return {name: prop for name, prop in props.items() if isinstance(prop, dict)}


def _compare_schemas(
    changes: List[BreakingChange],
    location: str,
    old_schema: Dict[str, Any],
    new_schema: Dict[str, Any],
    prefix: str = "",
) -> None:
    """Diff two schema dicts and append breaking changes."""
    # Changed required fields: newly required properties break clients that omit them.
    old_required = set(old_schema.get("required") or [])
    new_required = set(new_schema.get("required") or [])
    for field in sorted(new_required - old_required):
        changes.append(
            BreakingChange(
                kind="changed_required_field",
                location=f"{location} {prefix}".strip(),
                detail=f"field '{field}' is now required",
                old_value=None,
                new_value="required",
            )
        )
    old_props = _prop_map(old_schema)
    new_props = _prop_map(new_schema)
    for name in sorted(set(old_props) & set(new_props)):
        prop_location = f"{location} property '{name}'".strip()
        old_schema_node = old_props[name]
        new_schema_node = new_props[name]
        _compare_schema_nodes(changes, prop_location, old_schema_node, new_schema_node)
    # Removed body properties are removed parameters.
    for name in sorted(set(old_props) - set(new_props)):
        changes.append(
            BreakingChange(
                kind="removed_parameter",
                location=f"{location} property '{name}'".strip(),
                detail=f"body property '{name}' removed",
                old_value=str(old_props[name].get("type", "")) or "present",
                new_value=None,
            )
        )


def _compare_schema_nodes(
    changes: List[BreakingChange], location: str, old_node: Dict[str, Any], new_node: Dict[str, Any]
) -> None:
    old_type = old_node.get("type")
    new_type = new_node.get("type")
    if old_type is not None and new_type is not None:
        if (str(old_type), str(new_type)) in _TYPE_NARROWING:
            changes.append(
                BreakingChange(
                    kind="type_narrowing",
                    location=location,
                    detail=f"type narrowed from {old_type} to {new_type}",
                    old_value=str(old_type),
                    new_value=str(new_type),
                )
            )
    old_enum = old_node.get("enum")
    new_enum = new_node.get("enum")
    if isinstance(old_enum, list) and isinstance(new_enum, list):
        removed_values = [v for v in old_enum if v not in new_enum]
        if removed_values:
            changes.append(
                BreakingChange(
                    kind="enum_removal",
                    location=location,
                    detail="removed enum values: " + ", ".join(str(v) for v in removed_values),
                    old_value=str(old_enum),
                    new_value=str(new_enum),
                )
            )
    if "default" in old_node and "default" not in new_node:
        changes.append(
            BreakingChange(
                kind="default_removal",
                location=location,
                detail="default value removed",
                old_value=str(old_node.get("default")),
                new_value=None,
            )
        )


def _compare_parameters(
    changes: List[BreakingChange],
    location: str,
    old_params: Dict[Tuple[str, str], Dict[str, Any]],
    new_params: Dict[Tuple[str, str], Dict[str, Any]],
) -> None:
    for key in sorted(set(old_params) - set(new_params)):
        where, name = key
        old_node = _schema_of(old_params[key])
        changes.append(
            BreakingChange(
                kind="removed_parameter",
                location=f"{location} {where} parameter '{name}'".strip(),
                detail=f"{where} parameter '{name}' removed",
                old_value=str(old_node.get("type", "")) or "present",
                new_value=None,
            )
        )
    for key in sorted(set(old_params) & set(new_params)):
        where, name = key
        param_location = f"{location} {where} parameter '{name}'".strip()
        old_node = _schema_of(old_params[key])
        new_node = _schema_of(new_params[key])
        # requiredness change (optional -> required breaks clients that omit it).
        old_required = bool(old_params[key].get("required", False))
        new_required = bool(new_params[key].get("required", False))
        if old_required != new_required:
            changes.append(
                BreakingChange(
                    kind="changed_required_field",
                    location=param_location,
                    detail=f"required: {old_required} -> {new_required}",
                    old_value=str(old_required),
                    new_value=str(new_required),
                )
            )
        _compare_schema_nodes(changes, param_location, old_node, new_node)


def detect_breaking_changes(
    old_spec: Dict[str, Any], new_spec: Dict[str, Any]
) -> Tuple[BreakingChange, ...]:
    """Detect breaking changes from old_spec to new_spec. Sorted output."""
    old_ops = {(method, path): op for method, path, op in _operations(old_spec)}
    new_ops = {(method, path): op for method, path, op in _operations(new_spec)}

    changes: List[BreakingChange] = []
    for (method, path), old_op in sorted(old_ops.items()):
        new_op = new_ops.get((method, path))
        if new_op is None:
            continue
        location = f"{method} {path}"
        old_item = _path_item(old_spec, path)
        new_item = _path_item(new_spec, path)
        old_params = _param_map(old_item, old_op)
        new_params = _param_map(new_item, new_op)
        _compare_parameters(changes, location, old_params, new_params)
        for old_schema in _body_schemas(old_op):
            new_schemas = _body_schemas(new_op)
            if not new_schemas:
                continue
            new_schema = new_schemas[0]
            _compare_schemas(changes, f"{location} body schema", old_schema, new_schema)

    changes.sort(key=lambda change: (change.kind, change.location, change.detail))
    return tuple(changes)


def _path_item(spec: Dict[str, Any], path: str) -> Dict[str, Any]:
    paths = spec.get("paths") or {}
    item = paths.get(path)
    return item if isinstance(item, dict) else {}


def detect_breaking_changes_from_files(old_spec_path: str, new_spec_path: str) -> BreakingReport:
    """Load two spec files and return a BreakingReport."""
    old_spec = load_spec(old_spec_path)
    new_spec = load_spec(new_spec_path)
    changes = detect_breaking_changes(old_spec, new_spec)
    return BreakingReport(
        old_spec_path=old_spec_path,
        new_spec_path=new_spec_path,
        changes=changes,
        breaking=len(changes) > 0,
    )


def breaking_report_to_dict(report: BreakingReport) -> Dict[str, Any]:
    """JSON-serializable rendering of a BreakingReport."""
    return {
        "old_spec_path": report.old_spec_path,
        "new_spec_path": report.new_spec_path,
        "changes": [asdict(change) for change in report.changes],
        "breaking": report.breaking,
    }
