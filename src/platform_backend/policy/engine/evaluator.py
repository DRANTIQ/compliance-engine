from __future__ import annotations

from typing import Any


def _resolve_path(asset: dict[str, Any], path: str) -> Any:
    current: Any = asset
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


_MISSING = object()


def _field_check(asset: dict[str, Any], node: dict[str, Any]) -> bool:
    actual = _resolve_path(asset, node["path"])
    operator = node["operator"]
    expected = node.get("expected")

    if operator == "missing":
        return actual is _MISSING
    if operator == "exists":
        return actual is not _MISSING
    if actual is _MISSING:
        return False

    if operator == "eq":
        return actual == expected
    if operator == "ne":
        return actual != expected
    if operator == "gt":
        return actual > expected
    if operator == "gte":
        return actual >= expected
    if operator == "lt":
        return actual < expected
    if operator == "lte":
        return actual <= expected
    if operator == "in":
        return actual in (expected or [])
    if operator == "not_in":
        return actual not in (expected or [])
    if operator == "true":
        return bool(actual) is True
    if operator == "false":
        return bool(actual) is False

    raise ValueError(f"unsupported field_check operator: {operator}")


def _compound(asset: dict[str, Any], node: dict[str, Any]) -> bool:
    operator = node["operator"]
    conditions = node.get("conditions", [])
    results = [evaluate_condition(asset, condition) for condition in conditions]
    if operator == "and":
        return all(results)
    if operator == "or":
        return any(results)
    raise ValueError(f"unsupported compound operator: {operator}")


def evaluate_condition(asset: dict[str, Any], node: dict[str, Any]) -> bool:
    node_type = node["type"]
    if node_type == "field_check":
        return _field_check(asset, node)
    if node_type == "compound":
        return _compound(asset, node)
    raise ValueError(f"unsupported condition type: {node_type}")


def evaluate_policy_logic(asset: dict[str, Any], logic: dict[str, Any]) -> bool:
    """Return True when the policy fails (non-compliant)."""
    logic_type = logic["type"]
    if logic_type == "fail_when":
        return evaluate_condition(asset, logic["condition"])
    if logic_type == "field_check":
        return _field_check(asset, logic)
    if logic_type == "compound":
        return _compound(asset, logic)
    raise ValueError(f"unsupported logic type: {logic_type}")


def build_evidence(asset: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    for field in fields:
        value = _resolve_path(asset, field)
        if value is not _MISSING:
            evidence[field] = value
    return evidence
