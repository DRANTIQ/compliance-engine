from __future__ import annotations

from enum import StrEnum


class ScanStatus(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    COLLECTING = "collecting"
    COLLECTED = "collected"
    INGESTING = "ingesting"
    INVENTORY_READY = "inventory_ready"
    EVALUATING = "evaluating"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"


TERMINAL_STATUSES = frozenset(
    {
        ScanStatus.COMPLETED,
        ScanStatus.COMPLETED_WITH_ERRORS,
        ScanStatus.FAILED,
    }
)

ALLOWED_TRANSITIONS: dict[ScanStatus, frozenset[ScanStatus]] = {
    ScanStatus.CREATED: frozenset({ScanStatus.QUEUED, ScanStatus.FAILED}),
    ScanStatus.QUEUED: frozenset({ScanStatus.COLLECTING, ScanStatus.FAILED}),
    ScanStatus.COLLECTING: frozenset(
        {ScanStatus.COLLECTED, ScanStatus.COMPLETED_WITH_ERRORS, ScanStatus.FAILED}
    ),
    ScanStatus.COLLECTED: frozenset({ScanStatus.INGESTING, ScanStatus.FAILED}),
    ScanStatus.INGESTING: frozenset(
        {ScanStatus.INVENTORY_READY, ScanStatus.COMPLETED_WITH_ERRORS, ScanStatus.FAILED}
    ),
    ScanStatus.INVENTORY_READY: frozenset({ScanStatus.EVALUATING, ScanStatus.FAILED}),
    ScanStatus.COMPLETED_WITH_ERRORS: frozenset({ScanStatus.EVALUATING, ScanStatus.FAILED}),
    ScanStatus.EVALUATING: frozenset(
        {ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS, ScanStatus.FAILED}
    ),
}


def assert_transition(current: ScanStatus, target: ScanStatus) -> None:
    allowed = ALLOWED_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise ValueError(f"invalid scan transition: {current} -> {target}")
