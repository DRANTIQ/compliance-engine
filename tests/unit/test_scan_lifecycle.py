import pytest

from platform_backend.platform.models.scan import ScanStatus, assert_transition


def test_happy_path_transitions() -> None:
    path = [
        ScanStatus.CREATED,
        ScanStatus.QUEUED,
        ScanStatus.COLLECTING,
        ScanStatus.COLLECTED,
        ScanStatus.INGESTING,
        ScanStatus.INVENTORY_READY,
        ScanStatus.EVALUATING,
        ScanStatus.COMPLETED,
    ]
    for current, nxt in zip(path, path[1:], strict=False):
        assert_transition(current, nxt)


def test_invalid_transition_raises() -> None:
    with pytest.raises(ValueError, match="invalid scan transition"):
        assert_transition(ScanStatus.CREATED, ScanStatus.COMPLETED)
