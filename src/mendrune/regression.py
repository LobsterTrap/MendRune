"""Deterministic regression selection and required-result evaluation."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from mendrune.models import CampaignConfig, RegressionConfig, UnitConfig


@dataclass(frozen=True)
class ScheduledRegression:
    """A regression command and the unit that introduced it, if any."""

    command: RegressionConfig
    unit_id: str | None


class RegressionStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class RequiredRegressionResult:
    regression_id: str
    required: bool
    status: RegressionStatus
    exit_code: int | None
    timed_out: bool
    output_valid: bool
    reason_code: str | None

    @property
    def passed(self) -> bool:
        return self.required and self.status is RegressionStatus.PASSED


def select_shared_regressions(config: CampaignConfig) -> tuple[ScheduledRegression, ...]:
    """Select shared regressions in their declared order."""
    return tuple(
        ScheduledRegression(command, None) for command in config.commands.shared_regressions
    )


def select_unit_regressions(
    config: CampaignConfig, unit_id: str
) -> tuple[ScheduledRegression, ...]:
    """Select shared and unit-owned regressions for an isolated unit."""
    unit = _unit_by_id(config, unit_id)
    return select_shared_regressions(config) + tuple(
        ScheduledRegression(command, unit.id) for command in unit.regressions
    )


def select_accumulated_regressions(
    config: CampaignConfig, applied_unit_ids: Iterable[str]
) -> tuple[ScheduledRegression, ...]:
    """Select shared plus applied-unit regressions in composition order.

    Applied units must form a prefix of ``composition.order``. Requiring a prefix
    prevents a caller's set or input ordering from changing the command schedule.
    """
    applied = tuple(applied_unit_ids)
    if len(applied) != len(set(applied)):
        raise ValueError("applied unit IDs must be unique")
    expected = config.composition.order[: len(applied)]
    if set(applied) != set(expected):
        raise ValueError("applied unit IDs must form a prefix of composition.order")

    scheduled = list(select_shared_regressions(config))
    units = {unit.id: unit for unit in config.units}
    for unit_id in expected:
        unit = units[unit_id]
        scheduled.extend(ScheduledRegression(command, unit_id) for command in unit.regressions)
    return tuple(scheduled)


def evaluate_required_regression(
    regression_id: str,
    *,
    exit_code: int | None,
    timed_out: bool,
    skipped: bool = False,
    output_valid: bool = True,
    failure_reason_code: str = "regression_failed",
) -> RequiredRegressionResult:
    """Build the required-result record for one completed regression invocation."""
    if not regression_id:
        raise ValueError("regression_id must not be empty")
    if not failure_reason_code:
        raise ValueError("failure_reason_code must not be empty")

    if skipped:
        status = RegressionStatus.SKIPPED
    elif timed_out:
        status = RegressionStatus.TIMED_OUT
    elif exit_code is None or not output_valid:
        status = RegressionStatus.ERROR
    elif exit_code != 0:
        status = RegressionStatus.FAILED
    else:
        status = RegressionStatus.PASSED

    return RequiredRegressionResult(
        regression_id=regression_id,
        required=True,
        status=status,
        exit_code=exit_code,
        timed_out=timed_out,
        output_valid=output_valid,
        reason_code=None if status is RegressionStatus.PASSED else failure_reason_code,
    )


def _unit_by_id(config: CampaignConfig, unit_id: str) -> UnitConfig:
    for unit in config.units:
        if unit.id == unit_id:
            return unit
    raise ValueError(f"unknown unit ID: {unit_id}")
