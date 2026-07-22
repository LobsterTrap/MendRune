import pytest

from mendrune.models import (
    CampaignConfig,
    CommandsConfig,
    CompositionConfig,
    RegressionConfig,
    UnitConfig,
)
from mendrune.regression import (
    RegressionStatus,
    evaluate_required_regression,
    select_accumulated_regressions,
    select_shared_regressions,
    select_unit_regressions,
)


def regression(regression_id: str) -> RegressionConfig:
    return RegressionConfig(
        id=regression_id,
        argv=("check", regression_id),
        evidence_paths=(f"{regression_id}.py",),
        timeout_seconds=30,
    )


def campaign() -> CampaignConfig:
    first = UnitConfig.model_construct(id="first", regressions=(regression("first-a"),))
    second = UnitConfig.model_construct(
        id="second", regressions=(regression("second-a"), regression("second-b"))
    )
    commands = CommandsConfig.model_construct(
        shared_regressions=(regression("shared-a"), regression("shared-b"))
    )
    return CampaignConfig.model_construct(
        composition=CompositionConfig(order=("first", "second")),
        units=(second, first),
        commands=commands,
    )


def identities(selection) -> list[tuple[str | None, str]]:
    return [(item.unit_id, item.command.id) for item in selection]


def test_selects_shared_and_isolated_unit_regressions_deterministically() -> None:
    config = campaign()

    assert identities(select_shared_regressions(config)) == [
        (None, "shared-a"),
        (None, "shared-b"),
    ]
    assert identities(select_unit_regressions(config, "second")) == [
        (None, "shared-a"),
        (None, "shared-b"),
        ("second", "second-a"),
        ("second", "second-b"),
    ]


def test_accumulation_uses_composition_order_not_input_or_declaration_order() -> None:
    selection = select_accumulated_regressions(campaign(), {"second", "first"})

    assert identities(selection) == [
        (None, "shared-a"),
        (None, "shared-b"),
        ("first", "first-a"),
        ("second", "second-a"),
        ("second", "second-b"),
    ]


def test_accumulation_requires_a_composition_prefix() -> None:
    with pytest.raises(ValueError, match="prefix"):
        select_accumulated_regressions(campaign(), ("second",))


@pytest.mark.parametrize(
    ("arguments", "status"),
    [
        ({"exit_code": 0, "timed_out": False}, RegressionStatus.PASSED),
        ({"exit_code": 7, "timed_out": False}, RegressionStatus.FAILED),
        ({"exit_code": None, "timed_out": False}, RegressionStatus.ERROR),
        (
            {"exit_code": 0, "timed_out": False, "output_valid": False},
            RegressionStatus.ERROR,
        ),
        ({"exit_code": None, "timed_out": True}, RegressionStatus.TIMED_OUT),
        (
            {"exit_code": None, "timed_out": False, "skipped": True},
            RegressionStatus.SKIPPED,
        ),
    ],
)
def test_required_result_only_passes_timely_zero_valid_execution(
    arguments: dict, status: RegressionStatus
) -> None:
    result = evaluate_required_regression("shared-a", **arguments)

    assert result.required is True
    assert result.status is status
    assert result.passed is (status is RegressionStatus.PASSED)
    assert result.reason_code is (None if result.passed else "regression_failed")


def test_records_phase_specific_failure_reason() -> None:
    result = evaluate_required_regression(
        "first-a",
        exit_code=1,
        timed_out=False,
        failure_reason_code="accumulated_regression_failed",
    )

    assert result.reason_code == "accumulated_regression_failed"
