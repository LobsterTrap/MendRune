import yaml

from mendrune import __version__
from mendrune.cli import build_parser, main
from mendrune.errors import ConfigurationError, MendRuneError
from mendrune.runstore import RunStore


def test_parser_exposes_planned_commands() -> None:
    help_text = build_parser().format_help()

    for command in ("verify", "run", "status", "report"):
        assert command in help_text


def test_main_without_command_prints_help(capsys) -> None:
    assert main([]) == 0
    assert "Verify ordered security remediation campaigns" in capsys.readouterr().out


def test_status_and_report_read_stored_records(tmp_path, capsys) -> None:
    store = RunStore.create(tmp_path, "campaign", run_id="run-1")
    store.write_yaml("run.yaml", {"state": "accepted"})

    assert main(["--runs-root", str(tmp_path), "status", "run-1"]) == 0
    assert yaml.safe_load(capsys.readouterr().out) == {"state": "accepted"}
    assert main(["--runs-root", str(tmp_path), "report", "run-1"]) == 0
    assert yaml.safe_load(capsys.readouterr().out)["verdict"] is None


def test_status_fails_for_missing_record(tmp_path, capsys) -> None:
    assert main(["--runs-root", str(tmp_path), "status", "missing"]) == 2
    assert "artifact_missing" in capsys.readouterr().err


def test_run_maps_outcomes_to_exit_categories(monkeypatch, capsys) -> None:
    monkeypatch.setattr("mendrune.cli.run_campaign", lambda path: {"run_id": "accepted-1"})
    assert main(["run", "campaign.yaml"]) == 0
    assert "accepted run accepted-1" in capsys.readouterr().out

    cases = (
        (ConfigurationError("bad", reason_code="invalid_campaign"), 2),
        (MendRuneError("failed", reason_code="cumulative_build_failed"), 3),
        (MendRuneError("infra", reason_code="container_launch_failed"), 4),
        (MendRuneError("bug", reason_code="unexpected_exception"), 5),
    )
    for error, expected in cases:

        def fail(path, error=error):
            raise error

        monkeypatch.setattr("mendrune.cli.run_campaign", fail)
        assert main(["run", "campaign.yaml"]) == expected
        assert error.reason_code in capsys.readouterr().err


def test_version(capsys) -> None:
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("argparse version action did not exit")

    assert __version__ in capsys.readouterr().out
