from mendrune import __version__
from mendrune.cli import build_parser, main


def test_parser_exposes_planned_commands() -> None:
    help_text = build_parser().format_help()

    for command in ("verify", "run", "status", "report"):
        assert command in help_text


def test_main_without_command_prints_help(capsys) -> None:
    assert main([]) == 0
    assert "Verify ordered security remediation campaigns" in capsys.readouterr().out


def test_version(capsys) -> None:
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("argparse version action did not exit")

    assert __version__ in capsys.readouterr().out
