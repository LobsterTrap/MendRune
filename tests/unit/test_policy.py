import pytest

from mendrune.errors import ConfigurationError
from mendrune.policy import enforce_path_policy, matches_path


def test_glob_semantics() -> None:
    assert matches_path("src/**", "src/a/b.py")
    assert matches_path("src/*.py", "src/a.py")
    assert not matches_path("src/*.py", "src/a/b.py")
    assert not matches_path("build/**", "build-evil/file")


def test_denied_path_takes_precedence() -> None:
    with pytest.raises(ConfigurationError):
        enforce_path_policy("src/generated/a.py", ("src/**",), ("src/generated/**",))


def test_path_must_be_allowed() -> None:
    with pytest.raises(ConfigurationError):
        enforce_path_policy("tests/a.py", ("src/**",), ())
