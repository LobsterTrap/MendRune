from pathlib import Path
from unittest.mock import patch

import pytest

from mendrune.errors import ConfigurationError
from mendrune.goose import validate_recipe


def test_validate_recipe_invokes_documented_command(tmp_path: Path) -> None:
    recipe = tmp_path / "recipe.yaml"
    recipe.write_text("title: test\n")
    with patch("mendrune.goose.subprocess.run") as run:
        run.return_value.returncode = 0

        validate_recipe(recipe, timeout_seconds=10)

    assert run.call_args.args[0] == ["goose", "recipe", "validate", str(recipe)]
    assert run.call_args.kwargs["timeout"] == 10


def test_validate_recipe_rejects_failure(tmp_path: Path) -> None:
    recipe = tmp_path / "recipe.yaml"
    recipe.write_text("invalid")
    with patch("mendrune.goose.subprocess.run") as run:
        run.return_value.returncode = 1
        run.return_value.stderr = "bad recipe"
        run.return_value.stdout = ""

        with pytest.raises(ConfigurationError) as raised:
            validate_recipe(recipe, timeout_seconds=10)

    assert raised.value.reason_code == "goose_recipe_invalid"
