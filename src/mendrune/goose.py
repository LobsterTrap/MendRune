"""Bounded Goose recipe validation and adaptation helpers."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from mendrune.errors import ConfigurationError


def validate_recipe(recipe: Path, *, timeout_seconds: int) -> None:
    """Validate a Goose recipe without starting a recipe run."""
    environment = {
        key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}
    }
    try:
        result = subprocess.run(
            ["goose", "recipe", "validate", os.fspath(recipe)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConfigurationError(
            f"unable to validate Goose recipe: {exc}", reason_code="goose_recipe_invalid"
        ) from exc
    if result.returncode != 0:
        diagnostic = (result.stderr or result.stdout).strip()[:2000]
        raise ConfigurationError(
            f"Goose recipe validation failed: {diagnostic}",
            reason_code="goose_recipe_invalid",
        )
