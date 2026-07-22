"""Small, deterministic POSIX path-pattern policy."""

from __future__ import annotations

import re

from mendrune.errors import ConfigurationError


def matches_path(pattern: str, path: str) -> bool:
    """Match `*` within one component and `**` across components."""
    expression: list[str] = ["^"]
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    expression.append("(?:.*/)?")
                    index += 1
                else:
                    expression.append(".*")
                continue
            expression.append("[^/]*")
        else:
            expression.append(re.escape(character))
        index += 1
    expression.append("$")
    return re.fullmatch("".join(expression), path) is not None


def enforce_path_policy(path: str, allowed: tuple[str, ...], denied: tuple[str, ...]) -> None:
    if any(matches_path(pattern, path) for pattern in denied):
        raise ConfigurationError(
            f"patch path is denied: {path}", reason_code="patch_policy_violation"
        )
    if not any(matches_path(pattern, path) for pattern in allowed):
        raise ConfigurationError(
            f"patch path is not allowed: {path}", reason_code="patch_policy_violation"
        )
