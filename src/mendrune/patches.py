"""Strict parsing and static validation for text unified diffs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from mendrune.errors import ConfigurationError
from mendrune.models import PatchPolicyConfig
from mendrune.policy import enforce_path_policy

_HUNK = re.compile(rb"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")
_FORBIDDEN_PREFIXES = (
    b"GIT binary patch",
    b"Binary files ",
    b"diff --cc ",
    b"diff --combined ",
    b"rename from ",
    b"rename to ",
    b"similarity index ",
    b"old mode ",
    b"new mode ",
    b"new file mode ",
    b"deleted file mode ",
)


@dataclass(frozen=True)
class PatchFile:
    old_path: PurePosixPath | None
    new_path: PurePosixPath | None
    added_lines: int
    deleted_lines: int
    hunks: int


@dataclass(frozen=True)
class ParsedPatch:
    files: tuple[PatchFile, ...]

    @property
    def changed_lines(self) -> int:
        return sum(item.added_lines + item.deleted_lines for item in self.files)


def parse_patch(data: bytes, policy: PatchPolicyConfig) -> ParsedPatch:
    if not data or b"\x00" in data:
        raise ConfigurationError(
            "patch is empty or contains NUL", reason_code="patch_format_unsupported"
        )
    if len(data) > 16 * 1024 * 1024:
        raise ConfigurationError("patch exceeds size limit", reason_code="patch_format_unsupported")
    lines = data.splitlines()
    if any(line.startswith(_FORBIDDEN_PREFIXES) for line in lines):
        raise ConfigurationError(
            "patch uses an unsupported binary, combined, rename, or mode feature",
            reason_code="patch_format_unsupported",
        )

    files: list[PatchFile] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith((b"diff --git ", b"index ")) or line == b"":
            index += 1
            continue
        if not line.startswith(b"--- "):
            raise ConfigurationError(
                f"unexpected patch content at line {index + 1}",
                reason_code="patch_format_unsupported",
            )
        old_path = _parse_header_path(line[4:], prefix=b"a/")
        index += 1
        if index >= len(lines) or not lines[index].startswith(b"+++ "):
            raise ConfigurationError(
                "missing new-file header", reason_code="patch_format_unsupported"
            )
        new_path = _parse_header_path(lines[index][4:], prefix=b"b/")
        _validate_file_state(old_path, new_path, policy)
        effective_path = new_path or old_path
        assert effective_path is not None
        enforce_path_policy(effective_path.as_posix(), policy.allowed_paths, policy.denied_paths)
        index += 1

        added = deleted = hunks = 0
        while index < len(lines) and not lines[index].startswith((b"--- ", b"diff --git ")):
            if lines[index].startswith(b"index ") or lines[index] == b"":
                index += 1
                continue
            match = _HUNK.match(lines[index])
            if match is None:
                raise ConfigurationError(
                    f"expected hunk header at line {index + 1}",
                    reason_code="patch_format_unsupported",
                )
            old_expected = int(match.group(2) or b"1")
            new_expected = int(match.group(4) or b"1")
            old_seen = new_seen = 0
            hunks += 1
            index += 1
            while index < len(lines):
                body = lines[index]
                if _HUNK.match(body) or body.startswith((b"--- ", b"diff --git ")):
                    break
                if body.startswith(b"\\ No newline at end of file"):
                    index += 1
                    continue
                if not body:
                    raise ConfigurationError(
                        f"unprefixed empty hunk line at {index + 1}",
                        reason_code="patch_format_unsupported",
                    )
                marker = body[:1]
                if marker == b" ":
                    old_seen += 1
                    new_seen += 1
                elif marker == b"-":
                    old_seen += 1
                    deleted += 1
                elif marker == b"+":
                    new_seen += 1
                    added += 1
                else:
                    raise ConfigurationError(
                        f"invalid hunk line at {index + 1}",
                        reason_code="patch_format_unsupported",
                    )
                index += 1
            if old_seen != old_expected or new_seen != new_expected:
                raise ConfigurationError(
                    "hunk line counts do not match its header",
                    reason_code="patch_format_unsupported",
                )
        if hunks == 0:
            raise ConfigurationError(
                "patch file has no hunks", reason_code="patch_format_unsupported"
            )
        files.append(PatchFile(old_path, new_path, added, deleted, hunks))

    if not files:
        raise ConfigurationError(
            "patch contains no file changes", reason_code="patch_format_unsupported"
        )
    if len(files) > policy.max_files_changed_per_patch:
        raise ConfigurationError(
            "patch changes too many files", reason_code="patch_policy_violation"
        )
    parsed = ParsedPatch(tuple(files))
    if parsed.changed_lines > policy.max_changed_lines_per_patch:
        raise ConfigurationError(
            "patch changes too many lines", reason_code="patch_policy_violation"
        )
    return parsed


def _parse_header_path(value: bytes, *, prefix: bytes) -> PurePosixPath | None:
    raw = value.split(b"\t", 1)[0].split(b" ", 1)[0]
    if raw == b"/dev/null":
        return None
    if not raw.startswith(prefix):
        raise ConfigurationError(
            "patch paths must use a/ and b/ prefixes", reason_code="patch_format_unsupported"
        )
    try:
        text = raw[len(prefix) :].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigurationError(
            "patch path must be UTF-8", reason_code="patch_format_unsupported"
        ) from exc
    path = PurePosixPath(text)
    if not text or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ConfigurationError("unsafe patch path", reason_code="patch_policy_violation")
    return path


def _validate_file_state(
    old_path: PurePosixPath | None,
    new_path: PurePosixPath | None,
    policy: PatchPolicyConfig,
) -> None:
    if old_path is None and not policy.allow_new_files:
        raise ConfigurationError("new files are not allowed", reason_code="patch_policy_violation")
    if new_path is None and not policy.allow_deleted_files:
        raise ConfigurationError(
            "deleted files are not allowed", reason_code="patch_policy_violation"
        )
    if old_path is not None and new_path is not None and old_path != new_path:
        raise ConfigurationError("renames are not allowed", reason_code="patch_policy_violation")
