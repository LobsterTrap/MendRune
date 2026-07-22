"""Strict campaign configuration models."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CommandConfig(StrictModel):
    argv: tuple[str, ...]
    evidence_paths: tuple[str, ...]
    timeout_seconds: int = Field(gt=0, le=86_400)

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or any(not item or "\x00" in item for item in value):
            raise ValueError("argv must contain nonempty NUL-free strings")
        return value

    @field_validator("evidence_paths")
    @classmethod
    def validate_evidence_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("evidence_paths must contain at least one declared path")
        if len(value) != len(set(value)):
            raise ValueError("evidence_paths must not contain duplicates")
        for path in value:
            _validate_relative_posix_path(path, "evidence path")
        return value


class OracleConfig(CommandConfig):
    result_file: str

    @field_validator("result_file")
    @classmethod
    def validate_result_file(cls, value: str) -> str:
        path = PurePosixPath(value)
        if not path.is_absolute() or ".." in path.parts or "\x00" in value:
            raise ValueError("result_file must be an absolute normalized container path")
        return value


class VulnerabilityConfig(StrictModel):
    id: str
    oracle: OracleConfig

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _validate_id(value)


class PatchConfig(StrictModel):
    id: str
    path: str
    sha256: str
    adapt_with_goose: bool = False

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _validate_id(value)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _validate_relative_posix_path(value, "patch path")

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _SHA256_PATTERN.fullmatch(value):
            raise ValueError("sha256 must contain exactly 64 lowercase hexadecimal characters")
        return value


class RegressionConfig(CommandConfig):
    id: str

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _validate_id(value)


class UnitConfig(StrictModel):
    id: str
    vulnerabilities: tuple[VulnerabilityConfig, ...]
    patches: tuple[PatchConfig, ...]
    regressions: tuple[RegressionConfig, ...]

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _validate_id(value)

    @model_validator(mode="after")
    def validate_contents(self) -> UnitConfig:
        if not self.vulnerabilities:
            raise ValueError("unit must contain at least one vulnerability")
        if not self.patches:
            raise ValueError("unit must contain at least one patch")
        _ensure_unique((patch.id for patch in self.patches), "patch IDs within a unit")
        return self


class RepositoryConfig(StrictModel):
    path: str
    base_ref: str

    @field_validator("path", "base_ref")
    @classmethod
    def validate_nonempty(cls, value: str) -> str:
        if not value or "\x00" in value:
            raise ValueError("value must be nonempty and NUL-free")
        return value


class CompositionConfig(StrictModel):
    order: tuple[str, ...]

    @field_validator("order")
    @classmethod
    def validate_order(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("composition order must not be empty")
        for item in value:
            _validate_id(item)
        _ensure_unique(value, "composition order")
        return value


class BuildConfig(StrictModel):
    argv: tuple[str, ...]
    timeout_seconds: int = Field(gt=0, le=86_400)

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or any(not item or "\x00" in item for item in value):
            raise ValueError("argv must contain nonempty NUL-free strings")
        return value


class ScanConfig(CommandConfig):
    id: str
    required: bool
    raw_output: str
    normalizer: str

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _validate_id(value)

    @field_validator("required")
    @classmethod
    def required_must_be_true(cls, value: bool) -> bool:
        if not value:
            raise ValueError("optional scanners are not supported in v1")
        return value


class CommandsConfig(StrictModel):
    build: BuildConfig
    shared_regressions: tuple[RegressionConfig, ...]
    scans: tuple[ScanConfig, ...]

    @model_validator(mode="after")
    def validate_required_commands(self) -> CommandsConfig:
        if not self.shared_regressions:
            raise ValueError("at least one shared regression is required")
        if not self.scans:
            raise ValueError("at least one scanner is required")
        return self


class ExecutionConfig(StrictModel):
    image: str
    runtime: str
    network: str
    container_workdir: str
    default_timeout_seconds: int = Field(gt=0, le=86_400)
    cpus: int = Field(gt=0, le=64)
    memory_mib: int = Field(ge=128, le=1_048_576)
    pids_limit: int = Field(gt=0, le=1_048_576)
    maximum_output_bytes: int = Field(gt=0, le=1_073_741_824)
    allowed_generated_paths: tuple[str, ...] = ()
    environment: dict[str, str]

    @field_validator("image")
    @classmethod
    def validate_image(cls, value: str) -> str:
        if not re.search(r"@sha256:[0-9a-f]{64}$", value):
            raise ValueError("image must end with an immutable sha256 digest")
        return value

    @field_validator("network")
    @classmethod
    def validate_network(cls, value: str) -> str:
        if value != "none":
            raise ValueError("v1 requires network: none")
        return value

    @field_validator("allowed_generated_paths")
    @classmethod
    def validate_generated_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("allowed_generated_paths must not contain duplicates")
        for pattern in value:
            _validate_relative_posix_path(pattern, "generated path pattern", allow_glob=True)
            if pattern == ".git" or pattern.startswith(".git/"):
                raise ValueError("generated path patterns must not include .git")
        return value


class MountsConfig(StrictModel):
    evidence_source: str
    container_evidence_dir: str
    container_output_dir: str

    @field_validator("evidence_source")
    @classmethod
    def validate_evidence_source(cls, value: str) -> str:
        return _validate_relative_posix_path(value, "evidence source")

    @field_validator("container_evidence_dir", "container_output_dir")
    @classmethod
    def validate_container_directory(cls, value: str) -> str:
        path = PurePosixPath(value)
        if not value or not path.is_absolute() or ".." in path.parts or "\x00" in value:
            raise ValueError("container directories must be normalized absolute paths")
        return value

    @model_validator(mode="after")
    def validate_distinct_mounts(self) -> MountsConfig:
        if self.container_evidence_dir == self.container_output_dir:
            raise ValueError("evidence and output container directories must differ")
        return self


class PatchPolicyConfig(StrictModel):
    allowed_paths: tuple[str, ...]
    denied_paths: tuple[str, ...]
    max_files_changed_per_patch: int = Field(gt=0)
    max_changed_lines_per_patch: int = Field(gt=0)
    max_changed_lines_campaign: int = Field(gt=0)
    allow_binary: bool = False
    allow_renames: bool = False
    allow_new_files: bool = False
    allow_deleted_files: bool = False
    allow_mode_changes: bool = False

    @model_validator(mode="after")
    def reject_unsupported_patch_features(self) -> PatchPolicyConfig:
        if any(
            (
                self.allow_binary,
                self.allow_renames,
                self.allow_new_files,
                self.allow_deleted_files,
                self.allow_mode_changes,
            )
        ):
            raise ValueError("v1 does not support binary, rename, create, delete, or mode patches")
        return self

    @field_validator("allowed_paths", "denied_paths")
    @classmethod
    def validate_path_patterns(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("patch path patterns must be nonempty and unique")
        for pattern in value:
            _validate_relative_posix_path(pattern, "patch path pattern", allow_glob=True)
        return value


class ScanPolicyConfig(StrictModel):
    severity_order: tuple[str, ...]
    reject_new_findings_at_or_above: str

    @model_validator(mode="after")
    def validate_threshold(self) -> ScanPolicyConfig:
        if not self.severity_order or len(set(self.severity_order)) != len(self.severity_order):
            raise ValueError("severity_order must contain unique values")
        if self.reject_new_findings_at_or_above not in self.severity_order:
            raise ValueError("scan threshold must appear in severity_order")
        return self


class GooseConfig(StrictModel):
    enabled: bool = False
    recipe: str | None = None
    maximum_bundle_bytes: int = Field(default=131_072, gt=0)
    maximum_response_bytes: int = Field(default=131_072, gt=0)
    timeout_seconds: int = Field(default=300, gt=0, le=86_400)


class StorageConfig(StrictModel):
    runs_directory: str
    keep_failed_workspaces: bool = False


class CampaignConfig(StrictModel):
    schema_version: int
    campaign_id: str
    title: str
    repository: RepositoryConfig
    composition: CompositionConfig
    units: tuple[UnitConfig, ...]
    commands: CommandsConfig
    execution: ExecutionConfig
    mounts: MountsConfig
    patch_policy: PatchPolicyConfig
    scan_policy: ScanPolicyConfig
    goose: GooseConfig = GooseConfig()
    storage: StorageConfig

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError("schema_version must equal 1")
        return value

    @field_validator("campaign_id")
    @classmethod
    def validate_campaign_id(cls, value: str) -> str:
        return _validate_id(value)

    @model_validator(mode="after")
    def validate_campaign_relationships(self) -> CampaignConfig:
        if not self.units:
            raise ValueError("campaign must contain at least one unit")
        unit_ids = tuple(unit.id for unit in self.units)
        _ensure_unique(unit_ids, "unit IDs")
        if set(unit_ids) != set(self.composition.order):
            raise ValueError("composition.order must contain every unit ID exactly once")

        vulnerability_ids = tuple(
            vulnerability.id for unit in self.units for vulnerability in unit.vulnerabilities
        )
        _ensure_unique(vulnerability_ids, "vulnerability IDs")

        command_ids = (
            tuple(reg.id for reg in self.commands.shared_regressions)
            + tuple(scan.id for scan in self.commands.scans)
            + tuple(reg.id for unit in self.units for reg in unit.regressions)
        )
        _ensure_unique(command_ids, "regression and scanner command IDs")

        if not self.goose.enabled and any(
            patch.adapt_with_goose for unit in self.units for patch in unit.patches
        ):
            raise ValueError("adapt_with_goose requires goose.enabled")
        if self.goose.enabled and not self.goose.recipe:
            raise ValueError("goose.recipe is required when Goose is enabled")
        return self


def _validate_id(value: str) -> str:
    if not _ID_PATTERN.fullmatch(value):
        raise ValueError("ID must match ^[A-Za-z0-9][A-Za-z0-9._-]*$")
    return value


def _validate_relative_posix_path(value: str, label: str, *, allow_glob: bool = False) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError(f"{label} must be a nonempty NUL-free POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{label} must be relative and must not contain dot components")
    if not allow_glob and any(char in value for char in "*?["):
        raise ValueError(f"{label} must not contain glob syntax")
    return value


def _ensure_unique(values, label: str) -> None:
    items = tuple(values)
    if len(items) != len(set(items)):
        raise ValueError(f"{label} must be unique")
