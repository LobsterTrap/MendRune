"""Non-executing campaign verification."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from mendrune.config import load_campaign
from mendrune.errors import ConfigurationError
from mendrune.goose import validate_recipe
from mendrune.models import CampaignConfig
from mendrune.patches import parse_patch
from mendrune.paths import EvidenceFile, inventory_evidence, resolve_directory
from mendrune.repository import VerifiedRepository, verify_repository


@dataclass(frozen=True)
class VerifiedPatch:
    unit_id: str
    patch_id: str
    path: Path
    sha256: str


@dataclass(frozen=True)
class VerifiedCampaign:
    path: Path
    config: CampaignConfig
    repository: VerifiedRepository
    patches: tuple[VerifiedPatch, ...]
    evidence: tuple[EvidenceFile, ...]
    evidence_root: Path
    runs_directory: Path


def verify_campaign(path: Path) -> VerifiedCampaign:
    campaign_path = path.resolve(strict=True)
    config = load_campaign(campaign_path)
    campaign_root = campaign_path.parent

    repository_path = _resolve_config_path(campaign_root, config.repository.path)
    repository = verify_repository(repository_path, config.repository.base_ref)

    evidence_root = resolve_directory(
        _resolve_config_path(campaign_root, config.mounts.evidence_source),
        label="evidence root",
    )
    declarations = _evidence_declarations(config)
    evidence = inventory_evidence(evidence_root, declarations)
    _validate_container_evidence_arguments(config, declarations)

    patches: list[VerifiedPatch] = []
    patch_changed_paths: set[str] = set()
    for unit in config.units:
        for patch in unit.patches:
            patch_path = _regular_file(campaign_root, patch.path, "patch")
            patch_bytes = patch_path.read_bytes()
            digest = hashlib.sha256(patch_bytes).hexdigest()
            if digest != patch.sha256:
                raise ConfigurationError(
                    f"patch hash mismatch: {unit.id}/{patch.id}",
                    reason_code="patch_hash_mismatch",
                )
            parsed = parse_patch(patch_bytes, config.patch_policy)
            for changed_file in parsed.files:
                changed = changed_file.new_path or changed_file.old_path
                if changed is not None:
                    patch_changed_paths.add(changed.as_posix())
            patches.append(VerifiedPatch(unit.id, patch.id, patch_path, digest))

    _validate_generated_path_overlaps(config, patch_changed_paths)

    if config.goose.enabled:
        assert config.goose.recipe is not None
        recipe = _regular_file(campaign_root, config.goose.recipe, "Goose recipe")
        validate_recipe(recipe, timeout_seconds=config.goose.timeout_seconds)

    runs_directory = _resolve_config_path(campaign_root, config.storage.runs_directory)
    if _is_beneath(repository.path, runs_directory):
        raise ConfigurationError(
            "runs directory must be outside the target repository",
            reason_code="unsafe_path",
        )

    return VerifiedCampaign(
        path=campaign_path,
        config=config,
        repository=repository,
        patches=tuple(patches),
        evidence=evidence,
        evidence_root=evidence_root,
        runs_directory=runs_directory,
    )


def _evidence_declarations(config: CampaignConfig) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    for regression in config.commands.shared_regressions:
        result[f"shared-regression:{regression.id}"] = regression.evidence_paths
    for scanner in config.commands.scans:
        result[f"scanner:{scanner.id}"] = scanner.evidence_paths
    for unit in config.units:
        for vulnerability in unit.vulnerabilities:
            result[f"oracle:{vulnerability.id}"] = vulnerability.oracle.evidence_paths
        for regression in unit.regressions:
            result[f"unit-regression:{unit.id}:{regression.id}"] = regression.evidence_paths
    return result


def _validate_container_evidence_arguments(
    config: CampaignConfig, declarations: dict[str, tuple[str, ...]]
) -> None:
    prefix = config.mounts.container_evidence_dir.rstrip("/") + "/"
    commands: dict[str, tuple[str, ...]] = {}
    for regression in config.commands.shared_regressions:
        commands[f"shared-regression:{regression.id}"] = regression.argv
    for scanner in config.commands.scans:
        commands[f"scanner:{scanner.id}"] = scanner.argv
    for unit in config.units:
        for vulnerability in unit.vulnerabilities:
            commands[f"oracle:{vulnerability.id}"] = vulnerability.oracle.argv
        for regression in unit.regressions:
            commands[f"unit-regression:{unit.id}:{regression.id}"] = regression.argv

    for owner, argv in commands.items():
        declared = declarations[owner]
        for argument in argv:
            if not argument.startswith(prefix):
                continue
            relative = argument[len(prefix) :]
            if not any(
                relative == item or relative.startswith(item.rstrip("/") + "/") for item in declared
            ):
                raise ConfigurationError(
                    f"{owner} references undeclared evidence: {argument}",
                    reason_code="evidence_paths_missing",
                )


def _validate_generated_path_overlaps(
    config: CampaignConfig, patch_changed_paths: set[str]
) -> None:
    for pattern in config.execution.allowed_generated_paths:
        static_prefix = pattern.split("*", 1)[0].rstrip("/")
        for changed_path in patch_changed_paths:
            if changed_path == static_prefix or changed_path.startswith(static_prefix + "/"):
                raise ConfigurationError(
                    f"generated path pattern overlaps patch changes: {pattern}",
                    reason_code="generated_path_policy_invalid",
                )


def _resolve_config_path(root: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path.resolve(strict=False)


def _regular_file(root: Path, value: str, label: str) -> Path:
    path = _resolve_config_path(root, value)
    try:
        campaign_relative = path.relative_to(root.resolve())
    except ValueError as exc:
        raise ConfigurationError(
            f"{label} escapes campaign directory: {value}", reason_code="unsafe_path"
        ) from exc
    current = root.resolve()
    for part in campaign_relative.parts:
        current = current / part
        if current.is_symlink():
            raise ConfigurationError(
                f"{label} path contains a symlink: {value}", reason_code="unsafe_path"
            )
    if not path.is_file():
        raise ConfigurationError(
            f"{label} must be a regular file: {value}", reason_code="unsafe_path"
        )
    return path


def _is_beneath(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
