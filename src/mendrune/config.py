"""Bounded safe YAML campaign loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
import yaml.constructor
import yaml.resolver
from pydantic import ValidationError
from yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent, ScalarEvent

from mendrune.errors import ConfigurationError
from mendrune.models import CampaignConfig

MAX_CAMPAIGN_BYTES = 1_048_576
MAX_YAML_DEPTH = 64
MAX_YAML_NODES = 100_000
MAX_SCALAR_BYTES = 262_144


class _UniqueSafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueSafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_campaign(path: Path) -> CampaignConfig:
    """Load and structurally validate a bounded campaign YAML file."""
    try:
        if path.is_symlink() or not path.is_file():
            raise ConfigurationError(
                f"campaign must be a regular non-symlink file: {path}",
                reason_code="invalid_campaign_path",
            )
        data = path.read_bytes()
    except OSError as exc:
        raise ConfigurationError(
            f"unable to read campaign: {exc}", reason_code="invalid_campaign_path"
        ) from exc

    if len(data) > MAX_CAMPAIGN_BYTES:
        raise ConfigurationError(
            f"campaign exceeds {MAX_CAMPAIGN_BYTES} bytes",
            reason_code="campaign_limit_exceeded",
        )

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigurationError("campaign must be UTF-8", reason_code="invalid_yaml") from exc

    _validate_yaml_events(text)
    try:
        raw = yaml.load(text, Loader=_UniqueSafeLoader)
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"invalid campaign YAML: {exc}", reason_code="invalid_yaml"
        ) from exc
    if not isinstance(raw, dict):
        raise ConfigurationError("campaign root must be a mapping", reason_code="invalid_yaml")

    try:
        return CampaignConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigurationError(
            f"invalid campaign: {exc}", reason_code="invalid_campaign"
        ) from exc


def _validate_yaml_events(text: str) -> None:
    depth = 0
    nodes = 0
    try:
        events = yaml.parse(text, Loader=yaml.SafeLoader)
        for event in events:
            if isinstance(event, AliasEvent):
                raise ConfigurationError("YAML aliases are not allowed", reason_code="invalid_yaml")
            if getattr(event, "anchor", None) is not None:
                raise ConfigurationError("YAML anchors are not allowed", reason_code="invalid_yaml")
            if isinstance(event, CollectionStartEvent):
                depth += 1
                nodes += 1
                if depth > MAX_YAML_DEPTH:
                    raise ConfigurationError(
                        "YAML nesting limit exceeded", reason_code="campaign_limit_exceeded"
                    )
            elif isinstance(event, CollectionEndEvent):
                depth -= 1
            elif isinstance(event, ScalarEvent):
                nodes += 1
                if len(event.value.encode("utf-8")) > MAX_SCALAR_BYTES:
                    raise ConfigurationError(
                        "YAML scalar limit exceeded", reason_code="campaign_limit_exceeded"
                    )
            if nodes > MAX_YAML_NODES:
                raise ConfigurationError(
                    "YAML node limit exceeded", reason_code="campaign_limit_exceeded"
                )
    except ConfigurationError:
        raise
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"invalid campaign YAML: {exc}", reason_code="invalid_yaml"
        ) from exc
