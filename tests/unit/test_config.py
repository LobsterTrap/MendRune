from pathlib import Path

import pytest
import yaml

from mendrune.config import load_campaign
from mendrune.errors import ConfigurationError
from tests.unit.test_models import campaign_data


class _NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data) -> bool:
        return True


def write_campaign(path: Path, data: dict) -> None:
    path.write_text(yaml.dump(data, Dumper=_NoAliasDumper, sort_keys=False), encoding="utf-8")


def test_load_campaign(tmp_path: Path) -> None:
    path = tmp_path / "campaign.yaml"
    write_campaign(path, campaign_data())

    campaign = load_campaign(path)

    assert campaign.campaign_id == "example"


def test_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "campaign.yaml"
    path.write_text("schema_version: 1\nschema_version: 1\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="duplicate key") as raised:
        load_campaign(path)

    assert raised.value.reason_code == "invalid_yaml"


def test_rejects_aliases(tmp_path: Path) -> None:
    path = tmp_path / "campaign.yaml"
    path.write_text("value: &shared [1]\nother: *shared\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="anchors") as raised:
        load_campaign(path)

    assert raised.value.reason_code == "invalid_yaml"


def test_rejects_campaign_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.yaml"
    write_campaign(target, campaign_data())
    link = tmp_path / "campaign.yaml"
    link.symlink_to(target)

    with pytest.raises(ConfigurationError) as raised:
        load_campaign(link)

    assert raised.value.reason_code == "invalid_campaign_path"


def test_rejects_oversized_campaign(tmp_path: Path) -> None:
    path = tmp_path / "campaign.yaml"
    path.write_bytes(b"x" * 1_048_577)

    with pytest.raises(ConfigurationError) as raised:
        load_campaign(path)

    assert raised.value.reason_code == "campaign_limit_exceeded"
