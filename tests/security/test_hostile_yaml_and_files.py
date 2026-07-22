import os
from pathlib import Path

import pytest

from mendrune.config import (
    MAX_CAMPAIGN_BYTES,
    MAX_SCALAR_BYTES,
    MAX_YAML_DEPTH,
    MAX_YAML_NODES,
    load_campaign,
)
from mendrune.errors import ConfigurationError
from mendrune.paths import MAX_EVIDENCE_FILE_BYTES, inventory_evidence
from tests.unit.test_config import write_campaign
from tests.unit.test_models import campaign_data


def test_rejects_exponential_alias_bomb(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign.yaml"
    campaign.write_text(
        "a: &a [x, x, x, x, x, x, x, x, x]\n"
        "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
        "c: [*b, *b, *b, *b, *b, *b, *b, *b, *b]\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError) as raised:
        load_campaign(campaign)

    assert raised.value.reason_code == "invalid_yaml"


@pytest.mark.parametrize(
    "document",
    [
        "value: " + "[" * (MAX_YAML_DEPTH + 1) + "0" + "]" * (MAX_YAML_DEPTH + 1),
        "value:\n" + "  - x\n" * MAX_YAML_NODES,
        "value: " + "x" * (MAX_SCALAR_BYTES + 1),
    ],
    ids=["depth", "nodes", "scalar"],
)
def test_rejects_yaml_structural_limit_bombs(tmp_path: Path, document: str) -> None:
    campaign = tmp_path / "campaign.yaml"
    campaign.write_text(document, encoding="utf-8")

    with pytest.raises(ConfigurationError) as raised:
        load_campaign(campaign)

    assert raised.value.reason_code == "campaign_limit_exceeded"


def test_rejects_campaign_byte_limit_before_yaml_parsing(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign.yaml"
    campaign.write_bytes(b"x" * (MAX_CAMPAIGN_BYTES + 1))

    with pytest.raises(ConfigurationError) as raised:
        load_campaign(campaign)

    assert raised.value.reason_code == "campaign_limit_exceeded"


@pytest.mark.parametrize("kind", ["symlink", "fifo", "hardlink"])
def test_rejects_non_unique_regular_evidence(tmp_path: Path, kind: str) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    source = evidence / "source"
    source.write_text("untrusted evidence", encoding="utf-8")
    hostile = evidence / "hostile"
    if kind == "symlink":
        hostile.symlink_to(source)
    elif kind == "fifo":
        os.mkfifo(hostile)
    else:
        os.link(source, hostile)

    with pytest.raises(ConfigurationError) as raised:
        inventory_evidence(evidence, {"oracle": (hostile.name,)})

    assert raised.value.reason_code == "evidence_type_unsupported"


def test_rejects_sparse_oversized_evidence_without_reading_it(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    oversized = evidence / "oversized.bin"
    with oversized.open("wb") as stream:
        stream.truncate(MAX_EVIDENCE_FILE_BYTES + 1)

    with pytest.raises(ConfigurationError) as raised:
        inventory_evidence(evidence, {"oracle": (oversized.name,)})

    assert raised.value.reason_code == "evidence_limit_exceeded"


def test_rejects_campaign_symlink_and_fifo_without_consuming_them(tmp_path: Path) -> None:
    target = tmp_path / "target.yaml"
    write_campaign(target, campaign_data())
    symlink = tmp_path / "linked.yaml"
    symlink.symlink_to(target)
    fifo = tmp_path / "campaign.fifo"
    os.mkfifo(fifo)

    for hostile in (symlink, fifo):
        with pytest.raises(ConfigurationError) as raised:
            load_campaign(hostile)
        assert raised.value.reason_code == "invalid_campaign_path"


def test_hostile_yaml_tags_are_inert(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    campaign = tmp_path / "campaign.yaml"
    campaign.write_text(
        f"value: !!python/object/apply:pathlib.Path ['{marker}']\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError) as raised:
        load_campaign(campaign)

    assert raised.value.reason_code == "invalid_yaml"
    assert not marker.exists()
