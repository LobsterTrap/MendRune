import os
from pathlib import Path, PurePosixPath

import pytest

from mendrune.errors import ConfigurationError
from mendrune.paths import inventory_evidence


def test_inventory_evidence_is_stable_and_tracks_owners(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    (evidence / "fixtures").mkdir(parents=True)
    (evidence / "fixtures" / "b.txt").write_text("b")
    (evidence / "fixtures" / "a.txt").write_text("a")

    files = inventory_evidence(
        evidence,
        {
            "oracle-a": ("fixtures",),
            "regression-a": ("fixtures/a.txt",),
        },
    )

    assert [item.relative_path for item in files] == [
        PurePosixPath("fixtures/a.txt"),
        PurePosixPath("fixtures/b.txt"),
    ]
    assert files[0].declared_by == ("oracle-a", "regression-a")


def test_inventory_rejects_symlink(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "target"
    target.write_text("secret")
    (evidence / "link").symlink_to(target)

    with pytest.raises(ConfigurationError) as raised:
        inventory_evidence(evidence, {"oracle": ("link",)})

    assert raised.value.reason_code == "evidence_type_unsupported"


def test_inventory_rejects_special_file(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    fifo = evidence / "fifo"
    os.mkfifo(fifo)

    with pytest.raises(ConfigurationError) as raised:
        inventory_evidence(evidence, {"oracle": ("fifo",)})

    assert raised.value.reason_code == "evidence_type_unsupported"


def test_inventory_rejects_hard_link(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    first = evidence / "first"
    first.write_text("data")
    os.link(first, evidence / "second")

    with pytest.raises(ConfigurationError) as raised:
        inventory_evidence(evidence, {"oracle": ("first",)})

    assert raised.value.reason_code == "evidence_type_unsupported"
