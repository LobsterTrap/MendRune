import hashlib
from pathlib import Path

import pytest
import yaml

from mendrune.errors import ConfigurationError
from mendrune.paths import inventory_evidence
from mendrune.storage import capture_evidence, write_evidence_manifest


def test_capture_evidence_hashes_snapshot_and_writes_manifest(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "check.py").write_text("print('ok')\n")
    inventory = inventory_evidence(source, {"oracle:one": ("check.py",)})

    captured = capture_evidence(inventory, tmp_path / "snapshot")
    manifest = tmp_path / "manifest.yaml"
    write_evidence_manifest(manifest, captured)

    expected = hashlib.sha256(b"print('ok')\n").hexdigest()
    assert captured[0].sha256 == expected
    assert captured[0].snapshot_path.read_text() == "print('ok')\n"
    document = yaml.safe_load(manifest.read_text())
    assert document["files"][0]["sha256"] == expected
    assert document["files"][0]["declared_by"] == ["oracle:one"]


def test_capture_rejects_existing_destination(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "check.py").write_text("ok")
    inventory = inventory_evidence(source, {"oracle:one": ("check.py",)})
    destination = tmp_path / "snapshot"
    destination.mkdir()

    with pytest.raises(ConfigurationError) as raised:
        capture_evidence(inventory, destination)

    assert raised.value.reason_code == "evidence_manifest_mismatch"
