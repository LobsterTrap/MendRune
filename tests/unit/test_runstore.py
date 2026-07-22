from pathlib import Path

import pytest
import yaml

from mendrune.errors import MendRuneError
from mendrune.runstore import RunStore


def test_runstore_writes_atomic_yaml_and_hashes(tmp_path: Path) -> None:
    store = RunStore.create(tmp_path, "campaign", run_id="run-1")

    artifact = store.write_yaml("state/run.yaml", {"state": "created"})

    assert yaml.safe_load(artifact.path.read_text()) == {"state": "created"}
    assert len(artifact.sha256) == 64
    assert artifact.relative_path.as_posix() == "state/run.yaml"


@pytest.mark.parametrize("path", ["../escape", "/absolute", "a/../../escape", ""])
def test_runstore_rejects_unsafe_paths(tmp_path: Path, path: str) -> None:
    store = RunStore.create(tmp_path, "campaign", run_id="run-1")

    with pytest.raises(MendRuneError) as raised:
        store.write_yaml(path, {})

    assert raised.value.reason_code == "unsafe_path"


def test_hash_manifest_detects_tampering(tmp_path: Path) -> None:
    store = RunStore.create(tmp_path, "campaign", run_id="run-1")
    artifact = store.write_yaml("input/campaign.yaml", {"campaign": "test"})
    store.write_hash_manifest()
    store.verify_hash_manifest()

    artifact.path.write_text("tampered\n")
    with pytest.raises(MendRuneError) as raised:
        store.verify_hash_manifest()
    assert raised.value.reason_code == "artifact_hash_mismatch"


def test_runstore_rejects_symlink_parent(tmp_path: Path) -> None:
    store = RunStore.create(tmp_path, "campaign", run_id="run-1")
    outside = tmp_path / "outside"
    outside.mkdir()
    (store.path / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(MendRuneError):
        store.write_yaml("linked/file.yaml", {})
    assert not (outside / "file.yaml").exists()
