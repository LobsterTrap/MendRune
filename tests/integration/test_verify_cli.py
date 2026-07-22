import hashlib
import subprocess
from pathlib import Path

import yaml

from mendrune.cli import main
from tests.unit.test_config import write_campaign
from tests.unit.test_models import campaign_data
from tests.unit.test_repository import create_repository


def create_campaign(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    create_repository(repository)
    evidence = tmp_path / "campaign" / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "check.py").write_text("print('check')\n")
    patches = tmp_path / "campaign" / "patches"
    patches.mkdir()
    patch = patches / "a.diff"
    patch.write_bytes(b"--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-old\n+new\n")

    data = campaign_data()
    data["repository"]["path"] = str(repository)
    data["units"][0]["patches"][0]["sha256"] = hashlib.sha256(patch.read_bytes()).hexdigest()
    data["storage"]["runs_directory"] = str(tmp_path / "runs")
    path = tmp_path / "campaign" / "campaign.yaml"
    write_campaign(path, data)
    return path


def test_verify_command_accepts_valid_campaign(tmp_path: Path, capsys) -> None:
    campaign = create_campaign(tmp_path)

    assert main(["verify", str(campaign)]) == 0
    output = capsys.readouterr().out
    assert "verified campaign example" in output


def test_verify_command_rejects_tampered_patch(tmp_path: Path, capsys) -> None:
    campaign = create_campaign(tmp_path)
    patch = campaign.parent / "patches" / "a.diff"
    patch.write_bytes(patch.read_bytes() + b"\n")

    assert main(["verify", str(campaign)]) == 2
    assert "patch_hash_mismatch" in capsys.readouterr().err


def test_verify_does_not_modify_dirty_source_worktree(tmp_path: Path) -> None:
    campaign = create_campaign(tmp_path)
    data = yaml.safe_load(campaign.read_text())
    repository = Path(data["repository"]["path"])
    source = repository / "file.txt"
    source.write_text("dirty\n")
    before = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout

    assert main(["verify", str(campaign)]) == 0
    after = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert after == before
    assert source.read_text() == "dirty\n"
