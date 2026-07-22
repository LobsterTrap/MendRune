import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from mendrune.cli import main

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_documented_example_generates_and_verifies_without_podman(tmp_path: Path, capsys) -> None:
    example = tmp_path / "example"
    example.mkdir()
    shutil.copy2(PROJECT_ROOT / "campaigns" / "example" / "setup.py", example / "setup.py")

    subprocess.run([sys.executable, str(example / "setup.py")], check=True)
    campaign = example / "generated" / "campaign.yaml"
    data = yaml.safe_load(campaign.read_text())

    assert len(data["repository"]["base_ref"]) == 40
    assert data["execution"]["image"].endswith("sha256:" + "0" * 64)
    assert main(["verify", str(campaign)]) == 0
    assert "verified campaign documented-example" in capsys.readouterr().out
