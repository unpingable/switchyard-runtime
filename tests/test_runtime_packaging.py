import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    not (ROOT / "SOURCE-PROVENANCE.json").is_file(),
    reason="source-export installation check",
)


def test_installed_runner_has_declared_dependency_schemas_and_entry_point(tmp_path):
    probe = """
import importlib.metadata as metadata
import importlib.resources as resources
from pathlib import Path
import sys
import switchyard.provider_runner as runner
import switchyard.review_verifier as review_verifier
assert Path(runner.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
assert Path(review_verifier.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
provenance_path = Path(sys.argv[1])
provenance = json.loads(provenance_path.read_text())
runner.verify_runner_provenance(
    provenance_path,
    {"switchyard_owner_head": provenance["canonical_revision"]},
)
distribution = metadata.distribution('switchyard-codex-foreman')
requirements = {item.replace(' ', '') for item in distribution.requires or ()}
assert 'jsonschema[format]>=4.10' in requirements
scripts = {item.name: item.value for item in distribution.entry_points if item.group == 'console_scripts'}
assert scripts['switchyard-provider-runner'] == 'switchyard.provider_runner:main'
assert scripts['switchyard-review-verifier'] == 'switchyard.review_verifier:main'
schemas = resources.files('switchyard').joinpath('schemas')
names = sorted(item.name for item in schemas.iterdir() if item.name.endswith('.json'))
assert set(names) == {
    'nightshift.orientation-packet.v1.schema.json',
    'nightshift.provider-dispatch-occurrence.v1.schema.json',
    'nightshift.worker-start-request.v3.schema.json',
    'switchyard.codex-provider-admission.v1.schema.json',
    'switchyard.codex-provider-admission.beta.v1.schema.json',
    'switchyard.codex-provider-admission.beta-final.v1.schema.json',
    'switchyard.codex-provider-admission.bounded-turn.v1.schema.json',
    'switchyard.codex-provider-admission.bounded-turn-echo.v1.schema.json',
    'switchyard.codex-provider-admission.bounded-turn-echo.v2.schema.json',
}
for name in names: assert json.loads(schemas.joinpath(name).read_text())['$schema']
"""
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import json\n" + probe,
            str(ROOT / "SOURCE-PROVENANCE.json"),
        ],
        cwd=tmp_path, env=environment, check=True, capture_output=True, text=True,
    )
    result = subprocess.run(
        [sys.executable, "-I", "-m", "switchyard.provider_runner", "--state", "unused", "run", "--help"],
        cwd=tmp_path, env=environment, check=True, capture_output=True, text=True,
    )
    assert "--source-provenance" in result.stdout
    review = subprocess.run(
        [str(Path(sys.executable).with_name("switchyard-review-verifier")), "--help"],
        cwd=tmp_path, env=environment, check=True, capture_output=True, text=True,
    )
    assert "--config" in review.stdout


def test_export_manifest_binds_every_declared_file():
    manifest = json.loads((ROOT / "SOURCE-PROVENANCE.json").read_text())
    assert manifest["canonical_revision"]
    assert "src/switchyard/provider_runner.py" in manifest["files"]
    assert "src/switchyard/review_verifier.py" in manifest["files"]
    assert "tests/test_review_verifier_export.py" in manifest["files"]
    assert "tests/test_runtime_packaging.py" in manifest["files"]
    for name, item in manifest["files"].items():
        raw = (ROOT / name).read_bytes()
        assert len(raw) == item["bytes"]
        assert hashlib.sha256(raw).hexdigest() == item["sha256"]
