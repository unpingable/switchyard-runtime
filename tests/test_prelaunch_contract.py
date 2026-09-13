"""Public closed-contract checks; no provider or private source dependency."""
import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from switchyard import provider_runner as runner
from switchyard.nightshift_adapter import AdapterProtocolError


def vector():
    return json.loads((Path(__file__).parent / "fixtures/prelaunch-vector.json").read_bytes())


def test_prelaunch_public_vector_preserves_owner_testimony_and_nanoseconds():
    value = vector()
    runner.validate_prelaunch_closure(value)
    assert value["supervisor_attestation"]["trust_basis"] == "OWNER_ATTESTATION_NOT_INDEPENDENT_PROCESS_PROOF"
    assert runner._timestamp(value["closed_at"]) - runner._timestamp(value["supervisor_attestation"]["observed_at"]) == 1


@pytest.mark.parametrize("field,replacement", [("active_state", "active"),
    ("original_producer_terminated", False), ("alternate_writers_excluded", False)])
def test_prelaunch_public_contract_refuses_uncertain_owner_attestation(field, replacement):
    value = copy.deepcopy(vector())
    value["supervisor_attestation"][field] = replacement
    value["closure_digest"] = runner.digest(runner.PRELAUNCH_DOMAIN + runner._canonical(
        {k: v for k, v in value.items() if k != "closure_digest"}))
    with pytest.raises(AdapterProtocolError):
        runner.validate_prelaunch_closure(value)


def test_request_preflight_public_contract_requires_preclaim_owner_testimony():
    closure = copy.deepcopy(vector())
    closure["failure_code"] = "REQUEST_PREFLIGHT_FAILED"
    closure["closure_digest"] = runner.digest(runner.PRELAUNCH_DOMAIN + runner._canonical(
        {k: v for k, v in closure.items() if k != "closure_digest"}))
    runner.validate_prelaunch_closure(closure)
    closure["evidence_mode"] = "OBSERVED_CAPTURE_FAILURE"
    closure["supervisor_attestation"] = None
    closure["closure_digest"] = runner.digest(runner.PRELAUNCH_DOMAIN + runner._canonical(
        {k: v for k, v in closure.items() if k != "closure_digest"}))
    with pytest.raises(AdapterProtocolError):
        runner.validate_prelaunch_closure(closure)


@pytest.mark.parametrize("field,replacement", [("provider_claim_absent", False), ("backend_started", True)])
def test_request_preflight_public_contract_refuses_provider_claim_boundary(field, replacement):
    closure = copy.deepcopy(vector())
    closure["failure_code"] = "REQUEST_PREFLIGHT_FAILED"
    closure[field] = replacement
    closure["closure_digest"] = runner.digest(runner.PRELAUNCH_DOMAIN + runner._canonical(
        {k: v for k, v in closure.items() if k != "closure_digest"}))
    with pytest.raises(AdapterProtocolError):
        runner.validate_prelaunch_closure(closure)


def test_prelaunch_native_cli_exposes_closed_recovery_without_opening_store(tmp_path):
    state = tmp_path / "never-created.sqlite"
    for operation in ("close-prelaunch", "inspect-prelaunch"):
        result = subprocess.run([sys.executable, "-m", "switchyard.provider_runner", "--state", str(state), operation, "--help"],
            check=True, capture_output=True, text=True)
        assert operation in result.stdout
    assert not state.exists()
