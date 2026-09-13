"""Public source-cut checks for the closed local review verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from switchyard import review_verifier as verifier


def digest(byte: str) -> str:
    return "sha256:" + byte * 64


def config() -> dict:
    return {
        "schema": verifier.CONFIG_SCHEMA,
        "reviewer_id": "independent-reviewer",
        "author_principal": "proposal-author",
        "excluded_thread_ids": [],
        "switchyard_state_path": "/tmp/review-store.sqlite",
        "nightshift_foreman_program": "/tmp/nightshift-foreman",
        "nightshift_foreman_sha256": digest("a"),
        "nightshift_state_path": "/tmp/foreman-store.sqlite",
        "nightshift_run_id": "review-run",
        "brief_manifest_pointer": ["acceptance_tests", "0"],
        "brief_contract": "example.review-manifest/v1",
        "route": {
            "codex_source_head": "source-revision",
            "app_server_executable_sha256": digest("b"),
            "provider": "example-provider",
            "model": "example-model",
            "adapter_id": "example.adapter",
            "adapter_version": "1.0.0",
            "adapter_protocol": "example.adapter/v1",
        },
        "limits": {
            "max_result_bytes": 4096,
            "max_custody_bytes": 4096,
            "max_events_bytes": 4096,
            "foreman_timeout_seconds": 1,
        },
    }


def test_load_config_accepts_exact_closed_public_shape(tmp_path: Path) -> None:
    value = config()
    raw = verifier.canonical(value)
    path = tmp_path / "config.json"
    path.write_bytes(raw)
    assert verifier.load_config(path) == (
        value,
        "sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def test_load_config_refuses_an_unrecognized_member(tmp_path: Path) -> None:
    value = config()
    value["extra"] = "not part of the contract"
    path = tmp_path / "config.json"
    path.write_bytes(verifier.canonical(value))
    with pytest.raises(verifier.VerificationError, match="fields do not match"):
        verifier.load_config(path)
