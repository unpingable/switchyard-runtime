from __future__ import annotations

import copy
import hashlib
import os
import json
import queue
import sqlite3
import threading
import sys
from pathlib import Path

import pytest

from packet_fixture import packet_obj, seal_obj
from switchyard.appserver import AcquisitionCut, ServerMessage
from switchyard.config import BackendIdentity, Config
from switchyard.nightshift_adapter import (
    ADAPTER_ID,
    ADAPTER_PROTOCOL,
    ADAPTER_VERSION,
    BRIEF_DOMAIN,
    MAXIMUM_CONTROL_INPUT_BYTES,
    NOT_STARTED_DOMAIN,
    OUTCOME_SCHEMA,
    RAW_APP_SERVER_EVENT_DOMAIN,
    RAW_DOMAIN,
    RECEIPT_DOMAIN,
    START_DOMAIN,
    AdapterProtocolError,
    AdapterStore,
    NightshiftAdapter,
    _canonical,
    _digest,
    _load_closed,
    _preflight_existing_store,
    _raw_digest,
    _validate_interoperable_extension,
    _without,
    START_FIELDS,
    binding_from_start,
    capabilities,
    main,
    receipt_from_outcome,
    validate_receipt,
    validate_start,
)


class FakeAppServer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.responses: list[tuple[object, dict]] = []
        self.notifications: queue.Queue[ServerMessage] = queue.Queue()
        self.server_requests: queue.Queue[ServerMessage] = queue.Queue()
        self.threads: dict[str, dict] = {}
        self.thread_count = 0
        self.turn_count = 0
        self.acquisition_diagnostics: list[str] = []
        self.quiesce_callback = None
        self.quiesced = False
        self.forced_loss_generation = 0
        self.process_disposition = "EXITED"
        self.quiesce_error = None

    def request(self, method: str, params: dict) -> dict:
        self.calls.append((method, params))
        if method == "thread/start":
            self.thread_count += 1
            thread_id = f"thread-{self.thread_count}"
            thread = {"id": thread_id, "status": {"type": "idle"}, "turns": []}
            self.threads[thread_id] = thread
            return {"thread": copy.deepcopy(thread)}
        if method == "turn/start":
            self.turn_count += 1
            turn_id = f"turn-{self.turn_count}"
            thread = self.threads[params["threadId"]]
            thread["status"] = {"type": "active", "activeTurnId": turn_id}
            return {"turn": {"id": turn_id, "status": "inProgress"}}
        if method == "thread/read":
            return {"thread": copy.deepcopy(self.threads[params["threadId"]])}
        if method == "thread/resume":
            thread = self.threads[params["threadId"]]
            thread["status"] = {"type": "idle"}
            return {"thread": copy.deepcopy(thread)}
        raise AssertionError(f"unexpected App Server method: {method}")

    def respond(self, request_id: object, result: dict) -> None:
        self.responses.append((request_id, result))

    def drain_acquisition_diagnostics(self) -> list[str]:
        diagnostics = list(self.acquisition_diagnostics)
        self.acquisition_diagnostics.clear()
        return diagnostics

    def quiesce_acquisition(self, timeout: float = 5.0) -> AcquisitionCut:
        del timeout
        if self.quiesce_error is not None:
            raise self.quiesce_error
        if self.quiesce_callback is not None:
            self.quiesce_callback()
        self.quiesced = True
        generation = self.forced_loss_generation + len(self.acquisition_diagnostics)
        return AcquisitionCut(True, generation, self.process_disposition)


def make_config(tmp_path: Path) -> Config:
    home = tmp_path / "codex-home"
    home.mkdir(exist_ok=True)
    return Config(
        github_repo=None,
        allowed_actors=frozenset(),
        dispatch_label="codex-dispatch",
        poll_seconds=1,
        state_path=tmp_path / "switchyard.sqlite",
        codex_executable=tmp_path / "codex",
        codex_expected_version="codex-cli 0.150.1",
        codex_expected_sha256="a" * 64,
        codex_home=home,
        cwd_allow_roots=(tmp_path,),
        allow_interrupt=False,
        allow_approval_responses=False,
    )


def make_adapter(
    tmp_path: Path, appserver: FakeAppServer, state_name: str = "adapter.sqlite",
) -> tuple[NightshiftAdapter, AdapterStore]:
    config = make_config(tmp_path)
    identity = BackendIdentity(
        executable=config.codex_executable,
        version=config.codex_expected_version,
        sha256=config.codex_expected_sha256,
        home=config.codex_home,
    )
    store = AdapterStore(tmp_path / state_name)
    return NightshiftAdapter(identity, "qualified-isolated", appserver, store, config), store


def terminal_predecessor(packet_digest: str) -> dict:
    value = {
        "schema": "nightshift.worker-terminal-receipt/v1",
        "receipt_digest": "sha256:" + "0" * 64,
        "packet_digest": packet_digest,
        "run_id": "run-fixture",
        "work_item_id": "packet-v1",
        "attempt_id": "attempt-predecessor",
        "adapter_id": "fixture-adapter",
        "adapter_version": "fixture.adapter/v1",
        "provider_identity": "provider-fixture",
        "model_identity": "model-fixture",
        "session_identity": None,
        "thread_identity": None,
        "turn_identity": None,
        "queue_identity": None,
        "started_at": "2026-08-30T12:00:00Z",
        "ended_at": "2026-08-30T12:01:00Z",
        "state": "EXACT-UNKNOWN-STATE",
        "result_classification": "INDEPENDENT-CLASSIFICATION",
        "repositories": [],
        "tests": ["fixture"],
        "evidence": ["exact predecessor"],
        "live_or_production_mutations": [],
        "remaining_trigger": "none",
        "next_lawful_action": "inspect",
        "human_questions": [],
        "teardown": {"live_runtime": "none", "secrets": "none", "teardown": "complete"},
        "extensions": {"unknown_raw_extension": {"preserve": ["exact", "bytes"]}},
    }
    value["receipt_digest"] = _digest(RECEIPT_DOMAIN, _without(value, "receipt_digest"))
    return value


def not_started_predecessor(packet_digest: str) -> dict:
    value = {
        "schema": "nightshift.work-item-not-started-receipt/v1",
        "receipt_digest": "sha256:" + "0" * 64,
        "packet_digest": packet_digest,
        "run_id": "run-fixture",
        "work_item_id": "packet-v1",
        "recorded_at": "2026-08-30T12:01:00Z",
        "state": "NOT-STARTED",
        "result_classification": "DEPENDENCY-NOT-TERMINAL",
        "evidence": ["fixture"],
        "remaining_trigger": "dependency",
        "next_lawful_action": "inspect",
        "human_questions": [],
        "extensions": {},
    }
    value["receipt_digest"] = _digest(NOT_STARTED_DOMAIN, _without(value, "receipt_digest"))
    return value


def build_request_brief(tmp_path: Path, attempt_id: str = "attempt-fixture") -> tuple[dict, bytes, bytes]:
    packet = packet_obj()
    seal_obj(packet)
    packet_raw = json.dumps(packet, indent=2, ensure_ascii=False).encode("utf-8")
    item = next(item for item in packet["work_items"] if item["id"] == "switchyard-transport")
    receipt = terminal_predecessor(packet["packet_digest"])
    receipt_raw = json.dumps(receipt, indent=2, ensure_ascii=False).encode("utf-8")
    execution = {
        "adapter_id": ADAPTER_ID,
        "workspace_identity": str(tmp_path),
        "resource_lock_keys": ["repository:switchyard-fixture"],
        "provider_model_class": "large-model",
    }
    brief = {
        "schema": "nightshift.worker-brief-basis/v2",
        "packet_digest": packet["packet_digest"],
        "packet_source": {
            "retained_raw_digest": _raw_digest(RAW_DOMAIN, packet_raw),
            "encoding": "hex",
            "bytes_hex": packet_raw.hex(),
        },
        "work_item": {
            "contract": "nightshift.orientation-packet/v1#work-item",
            "canonical_json": _canonical(item).decode("utf-8"),
        },
        "predecessor_receipts": {
            "packet-v1": {
                "receipt_kind": "terminal",
                "retained_raw_digest": _raw_digest(RAW_DOMAIN, receipt_raw),
                "encoding": "hex",
                "bytes_hex": receipt_raw.hex(),
            }
        },
        "global_constraints": {
            "contract": "nightshift.orientation-packet/v1#global-constraints",
            "canonical_json": _canonical(packet["global_constraints"]).decode("utf-8"),
        },
        "execution": {
            "contract": "nightshift.foreman-execution-profile/v2#work-item",
            "canonical_json": _canonical(execution).decode("utf-8"),
        },
    }
    brief_raw = _canonical(brief)
    request = {
        "schema": "nightshift.worker-start-request/v2",
        "request_digest": "sha256:" + "0" * 64,
        "adapter_id": ADAPTER_ID,
        "adapter_version": ADAPTER_VERSION,
        "adapter_protocol": ADAPTER_PROTOCOL,
        "packet_digest": packet["packet_digest"],
        "run_id": "run-fixture",
        "work_item_id": "switchyard-transport",
        "attempt_id": attempt_id,
        "worker_brief_digest": _raw_digest(BRIEF_DOMAIN, brief_raw),
        "workspace_identity": str(tmp_path),
        "provider_model_class": "large-model",
        "timeout_seconds": 300,
        "maximum_output_bytes": 65536,
        "recursive_worker_swarms_forbidden": True,
        "approval_policy": "SURFACE_ONLY_NO_RESPONSE",
        "expected_receipt_schema": "nightshift.worker-terminal-receipt/v1",
    }
    request["request_digest"] = _digest(START_DOMAIN, _without(request, "request_digest"))
    return request, brief_raw, receipt_raw


def reseal_start(request: dict) -> None:
    request["request_digest"] = _digest(START_DOMAIN, _without(request, "request_digest"))


def rebind_predecessor(
    request: dict, brief: dict, receipt_raw: bytes, receipt_kind: str = "terminal",
) -> tuple[dict, bytes]:
    rebound = copy.deepcopy(brief)
    source = rebound["predecessor_receipts"]["packet-v1"]
    source["receipt_kind"] = receipt_kind
    source["retained_raw_digest"] = _raw_digest(RAW_DOMAIN, receipt_raw)
    source["bytes_hex"] = receipt_raw.hex()
    raw = _canonical(rebound)
    request = copy.deepcopy(request)
    request["worker_brief_digest"] = _raw_digest(BRIEF_DOMAIN, raw)
    reseal_start(request)
    return request, raw


def worker_outcome(state: str = "COMPLETE", classification: str = "EXACT-RAW") -> dict:
    return {
        "schema": OUTCOME_SCHEMA,
        "state": state,
        "result_classification": classification,
        "repositories": [],
        "tests": ["focused adapter lifecycle"],
        "evidence": ["worker-authored outcome"],
        "live_or_production_mutations": [],
        "remaining_trigger": "none",
        "next_lawful_action": "close occurrence",
        "human_questions": [],
        "teardown": {"live_runtime": "none", "secrets": "none", "teardown": "complete"},
        "extensions": {},
    }


def completion_message(thread_id: str, turn_id: str, outcome: dict) -> ServerMessage:
    raw = {
        "method": "turn/completed",
        "params": {
            "threadId": thread_id,
            "turnId": turn_id,
            "turn": {
                "id": turn_id,
                "status": "completed",
                "items": [{"type": "agentMessage", "text": _canonical(outcome).decode("utf-8")}],
            },
        },
    }
    return ServerMessage(raw, raw_bytes=(json.dumps(raw, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


def test_descriptor_inputs_refuse_symlink_and_oversize(tmp_path: Path) -> None:
    request, _, _ = build_request_brief(tmp_path)
    request_path = tmp_path / "request.json"
    request_path.write_bytes(_canonical(request))
    symlink = tmp_path / "request-link.json"
    symlink.symlink_to(request_path)
    with pytest.raises(AdapterProtocolError, match="unable to open exact"):
        _load_closed(symlink, START_FIELDS)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (MAXIMUM_CONTROL_INPUT_BYTES + 1))
    with pytest.raises(AdapterProtocolError, match="bounded regular file"):
        _load_closed(oversized, START_FIELDS)


@pytest.mark.parametrize(
    "case",
    ["malformed-request", "oversized-request", "malformed-brief", "oversized-brief"],
)
def test_start_cli_refuses_input_before_any_provider_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    request, brief_raw, _ = build_request_brief(tmp_path)
    request_path = tmp_path / "request.json"
    brief_path = tmp_path / "brief.json"
    request_path.write_bytes(_canonical(request))
    brief_path.write_bytes(brief_raw)
    if case == "malformed-request":
        request_path.write_bytes(b"{")
    elif case == "oversized-request":
        request_path.write_bytes(b"x" * (MAXIMUM_CONTROL_INPUT_BYTES + 1))
    elif case == "malformed-brief":
        brief_path.write_bytes(b"{")
    else:
        monkeypatch.setattr("switchyard.nightshift_adapter.MAXIMUM_BRIEF_BYTES", 128)
        brief_path.write_bytes(b"x" * 129)

    provider_starts: list[Path] = []

    def unexpected_config_load(cls: type[Config], path: Path) -> Config:
        provider_starts.append(path)
        raise AssertionError("configuration and provider verification must follow preflight")

    monkeypatch.setattr(Config, "load", classmethod(unexpected_config_load))
    state_path = tmp_path / "must-not-exist.sqlite"
    monkeypatch.setattr(
        sys, "argv",
        [
            "switchyard-nightshift-adapter",
            "--config", str(tmp_path / "unused.toml"),
            "--state", str(state_path),
            "--account-class", "qualified-isolated",
            "start",
            "--request", str(request_path),
            "--brief", str(brief_path),
        ],
    )
    with pytest.raises(AdapterProtocolError):
        main()
    assert provider_starts == []
    assert not state_path.exists()


def test_resume_cli_refuses_invalid_binding_before_any_provider_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "sha256:" + "0" * 64
    binding = {
        "schema": "foreign-binding/v1",
        "request_digest": digest, "packet_digest": digest,
        "run_id": "run-fixture", "work_item_id": "work-fixture",
        "attempt_id": "attempt-fixture", "adapter_id": ADAPTER_ID,
        "adapter_version": ADAPTER_VERSION,
    }
    binding_path = tmp_path / "binding.json"
    binding_path.write_bytes(_canonical(binding))
    provider_starts: list[Path] = []

    def unexpected_config_load(cls: type[Config], path: Path) -> Config:
        provider_starts.append(path)
        raise AssertionError("provider verification must follow binding validation")

    monkeypatch.setattr(Config, "load", classmethod(unexpected_config_load))
    state_path = tmp_path / "must-not-exist.sqlite"
    monkeypatch.setattr(
        sys, "argv",
        [
            "switchyard-nightshift-adapter", "--config", str(tmp_path / "unused.toml"),
            "--state", str(state_path), "--account-class", "qualified-isolated",
            "resume", "--binding", str(binding_path),
        ],
    )
    with pytest.raises(AdapterProtocolError, match="foreign binding"):
        main()
    assert provider_starts == []
    assert not state_path.exists()


@pytest.mark.parametrize("command", ["resume", "status", "collect"])
def test_existing_commands_refuse_absent_state_before_any_side_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str,
) -> None:
    request, _, _ = build_request_brief(tmp_path, f"attempt-absent-{command}")
    binding = binding_from_start(request)
    binding_path = tmp_path / f"{command}-binding.json"
    binding_path.write_bytes(_canonical(binding))
    state_path = tmp_path / "missing-state-parent" / "adapter.sqlite"
    config_loads: list[Path] = []

    def unexpected_config_load(cls: type[Config], path: Path) -> Config:
        config_loads.append(path)
        raise AssertionError("config must follow exact existing-state preflight")

    monkeypatch.setattr(Config, "load", classmethod(unexpected_config_load))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "switchyard-nightshift-adapter", "--config", str(tmp_path / "unused.toml"),
            "--state", str(state_path), "--account-class", "qualified-isolated",
            command, "--binding", str(binding_path),
        ],
    )
    with pytest.raises(AdapterProtocolError, match="exact existing adapter state"):
        main()
    assert config_loads == []
    assert not state_path.parent.exists()


@pytest.mark.parametrize("command", ["resume", "status", "collect"])
def test_existing_commands_refuse_substituted_binding_before_provider_or_state_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str,
) -> None:
    appserver = FakeAppServer()
    adapter, _ = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, f"attempt-substituted-{command}")
    admitted = adapter.start(request, brief_raw)["binding"]
    substituted = copy.deepcopy(admitted)
    substituted["request_digest"] = "sha256:" + "f" * 64
    binding_path = tmp_path / f"{command}-substituted-binding.json"
    binding_path.write_bytes(_canonical(substituted))
    state_path = tmp_path / "adapter.sqlite"
    before = {
        path.name: path.read_bytes()
        for path in tmp_path.iterdir()
        if path.is_file() and path.name.startswith("adapter.sqlite")
    }
    config_loads: list[Path] = []

    def unexpected_config_load(cls: type[Config], path: Path) -> Config:
        config_loads.append(path)
        raise AssertionError("config must follow exact retained binding preflight")

    monkeypatch.setattr(Config, "load", classmethod(unexpected_config_load))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "switchyard-nightshift-adapter", "--config", str(tmp_path / "unused.toml"),
            "--state", str(state_path), "--account-class", "qualified-isolated",
            command, "--binding", str(binding_path),
        ],
    )
    with pytest.raises(AdapterProtocolError, match="binding substitution"):
        main()
    after = {
        path.name: path.read_bytes()
        for path in tmp_path.iterdir()
        if path.is_file() and path.name.startswith("adapter.sqlite")
    }
    assert config_loads == []
    assert after == before


def test_binding_content_mutation_after_preflight_is_refused_before_provider_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    appserver = FakeAppServer()
    adapter, _ = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-binding-content-race")
    binding = adapter.start(request, brief_raw)["binding"]
    binding_path = tmp_path / "binding-content-race.json"
    binding_path.write_bytes(_canonical(binding))
    state_path = tmp_path / "adapter.sqlite"
    original_preflight = _preflight_existing_store
    mutation_finished = threading.Event()

    def mutate_after_preflight(path: Path, expected: dict[str, object]) -> int:
        descriptor = original_preflight(path, expected)
        substituted = copy.deepcopy(expected)
        substituted["request_digest"] = "sha256:" + "f" * 64

        def concurrent_writer() -> None:
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE attempts SET binding_json=? WHERE attempt_id=?",
                    (_canonical(substituted), expected["attempt_id"]),
                )
                connection.commit()
            finally:
                connection.close()
                mutation_finished.set()

        writer = threading.Thread(target=concurrent_writer)
        writer.start()
        writer.join(timeout=2)
        assert not writer.is_alive()
        return descriptor

    config_loads: list[Path] = []

    def unexpected_config_load(cls: type[Config], path: Path) -> Config:
        config_loads.append(path)
        raise AssertionError("provider verification must follow atomic exact binding admission")

    monkeypatch.setattr(
        "switchyard.nightshift_adapter._preflight_existing_store",
        mutate_after_preflight,
    )
    monkeypatch.setattr(Config, "load", classmethod(unexpected_config_load))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "switchyard-nightshift-adapter", "--config", str(tmp_path / "unused.toml"),
            "--state", str(state_path), "--account-class", "qualified-isolated",
            "status", "--binding", str(binding_path),
        ],
    )
    with pytest.raises(AdapterProtocolError, match="binding substitution"):
        main()
    assert mutation_finished.is_set()
    assert config_loads == []


def test_admitted_occurrence_blocks_concurrent_binding_content_mutation(
    tmp_path: Path,
) -> None:
    appserver = FakeAppServer()
    adapter, _ = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-binding-lock")
    binding = adapter.start(request, brief_raw)["binding"]
    state_path = tmp_path / "adapter.sqlite"
    descriptor = _preflight_existing_store(state_path, binding)
    admitted_store = AdapterStore(state_path, descriptor)
    admitted_store.begin_existing_occurrence(binding)
    concurrent = sqlite3.connect(state_path, timeout=0)
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            concurrent.execute(
                "UPDATE attempts SET binding_json=? WHERE attempt_id=?",
                (b"{}", binding["attempt_id"]),
            )
    finally:
        concurrent.close()
        admitted_store.finish_existing_occurrence()
        admitted_store.connection.close()
        os.close(descriptor)
    assert adapter.store.load(binding).binding == binding


def test_preflight_descriptor_is_the_writable_store_inode(tmp_path: Path) -> None:
    appserver = FakeAppServer()
    adapter, _ = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-descriptor-store")
    binding = adapter.start(request, brief_raw)["binding"]
    state_path = tmp_path / "adapter.sqlite"
    descriptor = _preflight_existing_store(state_path, binding)
    try:
        assert (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) == (
            state_path.stat().st_dev, state_path.stat().st_ino
        )
        admitted_store = AdapterStore(state_path, descriptor)
        retained = admitted_store.load(binding)
        assert retained.binding == binding
        admitted_store.update(binding["attempt_id"], status="RUNNING")
        assert admitted_store.load(binding).status == "RUNNING"
        admitted_store.connection.close()
    finally:
        os.close(descriptor)


def test_state_preflight_refuses_parent_symlink(tmp_path: Path) -> None:
    appserver = FakeAppServer()
    adapter, _ = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-state-symlink")
    binding = adapter.start(request, brief_raw)["binding"]
    linked_parent = tmp_path / "linked-state-parent"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(AdapterProtocolError, match="exact existing adapter state"):
        _preflight_existing_store(linked_parent / "adapter.sqlite", binding)


def test_capabilities_are_closed_and_have_no_approval_command() -> None:
    value = capabilities()
    assert value["commands"] == ["capabilities", "start", "resume", "status", "collect"]
    assert "approve" not in value["commands"]
    assert value["approval_policy"] == "SURFACE_ONLY_NO_RESPONSE"
    assert value["target_effects_authorized"] is False


def test_cross_language_digest_domain_vectors() -> None:
    raw = b"{}"
    assert _raw_digest(BRIEF_DOMAIN, raw) == (
        "sha256:ddd2a21b47c3abf533d27d85a53eb3ac93805d5d938f612929ea410a6ec705e7"
    )
    assert _raw_digest(RAW_DOMAIN, raw) == (
        "sha256:defbb1499ef874d99cdf029e5c1dc04dc253d0fc1e0f88f966278cf3934302fe"
    )
    assert _raw_digest(b"nightshift.worker-adapter-capabilities.raw/v1\0", raw) == (
        "sha256:4dbc0996b158b29f3e54274c8fd1ccb774422f75fb38b3fd1a1aae0662ff5c4c"
    )


def test_rfc8785_cross_language_vector_covers_numeric_unicode_and_escape_edges() -> None:
    value = {
        "numbers": [
            1e-7, 1e-6, 1e20, 1e21, -0.0,
            9_007_199_254_740_991, -9_007_199_254_740_991,
        ],
        "unicode": {"€": "euro", "\r": "cr", "דּ": "hebrew", "😀": "grin", "\u0080": "control"},
        "escapes": "\b\t\n\f\r\"\\\u0000",
    }
    expected = (
        "{\"escapes\":\"\\b\\t\\n\\f\\r\\\"\\\\\\u0000\","
        "\"numbers\":[1e-7,0.000001,100000000000000000000,1e+21,0,"
        "9007199254740991,-9007199254740991],\"unicode\":{"
        "\"\\r\":\"cr\",\"\u0080\":\"control\",\"€\":\"euro\","
        "\"😀\":\"grin\",\"דּ\":\"hebrew\"}}"
    ).encode("utf-8")
    assert _canonical(value) == expected
    assert hashlib.sha256(expected).hexdigest() == (
        "3e01e561f7ea8f1c5774a2d6f5608067675a43316cb41c9d91cdcd2440b4d90f"
    )
    for number in (
        1e-7, 1e-6, 1.25, -0.0, 1.0,
        9_007_199_254_740_991, -9_007_199_254_740_991,
    ):
        admitted = {"safe_number": number}
        _validate_interoperable_extension(admitted)
        canonical = _canonical(admitted)
        parsed = json.loads(canonical)
        _validate_interoperable_extension(parsed)
        assert _canonical(parsed) == canonical

    for unsafe in (9_007_199_254_740_992, -9_007_199_254_740_992):
        with pytest.raises(AdapterProtocolError, match="outside RFC8785-JCS"):
            _canonical({"unsafe_integer": unsafe})
    for unsafe_integral_float in (1e20, -1e20, 1e21, -1e21):
        with pytest.raises(AdapterProtocolError, match="RFC8785"):
            _validate_interoperable_extension({"unsafe_number": unsafe_integral_float})


def test_exact_brief_vector_and_substitutions(tmp_path: Path) -> None:
    request, brief_raw, receipt_raw = build_request_brief(tmp_path)
    validate_start(request, brief_raw)
    assert b"unknown_raw_extension" in bytes.fromhex(
        json.loads(brief_raw)["predecessor_receipts"]["packet-v1"]["bytes_hex"]
    )

    v1_namespace = copy.deepcopy(request)
    v1_namespace["worker_brief_digest"] = _raw_digest(
        b"nightshift.worker-brief.digest/v1\0", brief_raw
    )
    reseal_start(v1_namespace)
    with pytest.raises(AdapterProtocolError, match="worker_brief_digest"):
        validate_start(v1_namespace, brief_raw)

    excessive = copy.deepcopy(request)
    excessive["timeout_seconds"] = 86401
    reseal_start(excessive)
    with pytest.raises(AdapterProtocolError, match="start boundary"):
        validate_start(excessive, brief_raw)

    brief = json.loads(brief_raw)
    bad_receipt = json.loads(receipt_raw)
    bad_receipt["receipt_digest"] = "sha256:" + "0" * 64
    bad_request, bad_brief = rebind_predecessor(request, brief, _canonical(bad_receipt))
    with pytest.raises(AdapterProtocolError, match="receipt digest"):
        validate_start(bad_request, bad_brief)

    wrong_run = json.loads(receipt_raw)
    wrong_run["run_id"] = "run-substituted"
    wrong_run["receipt_digest"] = _digest(
        RECEIPT_DOMAIN, _without(wrong_run, "receipt_digest")
    )
    wrong_request, wrong_brief = rebind_predecessor(request, brief, _canonical(wrong_run))
    with pytest.raises(AdapterProtocolError, match="receipt binding"):
        validate_start(wrong_request, wrong_brief)

    structural_cases = [
        ("started_at", "not-a-date", "started_at"),
        ("started_at", "2026-08-30T12:02:00Z", "receipt timestamps"),
        ("session_identity", "bad identity", "session_identity"),
        ("state", "   ", "state"),
        ("human_questions", [{"question_id": "missing-fields"}], "human question"),
        ("repositories", [{"repository": 7, "branch": "b", "head": "h", "push_status": "p"}], "repositories"),
        ("extensions", {str(index): None for index in range(65)}, "extensions"),
    ]
    for field, substituted, error in structural_cases:
        malformed = json.loads(receipt_raw)
        malformed[field] = substituted
        malformed["receipt_digest"] = _digest(
            RECEIPT_DOMAIN, _without(malformed, "receipt_digest")
        )
        malformed_request, malformed_brief = rebind_predecessor(
            request, brief, _canonical(malformed)
        )
        with pytest.raises(AdapterProtocolError, match=error):
            validate_start(malformed_request, malformed_brief)

    for field, substituted, error in (
        ("started_at", "2026-08-30T08:00:00-04:00", "started_at"),
        ("started_at", "2026-08-30T12:00:00.1000Z", "started_at"),
        ("started_at", "2026-08-30T12:00:00.123000Z", "started_at"),
        ("started_at", "2026-08-30T12:00:00.0000001Z", "started_at"),
    ):
        malformed = json.loads(receipt_raw)
        malformed[field] = substituted
        malformed["receipt_digest"] = _digest(
            RECEIPT_DOMAIN, _without(malformed, "receipt_digest")
        )
        malformed_request, malformed_brief = rebind_predecessor(
            request, brief, _canonical(malformed)
        )
        with pytest.raises(AdapterProtocolError, match=error):
            validate_start(malformed_request, malformed_brief)

    inverted_nanoseconds = json.loads(receipt_raw)
    inverted_nanoseconds["started_at"] = "2026-08-30T12:01:00.000000100Z"
    inverted_nanoseconds["ended_at"] = "2026-08-30T12:01:00Z"
    inverted_nanoseconds["receipt_digest"] = _digest(
        RECEIPT_DOMAIN, _without(inverted_nanoseconds, "receipt_digest")
    )
    inverted_request, inverted_brief = rebind_predecessor(
        request, brief, _canonical(inverted_nanoseconds)
    )
    with pytest.raises(AdapterProtocolError, match="receipt timestamps"):
        validate_start(inverted_request, inverted_brief)

    unicode_boundary = json.loads(receipt_raw)
    unicode_boundary["state"] = "é" * 65_536
    unicode_boundary["evidence"] = ["é" * 65_536]
    unicode_boundary["receipt_digest"] = _digest(
        RECEIPT_DOMAIN, _without(unicode_boundary, "receipt_digest")
    )
    boundary_request, boundary_brief = rebind_predecessor(
        request, brief, _canonical(unicode_boundary)
    )
    validate_start(boundary_request, boundary_brief)

    unicode_overflow = copy.deepcopy(unicode_boundary)
    unicode_overflow["state"] = "é" * 65_537
    unicode_overflow["receipt_digest"] = _digest(
        RECEIPT_DOMAIN, _without(unicode_overflow, "receipt_digest")
    )
    overflow_request, overflow_brief = rebind_predecessor(
        request, brief, _canonical(unicode_overflow)
    )
    with pytest.raises(AdapterProtocolError, match="state"):
        validate_start(overflow_request, overflow_brief)

    unicode_list_overflow = copy.deepcopy(unicode_boundary)
    unicode_list_overflow["evidence"] = ["é" * 65_537]
    unicode_list_overflow["receipt_digest"] = _digest(
        RECEIPT_DOMAIN, _without(unicode_list_overflow, "receipt_digest")
    )
    overflow_request, overflow_brief = rebind_predecessor(
        request, brief, _canonical(unicode_list_overflow)
    )
    with pytest.raises(AdapterProtocolError, match="evidence"):
        validate_start(overflow_request, overflow_brief)

    for field in ("tests", "evidence", "live_or_production_mutations"):
        oversized_item = json.loads(receipt_raw)
        oversized_item[field] = ["x" * 65_537]
        oversized_item["receipt_digest"] = _digest(
            RECEIPT_DOMAIN, _without(oversized_item, "receipt_digest")
        )
        oversized_request, oversized_brief = rebind_predecessor(
            request, brief, _canonical(oversized_item)
        )
        with pytest.raises(AdapterProtocolError, match=field):
            validate_start(oversized_request, oversized_brief)

    numeric_extension = json.loads(receipt_raw)
    numeric_extension["extensions"] = {"nested": {"unsafe_number": 1e20}}
    numeric_extension["receipt_digest"] = _digest(
        RECEIPT_DOMAIN, _without(numeric_extension, "receipt_digest")
    )
    numeric_request, numeric_brief = rebind_predecessor(
        request, brief, _canonical(numeric_extension)
    )
    with pytest.raises(AdapterProtocolError, match="RFC8785"):
        validate_start(numeric_request, numeric_brief)

    unicode_extension = json.loads(receipt_raw)
    unicode_extension["extensions"] = {"nested": {"😀": "outside admitted object-key alphabet"}}
    unicode_extension["receipt_digest"] = _digest(
        RECEIPT_DOMAIN, _without(unicode_extension, "receipt_digest")
    )
    unicode_request, unicode_brief = rebind_predecessor(
        request, brief, _canonical(unicode_extension)
    )
    with pytest.raises(AdapterProtocolError, match="RFC8785 object key"):
        validate_start(unicode_request, unicode_brief)

    not_started = not_started_predecessor(request["packet_digest"])
    not_started_request, not_started_brief = rebind_predecessor(
        request, brief, _canonical(not_started), "not_started"
    )
    validate_start(not_started_request, not_started_brief)
    not_started["recorded_at"] = "not-a-date"
    not_started["receipt_digest"] = _digest(
        NOT_STARTED_DOMAIN, _without(not_started, "receipt_digest")
    )
    malformed_request, malformed_brief = rebind_predecessor(
        request, brief, _canonical(not_started), "not_started"
    )
    with pytest.raises(AdapterProtocolError, match="recorded_at"):
        validate_start(malformed_request, malformed_brief)

    for recorded_at in (
        "2026-08-30T08:01:00-04:00",
        "2026-08-30T12:01:00.1000Z",
        "2026-08-30T12:01:00.0000001Z",
    ):
        malformed = not_started_predecessor(request["packet_digest"])
        malformed["recorded_at"] = recorded_at
        malformed["receipt_digest"] = _digest(
            NOT_STARTED_DOMAIN, _without(malformed, "receipt_digest")
        )
        malformed_request, malformed_brief = rebind_predecessor(
            request, brief, _canonical(malformed), "not_started"
        )
        with pytest.raises(AdapterProtocolError, match="recorded_at"):
            validate_start(malformed_request, malformed_brief)

    oversized_evidence = not_started_predecessor(request["packet_digest"])
    oversized_evidence["evidence"] = ["x" * 65_537]
    oversized_evidence["receipt_digest"] = _digest(
        NOT_STARTED_DOMAIN, _without(oversized_evidence, "receipt_digest")
    )
    oversized_request, oversized_brief = rebind_predecessor(
        request, brief, _canonical(oversized_evidence), "not_started"
    )
    with pytest.raises(AdapterProtocolError, match="evidence"):
        validate_start(oversized_request, oversized_brief)


def test_direct_lifecycle_exact_event_custody_and_terminal_receipt(tmp_path: Path) -> None:
    appserver = FakeAppServer()
    adapter, store = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path)
    result = adapter.start(request, brief_raw)
    binding = result["binding"]
    assert [method for method, _ in appserver.calls] == ["thread/start", "turn/start"]
    assert all(method != "thread/queue/add" for method, _ in appserver.calls)
    attempt = store.load(binding)
    assert attempt.queue_id is None
    protected = worker_outcome()
    protected["live_or_production_mutations"] = ["not admitted"]
    with pytest.raises(AdapterProtocolError, match="protected effect"):
        receipt_from_outcome(protected, attempt)

    invalid_question = worker_outcome()
    invalid_question["human_questions"] = [{
        "question_id": "not an identifier",
        "question": "What remains?",
        "exhausted_evidence": "bounded fixture",
        "safe_default": "wait",
        "consequences": "lane remains paused",
        "resume_point": "after operator input",
    }]
    with pytest.raises(AdapterProtocolError, match="question_id"):
        receipt_from_outcome(invalid_question, attempt)

    appserver.notifications.put(
        completion_message(attempt.thread_id or "", attempt.turn_id or "", worker_outcome(
            "CLOSEOUT-COMPLETE/NOT-QUALIFIED", "UNKNOWN-VERBATIM"
        ))
    )
    adapter.observe(binding, 0.02)
    collected = adapter.collect(binding)
    receipt = collected["terminal_receipt"]
    assert receipt is not None
    retained_attempt = store.load(binding)
    validate_receipt(receipt, retained_attempt)
    malformed_terminal = copy.deepcopy(receipt)
    malformed_terminal["started_at"] = "not-a-date"
    malformed_terminal["receipt_digest"] = _digest(
        RECEIPT_DOMAIN, _without(malformed_terminal, "receipt_digest")
    )
    with pytest.raises(AdapterProtocolError, match="started_at"):
        validate_receipt(malformed_terminal, retained_attempt)
    assert receipt["state"] == "CLOSEOUT-COMPLETE/NOT-QUALIFIED"
    assert receipt["result_classification"] == "UNKNOWN-VERBATIM"
    assert receipt["thread_identity"] == attempt.thread_id
    assert receipt["turn_identity"] == attempt.turn_id
    assert receipt["queue_identity"] is None
    completion = next(
        event for event in collected["events"]
        if event["kind"] == "provider_completion_observation"
        and event["extensions"].get("appserver_evidence_kind") == "turn_completed_notification"
    )
    assert completion["extensions"]["appserver_evidence_representation"] == "exact_wire_bytes_including_line_terminator"
    completion_raw = bytes.fromhex(completion["extensions"]["appserver_evidence_bytes_hex"])
    assert completion_raw.startswith(b"{\n")
    assert completion_raw.endswith(b"\n")
    assert completion["extensions"]["appserver_evidence_digest"] == _raw_digest(
        RAW_APP_SERVER_EVENT_DOMAIN, completion_raw
    )
    started = next(event for event in collected["events"] if event["kind"] == "worker_started")
    assert started["extensions"]["appserver_evidence_representation"] == "canonicalized_parsed_response"


def test_approval_wait_has_no_response_or_protected_effect(tmp_path: Path) -> None:
    appserver = FakeAppServer()
    adapter, store = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-approval")
    binding = adapter.start(request, brief_raw)["binding"]
    attempt = store.load(binding)
    raw = {
        "id": 91,
        "method": "item/commandExecution/requestApproval",
        "params": {"threadId": attempt.thread_id, "turnId": attempt.turn_id},
    }
    appserver.server_requests.put(
        ServerMessage(raw, raw_bytes=(json.dumps(raw, indent=2) + "\n").encode("utf-8"))
    )
    result = adapter.observe(binding, 0.02)
    assert result["mechanism_state"] == "WAITING_APPROVAL"
    event = result["events"][-1]
    assert event["kind"] == "waiting_approval"
    assert event["extensions"]["approval_response_sent"] is False
    assert event["extensions"]["protected_effect_absent"] is True
    assert event["extensions"]["appserver_evidence_representation"] == "exact_wire_bytes_including_line_terminator"
    assert appserver.responses == []

    before = len(result["events"])
    missing_turn = {
        "id": 92,
        "method": "item/commandExecution/requestApproval",
        "params": {"threadId": attempt.thread_id},
    }
    appserver.server_requests.put(ServerMessage(missing_turn))
    with pytest.raises(AdapterProtocolError, match="turn binding"):
        adapter.observe(binding, 0.02)
    assert len(adapter.result(binding)["events"]) == before

    oversized = {
        "id": 93,
        "method": "item/commandExecution/requestApproval",
        "params": {
            "threadId": attempt.thread_id,
            "turnId": attempt.turn_id,
            "detail": "x" * 17000,
        },
    }
    appserver.server_requests.put(ServerMessage(oversized, raw_bytes=(json.dumps(oversized) + "\n").encode("utf-8")))
    result = adapter.observe(binding, 0.02)
    assert result["mechanism_state"] == "INDETERMINATE"
    assert result["terminal_receipt"] is None
    assert len(result["events"]) == before + 1
    assert result["events"][-1]["kind"] == "mechanism_indeterminate"


def test_oversized_notification_and_thread_read_are_durably_indeterminate(tmp_path: Path) -> None:
    notification_server = FakeAppServer()
    notification_adapter, notification_store = make_adapter(
        tmp_path, notification_server, "notification.sqlite"
    )
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-oversized-notification")
    binding = notification_adapter.start(request, brief_raw)["binding"]
    attempt = notification_store.load(binding)
    message = {
        "method": "item/completed",
        "params": {
            "threadId": attempt.thread_id,
            "turnId": attempt.turn_id,
            "detail": "x" * 17_000,
        },
    }
    notification_server.notifications.put(
        ServerMessage(message, raw_bytes=(json.dumps(message) + "\n").encode("utf-8"))
    )
    result = notification_adapter.observe(binding, 0.02)
    assert result["mechanism_state"] == "INDETERMINATE"
    assert result["terminal_receipt"] is None
    assert result["events"][-1]["kind"] == "mechanism_indeterminate"

    thread_server = FakeAppServer()
    thread_adapter, thread_store = make_adapter(tmp_path, thread_server, "thread-read.sqlite")
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-oversized-thread-read")
    binding = thread_adapter.start(request, brief_raw)["binding"]
    attempt = thread_store.load(binding)
    thread_server.threads[attempt.thread_id or ""]["oversizedEvidence"] = "x" * 17_000
    result = thread_adapter.status(binding)
    assert result["mechanism_state"] == "INDETERMINATE"
    assert result["terminal_receipt"] is None
    assert "thread/read response exceeds" in result["events"][-1]["message"]


def test_terminal_cut_refuses_loss_discovered_while_quiescing(tmp_path: Path) -> None:
    appserver = FakeAppServer()
    adapter, store = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-terminal-fence")
    binding = adapter.start(request, brief_raw)["binding"]
    attempt = store.load(binding)
    appserver.notifications.put(
        completion_message(attempt.thread_id or "", attempt.turn_id or "", worker_outcome())
    )
    observed = adapter.observe(binding, 0.02)
    assert observed["mechanism_state"] == "PROVIDER_COMPLETED"

    def acquire_unread_frame() -> None:
        appserver.acquisition_diagnostics.append(
            "App Server unread stdout frame refused at terminal evidence boundary"
        )

    appserver.quiesce_callback = acquire_unread_frame
    collected = adapter.collect(binding)
    assert appserver.quiesced is True
    assert collected["mechanism_state"] == "INDETERMINATE"
    assert collected["terminal_receipt"] is None
    assert collected["events"][-1]["kind"] == "mechanism_indeterminate"
    assert "unread stdout frame" in collected["events"][-1]["message"]


def test_terminal_cut_persists_late_malformed_approval_frame(
    tmp_path: Path,
) -> None:
    appserver = FakeAppServer()
    adapter, store = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-late-malformed-approval")
    binding = adapter.start(request, brief_raw)["binding"]
    attempt = store.load(binding)
    appserver.notifications.put(
        completion_message(attempt.thread_id or "", attempt.turn_id or "", worker_outcome())
    )
    observed = adapter.observe(binding, 0.02)
    assert observed["mechanism_state"] == "PROVIDER_COMPLETED"

    malformed = {
        "id": 109,
        "method": "item/commandExecution/requestApproval",
        "params": {"threadId": attempt.thread_id},
    }

    def acquire_late_malformed_approval() -> None:
        appserver.server_requests.put(
            ServerMessage(
                malformed,
                raw_bytes=_canonical(malformed) + b"\n",
            )
        )

    appserver.quiesce_callback = acquire_late_malformed_approval
    collected = adapter.collect(binding)
    assert collected["mechanism_state"] == "INDETERMINATE"
    assert collected["terminal_receipt"] is None
    assert collected["events"][-1]["kind"] == "mechanism_indeterminate"
    assert "turn binding" in collected["events"][-1]["message"]


def test_non_collect_occurrence_finalization_persists_late_tail_loss(
    tmp_path: Path,
) -> None:
    first_server = FakeAppServer()
    first, store = make_adapter(tmp_path, first_server)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-tail-loss")
    binding = first.start(request, brief_raw)["binding"]
    attempt = store.load(binding)

    def late_reader_loss() -> None:
        first_server.acquisition_diagnostics.append(
            "late App Server stdout loss discovered during occurrence finalization"
        )

    first_server.quiesce_callback = late_reader_loss
    finalized = first.finalize_occurrence(binding)
    assert finalized["mechanism_state"] == "INDETERMINATE"
    assert finalized["terminal_receipt"] is None

    second_server = FakeAppServer()
    second_server.threads[attempt.thread_id or ""] = {
        "id": attempt.thread_id,
        "status": {"type": "idle"},
        "turns": [{
            "id": attempt.turn_id,
            "status": "completed",
            "items": [{
                "type": "agentMessage",
                "text": _canonical(worker_outcome()).decode("utf-8"),
            }],
        }],
    }
    config = make_config(tmp_path)
    identity = BackendIdentity(
        executable=config.codex_executable,
        version=config.codex_expected_version,
        sha256=config.codex_expected_sha256,
        home=config.codex_home,
    )
    second = NightshiftAdapter(identity, "qualified-isolated", second_server, store, config)
    collected = second.collect(binding)
    assert second_server.calls == []
    assert collected["mechanism_state"] == "INDETERMINATE"
    assert collected["terminal_receipt"] is None


def test_terminal_cut_exception_is_persisted_indeterminate(tmp_path: Path) -> None:
    appserver = FakeAppServer()
    adapter, store = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-terminal-cut-error")
    binding = adapter.start(request, brief_raw)["binding"]
    attempt = store.load(binding)
    appserver.notifications.put(
        completion_message(attempt.thread_id or "", attempt.turn_id or "", worker_outcome())
    )
    adapter.observe(binding, 0.02)
    appserver.quiesce_error = RuntimeError("fixture cut failure")
    collected = adapter.collect(binding)
    assert collected["mechanism_state"] == "INDETERMINATE"
    assert collected["terminal_receipt"] is None
    assert "terminal acquisition cut failed" in collected["events"][-1]["message"]


def test_terminal_cut_refuses_loss_generation_without_diagnostic_capacity(tmp_path: Path) -> None:
    appserver = FakeAppServer()
    adapter, store = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-terminal-generation")
    binding = adapter.start(request, brief_raw)["binding"]
    attempt = store.load(binding)
    appserver.notifications.put(
        completion_message(attempt.thread_id or "", attempt.turn_id or "", worker_outcome())
    )
    adapter.observe(binding, 0.02)
    appserver.forced_loss_generation = 1
    collected = adapter.collect(binding)
    assert collected["mechanism_state"] == "INDETERMINATE"
    assert collected["terminal_receipt"] is None
    assert "acquisition loss preceded" in collected["events"][-1]["message"]


@pytest.mark.parametrize("disposition", ["UNKNOWN", "EXIT_UNCONFIRMED"])
def test_terminal_cut_requires_confirmed_process_exit(
    tmp_path: Path, disposition: str,
) -> None:
    appserver = FakeAppServer()
    adapter, store = make_adapter(
        tmp_path, appserver, f"unconfirmed-process-{disposition.lower()}.sqlite"
    )
    request, brief_raw, _ = build_request_brief(
        tmp_path, f"attempt-unconfirmed-process-{disposition.lower()}"
    )
    binding = adapter.start(request, brief_raw)["binding"]
    attempt = store.load(binding)
    appserver.notifications.put(
        completion_message(attempt.thread_id or "", attempt.turn_id or "", worker_outcome())
    )
    observed = adapter.observe(binding, 0.02)
    assert observed["mechanism_state"] == "PROVIDER_COMPLETED"
    appserver.process_disposition = disposition
    collected = adapter.collect(binding)
    assert collected["mechanism_state"] == "INDETERMINATE"
    assert collected["terminal_receipt"] is None
    assert collected["events"][-1]["kind"] == "mechanism_indeterminate"
    assert "unconfirmed process exit" in collected["events"][-1]["message"]


def test_acquisition_queue_overflow_is_lane_local_indeterminate(tmp_path: Path) -> None:
    appserver = FakeAppServer()
    adapter, _ = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-acquisition-overflow")
    binding = adapter.start(request, brief_raw)["binding"]
    appserver.acquisition_diagnostics.append(
        "App Server notification refused by bounded acquisition queue"
    )
    result = adapter.observe(binding, 0.02)
    assert result["mechanism_state"] == "INDETERMINATE"
    assert result["terminal_receipt"] is None
    event = result["events"][-1]
    assert event["kind"] == "mechanism_indeterminate"
    assert "bounded acquisition queue" in event["message"]


def test_restart_resume_same_attempt_and_new_process_occurrence(tmp_path: Path) -> None:
    first_server = FakeAppServer()
    first, store = make_adapter(tmp_path, first_server)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-restart")
    first_result = first.start(request, brief_raw)
    binding = first_result["binding"]
    attempt = store.load(binding)
    first_occurrence = first_result["events"][-1]["extensions"][
        "appserver_process_occurrence_identity"
    ]

    second_server = FakeAppServer()
    second_server.threads[attempt.thread_id or ""] = {
        "id": attempt.thread_id,
        "status": {"type": "notLoaded"},
        "turns": [],
    }
    config = make_config(tmp_path)
    identity = BackendIdentity(
        executable=config.codex_executable,
        version=config.codex_expected_version,
        sha256=config.codex_expected_sha256,
        home=config.codex_home,
    )
    second = NightshiftAdapter(identity, "qualified-isolated", second_server, store, config)
    resumed = second.resume(binding)
    methods = [method for method, _ in second_server.calls]
    assert methods == ["thread/read", "thread/resume"]
    assert "thread/start" not in methods and "turn/start" not in methods
    checkpoint = resumed["events"][-1]
    assert checkpoint["kind"] == "checkpoint"
    assert checkpoint["attempt_id"] == binding["attempt_id"]
    assert checkpoint["session_identity"] == attempt.session_identity
    assert checkpoint["extensions"]["appserver_process_occurrence_identity"] != first_occurrence

    wrong = copy.deepcopy(binding)
    wrong["request_digest"] = "sha256:" + "f" * 64
    with pytest.raises(AdapterProtocolError, match="binding substitution"):
        second.resume(wrong)


def test_concurrent_indeterminate_commit_prevents_terminal_materialization(
    tmp_path: Path,
) -> None:
    appserver = FakeAppServer()
    adapter, store = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-transition-race")
    binding = adapter.start(request, brief_raw)["binding"]
    state_path = tmp_path / "adapter.sqlite"
    writer_ready = threading.Event()
    writer_release = threading.Event()
    terminal_errors: list[Exception] = []

    def paused_terminal_writer() -> None:
        terminal_store = AdapterStore(state_path)
        writer_ready.set()
        writer_release.wait(timeout=2)
        try:
            terminal_store.update(
                binding["attempt_id"],
                status="TERMINAL",
                terminal_receipt_json=b"{}",
            )
        except Exception as exc:
            terminal_errors.append(exc)

    writer = threading.Thread(target=paused_terminal_writer)
    writer.start()
    assert writer_ready.wait(timeout=2)
    concurrent_store = AdapterStore(state_path)
    concurrent_store.update(binding["attempt_id"], status="INDETERMINATE")
    writer_release.set()
    writer.join(timeout=2)
    assert not writer.is_alive()
    assert terminal_errors
    assert "terminally prohibited" in str(terminal_errors[0])
    retained = store.load(binding)
    assert retained.status == "INDETERMINATE"
    assert retained.terminal_receipt is None


def test_restart_cannot_leave_persisted_indeterminate_for_completed_thread(
    tmp_path: Path,
) -> None:
    first_server = FakeAppServer()
    first, store = make_adapter(tmp_path, first_server)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-restart-indeterminate")
    binding = first.start(request, brief_raw)["binding"]
    attempt = store.load(binding)
    first_server.acquisition_diagnostics.append("prior App Server acquisition loss")
    prior = first.observe(binding, 0.02)
    assert prior["mechanism_state"] == "INDETERMINATE"

    completed_turn = {
        "id": attempt.turn_id,
        "status": "completed",
        "items": [
            {"type": "agentMessage", "text": _canonical(worker_outcome()).decode("utf-8")}
        ],
    }
    second_server = FakeAppServer()
    second_server.threads[attempt.thread_id or ""] = {
        "id": attempt.thread_id,
        "status": {"type": "idle"},
        "turns": [completed_turn],
    }
    config = make_config(tmp_path)
    identity = BackendIdentity(
        executable=config.codex_executable,
        version=config.codex_expected_version,
        sha256=config.codex_expected_sha256,
        home=config.codex_home,
    )
    second = NightshiftAdapter(identity, "qualified-isolated", second_server, store, config)
    status = second.status(binding)
    collected = second.collect(binding)
    assert second_server.calls == []
    assert status["mechanism_state"] == "INDETERMINATE"
    assert collected["mechanism_state"] == "INDETERMINATE"
    assert collected["terminal_receipt"] is None
    with pytest.raises(AdapterProtocolError, match="terminally prohibited"):
        store.update(binding["attempt_id"], status="PROVIDER_COMPLETED")


def test_resume_discovered_completion_retains_canonicalized_thread_read_evidence(
    tmp_path: Path,
) -> None:
    first_server = FakeAppServer()
    first, store = make_adapter(tmp_path, first_server)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-resume-completion")
    binding = first.start(request, brief_raw)["binding"]
    attempt = store.load(binding)

    second_server = FakeAppServer()
    completed_turn = {
        "id": attempt.turn_id,
        "status": "completed",
        "items": [
            {"type": "agentMessage", "text": _canonical(worker_outcome()).decode("utf-8")}
        ],
    }
    thread = {
        "id": attempt.thread_id,
        "status": {"type": "idle"},
        "turns": [completed_turn],
    }
    second_server.threads[attempt.thread_id or ""] = thread
    config = make_config(tmp_path)
    identity = BackendIdentity(
        executable=config.codex_executable,
        version=config.codex_expected_version,
        sha256=config.codex_expected_sha256,
        home=config.codex_home,
    )
    second = NightshiftAdapter(identity, "qualified-isolated", second_server, store, config)
    resumed = second.resume(binding)
    completion = next(
        event
        for event in resumed["events"]
        if event["kind"] == "provider_completion_observation"
        and event["extensions"].get("appserver_evidence_kind") == "thread_read_response"
    )
    expected = _canonical({"thread": thread})
    assert completion["extensions"]["appserver_evidence_representation"] == (
        "canonicalized_parsed_response"
    )
    assert bytes.fromhex(completion["extensions"]["appserver_evidence_bytes_hex"]) == expected
    assert completion["extensions"]["appserver_evidence_digest"] == _raw_digest(
        RAW_APP_SERVER_EVENT_DOMAIN, expected
    )
    assert resumed["binding"]["attempt_id"] == "attempt-resume-completion"
    assert resumed["mechanism_state"] == "PROVIDER_COMPLETED"


def test_utf8_byte_bound_is_indeterminate_not_terminal(tmp_path: Path) -> None:
    appserver = FakeAppServer()
    adapter, store = make_adapter(tmp_path, appserver)
    request, brief_raw, _ = build_request_brief(tmp_path, "attempt-utf8")
    request["maximum_output_bytes"] = 1024
    reseal_start(request)
    binding = adapter.start(request, brief_raw)["binding"]
    attempt = store.load(binding)
    outcome = worker_outcome(state="🙂" * 400)
    appserver.notifications.put(
        completion_message(attempt.thread_id or "", attempt.turn_id or "", outcome)
    )
    result = adapter.observe(binding, 0.02)
    retained = store.load(binding)
    assert result["mechanism_state"] == "INDETERMINATE"
    assert result["terminal_receipt"] is None
    assert retained.final_message is not None
    assert len(retained.final_message.encode("utf-8")) <= 1024
    assert result["events"][-1]["kind"] == "mechanism_indeterminate"
