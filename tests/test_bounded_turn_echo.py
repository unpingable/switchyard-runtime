"""Deterministic source-shaped echo controls; no App Server or provider process."""
import io
import json
import queue
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from switchyard.appserver import (AcquisitionCut, AcquisitionEnvelope, AppServerClient, ServerMessage,
    BOUNDED_TURN_ECHO_CAPTURE_CONTRACT, is_bounded_turn_agent_output,
    is_bounded_turn_user_input_echo, normalized_bounded_turn_input, request_wire)
from switchyard.provider_admission import (FINAL_CODEX_SOURCE_HEAD,
    ProviderAdmissionMapper, seal_binding)


THREAD = "thread-echo"
TURN = "turn-echo"
TEXT = "x" * 20000


def wire(method, params, *, emitted_at_ms=9):
    value = {"method": method, "params": params, "emittedAtMs": emitted_at_ms}
    raw = request_wire(value)
    return ServerMessage(value, raw)


def binding():
    return seal_binding({
        "work_attempt_id": "echo-attempt", "dispatch_occurrence_id": "echo-dispatch",
        "adapter_process_occurrence_id": "echo-process", "app_server_session_identity": "echo-session",
        "thread_id": THREAD, "turn_id": TURN, "provider": "openai", "model": "gpt-5.6-terra",
        "codex_source_head": FINAL_CODEX_SOURCE_HEAD, "executable_kind": "DETERMINISTIC_FIXTURE",
        "app_server_executable_identity": "source-shaped-local-fixture",
        "app_server_executable_sha256": "sha256:" + "a" * 64, "internal_provider_request_retries": 0,
    })


def user_item():
    return {"type": "userMessage", "id": "user-item", "clientId": None,
        "content": [{"type": "text", "text": TEXT, "text_elements": []}]}


def agent_item(text):
    return {"type": "agentMessage", "id": "agent-item", "text": text, "phase": "final_answer",
        "memoryCitation": None, "delivery": None}


def envelope(ordinal, kind, message, request_method=None):
    return AcquisitionEnvelope(ordinal, kind, message, request_method=request_method)


def test_source_defined_input_default_is_the_only_normalization():
    expected = normalized_bounded_turn_input([{"type": "text", "text": TEXT}])
    started = wire("item/started", {"threadId": THREAD, "turnId": TURN, "item": user_item(), "startedAtMs": 1})
    assert len(started.raw_bytes) > 16384
    assert is_bounded_turn_user_input_echo(started, expected, thread_id=THREAD, turn_id=TURN)
    changed = user_item(); changed["content"][0]["text_elements"] = [{"start": 0, "end": 1}]
    assert not is_bounded_turn_user_input_echo(wire("item/started", {
        "threadId": THREAD, "turnId": TURN, "item": changed, "startedAtMs": 1}), expected,
        thread_id=THREAD, turn_id=TURN)
    extra = {"id": 99, "method": "item/started", "emittedAtMs": 9, "params": {
        "threadId": THREAD, "turnId": TURN, "item": user_item(), "startedAtMs": 1}}
    assert not is_bounded_turn_user_input_echo(ServerMessage(extra, request_wire(extra)), expected,
        thread_id=THREAD, turn_id=TURN)
    missing_envelope_time = {"method": "item/started", "params": {
        "threadId": THREAD, "turnId": TURN, "item": user_item(), "startedAtMs": 1}}
    assert not is_bounded_turn_user_input_echo(
        ServerMessage(missing_envelope_time, request_wire(missing_envelope_time)), expected,
        thread_id=THREAD, turn_id=TURN)
    assert not is_bounded_turn_user_input_echo(wire("item/started", {
        "threadId": THREAD, "turnId": TURN, "item": user_item(), "startedAtMs": 1},
        emitted_at_ms=True), expected, thread_id=THREAD, turn_id=TURN)
    assert not is_bounded_turn_user_input_echo(wire("item/started", {
        "threadId": THREAD, "turnId": TURN, "item": user_item(), "startedAtMs": 1},
        emitted_at_ms=0), expected, thread_id=THREAD, turn_id=TURN)


def test_reader_sets_selected_turn_before_contiguous_large_agent_frame():
    """The reader, not the request caller, must close the response/frame race."""
    client = AppServerClient(["fixture-only"], enable_ordered_acquisition=True,
        capture_contract=BOUNDED_TURN_ECHO_CAPTURE_CONTRACT,
        adapter_process_occurrence_id="echo-process", app_server_session_identity="echo-session")
    client._bounded_turn_echo = (THREAD, normalized_bounded_turn_input([{"type": "text", "text": TEXT}]))
    response = {"id": 3, "result": {"turn": {"id": TURN}}}
    frame = {"method": "item/started", "emittedAtMs": 9, "params": {
        "threadId": THREAD, "turnId": TURN, "startedAtMs": 1, "item": agent_item(TEXT),
    }}
    raw = request_wire(response) + request_wire(frame)
    assert len(request_wire(frame)) > 16384
    client._pending[3] = queue.Queue(maxsize=1)
    client._pending_methods[3] = "turn/start"
    client._proc = SimpleNamespace(stdout=io.BytesIO(raw))
    client._read_stdout_loop()
    retained = client.drain_ordered_acquisition()
    assert [item.kind for item in retained] == ["CLIENT_RESPONSE", "NOTIFICATION"]
    assert retained[1].message.raw_bytes == request_wire(frame)
    assert client._bounded_turn_id == TURN
    assert client.stdout_refused_frames == 0


@pytest.mark.parametrize("response", [
    {"id": 3, "result": {"turn": {}}},
    {"id": 3, "result": {"turn": {"id": "different-turn"}}},
])
def test_reader_refuses_contiguous_large_agent_frame_without_exact_response_identity(response):
    client = AppServerClient(["fixture-only"], enable_ordered_acquisition=True,
        capture_contract=BOUNDED_TURN_ECHO_CAPTURE_CONTRACT,
        adapter_process_occurrence_id="echo-process", app_server_session_identity="echo-session")
    client._bounded_turn_echo = (THREAD, normalized_bounded_turn_input([{"type": "text", "text": TEXT}]))
    frame = {"method": "item/started", "emittedAtMs": 9, "params": {
        "threadId": THREAD, "turnId": TURN, "startedAtMs": 1, "item": agent_item(TEXT),
    }}
    client._pending[3] = queue.Queue(maxsize=1)
    client._pending_methods[3] = "turn/start"
    client._proc = SimpleNamespace(stdout=io.BytesIO(request_wire(response) + request_wire(frame)))
    client._read_stdout_loop()
    retained = client.drain_ordered_acquisition()
    assert [item.kind for item in retained] == ["CLIENT_RESPONSE", "LOSS"]
    assert client.stdout_refused_frames == 1


def test_exact_source_shaped_large_echoes_are_retained_as_watermarks():
    mapper = ProviderAdmissionMapper(binding(), capture_contract=BOUNDED_TURN_ECHO_CAPTURE_CONTRACT)
    turn_start = {"id": 3, "method": "turn/start", "params": {
        "threadId": THREAD, "model": "gpt-5.6-terra", "input": [{"type": "text", "text": TEXT}]}}
    mapper.consume_envelope(envelope(0, "CLIENT_REQUEST", ServerMessage(turn_start, request_wire(turn_start)), "turn/start"))
    response = {"id": 3, "result": {"turn": {"id": TURN}}}
    mapper.consume_envelope(envelope(1, "CLIENT_RESPONSE", ServerMessage(response, request_wire(response)), "turn/start"))
    frames = [
        ("item/started", {"threadId": THREAD, "turnId": TURN, "item": user_item(), "startedAtMs": 1}),
        ("item/completed", {"threadId": THREAD, "turnId": TURN, "item": user_item(), "completedAtMs": 2}),
        ("item/started", {"threadId": THREAD, "turnId": TURN, "item": agent_item(""), "startedAtMs": 3}),
        ("item/agentMessage/delta", {"threadId": THREAD, "turnId": TURN, "itemId": "agent-item", "delta": TEXT}),
        ("item/completed", {"threadId": THREAD, "turnId": TURN, "item": agent_item(TEXT), "completedAtMs": 4}),
    ]
    for ordinal, (method, params) in enumerate(frames, 2):
        mapper.consume_envelope(envelope(ordinal, "NOTIFICATION", wire(method, params)))
    summary = {"id": TURN, "items": [agent_item(TEXT)], "itemsView": "summary", "status": "completed",
        "error": None, "startedAt": 1, "completedAt": 4, "durationMs": 3}
    mapper.consume_envelope(envelope(7, "NOTIFICATION", wire("turn/completed", {
        "threadId": THREAD, "turn": summary, "emittedAtMs": 4})))
    methods = [record["method"] for record in mapper.records]
    assert methods.count("item/started") == 2 and methods.count("item/completed") == 2
    assert "item/agentMessage/delta" in methods and "turn/completed" in methods
    mapper.consume_cut(AcquisitionCut(True, 0, "EXITED", 8, "echo-process", "echo-session"))
    schema = json.loads((Path(__file__).parents[1] / "src/switchyard/schemas/"
        "switchyard.codex-provider-admission.bounded-turn-echo.v2.schema.json").read_bytes())
    Draft202012Validator(schema).validate(mapper.snapshot())


def test_large_nonselected_item_is_refused_and_old_context_stays_small():
    foreign = wire("item/started", {"threadId": THREAD, "turnId": TURN,
        "item": {"type": "agentMessage", "id": "agent-item", "text": TEXT, "phase": "final_answer",
            "memoryCitation": {"entries": [], "threadIds": []}, "delivery": None}, "startedAtMs": 1})
    assert len(foreign.raw_bytes) > 16384
    assert not is_bounded_turn_agent_output(foreign, thread_id=THREAD, turn_id=TURN)
    mapper = ProviderAdmissionMapper(binding(), capture_contract=BOUNDED_TURN_ECHO_CAPTURE_CONTRACT)
    mapper.consume_envelope(envelope(0, "NOTIFICATION", foreign))
    assert mapper.mechanism_state == "ADMISSION_INDETERMINATE"
    legacy = ProviderAdmissionMapper(binding(), capture_contract="BOUNDED_TURN_V1")
    legacy.consume_envelope(envelope(0, "NOTIFICATION", foreign))
    assert legacy.mechanism_state == "ADMISSION_INDETERMINATE"


def test_agent_output_refuses_above_the_unchanged_32k_limit():
    oversized = wire("item/completed", {"threadId": THREAD, "turnId": TURN,
        "item": agent_item("x" * 32769), "completedAtMs": 1})
    assert not is_bounded_turn_agent_output(oversized, thread_id=THREAD, turn_id=TURN)


def test_small_unselected_item_remains_a_legacy_watermark():
    mapper = ProviderAdmissionMapper(binding(), capture_contract=BOUNDED_TURN_ECHO_CAPTURE_CONTRACT)
    small = wire("item/started", {"threadId": THREAD, "turnId": TURN,
        "item": {"type": "reasoning", "id": "reasoning-item", "text": "local fact"}, "startedAtMs": 1})
    mapper.consume_envelope(envelope(0, "NOTIFICATION", small))
    assert mapper.mechanism_state == "DISPATCHING"
    assert mapper.records[-1]["kind"] == "ACQUISITION_WATERMARK"


def test_sequential_large_agent_items_preserve_the_32k_completed_aggregate():
    mapper = ProviderAdmissionMapper(binding(), capture_contract=BOUNDED_TURN_ECHO_CAPTURE_CONTRACT)
    commentary = "c" * 12000
    final = "f" * 20000
    first = wire("item/started", {"threadId": THREAD, "turnId": TURN,
        "item": agent_item(commentary), "startedAtMs": 1})
    mapper.consume_envelope(envelope(0, "NOTIFICATION", first))
    mapper.consume_envelope(envelope(1, "NOTIFICATION", wire("item/completed", {
        "threadId": THREAD, "turnId": TURN, "item": agent_item(commentary), "completedAtMs": 2})))
    second = agent_item(final); second["id"] = "second-agent-item"
    mapper.consume_envelope(envelope(2, "NOTIFICATION", wire("item/started", {
        "threadId": THREAD, "turnId": TURN, "item": second, "startedAtMs": 3})))
    mapper.consume_envelope(envelope(3, "NOTIFICATION", wire("item/completed", {
        "threadId": THREAD, "turnId": TURN, "item": second, "completedAtMs": 4})))
    assert mapper.mechanism_state == "DISPATCHING"
    third = agent_item("x" * 769); third["id"] = "third-agent-item"
    mapper.consume_envelope(envelope(4, "NOTIFICATION", wire("item/started", {
        "threadId": THREAD, "turnId": TURN, "item": third, "startedAtMs": 5})))
    mapper.consume_envelope(envelope(5, "NOTIFICATION", wire("item/completed", {
        "threadId": THREAD, "turnId": TURN, "item": third, "completedAtMs": 6})))
    assert mapper.mechanism_state == "ADMISSION_INDETERMINATE"


def test_small_unselected_agent_completion_counts_toward_the_same_32k_limit():
    mapper = ProviderAdmissionMapper(binding(), capture_contract=BOUNDED_TURN_ECHO_CAPTURE_CONTRACT)
    small = {"type": "agentMessage", "id": "small-agent", "text": "s" * 10000,
        "phase": "final_answer", "memoryCitation": {"entries": [], "threadIds": []}, "delivery": None}
    mapper.consume_envelope(envelope(0, "NOTIFICATION", wire("item/completed", {
        "threadId": THREAD, "turnId": TURN, "item": small, "completedAtMs": 1})))
    large = agent_item("l" * 23000)
    mapper.consume_envelope(envelope(1, "NOTIFICATION", wire("item/started", {
        "threadId": THREAD, "turnId": TURN, "item": large, "startedAtMs": 2})))
    mapper.consume_envelope(envelope(2, "NOTIFICATION", wire("item/completed", {
        "threadId": THREAD, "turnId": TURN, "item": large, "completedAtMs": 3})))
    assert mapper.mechanism_state == "ADMISSION_INDETERMINATE"


def test_cross_language_generic_vector_expands_to_the_pinned_full_snapshot():
    fixture_root = Path(__file__).parents[1] / "tests/fixtures"
    vector = runpy.run_path(str(fixture_root / "bounded_turn_echo_vector.py"))
    spec = json.loads((fixture_root / "bounded-turn-echo-vector.json").read_bytes())
    snapshot = vector["expanded_snapshot"]()
    assert snapshot["snapshot_digest"] == spec["expected_snapshot_digest"]
    assert snapshot["acquisition_cut"]["clean"] is True
    raw = [record["raw"]["byte_length"] for record in snapshot["records"] if record["raw"]]
    assert max(raw) < 256 * 1024 and raw[0] == 118500
