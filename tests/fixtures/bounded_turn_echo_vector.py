"""Generic cross-language Codex97 echo vector; never reads campaign records."""
from __future__ import annotations

import json
from pathlib import Path

from switchyard.appserver import AcquisitionCut, AcquisitionEnvelope, ServerMessage, request_wire
from switchyard.provider_admission import FINAL_CODEX_SOURCE_HEAD, ProviderAdmissionMapper, seal_binding


ROOT = Path(__file__).resolve().parent
SPEC = json.loads((ROOT / "bounded-turn-echo-vector.json").read_bytes())
THREAD = "echo-vector-thread"
TURN = "echo-vector-turn"


def _message(method: str, params: dict) -> ServerMessage:
    value = {"method": method, "params": params, "emittedAtMs": 9}
    return ServerMessage(value, request_wire(value))


def _envelope(ordinal: int, kind: str, message: ServerMessage, request_method: str | None = None) -> AcquisitionEnvelope:
    return AcquisitionEnvelope(ordinal, kind, message, request_method=request_method)


def _binding() -> dict:
    return seal_binding({
        "work_attempt_id": "echo-vector-attempt", "dispatch_occurrence_id": "echo-vector-dispatch",
        "adapter_process_occurrence_id": "echo-vector-process", "app_server_session_identity": "echo-vector-session",
        "thread_id": THREAD, "turn_id": TURN, "provider": "openai", "model": "gpt-5.6-terra",
        "codex_source_head": FINAL_CODEX_SOURCE_HEAD, "executable_kind": "DETERMINISTIC_FIXTURE",
        "app_server_executable_identity": "generic-echo-vector-not-a-provider",
        "app_server_executable_sha256": "sha256:" + "a" * 64, "internal_provider_request_retries": 0,
    })


def _agent(text: str) -> dict:
    return {"type": "agentMessage", "id": "echo-vector-agent", "text": text,
        "phase": "final_answer", "memoryCitation": None, "delivery": None}


def expanded_snapshot() -> dict:
    """Expand the compact generic recipe to exact custody records and a clean cut."""
    target = SPEC["turn_start_wire_bytes"]
    params = {"threadId": THREAD, "model": "gpt-5.6-terra", "input": [{"type": "text", "text": ""}]}
    request = {"id": 3, "method": "turn/start", "params": params}
    params["input"][0]["text"] = SPEC["turn_start_fill"] * (target - len(request_wire(request)))
    assert len(request_wire(request)) == target
    text = params["input"][0]["text"]
    output = "\0" * SPEC["agent_output_utf8_bytes"]
    mapper = ProviderAdmissionMapper(_binding(), capture_contract="BOUNDED_TURN_ECHO_V1")
    mapper.consume_envelope(_envelope(0, "CLIENT_REQUEST", ServerMessage(request, request_wire(request)), "turn/start"))
    response = {"id": 3, "result": {"turn": {"id": TURN}}}
    mapper.consume_envelope(_envelope(1, "CLIENT_RESPONSE", ServerMessage(response, request_wire(response)), "turn/start"))
    user = {"type": "userMessage", "id": "echo-vector-user", "clientId": None,
        "content": [{"type": "text", "text": text, "text_elements": []}]}
    common = {"threadId": THREAD, "turnId": TURN, "requestOccurrenceId": "echo-vector-request",
        "samplingOrdinal": 0, "requestOrder": 0, "provider": "openai", "model": "gpt-5.6-terra"}
    frames = [
        ("item/started", {"threadId": THREAD, "turnId": TURN, "item": user, "startedAtMs": 1}),
        ("item/completed", {"threadId": THREAD, "turnId": TURN, "item": user, "completedAtMs": 2}),
        ("providerRequest/started", {**common, "startedAtMs": 3}),
        ("rawResponse/started", {**common, "responseId": "echo-vector-response", "observedAtMs": 4}),
        ("rawResponse/completed", {"threadId": THREAD, "turnId": TURN, "responseId": "echo-vector-response", "usage": None}),
        ("item/started", {"threadId": THREAD, "turnId": TURN, "item": _agent(""), "startedAtMs": 5}),
        ("item/agentMessage/delta", {"threadId": THREAD, "turnId": TURN, "itemId": "echo-vector-agent", "delta": output}),
        ("item/completed", {"threadId": THREAD, "turnId": TURN, "item": _agent(output), "completedAtMs": 6}),
        ("turn/completed", {"threadId": THREAD, "turn": {"id": TURN, "items": [_agent(output)],
            "itemsView": "summary", "status": "completed", "error": None, "startedAt": 1,
            "completedAt": 6, "durationMs": 5}, "emittedAtMs": 6}),
    ]
    for ordinal, (method, values) in enumerate(frames, 2):
        mapper.consume_envelope(_envelope(ordinal, "NOTIFICATION", _message(method, values)))
    mapper.consume_cut(AcquisitionCut(True, 0, "EXITED", 11, "echo-vector-process", "echo-vector-session"))
    return mapper.snapshot()
