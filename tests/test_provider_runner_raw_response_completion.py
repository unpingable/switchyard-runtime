"""Deterministic app-server raw-response completion gate qualification."""

import copy

from switchyard.appserver import AcquisitionCut, AcquisitionEnvelope, ServerMessage
from switchyard.nightshift_adapter import _canonical
from switchyard import provider_runner
from switchyard.provider_runner import RunStore
from test_provider_runner import dispatch_for, inputs


class RawEventsGateClient:
    """Source-shaped fixture: completion is emitted only after the v2 opt-in."""

    thread_start_params = None

    def __init__(self, command, **kwargs):
        self.events = []
        self.ordinal = 0
        self.kwargs = kwargs

    def event(self, method, params):
        value = {
            "method": method,
            "params": params,
            # Standalone App Server notifications carry this source-level
            # envelope timestamp in addition to method-specific timestamps.
            "emittedAtMs": 1_000 + self.ordinal,
        }
        self.events.append(AcquisitionEnvelope(
            self.ordinal, "NOTIFICATION", ServerMessage(value, _canonical(value) + b"\n")))
        self.ordinal += 1

    def start(self):
        pass

    def request(self, method, params):
        if method == "thread/start":
            type(self).thread_start_params = copy.deepcopy(params)
            return {
                "thread": {"id": "thread-raw-events"},
                "model": "gpt-5.6-terra",
                "modelProvider": "openai",
                "cwd": params["cwd"],
                "runtimeWorkspaceRoots": params["runtimeWorkspaceRoots"],
                "instructionSources": [],
                "activePermissionProfile": {"id": "provider-bounded-read", "extends": None},
            }
        if method == "turn/start":
            common = {
                "threadId": "thread-raw-events",
                "turnId": "turn-raw-events",
                "requestOccurrenceId": "request-raw-events",
                "samplingOrdinal": 0,
                "requestOrder": 0,
                "provider": "openai",
                "model": "gpt-5.6-terra",
            }
            self.event("providerRequest/started", {**common, "startedAtMs": 100})
            self.event("rawResponse/started", {
                **common, "responseId": "response-raw-events", "observedAtMs": 101,
            })
            if type(self).thread_start_params.get("experimentalRawEvents") is True:
                self.event("rawResponse/completed", {
                    "threadId": "thread-raw-events",
                    "turnId": "turn-raw-events",
                    "responseId": "response-raw-events",
                    "usage": None,
                })
            self.event("item/completed", {
                "threadId": "thread-raw-events",
                "turnId": "turn-raw-events",
                "item": {"type": "agentMessage", "text": "fixture retained output"},
                "completedAtMs": 102,
            })
            self.event("turn/completed", {
                "threadId": "thread-raw-events",
                "turn": {"id": "turn-raw-events", "status": "completed"},
            })
            return {"turn": {"id": "turn-raw-events"}}
        raise AssertionError(method)

    def drain_ordered_acquisition(self):
        events, self.events = self.events, []
        return events

    def quiesce_acquisition(self, timeout=5):
        return AcquisitionCut(
            True, 0, "EXITED", self.ordinal,
            self.kwargs.get("adapter_process_occurrence_id"),
            self.kwargs.get("app_server_session_identity"),
        )


def _run(tmp_path):
    request, brief, backend = inputs(tmp_path)
    dispatch = dispatch_for(request, backend)
    return provider_runner.run(
        request, brief, backend, RunStore(tmp_path / "adapter.sqlite"),
        dispatch_record=dispatch, client_factory=RawEventsGateClient,
    )


def test_source_shaped_raw_events_gate_completes_with_thread_opt_in(tmp_path):
    """The documented thread/start opt-in restores the canonical completion event."""
    result = _run(tmp_path)

    assert RawEventsGateClient.thread_start_params["experimentalRawEvents"] is True
    assert result["worker_output"] == "fixture retained output"
    assert result["turn_status"] == "completed"
    assert result["state"] == "PROVIDER_COMPLETED"
    assert any(
        record["method"] == "rawResponse/completed"
        for record in result["provider_admission"]["records"]
    )


def test_source_shaped_raw_events_gate_fails_closed_when_thread_opt_in_is_omitted(tmp_path, monkeypatch):
    """Retained output is not an admissible completed provider boundary by itself."""
    original = provider_runner.bounded_thread_start

    def without_raw_events(workspace, backend):
        value = original(workspace, backend)
        value.pop("experimentalRawEvents")
        return value

    monkeypatch.setattr(provider_runner, "bounded_thread_start", without_raw_events)
    result = _run(tmp_path)

    assert RawEventsGateClient.thread_start_params.get("experimentalRawEvents") is not True
    assert result["state"] == "OUTCOME_UNKNOWN"
    assert result["worker_output"] == "fixture retained output"
    assert result["turn_status"] == "completed"
    assert result["provider_admission"]["mechanism_state"] == "POST_ADMISSION_INTERRUPTED"
    assert not any(
        record["method"] == "rawResponse/completed"
        for record in result["provider_admission"]["records"]
    )
