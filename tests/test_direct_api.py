import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

import pytest
import switchyard.direct_api as direct_api

from switchyard.direct_api import (
    BINDING_DOMAIN, ENDPOINT, PROTOCOL, REQUEST_DOMAIN, RunStore, digest,
    DirectApiCaller, inspect, run,
)
from switchyard.nightshift_adapter import AdapterProtocolError, _canonical


def inputs():
    admitted = b"Explain the bounded fixture without proposing effects."
    request = {
        "schema": "switchyard.direct-api-request/v1",
        "request_id": "request-direct-001",
        "work_attempt_id": "attempt-direct-001",
        "dispatch_occurrence_id": "dispatch-direct-001",
        "admitted_input_sha256": digest(admitted),
        "provider_id": "openrouter",
        "model_id": "openai/gpt-5.6-terra",
        "account_id": "openrouter-account-beta-primary",
        "credential_source": "environment:OPENROUTER_API_KEY",
        "adapter_protocol": PROTOCOL,
        "endpoint": ENDPOINT,
        "timeout_seconds": 30,
        "maximum_input_bytes": 4096,
        "maximum_response_bytes": 65536,
        "maximum_output_bytes": 4096,
        "internal_provider_retry_count": 0,
        "semantic_retry": False,
        "allow_provider_model_fallback": False,
        "authority_effect": "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY",
    }
    request["request_digest"] = digest(REQUEST_DOMAIN + _canonical(request))
    binding = {
        "schema": "switchyard.direct-api-owner-binding/v1",
        **{key: request[key] for key in (
            "request_digest", "request_id", "work_attempt_id", "dispatch_occurrence_id",
            "admitted_input_sha256", "provider_id", "model_id", "account_id",
            "credential_source", "adapter_protocol", "endpoint", "authority_effect",
        )},
    }
    binding["binding_digest"] = digest(BINDING_DOMAIN + _canonical(binding))
    return request, admitted, binding


def v2_inputs():
    request, admitted, binding = inputs()
    request["schema"] = "switchyard.direct-api-request/v2"
    request.update(maximum_input_bytes=3584, maximum_prompt_tokens=4096, maximum_completion_tokens=40,
                   maximum_total_tokens=5000, maximum_concurrent_requests=1,
                   spend_budget_id="maude-fixture-budget", spend_budget_micros=5000,
                   reserved_spend_micros=4176, prompt_token_price_micros=1,
                   completion_token_price_micros=2)
    request["request_digest"] = digest(REQUEST_DOMAIN + _canonical(
        {key: value for key, value in request.items() if key != "request_digest"}
    ))
    binding["schema"] = "switchyard.direct-api-owner-binding/v2"
    binding.update(owner_id="maude.proposal-service", owner_profile_id="maude-profile-fixture",
                   proposal_request_id="sha256:" + "a" * 64,
                   proposal_request_digest="sha256:" + "b" * 64,
                   request_digest=request["request_digest"])
    binding["binding_digest"] = digest(BINDING_DOMAIN + _canonical(
        {key: value for key, value in binding.items() if key != "binding_digest"}
    ))
    return request, admitted, binding


def v3_inputs():
    request, admitted, binding = v2_inputs()
    request["schema"] = "switchyard.direct-api-request/v3"
    request["response_format"] = {"type": "json_schema", "json_schema": {
        "name": "bounded_output", "strict": True,
        "schema": {"type": "object", "additionalProperties": False,
                   "properties": {"result": {"type": "string"}}, "required": ["result"]},
    }}
    request["request_digest"] = digest(REQUEST_DOMAIN + _canonical(
        {key: value for key, value in request.items() if key != "request_digest"}
    ))
    binding["schema"] = "switchyard.direct-api-owner-binding/v3"
    binding["request_digest"] = request["request_digest"]
    binding["binding_digest"] = digest(BINDING_DOMAIN + _canonical(
        {key: value for key, value in binding.items() if key != "binding_digest"}
    ))
    return request, admitted, binding


class FixtureTransport:
    calls = []
    status = 200
    response = None

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        response = self.response or {
            "id": "generation-fixture",
            "model": "openai/gpt-5.6-terra",
            "provider": "OpenAI",
            "choices": [{"message": {"role": "assistant", "content": "bounded result"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 9, "completion_tokens": 2,
                      "total_tokens": 11, "cost": 0.002},
        }
        return self.status, _canonical(response)


def execute(tmp_path, *, transport=None, credential_source=lambda _: "fixture-secret", cancelled=lambda: False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    request, admitted, binding = inputs()
    return run(request, admitted, binding, RunStore(tmp_path / "direct.sqlite"),
               transport=transport or FixtureTransport(), credential_source=credential_source,
               cancellation_requested=cancelled)


def test_completed_is_not_accepted_and_duplicate_does_not_regenerate(tmp_path):
    fixture = FixtureTransport()
    fixture.calls = []
    result = execute(tmp_path, transport=fixture)
    assert result["state"] == "PROVIDER_COMPLETED"
    assert result["completion_state"] == "COMPLETED"
    assert result["acceptance_state"] == "NOT_EVALUATED_BY_SWITCHYARD"
    assert result["requested_execution"] == {
        "provider_id": "openrouter", "model_id": "openai/gpt-5.6-terra",
        "endpoint": ENDPOINT, "account_id": "openrouter-account-beta-primary",
    }
    assert result["enrolled_endpoint"] == ENDPOINT
    assert result["enrolled_account_id"] == "openrouter-account-beta-primary"
    assert result["credential_source"] == "environment:OPENROUTER_API_KEY"
    assert result["reported_execution"] == {
        "state": "OBSERVED_RESPONSE_IDENTITY", "provider_id": "openrouter",
        "model_id": "openai/gpt-5.6-terra", "upstream_provider_id": "OpenAI",
        "account_id": None,
    }
    assert result["usage_state"] == "OBSERVED_RESPONSE_ATTRIBUTED"
    assert result["cost_state"] == "OBSERVED_AMOUNT_CURRENCY_NOT_OBSERVABLE"
    assert result["cost"] == {
        "amount": 0.002, "currency": "NOT_OBSERVABLE", "source": "response.usage.cost"
    }
    assert len(fixture.calls) == 1
    request, admitted, binding = inputs()
    assert run(request, admitted, binding, RunStore(tmp_path / "direct.sqlite"),
               transport=fixture, credential_source=lambda _: "fixture-secret") == result
    assert len(fixture.calls) == 1
    assert inspect(tmp_path / "direct.sqlite", request["dispatch_occurrence_id"]) == result


@pytest.mark.parametrize("status,state", [
    (400, "PROVIDER_REFUSED"),
    (401, "AUTHENTICATION_FAILED"), (403, "AUTHENTICATION_FAILED"),
    (402, "QUOTA_EXHAUSTED"), (429, "RATE_OR_CAPACITY_REFUSED"),
    (408, "PROVIDER_TIMEOUT_OUTCOME_UNKNOWN"), (504, "PROVIDER_TIMEOUT_OUTCOME_UNKNOWN"),
    (503, "PROVIDER_CAPACITY_UNAVAILABLE"), (500, "PROVIDER_REFUSED"),
])
def test_typed_http_failures_do_not_retain_body(tmp_path, status, state):
    fixture = FixtureTransport()
    fixture.calls = []
    fixture.status = status
    fixture.response = {"error": "fixture-secret should never persist"}
    result = execute(tmp_path, transport=fixture)
    assert result["state"] == state
    assert result["worker_output"] is None
    persisted = (tmp_path / "direct.sqlite").read_bytes()
    assert b"should never persist" not in persisted


def test_http_400_retains_only_bounded_provider_error_identifiers(tmp_path):
    fixture = FixtureTransport()
    fixture.calls = []
    fixture.status = 400
    fixture.response = {
        "error": {
            "code": "invalid_request.400",
            "type": "legacy_type",
            "message": "fixture-private diagnostic and request echo",
            "metadata": {
                "error_type": "response_format/unsupported",
                "provider_code": "upstream.invalid_schema",
                "provider": "fixture-private-provider",
            },
        },
        "request": "fixture-private-request",
    }
    request, admitted, binding = v2_inputs()
    state = tmp_path / "direct.sqlite"
    with RunStore(state) as store:
        result = run(request, admitted, binding, store, transport=fixture,
                     credential_source=lambda _: "fixture-secret")
    assert result["state"] == "PROVIDER_REFUSED"
    assert result["http_status"] == 400
    assert result["provider_error_code"] == "invalid_request.400"
    assert result["provider_error_type"] == "response_format/unsupported"
    assert result["upstream_provider_error_code"] == "upstream.invalid_schema"
    assert result["worker_output"] is None
    assert len(fixture.calls) == 1
    serialized = json.dumps(result)
    persisted = state.read_bytes()
    for private in (b"fixture-private diagnostic", b"fixture-private-provider",
                    b"fixture-private-request"):
        assert private not in serialized.encode()
        assert private not in persisted


@pytest.mark.parametrize("error", [
    b"not-json",
    b"[]",
    b'{"error":"not-an-object"}',
    b'{"error":{"code":true,"type":false,"metadata":{"error_type":true,"provider_code":false}}}',
    json.dumps({"error": {"code": "contains spaces", "type": "x" * 129}}).encode(),
    json.dumps({"error": {"code": ["not", "scalar"], "type": {"nested": 1}}}).encode(),
    json.dumps({"error": {"metadata": {"error_type": ["nested"],
                                         "provider_code": "contains spaces"}}}).encode(),
])
def test_http_400_omits_malformed_or_unbounded_provider_diagnostics(tmp_path, error):
    class Refused:
        calls = 0

        def __call__(self, **kwargs):
            self.calls += 1
            return 400, error

    fixture = Refused()
    result = execute(tmp_path, transport=fixture)
    assert result["state"] == "PROVIDER_REFUSED"
    assert result["http_status"] == 400
    assert "provider_error_code" not in result
    assert "provider_error_type" not in result
    assert "upstream_provider_error_code" not in result
    assert fixture.calls == 1


@pytest.mark.parametrize("secret", [
    "fixture-secret",
    "prefix.fixture-secret.suffix",
    "sk-or-v1-not-a-real-key",
    "pk_test_not-a-real-key",
])
def test_http_400_never_retains_credential_or_secret_shaped_identifier(tmp_path, secret):
    class Refused:
        calls = 0

        def __call__(self, **kwargs):
            self.calls += 1
            return 400, _canonical({"error": {
                "code": secret,
                "type": secret,
                "metadata": {"error_type": secret, "provider_code": secret},
            }})

    fixture = Refused()
    result = execute(tmp_path, transport=fixture,
                     credential_source=lambda _: "fixture-secret")
    assert result["state"] == "PROVIDER_REFUSED"
    assert "provider_error_code" not in result
    assert "provider_error_type" not in result
    assert "upstream_provider_error_code" not in result
    assert secret.encode() not in (tmp_path / "direct.sqlite").read_bytes()
    assert fixture.calls == 1


def test_http_400_numeric_code_is_normalized_without_changing_accounting(tmp_path):
    fixture = FixtureTransport()
    fixture.calls = []
    fixture.status = 400
    fixture.response = {"error": {"code": 400, "type": "invalid_request"}}
    request, admitted, binding = v2_inputs()
    with RunStore(tmp_path / "direct.sqlite") as store:
        result = run(request, admitted, binding, store, transport=fixture,
                     credential_source=lambda _: "fixture-secret")
    assert result["provider_error_code"] == "400"
    assert result["provider_error_type"] == "invalid_request"
    assert result["completion_state"] == "NOT_COMPLETED"
    assert result["contact_state"] == "RESPONSE_OBSERVED"
    assert result["spend_reservation"]["state"] == "RESERVED"
    assert len(fixture.calls) == 1


def test_missing_credential_and_precontact_cancel_never_contact(tmp_path):
    fixture = FixtureTransport()
    fixture.calls = []
    assert execute(tmp_path / "auth", transport=fixture, credential_source=lambda _: None)["state"] == "AUTHENTICATION_UNAVAILABLE"
    assert execute(tmp_path / "cancel", transport=fixture, cancelled=lambda: True)["state"] == "CANCELLED_BEFORE_CONTACT"
    assert fixture.calls == []


@pytest.mark.parametrize("cancelled,credential_source,first_state", [
    (lambda: True, lambda _: "fixture-secret", "CANCELLED_BEFORE_CONTACT"),
    (lambda: False, lambda _: None, "AUTHENTICATION_UNAVAILABLE"),
])
def test_known_no_contact_outcome_releases_only_concurrency_slot(
        tmp_path, cancelled, credential_source, first_state):
    request, admitted, binding = v2_inputs()
    request["spend_budget_micros"] = 10_000
    request["request_digest"] = digest(REQUEST_DOMAIN + _canonical(
        {key: value for key, value in request.items() if key != "request_digest"}
    ))
    binding["request_digest"] = request["request_digest"]
    binding["binding_digest"] = digest(BINDING_DOMAIN + _canonical(
        {key: value for key, value in binding.items() if key != "binding_digest"}
    ))
    state = tmp_path / "direct.sqlite"
    first = run(request, admitted, binding, RunStore(state),
                transport=FixtureTransport(), credential_source=credential_source,
                cancellation_requested=cancelled)
    assert first["state"] == first_state
    with sqlite3.connect(state) as db:
        assert db.execute(
            "SELECT active FROM direct_api_reservations WHERE dispatch=?",
            (request["dispatch_occurrence_id"],),
        ).fetchone() == (0,)
        assert db.execute("SELECT sum(reserved_micros) FROM direct_api_reservations").fetchone() == (4176,)

    second = copy.deepcopy(request)
    second_binding = copy.deepcopy(binding)
    second.update(request_id="request-direct-002", work_attempt_id="attempt-direct-002",
                  dispatch_occurrence_id="dispatch-direct-002")
    second["request_digest"] = digest(REQUEST_DOMAIN + _canonical(
        {key: value for key, value in second.items() if key != "request_digest"}
    ))
    for key in ("request_id", "work_attempt_id", "dispatch_occurrence_id", "request_digest"):
        second_binding[key] = second[key]
    second_binding["binding_digest"] = digest(BINDING_DOMAIN + _canonical(
        {key: value for key, value in second_binding.items() if key != "binding_digest"}
    ))
    fixture = FixtureTransport(); fixture.calls = []
    result = run(second, admitted, second_binding, RunStore(state), transport=fixture,
                 credential_source=lambda _: "fixture-secret")
    assert result["state"] == "PROVIDER_COMPLETED"
    assert len(fixture.calls) == 1


def _blocking_child(tmp_path: Path) -> tuple[tuple[str, ...], Path]:
    marker = tmp_path / "child.pid"
    script = tmp_path / "blocked_transport.py"
    script.write_text(
        "import pathlib,sys,time\n"
        "sys.stdin.buffer.read()\n"
        "pathlib.Path(sys.argv[1]).write_text(str(__import__('os').getpid()))\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )
    return (sys.executable, str(script), str(marker)), marker


def _assert_child_stopped(marker: Path) -> None:
    pid = int(marker.read_text(encoding="utf-8"))
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_isolated_transport_total_deadline_stops_blocked_child(tmp_path):
    command, marker = _blocking_child(tmp_path)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        direct_api._isolated_http_transport(
            endpoint=ENDPOINT, body=b"{}", credential="fixture-secret",
            timeout_seconds=1, maximum_response_bytes=1024,
            cancellation_requested=lambda: False, child_command=command,
        )
    assert 0.8 <= time.monotonic() - started < 3
    _assert_child_stopped(marker)


def test_isolated_transport_uses_one_private_pipe_and_strips_credential_environment(tmp_path, monkeypatch):
    marker = tmp_path / "child.json"
    script = tmp_path / "fixture_transport.py"
    script.write_text(
        "import base64,json,os,pathlib,sys\n"
        "request=json.load(sys.stdin)\n"
        "pathlib.Path(sys.argv[1]).write_text(json.dumps({'calls':1,'credential_in_pipe':request['credential']=='fixture-secret','credential_in_environment':'OPENROUTER_API_KEY' in os.environ}))\n"
        "json.dump({'kind':'response','status':200,'body':base64.b64encode(b'bounded').decode('ascii')},sys.stdout,separators=(',',':'),sort_keys=True)\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENROUTER_API_KEY", "fixture-secret")
    status, response = direct_api._isolated_http_transport(
        endpoint=ENDPOINT, body=b"{}", credential="fixture-secret",
        timeout_seconds=10, maximum_response_bytes=1024,
        cancellation_requested=lambda: False,
        child_command=(sys.executable, str(script), str(marker)),
    )
    assert (status, response) == (200, b"bounded")
    assert json.loads(marker.read_text(encoding="utf-8")) == {
        "calls": 1, "credential_in_pipe": True, "credential_in_environment": False,
    }


def test_isolated_transport_inflight_cancel_stops_one_child(tmp_path):
    command, marker = _blocking_child(tmp_path)
    observations = 0
    def cancelled():
        nonlocal observations
        observations += 1
        return marker.exists()
    with pytest.raises(direct_api.LocalCancellation):
        direct_api._isolated_http_transport(
            endpoint=ENDPOINT, body=b"{}", credential="fixture-secret",
            timeout_seconds=10, maximum_response_bytes=1024,
            cancellation_requested=cancelled, child_command=command,
        )
    assert observations >= 2
    assert marker.read_text(encoding="utf-8").isdigit()
    _assert_child_stopped(marker)


def test_isolated_transport_callback_failure_still_stops_child(tmp_path):
    command, marker = _blocking_child(tmp_path)
    def cancellation_failure():
        if marker.exists():
            raise RuntimeError("fixture callback failure")
        return False
    with pytest.raises(RuntimeError, match="fixture callback failure"):
        direct_api._isolated_http_transport(
            endpoint=ENDPOINT, body=b"{}", credential="fixture-secret",
            timeout_seconds=10, maximum_response_bytes=1024,
            cancellation_requested=cancellation_failure, child_command=command,
        )
    _assert_child_stopped(marker)


def test_default_child_entrypoint_is_pinned_against_cwd_and_pythonpath(tmp_path):
    shadow = tmp_path / "shadow" / "switchyard"
    shadow.mkdir(parents=True)
    marker = tmp_path / "shadow-imported"
    (shadow / "__init__.py").write_text("", encoding="utf-8")
    (shadow / "direct_api.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('wrong')\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(tmp_path / "shadow")
    result = subprocess.run(direct_api._http_child_command(), input=b"{}",
                            cwd=tmp_path / "shadow", env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=3, check=False)
    assert result.returncode == 2
    assert result.stdout == b""
    assert not marker.exists()


def test_exact_child_entrypoint_runs_existing_http_transport_against_loopback(tmp_path):
    observations = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            observations.append((self.path, self.headers["Authorization"], body))
            response = b'{"fixture":"bounded"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        def log_message(self, format, *args):
            del format, args
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}/synthetic"
    source_root = str(Path(direct_api.__file__).resolve().parents[1])
    bootstrap = (
        "import importlib,sys;module=sys.argv.pop(1);root=sys.argv.pop(1);"
        "endpoint=sys.argv.pop(1);sys.path.insert(0,root);"
        "loaded=importlib.import_module(module);loaded.ENDPOINT=endpoint;loaded.main()"
    )
    command = (sys.executable, "-P", "-c", bootstrap,
               direct_api._HTTP_CHILD_MODULE, source_root, endpoint,
               "--http-transport-child")
    try:
        status, response = direct_api._isolated_http_transport(
            endpoint=endpoint, body=b'{"request":"fixture"}',
            credential="fixture-secret", timeout_seconds=3,
            maximum_response_bytes=1024,
            cancellation_requested=lambda: False, child_command=command,
        )
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)
    assert (status, response) == (200, b'{"fixture":"bounded"}')
    assert observations == [("/synthetic", "Bearer fixture-secret", b'{"request":"fixture"}')]


def test_inflight_local_cancel_is_persisted_uncertain_and_keeps_slot(monkeypatch, tmp_path):
    request, admitted, binding = v2_inputs()
    def locally_cancelled(**kwargs):
        del kwargs
        raise direct_api.LocalCancellation
    monkeypatch.setattr(direct_api, "_isolated_http_transport", locally_cancelled)
    state = tmp_path / "direct.sqlite"
    result = run(request, admitted, binding, RunStore(state), transport=direct_api.http_transport,
                 credential_source=lambda _: "fixture-secret")
    assert result["state"] == "CANCELLED_AFTER_CONTACT_OUTCOME_UNKNOWN"
    assert result["contact_state"] == "CONTACT_STARTED_OUTCOME_UNKNOWN"
    with sqlite3.connect(state) as db:
        assert db.execute(
            "SELECT active FROM direct_api_reservations WHERE dispatch=?",
            (request["dispatch_occurrence_id"],),
        ).fetchone() == (1,)


def test_direct_api_caller_closes_owned_store(monkeypatch, tmp_path):
    closed = []
    real_store = direct_api.RunStore
    class TrackingStore(real_store):
        def close(self):
            closed.append(self)
            super().close()
    monkeypatch.setattr(direct_api, "RunStore", TrackingStore)
    request, admitted, binding = inputs()
    result = DirectApiCaller(tmp_path / "direct.sqlite", transport=FixtureTransport(),
                             credential_source=lambda _: "fixture-secret").run(
                                 request, admitted, binding,
                                 cancellation_requested=lambda: False)
    assert result["state"] == "PROVIDER_COMPLETED"
    assert len(closed) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        closed[0].db.execute("SELECT 1")

    invalid = copy.deepcopy(request)
    invalid["endpoint"] = "https://example.invalid"
    with pytest.raises(AdapterProtocolError):
        DirectApiCaller(tmp_path / "invalid.sqlite", transport=FixtureTransport(),
                        credential_source=lambda _: "fixture-secret").run(
                            invalid, admitted, binding,
                            cancellation_requested=lambda: False)
    assert len(closed) == 2
    with pytest.raises(sqlite3.ProgrammingError):
        closed[1].db.execute("SELECT 1")


def test_after_contact_cancel_is_uncertain_and_never_retried(tmp_path):
    fixture = FixtureTransport()
    fixture.calls = []
    observations = iter((False, True))
    result = execute(tmp_path, transport=fixture, cancelled=lambda: next(observations))
    assert result["state"] == "CANCELLED_AFTER_CONTACT_OUTCOME_UNKNOWN"
    assert result["completion_state"] == "NOT_OBSERVABLE"
    assert len(fixture.calls) == 1


@pytest.mark.parametrize("failure,state", [
    (TimeoutError(), "LOCAL_TIMEOUT_OUTCOME_UNKNOWN"),
    (ConnectionError("fixture-secret diagnostic"), "TRANSPORT_OUTCOME_UNKNOWN"),
])
def test_transport_failure_is_bounded_and_redacted(tmp_path, failure, state):
    class Failing:
        def __call__(self, **kwargs):
            raise failure
    result = execute(tmp_path, transport=Failing())
    assert result["state"] == state
    assert result["contact_state"] == "CONTACT_STARTED_OUTCOME_UNKNOWN"
    assert "fixture-secret" not in json.dumps(result)
    assert b"fixture-secret diagnostic" not in (tmp_path / "direct.sqlite").read_bytes()


def test_process_interruption_after_contact_is_inspect_only_and_never_regenerates(tmp_path):
    class Interrupted:
        calls = 0

        def __call__(self, **kwargs):
            self.calls += 1
            raise KeyboardInterrupt()

    transport = Interrupted()
    request, admitted, binding = inputs()
    state = tmp_path / "direct.sqlite"
    with pytest.raises(KeyboardInterrupt):
        run(request, admitted, binding, RunStore(state), transport=transport,
            credential_source=lambda _: "fixture-secret")
    retained = inspect(state, request["dispatch_occurrence_id"])
    assert retained["state"] == "OUTCOME_UNKNOWN"
    assert retained["contact_state"] == "CONTACT_STARTED_OUTCOME_UNKNOWN"
    assert retained["completion_state"] == "NOT_OBSERVABLE"
    duplicate = run(request, admitted, binding, RunStore(state), transport=transport,
                    credential_source=lambda _: "fixture-secret")
    assert duplicate == retained
    assert transport.calls == 1


def test_model_substitution_and_missing_identity_are_not_completion(tmp_path):
    for index, model in enumerate(("other/model", None)):
        fixture = FixtureTransport()
        fixture.response = {"model": model, "choices": [{"message": {"content": "wrong"}}]}
        result = execute(tmp_path / str(index), transport=fixture)
        assert result["state"] == "MODEL_IDENTITY_MISMATCH"
        assert result["worker_output"] is None


def test_usage_and_cost_unavailable_are_explicit(tmp_path):
    fixture = FixtureTransport()
    fixture.response = {
        "model": "openai/gpt-5.6-terra",
        "choices": [{"message": {"content": "bounded result"}, "finish_reason": "stop"}],
    }
    result = execute(tmp_path, transport=fixture)
    assert result["state"] == "PROVIDER_COMPLETED"
    assert result["usage"] is None and result["usage_state"] == "NOT_OBSERVABLE"
    assert result["cost"] is None and result["cost_state"] == "NOT_OBSERVABLE"


def test_transport_response_bound_is_enforced_independently(tmp_path):
    class OverBound:
        def __call__(self, **kwargs):
            return 200, b"x" * (kwargs["maximum_response_bytes"] + 1)
    result = execute(tmp_path, transport=OverBound())
    assert result["state"] == "RESPONSE_OVER_BOUND"
    assert result["completion_state"] == "NOT_ACCEPTABLE_AS_REQUESTED_COMPLETION"
    assert result["worker_output"] is None


def test_unbounded_finish_reason_is_not_retained(tmp_path):
    fixture = FixtureTransport()
    fixture.response = {
        "model": "openai/gpt-5.6-terra",
        "choices": [{"message": {"content": "bounded result"}, "finish_reason": "x" * 257}],
    }
    result = execute(tmp_path, transport=fixture)
    assert result["state"] == "PROVIDER_COMPLETED"
    assert result["finish_reason"] is None


@pytest.mark.parametrize("response", [b"not-json", b"[]", b'{"model":'])
def test_malformed_response_is_uncertain_not_accepted(tmp_path, response):
    class Malformed:
        def __call__(self, **kwargs):
            return 200, response

    result = execute(tmp_path, transport=Malformed())
    assert result["state"] == "MALFORMED_RESPONSE_OUTCOME_UNKNOWN"
    assert result["completion_state"] == "NOT_OBSERVABLE"
    assert result["acceptance_state"] == "NOT_EVALUATED_BY_SWITCHYARD"
    assert result["worker_output"] is None


def test_changed_owner_bound_input_or_selection_refuses_without_contact(tmp_path):
    request, admitted, binding = inputs()
    fixture = FixtureTransport()
    fixture.calls = []
    store = RunStore(tmp_path / "direct.sqlite")
    run(request, admitted, binding, store, transport=fixture,
        credential_source=lambda _: "fixture-secret")
    with pytest.raises(AdapterProtocolError):
        run(request, b"changed", binding, RunStore(tmp_path / "direct.sqlite"),
            transport=fixture, credential_source=lambda _: "fixture-secret")
    changed = copy.deepcopy(request)
    changed["model_id"] = "anthropic/claude-sonnet"
    changed["request_digest"] = digest(REQUEST_DOMAIN + _canonical({k: v for k, v in changed.items() if k != "request_digest"}))
    with pytest.raises(AdapterProtocolError):
        run(changed, admitted, binding, RunStore(tmp_path / "direct.sqlite"),
            transport=fixture, credential_source=lambda _: "fixture-secret")
    assert len(fixture.calls) == 1


@pytest.mark.parametrize("field,value", [
    ("account_id", "different-account"),
    ("endpoint", "https://example.invalid/v1/chat/completions"),
    ("credential_source", "environment:OTHER_KEY"),
])
def test_account_endpoint_and_credential_source_are_owner_bound(tmp_path, field, value):
    request, admitted, binding = inputs()
    request[field] = value
    request["request_digest"] = digest(REQUEST_DOMAIN + _canonical(
        {key: item for key, item in request.items() if key != "request_digest"}
    ))
    fixture = FixtureTransport()
    fixture.calls = []
    with pytest.raises(AdapterProtocolError):
        run(request, admitted, binding, RunStore(tmp_path / "direct.sqlite"),
            transport=fixture, credential_source=lambda _: "fixture-secret")
    assert fixture.calls == []


def test_input_bound_and_utf8_refuse_before_contact(tmp_path):
    fixture = FixtureTransport()
    fixture.calls = []
    for index, admitted in enumerate((b"x" * 4097, b"\xff")):
        request, _, binding = inputs()
        request["admitted_input_sha256"] = digest(admitted)
        request["request_digest"] = digest(REQUEST_DOMAIN + _canonical(
            {key: item for key, item in request.items() if key != "request_digest"}
        ))
        binding["admitted_input_sha256"] = request["admitted_input_sha256"]
        binding["request_digest"] = request["request_digest"]
        binding["binding_digest"] = digest(BINDING_DOMAIN + _canonical(
            {key: item for key, item in binding.items() if key != "binding_digest"}
        ))
        with pytest.raises(AdapterProtocolError):
            run(request, admitted, binding, RunStore(tmp_path / f"{index}.sqlite"),
                transport=fixture, credential_source=lambda _: "fixture-secret")
    assert fixture.calls == []


def test_fixture_secret_not_retained_on_success(tmp_path):
    fixture = FixtureTransport()
    execute(tmp_path, transport=fixture)
    assert b"fixture-secret" not in (tmp_path / "direct.sqlite").read_bytes()
    assert fixture.calls[0]["endpoint"] == ENDPOINT
    body = json.loads(fixture.calls[0]["body"])
    assert set(body) == {"model", "messages", "provider", "stream"}
    assert body["model"] == "openai/gpt-5.6-terra"
    assert body["provider"] == {"allow_fallbacks": False}
    assert body["stream"] is False


def test_v2_enrolled_owner_and_token_limits_are_retained_and_sent(tmp_path):
    request, admitted, binding = v2_inputs()
    fixture = FixtureTransport()
    fixture.calls = []
    result = run(request, admitted, binding, RunStore(tmp_path / "direct.sqlite"),
                 transport=fixture, credential_source=lambda _: "fixture-secret")
    assert result["state"] == "PROVIDER_COMPLETED"
    assert result["enrolled_owner"]["owner_id"] == "maude.proposal-service"
    assert result["token_limits"]["maximum_total_tokens"] == 5000
    assert json.loads(fixture.calls[0]["body"])["max_tokens"] == 40
    assert json.loads(fixture.calls[0]["body"])["provider"] == {
        "allow_fallbacks": False, "require_parameters": True,
        "max_price": {"prompt": 1, "completion": 2, "request": 0},
    }
    assert "response_format" not in json.loads(fixture.calls[0]["body"])


def test_v3_forwards_exact_owner_bound_strict_response_format(tmp_path):
    request, admitted, binding = v3_inputs()
    fixture = FixtureTransport(); fixture.calls = []
    run(request, admitted, binding, RunStore(tmp_path / "direct.sqlite"),
        transport=fixture, credential_source=lambda _: "fixture-secret")
    body = json.loads(fixture.calls[0]["body"])
    assert body["response_format"] == request["response_format"]
    assert body["provider"]["require_parameters"] is True
    assert body["provider"]["allow_fallbacks"] is False


def test_v3_response_format_substitution_or_unsupported_shape_refuses_before_contact(tmp_path):
    request, admitted, binding = v3_inputs()
    fixture = FixtureTransport(); fixture.calls = []
    changed = copy.deepcopy(request)
    changed["response_format"]["json_schema"]["name"] = "substituted"
    with pytest.raises(AdapterProtocolError, match="digest"):
        run(changed, admitted, binding, RunStore(tmp_path / "changed.sqlite"),
            transport=fixture, credential_source=lambda _: "fixture-secret")
    malformed = copy.deepcopy(request)
    malformed["response_format"] = {"type": "json_object"}
    malformed["request_digest"] = digest(REQUEST_DOMAIN + _canonical(
        {key: value for key, value in malformed.items() if key != "request_digest"}
    ))
    binding2 = copy.deepcopy(binding); binding2["request_digest"] = malformed["request_digest"]
    binding2["binding_digest"] = digest(BINDING_DOMAIN + _canonical(
        {key: value for key, value in binding2.items() if key != "binding_digest"}
    ))
    with pytest.raises(AdapterProtocolError, match="response format"):
        run(malformed, admitted, binding2, RunStore(tmp_path / "malformed.sqlite"),
            transport=fixture, credential_source=lambda _: "fixture-secret")
    assert fixture.calls == []


def test_v3_response_format_prompt_overbound_refuses_before_transport_and_claim(tmp_path):
    request, admitted, binding = v3_inputs()
    request["response_format"]["json_schema"]["schema"]["description"] = "x" * 5000
    request["request_digest"] = digest(REQUEST_DOMAIN + _canonical(
        {key: value for key, value in request.items() if key != "request_digest"}
    ))
    binding["request_digest"] = request["request_digest"]
    binding["binding_digest"] = digest(BINDING_DOMAIN + _canonical(
        {key: value for key, value in binding.items() if key != "binding_digest"}
    ))
    fixture = FixtureTransport(); fixture.calls = []
    state = tmp_path / "direct.sqlite"
    store = RunStore(state)
    with pytest.raises(AdapterProtocolError, match="prompt limit"):
        run(request, admitted, binding, store, transport=fixture,
            credential_source=lambda _: "fixture-secret")
    assert fixture.calls == []
    assert store.db.execute("SELECT count(*) FROM direct_api_runs").fetchone()[0] == 0


def test_v2_token_overage_is_not_acceptable_completion(tmp_path):
    request, admitted, binding = v2_inputs()
    fixture = FixtureTransport()
    fixture.response = {
        "model": "openai/gpt-5.6-terra",
        "choices": [{"message": {"content": "bounded result"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 4097, "completion_tokens": 2, "total_tokens": 4099},
    }
    result = run(request, admitted, binding, RunStore(tmp_path / "direct.sqlite"),
                 transport=fixture, credential_source=lambda _: "fixture-secret")
    assert result["state"] == "TOKEN_USAGE_OVER_BOUND"
    assert result["completion_state"] == "NOT_ACCEPTABLE_AS_REQUESTED_COMPLETION"


def test_v2_reservation_is_durable_and_limits_future_claims(tmp_path):
    request, admitted, binding = v2_inputs()
    fixture = FixtureTransport()
    run(request, admitted, binding, RunStore(tmp_path / "direct.sqlite"),
        transport=fixture, credential_source=lambda _: "fixture-secret")
    second, admitted, second_binding = v2_inputs()
    second["request_id"] = "request-direct-002"
    second["work_attempt_id"] = "attempt-direct-002"
    second["dispatch_occurrence_id"] = "dispatch-direct-002"
    second["request_digest"] = digest(REQUEST_DOMAIN + _canonical({k: v for k, v in second.items() if k != "request_digest"}))
    for key in ("request_id", "work_attempt_id", "dispatch_occurrence_id", "request_digest"):
        second_binding[key] = second[key]
    second_binding["binding_digest"] = digest(BINDING_DOMAIN + _canonical({k: v for k, v in second_binding.items() if k != "binding_digest"}))
    with pytest.raises(AdapterProtocolError, match="spend reservation"):
        run(second, admitted, second_binding, RunStore(tmp_path / "direct.sqlite"),
            transport=fixture, credential_source=lambda _: "fixture-secret")
