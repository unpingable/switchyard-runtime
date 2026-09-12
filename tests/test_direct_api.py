import copy
import json

import pytest

from switchyard.direct_api import (
    BINDING_DOMAIN, ENDPOINT, PROTOCOL, REQUEST_DOMAIN, RunStore, digest,
    inspect, run,
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


def test_missing_credential_and_precontact_cancel_never_contact(tmp_path):
    fixture = FixtureTransport()
    fixture.calls = []
    assert execute(tmp_path / "auth", transport=fixture, credential_source=lambda _: None)["state"] == "AUTHENTICATION_UNAVAILABLE"
    assert execute(tmp_path / "cancel", transport=fixture, cancelled=lambda: True)["state"] == "CANCELLED_BEFORE_CONTACT"
    assert fixture.calls == []


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
