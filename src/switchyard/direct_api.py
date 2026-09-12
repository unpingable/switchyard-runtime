"""One bounded direct OpenRouter attempt with durable, no-retry custody.

This transport consumes caller-issued identities and an exact owner binding.  It
does not admit work, authorize effects, evaluate the answer, or select a model.
"""
from __future__ import annotations

import hashlib
import argparse
import base64
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import time
from typing import Callable, Protocol
import urllib.error
import urllib.request

from .nightshift_adapter import AdapterProtocolError, IDENTIFIER, DIGEST, _canonical

PROTOCOL = "switchyard.openrouter-chat-completions/v1"
ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
REQUEST_DOMAIN = b"switchyard.direct-api-request.digest/v1\0"
BINDING_DOMAIN = b"switchyard.direct-api-owner-binding.digest/v1\0"
_HTTP_CHILD_MODULE = "switchyard.direct_api"
_HTTP_CHILD_BOOTSTRAP = (
    "import importlib,sys;module=sys.argv.pop(1);root=sys.argv.pop(1);"
    "sys.path.insert(0,root);importlib.import_module(module).main()"
)
REQUEST_FIELDS = frozenset({
    "schema", "request_digest", "request_id", "work_attempt_id",
    "dispatch_occurrence_id", "admitted_input_sha256", "provider_id",
    "model_id", "account_id", "credential_source", "adapter_protocol", "endpoint",
    "timeout_seconds", "maximum_input_bytes",
    "maximum_response_bytes", "maximum_output_bytes",
    "internal_provider_retry_count", "semantic_retry",
    "allow_provider_model_fallback", "authority_effect",
})
REQUEST_V2_FIELDS = REQUEST_FIELDS | frozenset({
    "maximum_prompt_tokens", "maximum_completion_tokens", "maximum_total_tokens",
    "maximum_concurrent_requests", "spend_budget_id", "spend_budget_micros",
    "reserved_spend_micros", "prompt_token_price_micros", "completion_token_price_micros",
})
REQUEST_V3_FIELDS = REQUEST_V2_FIELDS | frozenset({"response_format"})
BINDING_FIELDS = frozenset({
    "schema", "binding_digest", "request_digest", "request_id",
    "work_attempt_id", "dispatch_occurrence_id", "admitted_input_sha256",
    "provider_id", "model_id", "account_id", "credential_source", "adapter_protocol",
    "endpoint", "authority_effect",
})
BINDING_V2_FIELDS = BINDING_FIELDS | frozenset({
    "owner_id", "owner_profile_id", "proposal_request_id", "proposal_request_digest",
})
BINDING_V3_FIELDS = BINDING_V2_FIELDS


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class Transport(Protocol):
    def __call__(self, *, endpoint: str, body: bytes, credential: str,
                 timeout_seconds: int, maximum_response_bytes: int) -> tuple[int, bytes]: ...


class ResponseOverBound(Exception):
    """The single response crossed the admitted retained-byte boundary."""


class LocalCancellation(Exception):
    """The parent stopped local acquisition after contact had started."""


def _require_id(name: str, value: object) -> None:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise AdapterProtocolError(f"invalid {name}")


def _bounded_json(value: object, *, depth: int = 0, budget: list[int] | None = None) -> None:
    """Validate a small deterministic JSON value without interpreting its schema."""
    budget = [4096] if budget is None else budget
    budget[0] -= 1
    if budget[0] < 0 or depth > 32:
        raise AdapterProtocolError("v3 response JSON Schema exceeds structural bound")
    if value is None or isinstance(value, bool) or (isinstance(value, int) and not isinstance(value, bool)):
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > 16 * 1024:
            raise AdapterProtocolError("v3 response JSON Schema string exceeds bound")
        return
    if isinstance(value, list):
        for item in value:
            _bounded_json(item, depth=depth + 1, budget=budget)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            _bounded_json(key, depth=depth + 1, budget=budget)
            _bounded_json(item, depth=depth + 1, budget=budget)
        return
    raise AdapterProtocolError("v3 response JSON Schema contains an unsupported JSON value")


def validate(request: dict, admitted_input: bytes, owner_binding: dict) -> None:
    schema = request.get("schema")
    is_enrolled = schema in {"switchyard.direct-api-request/v2", "switchyard.direct-api-request/v3"}
    expected_request_fields = (REQUEST_V3_FIELDS if schema == "switchyard.direct-api-request/v3"
                               else REQUEST_V2_FIELDS if is_enrolled else REQUEST_FIELDS)
    if frozenset(request) != expected_request_fields or schema not in {
        "switchyard.direct-api-request/v1", "switchyard.direct-api-request/v2",
        "switchyard.direct-api-request/v3",
    }:
        raise AdapterProtocolError("closed direct API request fields do not match")
    for field in ("request_id", "work_attempt_id", "dispatch_occurrence_id", "provider_id",
                  "model_id", "account_id"):
        _require_id(field, request.get(field))
    if len({request["request_id"], request["work_attempt_id"], request["dispatch_occurrence_id"]}) != 3:
        raise AdapterProtocolError("request, attempt, and dispatch identities must be distinct")
    if not isinstance(request.get("admitted_input_sha256"), str) or DIGEST.fullmatch(request["admitted_input_sha256"]) is None:
        raise AdapterProtocolError("invalid admitted input digest")
    if request["admitted_input_sha256"] != digest(admitted_input):
        raise AdapterProtocolError("admitted input differs from owner-bound bytes")
    if (request["provider_id"] != "openrouter" or request["adapter_protocol"] != PROTOCOL
            or request["endpoint"] != ENDPOINT
            or request["credential_source"] not in ({"environment:OPENROUTER_API_KEY"} if not is_enrolled else {"environment:OPENROUTER_API_KEY", "maude-dedicated-config:OPENROUTER_API_KEY"})
            or request["internal_provider_retry_count"] != 0
            or request["semantic_retry"] is not False
            or request["allow_provider_model_fallback"] is not False
            or request["authority_effect"] != "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY"):
        raise AdapterProtocolError("direct API selection or effect boundary differs")
    for field, low, high in (("timeout_seconds", 1, 300),
                             ("maximum_input_bytes", 1, 1024 * 1024),
                             ("maximum_response_bytes", 1024, 16 * 1024 * 1024),
                             ("maximum_output_bytes", 1, 16 * 1024 * 1024)):
        value = request.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise AdapterProtocolError(f"invalid {field}")
    if len(admitted_input) > request["maximum_input_bytes"]:
        raise AdapterProtocolError("admitted input exceeds owner-bound limit")
    try:
        admitted_input.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdapterProtocolError("admitted input is not UTF-8") from error
    basis = {key: value for key, value in request.items() if key != "request_digest"}
    if request["request_digest"] != digest(REQUEST_DOMAIN + _canonical(basis)):
        raise AdapterProtocolError("direct API request digest mismatch")

    if is_enrolled:
        for field in ("maximum_prompt_tokens", "maximum_completion_tokens", "maximum_total_tokens"):
            value = request.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 2_000_000:
                raise AdapterProtocolError(f"invalid {field}")
        if request["maximum_prompt_tokens"] + request["maximum_completion_tokens"] > request["maximum_total_tokens"]:
            raise AdapterProtocolError("prompt and completion token limits exceed total token limit")
        # A UTF-8 byte is a conservative one-token upper-bound unit.  This
        # profile rule avoids assuming a tokenizer while ensuring the admitted
        # prompt cannot exceed the declared prompt ceiling.
        if request["maximum_input_bytes"] + 512 > request["maximum_prompt_tokens"]:
            raise AdapterProtocolError("input byte limit exceeds conservative prompt token limit")
        if not isinstance(request["maximum_concurrent_requests"], int) or isinstance(request["maximum_concurrent_requests"], bool) or not 1 <= request["maximum_concurrent_requests"] <= 64:
            raise AdapterProtocolError("invalid maximum_concurrent_requests")
        _require_id("spend_budget_id", request["spend_budget_id"])
        for field in ("spend_budget_micros", "reserved_spend_micros", "prompt_token_price_micros", "completion_token_price_micros"):
            if not isinstance(request[field], int) or isinstance(request[field], bool) or not 1 <= request[field] <= 10**12:
                raise AdapterProtocolError(f"invalid {field}")
        if request["reserved_spend_micros"] > request["spend_budget_micros"]:
            raise AdapterProtocolError("reserved spend exceeds enrolled budget")
        required_reservation = (request["maximum_prompt_tokens"] * request["prompt_token_price_micros"]
                                + request["maximum_completion_tokens"] * request["completion_token_price_micros"])
        if request["reserved_spend_micros"] != required_reservation:
            raise AdapterProtocolError("reserved spend is not the fixed-price token envelope")
    if schema == "switchyard.direct-api-request/v3":
        response_format = request["response_format"]
        _bounded_json(response_format)
        if (not isinstance(response_format, dict)
                or frozenset(response_format) != {"type", "json_schema"}
                or response_format.get("type") != "json_schema"):
            raise AdapterProtocolError("v3 response format must be a closed JSON Schema request")
        specification = response_format.get("json_schema")
        if (not isinstance(specification, dict)
                or frozenset(specification) != {"name", "strict", "schema"}
                or not isinstance(specification.get("name"), str)
                or not specification["name"] or len(specification["name"].encode()) > 128
                or specification.get("strict") is not True
                or not isinstance(specification.get("schema"), dict)
                or len(_canonical(response_format)) > 64 * 1024):
            raise AdapterProtocolError("v3 response JSON Schema is invalid or over bound")
        if len(admitted_input) + len(_canonical(response_format)) + 512 > request["maximum_prompt_tokens"]:
            raise AdapterProtocolError("v3 admitted input and response format exceed conservative prompt limit")

    binding_schema = owner_binding.get("schema")
    expected_binding_fields = BINDING_V3_FIELDS if schema == "switchyard.direct-api-request/v3" else BINDING_V2_FIELDS if is_enrolled else BINDING_FIELDS
    expected_binding_schema = ("switchyard.direct-api-owner-binding/v3" if schema == "switchyard.direct-api-request/v3"
                               else "switchyard.direct-api-owner-binding/v2" if is_enrolled
                               else "switchyard.direct-api-owner-binding/v1")
    if frozenset(owner_binding) != expected_binding_fields or binding_schema != expected_binding_schema:
        raise AdapterProtocolError("closed owner binding fields do not match")
    projected = {key: request[key] for key in BINDING_FIELDS - {"schema", "binding_digest"}}
    if any(owner_binding.get(key) != value for key, value in projected.items()):
        raise AdapterProtocolError("owner binding differs from exact request")
    binding_basis = {key: value for key, value in owner_binding.items() if key != "binding_digest"}
    if owner_binding["binding_digest"] != digest(BINDING_DOMAIN + _canonical(binding_basis)):
        raise AdapterProtocolError("owner binding digest mismatch")
    if is_enrolled:
        for field in ("owner_id", "owner_profile_id", "proposal_request_id"):
            _require_id(field, owner_binding.get(field))
        if not isinstance(owner_binding.get("proposal_request_digest"), str) or DIGEST.fullmatch(owner_binding["proposal_request_digest"]) is None:
            raise AdapterProtocolError("invalid proposal request digest")


def http_transport(*, endpoint: str, body: bytes, credential: str,
                   timeout_seconds: int, maximum_response_bytes: int) -> tuple[int, bytes]:
    """Perform exactly one HTTP request; redirect following is deliberately disabled."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    request = urllib.request.Request(endpoint, data=body, method="POST", headers={
        "Authorization": "Bearer " + credential,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "switchyard-direct-api/1",
    })
    opener = urllib.request.build_opener(NoRedirect)
    try:
        response = opener.open(request, timeout=timeout_seconds)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(maximum_response_bytes + 1)
        if len(raw) > maximum_response_bytes:
            raise ResponseOverBound
        return int(response.status), raw


def _http_transport_child() -> None:
    """Run only the existing urllib transport from bounded private stdin."""
    maximum_envelope = 16 * 1024 * 1024
    raw_request = sys.stdin.buffer.read(maximum_envelope + 1)
    if len(raw_request) > maximum_envelope:
        raise SystemExit(2)
    try:
        envelope = json.loads(raw_request)
        if (not isinstance(envelope, dict)
                or frozenset(envelope) != {"endpoint", "body", "credential", "timeout_seconds", "maximum_response_bytes"}
                or envelope["endpoint"] != ENDPOINT
                or not isinstance(envelope["body"], str)
                or not isinstance(envelope["credential"], str)
                or not isinstance(envelope["timeout_seconds"], int)
                or isinstance(envelope["timeout_seconds"], bool)
                or not 1 <= envelope["timeout_seconds"] <= 300
                or not isinstance(envelope["maximum_response_bytes"], int)
                or isinstance(envelope["maximum_response_bytes"], bool)
                or not 1024 <= envelope["maximum_response_bytes"] <= 16 * 1024 * 1024):
            raise ValueError
        body = base64.b64decode(envelope["body"], validate=True)
        if len(body) > 8 * 1024 * 1024:
            raise ValueError
    except (ValueError, TypeError, json.JSONDecodeError):
        raise SystemExit(2) from None
    try:
        status, response = http_transport(
            endpoint=envelope["endpoint"], body=body,
            credential=envelope["credential"],
            timeout_seconds=envelope["timeout_seconds"],
            maximum_response_bytes=envelope["maximum_response_bytes"],
        )
        result = {"kind": "response", "status": status,
                  "body": base64.b64encode(response).decode("ascii")}
    except BaseException as error:
        result = {"kind": "error", "error_class": type(error).__name__}
    sys.stdout.buffer.write(_canonical(result))


def _stop_child(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        process.wait()
        return
    try:
        process.terminate()
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait(timeout=1)


def _http_child_command() -> tuple[str, ...]:
    source_root = str(Path(__file__).resolve().parents[1])
    return (sys.executable, "-P", "-c", _HTTP_CHILD_BOOTSTRAP,
            _HTTP_CHILD_MODULE, source_root, "--http-transport-child")


def _isolated_http_transport(*, endpoint: str, body: bytes, credential: str,
                             timeout_seconds: int, maximum_response_bytes: int,
                             cancellation_requested: Callable[[], bool],
                             child_command: tuple[str, ...] | None = None) -> tuple[int, bytes]:
    """Supervise one urllib transport child under one total monotonic deadline."""
    payload = _canonical({
        "endpoint": endpoint,
        "body": base64.b64encode(body).decode("ascii"),
        "credential": credential,
        "timeout_seconds": timeout_seconds,
        "maximum_response_bytes": maximum_response_bytes,
    })
    command = child_command or _http_child_command()
    deadline = time.monotonic() + timeout_seconds
    child_environment = {
        key: os.environ[key] for key in (
            "HTTPS_PROXY", "NO_PROXY", "PATH", "SSL_CERT_DIR", "SSL_CERT_FILE",
            "http_proxy", "https_proxy", "no_proxy",
        ) if key in os.environ
    }
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, close_fds=True,
                               env=child_environment)
    pending_input: bytes | None = payload
    try:
        while True:
            if cancellation_requested():
                raise LocalCancellation
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            try:
                output, _ = process.communicate(input=pending_input, timeout=min(remaining, 0.05))
                break
            except subprocess.TimeoutExpired:
                pending_input = None
    finally:
        if process.poll() is None:
            _stop_child(process)
        for pipe in (process.stdin, process.stdout):
            if pipe is not None and not pipe.closed:
                pipe.close()
    if process.returncode != 0 or len(output) > (maximum_response_bytes * 2 + 4096):
        raise RuntimeError("isolated transport child failed")
    try:
        result = json.loads(output)
        if (not isinstance(result, dict) or result.get("kind") not in {"response", "error"}):
            raise ValueError
        if result["kind"] == "error":
            if result.get("error_class") in {"TimeoutError", "socket.timeout"}:
                raise TimeoutError
            if result.get("error_class") == "ResponseOverBound":
                raise ResponseOverBound
            raise RuntimeError("isolated transport failed")
        if (frozenset(result) != {"kind", "status", "body"}
                or not isinstance(result["status"], int)
                or isinstance(result["status"], bool)
                or not isinstance(result["body"], str)):
            raise ValueError
        response = base64.b64decode(result["body"], validate=True)
    except (ValueError, TypeError, json.JSONDecodeError):
        raise RuntimeError("invalid isolated transport response") from None
    if len(response) > maximum_response_bytes:
        raise ResponseOverBound
    return result["status"], response


class RunStore:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS direct_api_runs (dispatch TEXT PRIMARY KEY, request BLOB NOT NULL, admitted_input BLOB NOT NULL, owner_binding BLOB NOT NULL, record BLOB NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS direct_api_reservations (dispatch TEXT PRIMARY KEY, budget TEXT NOT NULL, reserved_micros INTEGER NOT NULL, active INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS direct_api_budget_config (budget TEXT PRIMARY KEY, config BLOB NOT NULL)")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "RunStore":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def claim(self, request: dict, admitted_input: bytes, owner_binding: dict) -> tuple[dict, bool]:
        exact = (_canonical(request), admitted_input, _canonical(owner_binding))
        key = request["dispatch_occurrence_id"]
        self.db.execute("BEGIN IMMEDIATE")
        try:
            prior = self.db.execute("SELECT request,admitted_input,owner_binding,record FROM direct_api_runs WHERE dispatch=?", (key,)).fetchone()
            if prior:
                if prior[:3] != exact:
                    raise AdapterProtocolError("dispatch reuse with different owner-bound input")
                self.db.commit()
                return json.loads(prior[3]), False
            record = {
                "schema": "switchyard.direct-api-run/v1",
                "request_id": request["request_id"],
                "work_attempt_id": request["work_attempt_id"],
                "dispatch_occurrence_id": key,
                "request_digest": request["request_digest"],
                "admitted_input_sha256": request["admitted_input_sha256"],
                "owner_binding_digest": owner_binding["binding_digest"],
                "requested_execution": {
                    "provider_id": "openrouter", "model_id": request["model_id"],
                    "endpoint": request["endpoint"], "account_id": request["account_id"],
                },
                "reported_execution": {"state": "NOT_OBSERVABLE", "provider_id": None, "model_id": None,
                                           "upstream_provider_id": None, "account_id": None},
                "enrolled_endpoint": request["endpoint"],
                "enrolled_account_id": request["account_id"],
                "credential_source": request["credential_source"],
                "state": "OUTCOME_UNKNOWN", "contact_state": "NOT_CONTACTED",
                "completion_state": "NOT_OBSERVABLE",
                "acceptance_state": "NOT_EVALUATED_BY_SWITCHYARD",
                "usage": None, "usage_state": "NOT_OBSERVABLE",
                "cost": None, "cost_state": "NOT_OBSERVABLE",
                "worker_output": None, "finish_reason": None,
                "internal_provider_retry_count": 0, "semantic_retry": False,
                "provider_or_model_substitution_allowed": False,
                "authority_effect": "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY",
                "started_at_unix_ms": time.time_ns() // 1_000_000,
                "operator_note": "claim precedes contact; duplicate dispatches inspect retained state and never regenerate",
            }
            if request["schema"] in {"switchyard.direct-api-request/v2", "switchyard.direct-api-request/v3"}:
                reservation_scope = digest(_canonical({"account_id": request["account_id"], "budget_id": request["spend_budget_id"], "owner_id": owner_binding["owner_id"]}))
                ledger_config = _canonical({key: request[key] for key in (
                    "maximum_concurrent_requests", "spend_budget_micros",
                    "prompt_token_price_micros", "completion_token_price_micros",
                )})
                prior_config = self.db.execute("SELECT config FROM direct_api_budget_config WHERE budget=?", (reservation_scope,)).fetchone()
                if prior_config is not None and prior_config[0] != ledger_config:
                    raise AdapterProtocolError("enrolled ledger configuration differs from the pinned budget")
                if prior_config is None:
                    self.db.execute("INSERT INTO direct_api_budget_config VALUES (?,?)", (reservation_scope, ledger_config))
                active_count, reserved = self.db.execute(
                    "SELECT count(*),coalesce(sum(reserved_micros),0) FROM direct_api_reservations WHERE budget=? AND active=1",
                    (reservation_scope,),
                ).fetchone()
                total_reserved = self.db.execute(
                    "SELECT coalesce(sum(reserved_micros),0) FROM direct_api_reservations WHERE budget=?",
                    (reservation_scope,),
                ).fetchone()[0]
                if active_count >= request["maximum_concurrent_requests"]:
                    raise AdapterProtocolError("enrolled concurrent request limit is exhausted")
                if total_reserved + request["reserved_spend_micros"] > request["spend_budget_micros"]:
                    raise AdapterProtocolError("enrolled spend reservation budget is exhausted")
                record["token_limits"] = {
                    "maximum_prompt_tokens": request["maximum_prompt_tokens"],
                    "maximum_completion_tokens": request["maximum_completion_tokens"],
                    "maximum_total_tokens": request["maximum_total_tokens"],
                }
                record["enrolled_owner"] = {
                    key: owner_binding[key] for key in (
                        "owner_id", "owner_profile_id", "proposal_request_id",
                        "proposal_request_digest",
                    )
                }
                record["spend_reservation"] = {
                    "budget_id": request["spend_budget_id"],
                    "reservation_scope": reservation_scope,
                    "budget_micros": request["spend_budget_micros"],
                    "reserved_micros": request["reserved_spend_micros"],
                    "state": "RESERVED",
                }
            self.db.execute("INSERT INTO direct_api_runs VALUES (?,?,?,?,?)", (key, *exact, _canonical(record)))
            if request["schema"] in {"switchyard.direct-api-request/v2", "switchyard.direct-api-request/v3"}:
                self.db.execute("INSERT INTO direct_api_reservations VALUES (?,?,?,1)", (key, reservation_scope, request["reserved_spend_micros"]))
            self.db.commit()
            return record, True
        except BaseException:
            self.db.rollback()
            raise

    def update(self, record: dict) -> None:
        self.db.execute("UPDATE direct_api_runs SET record=? WHERE dispatch=?", (_canonical(record), record["dispatch_occurrence_id"]))
        self.db.commit()

    def close_concurrency_slot(self, record: dict) -> None:
        """End only the in-flight slot; the monetary reservation stays retained."""
        self.db.execute("UPDATE direct_api_reservations SET active=0 WHERE dispatch=?", (record["dispatch_occurrence_id"],))
        self.db.commit()


class DirectApiCaller:
    """Concrete installed-runtime bridge; caller owns its state pathname."""
    def __init__(self, state: Path, *, credential_source: Callable[[str], str | None] = os.environ.get,
                 transport: Transport = http_transport):
        self.state = state
        self.credential_source = credential_source
        self.transport = transport

    def run(self, request: dict, admitted_input: bytes, owner_binding: dict, *,
            cancellation_requested: Callable[[], bool]) -> dict:
        with RunStore(self.state) as store:
            return run(request, admitted_input, owner_binding, store,
                       credential_source=self.credential_source, transport=self.transport,
                       cancellation_requested=cancellation_requested)


def inspect(path: Path, dispatch: str) -> dict:
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        row = db.execute("SELECT record FROM direct_api_runs WHERE dispatch=?", (dispatch,)).fetchone()
    if row is None:
        raise AdapterProtocolError("unknown direct API dispatch")
    return json.loads(row[0])


def _status_state(status: int) -> str:
    if status in {401, 403}:
        return "AUTHENTICATION_FAILED"
    if status == 402:
        return "QUOTA_EXHAUSTED"
    if status == 429:
        return "RATE_OR_CAPACITY_REFUSED"
    if status == 503:
        return "PROVIDER_CAPACITY_UNAVAILABLE"
    if status in {408, 504}:
        return "PROVIDER_TIMEOUT_OUTCOME_UNKNOWN"
    return "PROVIDER_REFUSED"


def _number(value: object) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return value


def run(request: dict, admitted_input: bytes, owner_binding: dict, store: RunStore, *,
        credential_source: Callable[[str], str | None] = os.environ.get,
        transport: Transport = http_transport,
        cancellation_requested: Callable[[], bool] = lambda: False) -> dict:
    validate(request, admitted_input, owner_binding)
    record, fresh = store.claim(request, admitted_input, owner_binding)
    if not fresh:
        return record
    try:
        if cancellation_requested():
            record.update(state="CANCELLED_BEFORE_CONTACT", contact_state="NOT_CONTACTED",
                          completion_state="NOT_COMPLETED")
            return record
        credential = credential_source("OPENROUTER_API_KEY")
        if not isinstance(credential, str) or not credential or len(credential) > 8192:
            record.update(state="AUTHENTICATION_UNAVAILABLE", contact_state="NOT_CONTACTED",
                          completion_state="NOT_COMPLETED")
            return record
        body = _canonical({
            "model": request["model_id"],
            "messages": [{"role": "user", "content": admitted_input.decode("utf-8")}],
            "provider": {"allow_fallbacks": False},
            "stream": False,
        })
        if request["schema"] in {"switchyard.direct-api-request/v2", "switchyard.direct-api-request/v3"}:
            body = _canonical({**json.loads(body), "max_tokens": request["maximum_completion_tokens"], "provider": {
                "allow_fallbacks": False, "require_parameters": True,
                "max_price": {"prompt": request["prompt_token_price_micros"],
                              "completion": request["completion_token_price_micros"],
                              "request": 0},
            }})
        if request["schema"] == "switchyard.direct-api-request/v3":
            body = _canonical({**json.loads(body), "response_format": request["response_format"]})
        record["contact_state"] = "CONTACT_STARTED_OUTCOME_UNKNOWN"
        store.update(record)
        if transport is http_transport:
            status, raw = _isolated_http_transport(
                endpoint=ENDPOINT, body=body, credential=credential,
                timeout_seconds=request["timeout_seconds"],
                maximum_response_bytes=request["maximum_response_bytes"],
                cancellation_requested=cancellation_requested,
            )
        else:
            status, raw = transport(endpoint=ENDPOINT, body=body, credential=credential,
                                    timeout_seconds=request["timeout_seconds"],
                                    maximum_response_bytes=request["maximum_response_bytes"])
        if not isinstance(status, int) or isinstance(status, bool) or not isinstance(raw, bytes):
            raise AdapterProtocolError("transport returned an invalid response envelope")
        if len(raw) > request["maximum_response_bytes"]:
            record.update(state="RESPONSE_OVER_BOUND", contact_state="RESPONSE_OBSERVED",
                          completion_state="NOT_ACCEPTABLE_AS_REQUESTED_COMPLETION")
            return record
        record["http_status"] = status
        if cancellation_requested():
            record.update(state="CANCELLED_AFTER_CONTACT_OUTCOME_UNKNOWN", completion_state="NOT_OBSERVABLE")
            return record
        if status != 200:
            record.update(state=_status_state(status), contact_state="RESPONSE_OBSERVED",
                          completion_state="NOT_COMPLETED")
            return record
        try:
            response = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            record.update(state="MALFORMED_RESPONSE_OUTCOME_UNKNOWN", contact_state="RESPONSE_OBSERVED")
            return record
        if not isinstance(response, dict):
            record.update(state="MALFORMED_RESPONSE_OUTCOME_UNKNOWN", contact_state="RESPONSE_OBSERVED")
            return record
        model = response.get("model")
        upstream = response.get("provider") if isinstance(response.get("provider"), str) else None
        record["reported_execution"] = {
            "state": "OBSERVED_RESPONSE_IDENTITY" if isinstance(model, str) else "PARTIALLY_OBSERVED",
            "provider_id": "openrouter", "model_id": model if isinstance(model, str) else None,
            "upstream_provider_id": upstream, "account_id": None,
        }
        if model != request["model_id"]:
            record.update(state="MODEL_IDENTITY_MISMATCH", contact_state="RESPONSE_OBSERVED",
                          completion_state="NOT_ACCEPTABLE_AS_REQUESTED_COMPLETION")
            return record
        choices = response.get("choices")
        if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
            record.update(state="MALFORMED_RESPONSE_OUTCOME_UNKNOWN", contact_state="RESPONSE_OBSERVED")
            return record
        message = choices[0].get("message")
        output = message.get("content") if isinstance(message, dict) else None
        if not isinstance(output, str) or len(output.encode()) > request["maximum_output_bytes"]:
            record.update(state="OUTPUT_UNAVAILABLE_OR_OVER_BOUND", contact_state="RESPONSE_OBSERVED",
                          completion_state="NOT_ACCEPTABLE_AS_REQUESTED_COMPLETION")
            return record
        usage = response.get("usage")
        if isinstance(usage, dict):
            observed = {name: _number(usage.get(name)) for name in ("prompt_tokens", "completion_tokens", "total_tokens")}
            if all(value is not None for value in observed.values()):
                record.update(usage=observed, usage_state="OBSERVED_RESPONSE_ATTRIBUTED")
                if request["schema"] in {"switchyard.direct-api-request/v2", "switchyard.direct-api-request/v3"} and (
                    observed["prompt_tokens"] > request["maximum_prompt_tokens"]
                    or observed["completion_tokens"] > request["maximum_completion_tokens"]
                    or observed["total_tokens"] > request["maximum_total_tokens"]
                ):
                    record.update(state="TOKEN_USAGE_OVER_BOUND", contact_state="RESPONSE_OBSERVED",
                                  completion_state="NOT_ACCEPTABLE_AS_REQUESTED_COMPLETION")
                    return record
            cost = _number(usage.get("cost"))
            if cost is not None:
                record.update(cost={"amount": cost, "currency": "NOT_OBSERVABLE",
                                    "source": "response.usage.cost"},
                              cost_state="OBSERVED_AMOUNT_CURRENCY_NOT_OBSERVABLE")
        finish_reason = choices[0].get("finish_reason")
        if not isinstance(finish_reason, str) or len(finish_reason.encode("utf-8")) > 256:
            finish_reason = None
        record.update(state="PROVIDER_COMPLETED", contact_state="RESPONSE_OBSERVED",
                      completion_state="COMPLETED", worker_output=output,
                      finish_reason=finish_reason)
        return record
    except ResponseOverBound:
        record.update(state="RESPONSE_OVER_BOUND", contact_state="RESPONSE_OBSERVED",
                      completion_state="NOT_ACCEPTABLE_AS_REQUESTED_COMPLETION")
        return record
    except LocalCancellation:
        record.update(state="CANCELLED_AFTER_CONTACT_OUTCOME_UNKNOWN",
                      completion_state="NOT_OBSERVABLE")
        return record
    except TimeoutError:
        record.update(state="LOCAL_TIMEOUT_OUTCOME_UNKNOWN", completion_state="NOT_OBSERVABLE")
        return record
    except Exception as error:
        # Type only: exception text and response bodies can contain credentials or private data.
        record.update(state="TRANSPORT_OUTCOME_UNKNOWN", completion_state="NOT_OBSERVABLE",
                      local_error_class=type(error).__name__)
        return record
    finally:
        record["ended_at_unix_ms"] = time.time_ns() // 1_000_000
        store.update(record)
        if (record["contact_state"] != "CONTACT_STARTED_OUTCOME_UNKNOWN"
                and not record["state"].endswith("OUTCOME_UNKNOWN")):
            store.close_concurrency_slot(record)


def _read_bounded(path: Path, maximum: int, label: str) -> bytes:
    if not path.is_absolute():
        raise AdapterProtocolError(f"{label} path must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode) or value.st_size > maximum:
            raise AdapterProtocolError(f"{label} is not a bounded regular file")
        raw = os.read(descriptor, maximum + 1)
        if len(raw) > maximum or os.read(descriptor, 1):
            raise AdapterProtocolError(f"{label} exceeds bound")
        return raw
    finally:
        os.close(descriptor)


def _load_canonical(path: Path, maximum: int, label: str) -> dict:
    raw = _read_bounded(path, maximum, label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdapterProtocolError(f"invalid {label} JSON") from error
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise AdapterProtocolError(f"{label} must be a canonical JSON object")
    return value


def main() -> None:
    if sys.argv[1:] == ["--http-transport-child"]:
        _http_transport_child()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("run")
    start.add_argument("--request", type=Path, required=True)
    start.add_argument("--admitted-input", type=Path, required=True)
    start.add_argument("--owner-binding", type=Path, required=True)
    read = sub.add_parser("inspect")
    read.add_argument("--dispatch", required=True)
    args = parser.parse_args()
    if args.command == "inspect":
        result = inspect(args.state, args.dispatch)
    else:
        request = _load_canonical(args.request, 64 * 1024, "request")
        owner_binding = _load_canonical(args.owner_binding, 64 * 1024, "owner binding")
        maximum = request.get("maximum_input_bytes", 0)
        if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 1024 * 1024:
            raise AdapterProtocolError("invalid maximum_input_bytes")
        admitted_input = _read_bounded(args.admitted_input, maximum, "admitted input")
        with RunStore(args.state) as store:
            result = run(request, admitted_input, owner_binding, store)
    print(_canonical(result).decode())


if __name__ == "__main__":
    main()
