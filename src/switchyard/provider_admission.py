from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, TypeVar

from ._vendor import rfc8785
from .appserver import AcquisitionCut, AcquisitionEnvelope, ServerMessage


BINDING_SCHEMA = "switchyard.codex-provider-admission-binding/v1"
EVIDENCE_SCHEMA = "switchyard.codex-provider-admission-evidence/v1"
SNAPSHOT_SCHEMA = "switchyard.codex-provider-admission-snapshot/v1"
CODEX_SOURCE_HEAD = "c36a8137638decf8b04a49611354a90f32c5a945"
BETA_CODEX_SOURCE_HEAD = "6893ae42233aa95b1c1623497405681d99a589da"
FINAL_CODEX_SOURCE_HEAD = "97b0acd5ce2ccb3c87a763606696c35a450947f6"
MAXIMUM_RAW_EVIDENCE_BYTES = 16 * 1024
MAXIMUM_ID_CODEPOINTS = 512
MAXIMUM_DIAGNOSTIC_CODEPOINTS = 4096
MAXIMUM_RECORDS = 4096
MAXIMUM_SNAPSHOT_BYTES = 16 * 1024 * 1024
U32_MAX = 2**32 - 1
SAFE_INTEGER_MAX = 2**53 - 1
SAFE_INTEGER_MIN = -SAFE_INTEGER_MAX

_BINDING_DOMAIN = b"switchyard.codex-provider-admission-binding.digest/v1\0"
_EVIDENCE_DOMAIN = b"switchyard.codex-provider-admission-evidence.digest/v1\0"
_SNAPSHOT_DOMAIN = b"switchyard.codex-provider-admission-snapshot.digest/v1\0"

_BINDING_FIELDS = frozenset(
    {
        "schema",
        "binding_digest",
        "work_attempt_id",
        "dispatch_occurrence_id",
        "adapter_process_occurrence_id",
        "app_server_session_identity",
        "thread_id",
        "turn_id",
        "provider",
        "model",
        "codex_source_head",
        "executable_kind",
        "app_server_executable_identity",
        "app_server_executable_sha256",
        "internal_provider_request_retries",
    }
)
_REQUEST_FIELDS = frozenset(
    {
        "threadId",
        "turnId",
        "requestOccurrenceId",
        "samplingOrdinal",
        "requestOrder",
        "provider",
        "model",
        "startedAtMs",
    }
)
_RESPONSE_FIELDS = frozenset(
    (_REQUEST_FIELDS - {"startedAtMs"}) | {"responseId", "observedAtMs"}
)
_REFUSAL_FIELDS = frozenset(
    (_REQUEST_FIELDS - {"startedAtMs"})
    | {
        "responseCreated",
        "willRetry",
        "refusalKind",
        "codexErrorInfo",
        "retryAfterMs",
        "diagnostic",
        "observedAtMs",
    }
)
_COMPLETED_FIELDS = frozenset({"threadId", "turnId", "responseId", "usage"})


class ProviderAdmissionError(ValueError):
    pass


_Result = TypeVar("_Result")


def _canonical(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        raise ProviderAdmissionError(f"value is outside RFC8785-JCS: {exc}") from exc


def _digest(domain: bytes, value: dict[str, Any], field: str) -> str:
    basis = dict(value)
    basis.pop(field, None)
    return "sha256:" + hashlib.sha256(domain + _canonical(basis)).hexdigest()


def _plain_sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _identity(field: str, value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAXIMUM_ID_CODEPOINTS:
        raise ProviderAdmissionError(f"invalid {field}")
    return value


def _bounded_int(field: str, value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ProviderAdmissionError(f"invalid {field}")
    return value


def _raw_custody(message: ServerMessage, maximum: int = MAXIMUM_RAW_EVIDENCE_BYTES) -> dict[str, Any]:
    raw = message.raw_bytes
    if raw is None:
        raise ProviderAdmissionError("exact App Server wire bytes are required")
    if not 1 <= len(raw) <= maximum:
        raise ProviderAdmissionError("App Server evidence exceeds exact byte bound")
    if not raw.endswith(b"\n"):
        raise ProviderAdmissionError("exact App Server wire bytes lack line terminator")
    try:
        parsed = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderAdmissionError(f"invalid retained App Server wire JSON: {exc}") from exc
    if parsed != message.raw:
        raise ProviderAdmissionError("retained App Server wire bytes differ from parsed message")
    return _raw_bytes_custody(
        raw, "EXACT_WIRE_BYTES_INCLUDING_LINE_TERMINATOR", maximum
    )


def _raw_bytes_custody(raw: bytes, representation: str, maximum: int = MAXIMUM_RAW_EVIDENCE_BYTES) -> dict[str, Any]:
    if not 1 <= len(raw) <= maximum:
        raise ProviderAdmissionError("App Server evidence exceeds exact byte bound")
    if representation not in {
        "EXACT_WIRE_BYTES_INCLUDING_LINE_TERMINATOR",
        "EXACT_ACQUIRED_FRAME_BYTES_INCLUDING_LINE_TERMINATOR",
    }:
        raise ProviderAdmissionError("unknown App Server raw custody representation")
    if not raw.endswith(b"\n"):
        raise ProviderAdmissionError("exact App Server evidence lacks line terminator")
    return {
        "representation": representation,
        "byte_length": len(raw),
        "sha256": _plain_sha256(raw),
        "encoding": "hex",
        "bytes_hex": raw.hex(),
    }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProviderAdmissionError(f"duplicate App Server JSON key: {key}")
        value[key] = item
    return value


def seal_binding(value: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(value)
    sealed.setdefault("schema", BINDING_SCHEMA)
    sealed.setdefault("binding_digest", "sha256:" + "0" * 64)
    sealed["binding_digest"] = _digest(_BINDING_DOMAIN, sealed, "binding_digest")
    validate_binding(sealed)
    return sealed


def validate_binding(value: dict[str, Any]) -> None:
    if not isinstance(value, dict) or frozenset(value) != _BINDING_FIELDS:
        raise ProviderAdmissionError("closed provider-admission binding fields do not match")
    if value["schema"] != BINDING_SCHEMA:
        raise ProviderAdmissionError("foreign provider-admission binding schema")
    for field in (
        "work_attempt_id",
        "dispatch_occurrence_id",
        "adapter_process_occurrence_id",
        "app_server_session_identity",
        "thread_id",
        "turn_id",
        "provider",
        "model",
        "app_server_executable_identity",
    ):
        _identity(field, value[field])
    if value["codex_source_head"] not in {CODEX_SOURCE_HEAD, BETA_CODEX_SOURCE_HEAD, FINAL_CODEX_SOURCE_HEAD}:
        raise ProviderAdmissionError("Codex source head is not the accepted owner source")
    if value["executable_kind"] not in {"CAMPAIGN_CODEX_BUILD", "DETERMINISTIC_FIXTURE"}:
        raise ProviderAdmissionError("unknown App Server executable custody kind")
    executable_digest = value["app_server_executable_sha256"]
    if not isinstance(executable_digest, str) or len(executable_digest) != 71:
        raise ProviderAdmissionError("invalid App Server executable SHA-256")
    prefix, _, hexadecimal = executable_digest.partition(":")
    if prefix != "sha256" or any(char not in "0123456789abcdef" for char in hexadecimal):
        raise ProviderAdmissionError("invalid App Server executable SHA-256")
    if value["internal_provider_request_retries"] != 0:
        raise ProviderAdmissionError("provider request retries must be exactly zero")
    expected = _digest(_BINDING_DOMAIN, value, "binding_digest")
    if value["binding_digest"] != expected:
        raise ProviderAdmissionError("provider-admission binding digest mismatch")


@dataclass(frozen=True)
class _ClientRequest:
    request_id: int
    method: str
    params_digest: str


@dataclass(frozen=True)
class _Request:
    occurrence_id: str
    ordinal: int
    order: int
    provider: str
    model: str


class ProviderAdmissionMapper:
    """Closed consumer for exact Codex provider-boundary notifications.

    The mapper owns evidence normalization only. It does not calculate wake time,
    choose fallback, start a second dispatch, or answer approval requests.
    """

    def __init__(self, binding: dict[str, Any], *, allow_unordered_fixture: bool = False,
                 capture_contract: str = "LEGACY_V1"):
        validate_binding(binding)
        from .appserver import client_request_byte_bound
        client_request_byte_bound(None, capture_contract)
        if capture_contract == "BOUNDED_TURN_V1" and binding["codex_source_head"] != FINAL_CODEX_SOURCE_HEAD:
            raise ProviderAdmissionError("bounded capture requires the final supported source")
        self._capture_contract = capture_contract
        self._binding = copy.deepcopy(binding)
        self._allow_unordered_fixture = allow_unordered_fixture
        self._records: list[dict[str, Any]] = []
        self.pending: _Request | None = None
        self.completed_requests: set[str] = set()
        self.pending_started_at_ms: int | None = None
        self.open_response_id: str | None = None
        self.client_requests: dict[int, _ClientRequest] = {}
        self.acquisition_cut: dict[str, Any] | None = None
        self.expected_acquisition_ordinal = 0
        self._current_acquisition_ordinal: int | None = None
        self._current_acquisition_kind: str | None = None
        self.last_boundary_ms: int | None = None
        self._retained_record_bytes = 0
        self.admission_disposition = "UNRESOLVED"
        self.mechanism_state = "DISPATCHING"
        self._provider_execution_identity: dict[str, Any] | None = None


    @property
    def binding(self) -> dict[str, Any]:
        return copy.deepcopy(self._binding)


    @property
    def records(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._records)


    @property
    def provider_execution_identity(self) -> dict[str, Any] | None:
        return copy.deepcopy(self._provider_execution_identity)

    def _base_fields(self) -> dict[str, Any]:
        return {
            "binding_digest": self._binding["binding_digest"],
            "work_attempt_id": self._binding["work_attempt_id"],
            "dispatch_occurrence_id": self._binding["dispatch_occurrence_id"],
            "adapter_process_occurrence_id": self._binding[
                "adapter_process_occurrence_id"
            ],
            "app_server_session_identity": self._binding[
                "app_server_session_identity"
            ],
            "thread_id": self._binding["thread_id"],
            "turn_id": self._binding["turn_id"],
            "provider": self._binding["provider"],
            "model": self._binding["model"],
        }

    def _record(
        self,
        kind: str,
        method: str,
        raw: dict[str, Any] | None,
        normalized: dict[str, Any],
    ) -> dict[str, Any]:
        if len(self._records) >= MAXIMUM_RECORDS:
            raise ProviderAdmissionError("provider-admission evidence record bound exceeded")
        record: dict[str, Any] = {
            "schema": EVIDENCE_SCHEMA,
            "evidence_digest": "sha256:" + "0" * 64,
            "sequence": len(self._records),
            "acquisition_ordinal": self._current_acquisition_ordinal,
            "acquisition_kind": self._current_acquisition_kind,
            **self._base_fields(),
            "kind": kind,
            "method": method,
            "normalized": normalized,
            "raw": raw,
        }
        record["evidence_digest"] = _digest(
            _EVIDENCE_DOMAIN, record, "evidence_digest"
        )
        stored_record = copy.deepcopy(record)
        record_bytes = len(_canonical(stored_record))
        if record_bytes > MAXIMUM_SNAPSHOT_BYTES - self._retained_record_bytes:
            raise ProviderAdmissionError(
                "provider-admission evidence exceeds cumulative byte bound"
            )
        self._retained_record_bytes += record_bytes
        self._records.append(stored_record)
        return copy.deepcopy(stored_record)

    def _mark_discrepancy(
        self,
        detail: str,
        method: str = "adapter/acquisition",
        raw: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self._provider_execution_identity is None:
            self.admission_disposition = "ADMISSION_INDETERMINATE"
            self.mechanism_state = "ADMISSION_INDETERMINATE"
        else:
            self.mechanism_state = "POST_ADMISSION_INTERRUPTED"
        return self._record(
            "ADMISSION_DISCREPANCY",
            method,
            raw,
            {
                "detail": detail[:MAXIMUM_DIAGNOSTIC_CODEPOINTS],
                "provider_execution_identity": copy.deepcopy(self._provider_execution_identity),
                "resume_same_attempt_only": self._provider_execution_identity is not None,
            },
        )

    def _atomic(self, operation: Callable[[], _Result]) -> _Result:
        checkpoint = (
            self.pending,
            self.pending_started_at_ms,
            self.open_response_id,
            dict(self.client_requests),
            copy.deepcopy(self.acquisition_cut),
            self.expected_acquisition_ordinal,
            self._current_acquisition_ordinal,
            self._current_acquisition_kind,
            self.last_boundary_ms,
            set(self.completed_requests),
            self.admission_disposition,
            self.mechanism_state,
            copy.deepcopy(self._provider_execution_identity),
            len(self._records),
            self._retained_record_bytes,
        )
        try:
            return operation()
        except Exception:
            (
                self.pending,
                self.pending_started_at_ms,
                self.open_response_id,
                self.client_requests,
                self.acquisition_cut,
                self.expected_acquisition_ordinal,
                self._current_acquisition_ordinal,
                self._current_acquisition_kind,
                self.last_boundary_ms,
                completed_requests,
                self.admission_disposition,
                self.mechanism_state,
                self._provider_execution_identity,
                record_count,
                self._retained_record_bytes,
            ) = checkpoint
            self.completed_requests = completed_requests
            del self._records[record_count:]
            raise

    def _require_acquisition_open(self) -> None:
        if self.acquisition_cut is not None:
            raise ProviderAdmissionError("terminal acquisition cut is already retained")

    def mark_acquisition_loss(self, detail: str) -> dict[str, Any]:
        def operation() -> dict[str, Any]:
            self._require_acquisition_open()
            return self._mark_discrepancy(detail)
        return self._atomic(operation)

    def record_legacy_local_fact(self, kind: str) -> dict[str, Any]:
        def operation() -> dict[str, Any]:
            self._require_acquisition_open()
            return self._record_legacy_local_fact(kind)
        return self._atomic(operation)

    def _record_legacy_local_fact(self, kind: str) -> dict[str, Any]:
        if kind not in {"thread/start", "turn/start", "turn/started", "worker_started"}:
            return self._mark_discrepancy("unknown legacy local-turn fact", kind)
        return self._record(
            "LOCAL_TURN_FACT",
            kind,
            None,
            {"proves_provider_admission": False},
        )

    def consume_envelope(self, envelope: AcquisitionEnvelope) -> dict[str, Any] | None:
        return self._atomic(lambda: self._consume_envelope_impl(envelope))

    def _consume_envelope_impl(
        self, envelope: AcquisitionEnvelope
    ) -> dict[str, Any] | None:
        self._require_acquisition_open()
        ordinal = _bounded_int(
            "acquisition ordinal", envelope.ordinal, 0, SAFE_INTEGER_MAX
        )
        self._current_acquisition_ordinal = ordinal
        self._current_acquisition_kind = (
            envelope.kind
            if envelope.kind in {"LOSS", "NOTIFICATION", "SERVER_REQUEST", "CLIENT_REQUEST", "CLIENT_RESPONSE"}
            else "UNKNOWN"
        )
        try:
            if ordinal != self.expected_acquisition_ordinal:
                self.expected_acquisition_ordinal = max(
                    self.expected_acquisition_ordinal, ordinal + 1
                )
                return self._mark_discrepancy(
                    "ordered acquisition ordinal gap, duplicate, or reorder"
                )
            self.expected_acquisition_ordinal += 1
            if envelope.kind == "LOSS":
                if envelope.message is not None:
                    return self._mark_discrepancy(
                        "loss envelope unexpectedly contains a decoded message"
                    )
                diagnostic = envelope.diagnostic
                if (
                    not isinstance(diagnostic, str)
                    or not diagnostic
                    or len(diagnostic) > MAXIMUM_DIAGNOSTIC_CODEPOINTS
                ):
                    raise ProviderAdmissionError("invalid acquisition loss diagnostic")
                raw = (
                    _raw_bytes_custody(
                        envelope.raw_bytes,
                        "EXACT_ACQUIRED_FRAME_BYTES_INCLUDING_LINE_TERMINATOR",
                    )
                    if envelope.raw_bytes is not None
                    else None
                )
                return self._mark_discrepancy(diagnostic, raw=raw)
            if envelope.kind not in {"NOTIFICATION", "SERVER_REQUEST", "CLIENT_REQUEST", "CLIENT_RESPONSE"}:
                return self._mark_discrepancy("unknown ordered acquisition envelope kind")
            if envelope.message is None or envelope.diagnostic is not None or envelope.raw_bytes is not None:
                return self._mark_discrepancy("ordered message envelope shape mismatch")
            if envelope.kind == "CLIENT_REQUEST":
                if (
                    not isinstance(envelope.request_method, str)
                    or not 1 <= len(envelope.request_method) <= MAXIMUM_ID_CODEPOINTS
                ):
                    return self._mark_discrepancy(
                        "client request lacks exact bounded request method"
                    )
                return self._client_request(envelope.request_method, envelope.message)
            if envelope.kind == "CLIENT_RESPONSE":
                if (
                    not isinstance(envelope.request_method, str)
                    or not 1 <= len(envelope.request_method) <= MAXIMUM_ID_CODEPOINTS
                ):
                    return self._mark_discrepancy(
                        "client response lacks exact bounded request method"
                    )
                return self._client_response(envelope.request_method, envelope.message)
            if envelope.request_method is not None:
                return self._mark_discrepancy(
                    "ordered provider message unexpectedly carries a request method"
                )
            return self._consume_impl(
                envelope.message, server_request=envelope.kind == "SERVER_REQUEST"
            )
        finally:
            self._current_acquisition_ordinal = None
            self._current_acquisition_kind = None

    def consume(self, message: ServerMessage, *, server_request: bool = False) -> dict[str, Any] | None:
        if not self._allow_unordered_fixture:
            raise ProviderAdmissionError(
                "V2 provider admission requires an ordered acquisition envelope"
            )
        def operation() -> dict[str, Any] | None:
            self._require_acquisition_open()
            return self._consume_impl(message, server_request=server_request)
        return self._atomic(operation)

    def _client_request(
        self, request_method: str, message: ServerMessage
    ) -> dict[str, Any]:
        from .appserver import client_request_byte_bound
        maximum = client_request_byte_bound(request_method, self._capture_contract)
        raw = _raw_custody(message, maximum)
        request = message.raw
        request_id = request.get("id")
        try:
            _bounded_int("client request id", request_id, 0, SAFE_INTEGER_MAX)
        except ProviderAdmissionError as exc:
            return self._mark_discrepancy(
                str(exc), f"client-request/{request_method}", raw
            )
        fields = {"id", "method"} | ({"params"} if "params" in request else set())
        if frozenset(request) != fields or request.get("method") != request_method:
            return self._mark_discrepancy(
                "client request method or closed shape substitution",
                f"client-request/{request_method}",
                raw,
            )
        params = request.get("params")
        if params is not None and not isinstance(params, dict):
            return self._mark_discrepancy(
                "client request params are not an object",
                f"client-request/{request_method}",
                raw,
            )
        fixture_methods = {
            "fixture/provider-admission-positive",
            "fixture/provider-order-approval-before-created",
            "fixture/provider-order-loss-before-created",
            "fixture/provider-order-duplicate-key",
            "fixture/provider-order-nested-duplicate-key",
        }
        owner_methods = {
            "initialize", "thread/start", "turn/start", "thread/read", "thread/resume"
        }
        if request_method in fixture_methods:
            if self._binding["executable_kind"] != "DETERMINISTIC_FIXTURE":
                return self._mark_discrepancy(
                    "fixture client request is not permitted for a campaign Codex build",
                    f"client-request/{request_method}",
                    raw,
                )
        elif request_method not in owner_methods:
            return self._mark_discrepancy(
                "unknown client request method", f"client-request/{request_method}", raw
            )
        if request_method in {"turn/start", "thread/read", "thread/resume"}:
            if not isinstance(params, dict) or params.get("threadId") != self._binding["thread_id"]:
                return self._mark_discrepancy(
                    "client request thread identity substitution",
                    f"client-request/{request_method}",
                    raw,
                )
        if request_id in self.client_requests:
            return self._mark_discrepancy(
                "duplicate client request identity", f"client-request/{request_method}", raw
            )
        params_digest = _plain_sha256(_canonical(params))
        self.client_requests[request_id] = _ClientRequest(
            request_id, request_method, params_digest
        )
        return self._record(
            "CLIENT_REQUEST_ISSUED",
            f"client-request/{request_method}",
            raw,
            {
                "request_id": request_id,
                "request_method": request_method,
                "params_sha256": params_digest,
                "proves_provider_admission": False,
            },
        )

    def _client_response(
        self, request_method: str, message: ServerMessage
    ) -> dict[str, Any]:
        raw = _raw_custody(message)
        response = message.raw
        response_id = response.get("id")
        try:
            _bounded_int("client response id", response_id, 0, SAFE_INTEGER_MAX)
        except ProviderAdmissionError as exc:
            return self._mark_discrepancy(
                str(exc), f"client-response/{request_method}", raw
            )
        expected = self.client_requests.get(response_id)
        if expected is None or expected.method != request_method:
            return self._mark_discrepancy(
                "client response request identity or method substitution",
                f"client-response/{request_method}",
                raw,
            )
        has_result = "result" in response
        has_error = "error" in response
        closed_fields = {"id", "result"} if has_result else {"id", "error"}
        if has_result == has_error or frozenset(response) != closed_fields:
            return self._mark_discrepancy(
                "client response has non-closed result/error shape",
                f"client-response/{request_method}",
                raw,
            )
        if has_error:
            return self._mark_discrepancy(
                "client request returned an App Server error",
                f"client-response/{request_method}",
                raw,
            )
        result = response["result"]
        if not isinstance(result, dict):
            return self._mark_discrepancy(
                "client response result is not an object",
                f"client-response/{request_method}",
                raw,
            )
        if request_method in {"thread/start", "thread/read", "thread/resume"}:
            thread = result.get("thread")
            if not isinstance(thread, dict) or thread.get("id") != self._binding["thread_id"]:
                return self._mark_discrepancy(
                    f"{request_method} response thread identity substitution",
                    f"client-response/{request_method}",
                    raw,
                )
        elif request_method == "turn/start":
            turn = result.get("turn")
            if not isinstance(turn, dict) or turn.get("id") != self._binding["turn_id"]:
                return self._mark_discrepancy(
                    "turn/start response turn identity substitution",
                    "client-response/turn/start",
                    raw,
                )
        result_digest = _plain_sha256(_canonical(result))
        del self.client_requests[response_id]
        return self._record(
            "CLIENT_RESPONSE_RETAINED",
            f"client-response/{request_method}",
            raw,
            {
                "request_id": response_id,
                "request_method": request_method,
                "params_sha256": expected.params_digest,
                "result_sha256": result_digest,
                "proves_provider_admission": False,
            },
        )

    def _consume_impl(self, message: ServerMessage, *, server_request: bool = False) -> dict[str, Any] | None:
        try:
            raw = _raw_custody(message)
        except ProviderAdmissionError as exc:
            return self._mark_discrepancy(str(exc), message.method or "unknown")
        method = message.method
        if method is None:
            return self._mark_discrepancy("App Server method is not a string", "unknown", raw)
        if not 1 <= len(method) <= MAXIMUM_ID_CODEPOINTS:
            return self._mark_discrepancy("App Server method exceeds identity bound", "unknown", raw)
        if self.admission_disposition == "ADMISSION_INDETERMINATE":
            return self._mark_discrepancy(
                "provider evidence followed an indeterminate dispatch", method, raw
            )
        if self.mechanism_state == "PROVIDER_COMPLETED":
            return self._mark_discrepancy(
                "App Server activity followed completed turn",
                method,
                raw,
            )
        if self.mechanism_state == "POST_ADMISSION_INTERRUPTED":
            return self._mark_discrepancy(
                "provider evidence followed a post-admission interruption", method, raw
            )
        if self.mechanism_state == "WAITING_APPROVAL" and (
            server_request
            or method.startswith(("providerAdmission/", "providerRequest/", "rawResponse/"))
        ):
            return self._mark_discrepancy(
                "provider activity followed unanswered approval", method, raw
            )
        if server_request:
            return self._approval_or_discrepancy(method, message.params, raw)
        if method == "providerRequest/started":
            return self._provider_request(message.params, raw)
        if method == "rawResponse/started":
            return self._response_started(message.params, raw)
        if method == "providerAdmission/refused":
            return self._provider_refused(message.params, raw)
        if method == "rawResponse/completed":
            return self._response_completed(message.params, raw)
        if method == "error":
            return self._mark_discrepancy(
                "coarse or unclassified App Server error cannot establish admission",
                method,
                raw,
            )
        if method in {"thread/started", "turn/started", "turn/completed"}:
            return self._local_fact(method, message.params, raw)
        if method.startswith(("providerAdmission/", "providerRequest/", "rawResponse/")):
            return self._mark_discrepancy(
                "unknown provider-boundary notification", method, raw
            )
        return self._record(
            "ACQUISITION_WATERMARK",
            method,
            raw,
            {"proves_provider_admission": False},
        )

    def _common_request(self, params: dict[str, Any], fields: frozenset[str]) -> _Request:
        if not isinstance(params, dict) or frozenset(params) != fields:
            raise ProviderAdmissionError("closed provider notification fields do not match")
        for field, expected in (
            ("threadId", self._binding["thread_id"]),
            ("turnId", self._binding["turn_id"]),
            ("provider", self._binding["provider"]),
            ("model", self._binding["model"]),
        ):
            if _identity(field, params[field]) != expected:
                raise ProviderAdmissionError(f"provider notification {field} substitution")
        return _Request(
            _identity("requestOccurrenceId", params["requestOccurrenceId"]),
            _bounded_int("samplingOrdinal", params["samplingOrdinal"], 0, U32_MAX),
            _bounded_int("requestOrder", params["requestOrder"], 0, U32_MAX),
            params["provider"],
            params["model"],
        )

    def _provider_request(self, params: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
        try:
            request = self._common_request(params, _REQUEST_FIELDS)
            started_at_ms = _bounded_int(
                "startedAtMs", params["startedAtMs"], SAFE_INTEGER_MIN, SAFE_INTEGER_MAX
            )
            if self.last_boundary_ms is not None and started_at_ms < self.last_boundary_ms:
                raise ProviderAdmissionError("provider request time precedes retained boundary")
            if self.admission_disposition in {
                "NOT_ADMITTED_MODEL_AT_CAPACITY",
                "ADMISSION_INDETERMINATE",
            }:
                raise ProviderAdmissionError("provider request follows closed dispatch disposition")
            if self.pending is not None:
                raise ProviderAdmissionError("new provider request hides an unresolved request occurrence")
            if self.open_response_id is not None:
                raise ProviderAdmissionError("new provider request precedes exact response completion")
            expected_ordinal = len(self.completed_requests)
            if request.ordinal != expected_ordinal or request.order != expected_ordinal:
                raise ProviderAdmissionError("provider request ordering or hidden retry discrepancy")
            if request.occurrence_id in self.completed_requests:
                raise ProviderAdmissionError("duplicate provider request occurrence identity")
            if request.ordinal > 0 and self._provider_execution_identity is None:
                raise ProviderAdmissionError("multiple pre-admission sampling requests are not allowed")
        except ProviderAdmissionError as exc:
            return self._mark_discrepancy(str(exc), "providerRequest/started", raw)
        self.pending = request
        self.pending_started_at_ms = started_at_ms
        return self._record(
            "PROVIDER_REQUEST_STARTED",
            "providerRequest/started",
            raw,
            {
                "request_occurrence_id": request.occurrence_id,
                "sampling_ordinal": request.ordinal,
                "request_order": request.order,
                "started_at_ms": params["startedAtMs"],
                "proves_provider_admission": False,
            },
        )

    def _match_pending(self, request: _Request) -> None:
        if self.pending is None or request != self.pending:
            raise ProviderAdmissionError("provider boundary has no exact pending request")

    def _response_started(self, params: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
        try:
            request = self._common_request(params, _RESPONSE_FIELDS)
            self._match_pending(request)
            response_id = _identity("responseId", params["responseId"])
            observed_at_ms = _bounded_int(
                "observedAtMs", params["observedAtMs"], SAFE_INTEGER_MIN, SAFE_INTEGER_MAX
            )
            if self.pending_started_at_ms is None or observed_at_ms < self.pending_started_at_ms:
                raise ProviderAdmissionError("response-created time precedes request start")
            if any(
                record["kind"] == "PROVIDER_EXECUTION_STEP"
                and record["normalized"]["provider_execution_step_identity"]["response_id"]
                == response_id
                for record in self._records
            ):
                raise ProviderAdmissionError("duplicate upstream response identity")
        except ProviderAdmissionError as exc:
            return self._mark_discrepancy(str(exc), "rawResponse/started", raw)
        self.pending = None
        self.pending_started_at_ms = None
        self.last_boundary_ms = observed_at_ms
        self.open_response_id = response_id
        self.completed_requests.add(request.occurrence_id)
        step_identity = {
            "provider": request.provider,
            "model": request.model,
            "thread_id": self._binding["thread_id"],
            "turn_id": self._binding["turn_id"],
            "request_occurrence_id": request.occurrence_id,
            "sampling_ordinal": request.ordinal,
            "request_order": request.order,
            "response_id": response_id,
        }
        first = self._provider_execution_identity is None
        if first:
            self._provider_execution_identity = {
                "provider": request.provider,
                "model": request.model,
                "app_server_session_identity": self._binding[
                    "app_server_session_identity"
                ],
                "thread_id": self._binding["thread_id"],
                "turn_id": self._binding["turn_id"],
                "first_response_id": response_id,
            }
            self.admission_disposition = "EXECUTION_ADMITTED"
            self.mechanism_state = "EXECUTION_ADMITTED"
        else:
            self.mechanism_state = "RUNNING"
        return self._record(
            "PROVIDER_EXECUTION_STEP",
            "rawResponse/started",
            raw,
            {
                "provider_execution_identity": self._provider_execution_identity,
                "provider_execution_step_identity": step_identity,
                "first_admission_boundary": first,
                "observed_at_ms": params["observedAtMs"],
            },
        )

    def _provider_refused(self, params: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
        try:
            request = self._common_request(params, _REFUSAL_FIELDS)
            self._match_pending(request)
            if self._provider_execution_identity is not None:
                raise ProviderAdmissionError("provider refusal follows admitted execution")
            if params["responseCreated"] is not False or params["willRetry"] is not False:
                raise ProviderAdmissionError("provider refusal does not prove terminal pre-created state")
            if params["refusalKind"] != "modelAtCapacity":
                raise ProviderAdmissionError("unknown provider refusal kind")
            if params["codexErrorInfo"] != "serverOverloaded":
                raise ProviderAdmissionError("provider refusal typed error mismatch")
            retry_after = params["retryAfterMs"]
            if retry_after is not None:
                _bounded_int("retryAfterMs", retry_after, 0, SAFE_INTEGER_MAX)
            diagnostic = params["diagnostic"]
            if not isinstance(diagnostic, str) or len(diagnostic) > MAXIMUM_DIAGNOSTIC_CODEPOINTS:
                raise ProviderAdmissionError("provider refusal diagnostic exceeds bound")
            observed_at_ms = _bounded_int(
                "observedAtMs", params["observedAtMs"], SAFE_INTEGER_MIN, SAFE_INTEGER_MAX
            )
            if self.pending_started_at_ms is None or observed_at_ms < self.pending_started_at_ms:
                raise ProviderAdmissionError("provider refusal time precedes request start")
        except ProviderAdmissionError as exc:
            return self._mark_discrepancy(str(exc), "providerAdmission/refused", raw)
        self.pending = None
        self.pending_started_at_ms = None
        self.last_boundary_ms = observed_at_ms
        self.completed_requests.add(request.occurrence_id)
        self.admission_disposition = "NOT_ADMITTED_MODEL_AT_CAPACITY"
        self.mechanism_state = "PARKED_NOT_ADMITTED"
        return self._record(
            "PROVIDER_ADMISSION_REFUSED",
            "providerAdmission/refused",
            raw,
            {
                "request_occurrence_id": request.occurrence_id,
                "sampling_ordinal": request.ordinal,
                "request_order": request.order,
                "response_created": False,
                "will_retry": False,
                "refusal_kind": "MODEL_AT_CAPACITY",
                "codex_error_info": "serverOverloaded",
                "retry_after_ms": retry_after,
                "diagnostic": diagnostic,
                "observed_at_ms": params["observedAtMs"],
                "provider_execution_identity": None,
            },
        )

    def _response_completed(self, params: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(params, dict) or frozenset(params) != _COMPLETED_FIELDS:
            return self._mark_discrepancy(
                "closed response-completed fields do not match", "rawResponse/completed", raw
            )
        if self._provider_execution_identity is None:
            return self._mark_discrepancy(
                "response completion lacks an exact response-created boundary",
                "rawResponse/completed", raw,
            )
        if (
            params.get("threadId") != self._binding["thread_id"]
            or params.get("turnId") != self._binding["turn_id"]
        ):
            return self._mark_discrepancy(
                "response completion identity substitution", "rawResponse/completed", raw
            )
        response_id = params.get("responseId")
        if response_id != self.open_response_id or not any(
            record["kind"] == "PROVIDER_EXECUTION_STEP"
            and record["normalized"]["provider_execution_step_identity"]["response_id"]
            == response_id
            for record in self._records
        ):
            return self._mark_discrepancy(
                "response completion has no exact admitted response identity",
                "rawResponse/completed", raw,
            )
        self.open_response_id = None
        self.mechanism_state = "RUNNING"
        return self._record(
            "PROVIDER_RESPONSE_COMPLETED",
            "rawResponse/completed",
            raw,
            {"response_id": response_id, "proves_new_admission": False},
        )

    def _local_fact(self, method: str, params: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(params, dict):
            return self._mark_discrepancy("local fact params are not an object", method, raw)
        thread = params.get("thread")
        turn = params.get("turn")
        if method == "thread/started":
            thread_id = thread.get("id") if isinstance(thread, dict) else None
            turn_id = None
        else:
            thread_id = params.get("threadId")
            turn_id = turn.get("id") if isinstance(turn, dict) else None
        if thread_id != self._binding["thread_id"]:
            return self._mark_discrepancy("local fact thread identity substitution", method, raw)
        if method != "thread/started" and turn_id != self._binding["turn_id"]:
            return self._mark_discrepancy("local fact turn identity substitution", method, raw)
        if method == "turn/completed":
            if self._provider_execution_identity is None:
                if not (
                    self.admission_disposition == "NOT_ADMITTED_MODEL_AT_CAPACITY"
                    and self.mechanism_state == "PARKED_NOT_ADMITTED"
                    and self.pending is None
                    and self.open_response_id is None
                ):
                    return self._mark_discrepancy(
                        "turn completed without exact provider execution identity",
                        method,
                        raw,
                    )
            elif (
                self.pending is not None
                or self.open_response_id is not None
                or self.mechanism_state == "WAITING_APPROVAL"
            ):
                return self._mark_discrepancy(
                    "turn completed before exact response/approval sequence closed",
                    method,
                    raw,
                )
            if self._provider_execution_identity is not None:
                self.mechanism_state = "PROVIDER_COMPLETED"
        return self._record(
            "LOCAL_TURN_FACT",
            method,
            raw,
            {"proves_provider_admission": False},
        )

    def _approval_or_discrepancy(
        self, method: str, params: dict[str, Any], raw: dict[str, Any]
    ) -> dict[str, Any]:
        if method not in {
            "item/commandExecution/requestApproval",
            "item/fileChange/requestApproval",
        }:
            return self._mark_discrepancy("unknown App Server server request", method, raw)
        thread_id = params.get("threadId")
        turn_id = params.get("turnId")
        if thread_id != self._binding["thread_id"] or turn_id != self._binding["turn_id"]:
            return self._mark_discrepancy("approval identity substitution", method, raw)
        if self._provider_execution_identity is None:
            return self._mark_discrepancy("approval request preceded provider admission", method, raw)
        if self.open_response_id is not None:
            return self._mark_discrepancy(
                "approval request preceded exact response completion", method, raw
            )
        self.mechanism_state = "WAITING_APPROVAL"
        return self._record(
            "WAITING_APPROVAL",
            method,
            raw,
            {
                "approval_response_sent": False,
                "protected_effect_absent": True,
                "provider_execution_identity": self._provider_execution_identity,
            },
        )

    def consume_cut(self, cut: AcquisitionCut) -> dict[str, Any]:
        return self._atomic(lambda: self._consume_cut_impl(cut))

    def _consume_cut_impl(self, cut: AcquisitionCut) -> dict[str, Any]:
        if self.acquisition_cut is not None:
            raise ProviderAdmissionError("terminal acquisition cut is already retained")
        if (
            cut.adapter_process_occurrence_id
            != self._binding["adapter_process_occurrence_id"]
            or cut.app_server_session_identity
            != self._binding["app_server_session_identity"]
        ):
            raise ProviderAdmissionError("acquisition-cut occurrence identity substitution")
        if not isinstance(cut.stream_quiesced, bool):
            raise ProviderAdmissionError("invalid acquisition-cut stream disposition")
        loss_generation = _bounded_int(
            "acquisition-cut loss generation", cut.loss_generation, 0, SAFE_INTEGER_MAX
        )
        high_water = _bounded_int(
            "acquisition-cut ordered high water",
            cut.ordered_high_water,
            0,
            SAFE_INTEGER_MAX,
        )
        known_process_dispositions = {
            "UNKNOWN", "ABSENT", "RUNNING", "EXITED",
            "EXITED_AFTER_TERMINATE", "EXITED_AFTER_KILL", "EXIT_UNCONFIRMED",
        }
        if cut.process_disposition not in known_process_dispositions:
            raise ProviderAdmissionError("unknown acquisition-cut process disposition")
        process_closed = cut.process_disposition in {
            "EXITED", "EXITED_AFTER_TERMINATE", "EXITED_AFTER_KILL"
        }
        semantic_closed = self.mechanism_state in {
            "PROVIDER_COMPLETED", "PARKED_NOT_ADMITTED"
        }
        clean = (
            cut.stream_quiesced
            and process_closed
            and loss_generation == 0
            and high_water == self.expected_acquisition_ordinal
            and not self.client_requests
            and semantic_closed
        )
        normalized = {
            "adapter_process_occurrence_id": cut.adapter_process_occurrence_id,
            "app_server_session_identity": cut.app_server_session_identity,
            "stream_quiesced": cut.stream_quiesced,
            "loss_generation": loss_generation,
            "process_disposition": cut.process_disposition,
            "ordered_high_water": high_water,
            "consumed_ordinal_count": self.expected_acquisition_ordinal,
            "outstanding_client_request_count": len(self.client_requests),
            "clean": clean,
        }
        self.acquisition_cut = copy.deepcopy(normalized)
        if not clean:
            if self._provider_execution_identity is None:
                self.admission_disposition = "ADMISSION_INDETERMINATE"
                self.mechanism_state = "ADMISSION_INDETERMINATE"
            else:
                self.mechanism_state = "POST_ADMISSION_INTERRUPTED"
        return self._record(
            "ACQUISITION_CUT", "adapter/acquisition-cut", None, normalized
        )

    def snapshot(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema": SNAPSHOT_SCHEMA,
            "snapshot_digest": "sha256:" + "0" * 64,
            "binding": copy.deepcopy(self._binding),
            "admission_disposition": self.admission_disposition,
            "mechanism_state": self.mechanism_state,
            "provider_execution_identity": copy.deepcopy(self._provider_execution_identity),
            "acquisition_cut": copy.deepcopy(self.acquisition_cut),
            "records": copy.deepcopy(self._records),
        }
        value["snapshot_digest"] = _digest(
            _SNAPSHOT_DOMAIN, value, "snapshot_digest"
        )
        return value


    @classmethod
    def replay(
        cls, binding: dict[str, Any], retained_records: list[dict[str, Any]], *,
        capture_contract: str = "LEGACY_V1"
    ) -> "ProviderAdmissionMapper":
        if not isinstance(retained_records, list) or len(retained_records) > MAXIMUM_RECORDS:
            raise ProviderAdmissionError("invalid retained provider-admission record set")
        mapper = cls(binding, allow_unordered_fixture=True, capture_contract=capture_contract)
        for expected in retained_records:
            if not isinstance(expected, dict):
                raise ProviderAdmissionError("retained provider-admission record is not an object")
            if expected.get("sequence") != len(mapper.records):
                raise ProviderAdmissionError("retained provider-admission sequence mismatch")
            if expected.get("evidence_digest") != _digest(
                _EVIDENCE_DOMAIN, expected, "evidence_digest"
            ):
                raise ProviderAdmissionError("retained provider-admission evidence digest mismatch")
            raw = expected.get("raw")
            kind = expected.get("kind")
            method = expected.get("method")
            ordinal = expected.get("acquisition_ordinal")
            acquisition_kind = expected.get("acquisition_kind")
            wire: bytes | None = None
            if raw is not None:
                if not isinstance(raw, dict) or raw.get("encoding") != "hex":
                    raise ProviderAdmissionError("invalid retained raw evidence wrapper")
                try:
                    wire = bytes.fromhex(raw.get("bytes_hex", ""))
                except ValueError as exc:
                    raise ProviderAdmissionError("invalid retained raw evidence") from exc
            if ordinal is not None:
                if acquisition_kind == "LOSS":
                    envelope = AcquisitionEnvelope(
                        ordinal, "LOSS", diagnostic=expected.get("normalized", {}).get("detail"),
                        raw_bytes=wire,
                    )
                elif acquisition_kind == "UNKNOWN":
                    envelope = AcquisitionEnvelope(ordinal, "UNKNOWN")
                else:
                    message = None
                    if wire is not None:
                        try:
                            parsed = json.loads(wire, object_pairs_hook=_unique_object)
                        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                            raise ProviderAdmissionError("invalid retained raw evidence") from exc
                        if not isinstance(parsed, dict):
                            raise ProviderAdmissionError("retained message is not an object")
                        message = ServerMessage(parsed, raw_bytes=wire)
                    request_method = None
                    if acquisition_kind in {"CLIENT_REQUEST", "CLIENT_RESPONSE"}:
                        prefix = (
                            "client-request/"
                            if acquisition_kind == "CLIENT_REQUEST"
                            else "client-response/"
                        )
                        if not isinstance(method, str) or not method.startswith(prefix):
                            raise ProviderAdmissionError(
                                "retained client message lacks request method"
                            )
                        request_method = method[len(prefix):]
                    envelope = AcquisitionEnvelope(
                        ordinal,
                        acquisition_kind,
                        message=message,
                        request_method=request_method,
                    )
                actual = mapper.consume_envelope(envelope)
            elif raw is None:
                if kind == "ACQUISITION_CUT":
                    normalized = expected.get("normalized", {})
                    actual = mapper.consume_cut(AcquisitionCut(
                        normalized.get("stream_quiesced"),
                        normalized.get("loss_generation"),
                        normalized.get("process_disposition"),
                        normalized.get("ordered_high_water"),
                        normalized.get("adapter_process_occurrence_id"),
                        normalized.get("app_server_session_identity"),
                    ))
                elif kind == "ADMISSION_DISCREPANCY" and method == "adapter/acquisition":
                    actual = mapper.mark_acquisition_loss(
                        expected.get("normalized", {}).get("detail", "")
                    )
                elif kind == "LOCAL_TURN_FACT":
                    actual = mapper.record_legacy_local_fact(method)
                else:
                    raise ProviderAdmissionError("retained evidence lacks required exact bytes")
            else:
                try:
                    parsed = json.loads(wire, object_pairs_hook=_unique_object)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ProviderAdmissionError("invalid retained raw evidence") from exc
                if not isinstance(parsed, dict):
                    raise ProviderAdmissionError("retained message is not an object")
                message = ServerMessage(parsed, raw_bytes=wire)
                actual = mapper.consume(message, server_request=kind == "WAITING_APPROVAL")
                if actual is None:
                    raise ProviderAdmissionError("retained evidence no longer maps to a record")
            if actual != expected:
                raise ProviderAdmissionError("retained provider-admission evidence substitution")
        return mapper



def replay_snapshot(snapshot: dict[str, Any], *, capture_contract: str = "LEGACY_V1") -> ProviderAdmissionMapper:
    fields = {
        "schema", "snapshot_digest", "binding", "admission_disposition",
        "mechanism_state", "provider_execution_identity", "acquisition_cut", "records",
    }
    if not isinstance(snapshot, dict) or set(snapshot) != fields:
        raise ProviderAdmissionError("closed provider-admission snapshot fields do not match")
    if snapshot["schema"] != SNAPSHOT_SCHEMA:
        raise ProviderAdmissionError("foreign provider-admission snapshot schema")
    if snapshot["snapshot_digest"] != _digest(
        _SNAPSHOT_DOMAIN, snapshot, "snapshot_digest"
    ):
        raise ProviderAdmissionError("provider-admission snapshot digest mismatch")
    mapper = ProviderAdmissionMapper.replay(snapshot["binding"], snapshot["records"], capture_contract=capture_contract)
    if mapper.snapshot() != snapshot:
        raise ProviderAdmissionError("provider-admission snapshot state substitution")
    return mapper
