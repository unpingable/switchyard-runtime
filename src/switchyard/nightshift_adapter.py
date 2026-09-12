from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import queue
import re
import sqlite3
import stat
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ._vendor import rfc8785
from .appserver import AcquisitionCut, AppServerClient, ServerMessage
from .config import BackendIdentity, Config

ADAPTER_ID = "switchyard.codex-app-server"
ADAPTER_PROTOCOL = "switchyard.codex-app-server/v1"
ADAPTER_VERSION = "switchyard.codex-app-server/v1"
CAPABILITIES_SCHEMA = "nightshift.worker-adapter-capabilities/v1"
START_SCHEMA = "nightshift.worker-start-request/v2"
BINDING_SCHEMA = "nightshift.worker-attempt-binding/v1"
EVENT_SCHEMA = "nightshift.worker-adapter-event/v1"
RECEIPT_SCHEMA = "nightshift.worker-terminal-receipt/v1"
RESULT_SCHEMA = "switchyard.codex-app-server-command-result/v1"
OUTCOME_SCHEMA = "switchyard.codex-worker-outcome/v1"
START_DOMAIN = b"nightshift.worker-start-request.digest/v2\0"
BRIEF_DOMAIN = b"nightshift.worker-brief.digest/v2\0"
EVENT_DOMAIN = b"nightshift.worker-adapter-event.digest/v1\0"
RECEIPT_DOMAIN = b"nightshift.worker-terminal-receipt.digest/v1\0"
RAW_DOMAIN = b"nightshift.foreman-retained-raw.digest/v1\0"
PACKET_DOMAIN = b"nightshift.orientation-packet.digest/v1\0"
NOT_STARTED_DOMAIN = b"nightshift.work-item-not-started-receipt.digest/v1\0"
BRIEF_SCHEMA = "nightshift.worker-brief-basis/v2"
MAXIMUM_BRIEF_BYTES = 16 * 1024 * 1024
MAXIMUM_CONTROL_INPUT_BYTES = 1024 * 1024
RAW_APP_SERVER_EVENT_DOMAIN = b"switchyard.codex-app-server.raw-event/v1\0"
MAXIMUM_RAW_APP_SERVER_EVENT_BYTES = 16 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z0-9._:/-]{1,512}\Z")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}\Z")
START_FIELDS = frozenset({
    "schema", "request_digest", "adapter_id", "adapter_version",
    "adapter_protocol", "packet_digest", "run_id", "work_item_id",
    "attempt_id", "worker_brief_digest", "workspace_identity",
    "provider_model_class", "timeout_seconds", "maximum_output_bytes",
    "recursive_worker_swarms_forbidden", "approval_policy",
    "expected_receipt_schema",
})
BINDING_FIELDS = frozenset({
    "schema", "request_digest", "packet_digest", "run_id",
    "work_item_id", "attempt_id", "adapter_id", "adapter_version",
})
RECEIPT_FIELDS = frozenset({
    "schema", "receipt_digest", "packet_digest", "run_id", "work_item_id",
    "attempt_id", "adapter_id", "adapter_version", "provider_identity",
    "model_identity", "session_identity", "thread_identity", "turn_identity",
    "queue_identity", "started_at", "ended_at", "state",
    "result_classification", "repositories", "tests", "evidence",
    "live_or_production_mutations", "remaining_trigger", "next_lawful_action",
    "human_questions", "teardown", "extensions",
})
BRIEF_FIELDS = frozenset({
    "schema", "packet_digest", "packet_source", "work_item",
    "predecessor_receipts", "global_constraints", "execution",
})
SOURCE_FIELDS = frozenset({"retained_raw_digest", "encoding", "bytes_hex"})
PREDECESSOR_FIELDS = frozenset({
    "receipt_kind", "retained_raw_digest", "encoding", "bytes_hex",
})
OUTCOME_FIELDS = frozenset({
    "schema", "state", "result_classification", "repositories", "tests",
    "evidence", "live_or_production_mutations", "remaining_trigger",
    "next_lawful_action", "human_questions", "teardown", "extensions",
})
NOT_STARTED_FIELDS = frozenset({
    "schema", "receipt_digest", "packet_digest", "run_id", "work_item_id",
    "recorded_at", "state", "result_classification", "evidence",
    "remaining_trigger", "next_lawful_action", "human_questions", "extensions",
})
RECOGNIZED_FIELDS = frozenset({"contract", "canonical_json"})


class AdapterProtocolError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        raise AdapterProtocolError(f"value is outside RFC8785-JCS: {exc}") from exc


def _read_bounded_regular(path: Path, maximum_bytes: int, label: str) -> bytes:
    if maximum_bytes < 1 or not hasattr(os, "O_NOFOLLOW"):
        raise AdapterProtocolError(f"{label} descriptor boundary unavailable")
    candidate = path if path.is_absolute() else Path.cwd() / path
    parts = candidate.parts
    if len(parts) < 2 or any(part in {"", ".", ".."} for part in parts[1:]):
        raise AdapterProtocolError(f"invalid {label} path")
    directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    file_fd: int | None = None
    try:
        for component in parts[1:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd
        )
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
            raise AdapterProtocolError(f"{label} is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(file_fd, min(65536, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise AdapterProtocolError(f"{label} exceeds byte bound")
        after = os.fstat(file_fd)
        custody = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in custody):
            raise AdapterProtocolError(f"{label} changed during descriptor read")
        return b"".join(chunks)
    except OSError as exc:
        raise AdapterProtocolError(f"unable to open exact {label}: {exc}") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)


def _load_closed(
    path: Path, fields: frozenset[str], maximum_bytes: int = MAXIMUM_CONTROL_INPUT_BYTES,
) -> tuple[dict[str, Any], bytes]:
    raw = _read_bounded_regular(path, maximum_bytes, "closed control input")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterProtocolError(f"invalid JSON: {exc}") from exc
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise AdapterProtocolError("closed record fields do not match")
    if _canonical(value) != raw:
        raise AdapterProtocolError("record is not exact canonical JSON")
    return value, raw


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdapterProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _digest(domain: bytes, value: Any) -> str:
    return "sha256:" + hashlib.sha256(domain + _canonical(value)).hexdigest()


def _raw_digest(domain: bytes, raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain + raw).hexdigest()


def _without(value: dict[str, Any], field: str) -> dict[str, Any]:
    result = dict(value)
    result.pop(field, None)
    return result


def _require_id(field: str, value: Any) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise AdapterProtocolError(f"invalid {field}")
    return value


def _require_digest(field: str, value: Any) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise AdapterProtocolError(f"invalid {field}")
    return value


def _exact_source(label: str, value: Any, fields: frozenset[str]) -> bytes:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise AdapterProtocolError(f"{label} source fields do not match")
    if value.get("encoding") != "hex":
        raise AdapterProtocolError(f"{label} source encoding mismatch")
    _require_digest(f"{label} retained_raw_digest", value.get("retained_raw_digest"))
    encoded = value.get("bytes_hex")
    if not isinstance(encoded, str) or len(encoded) % 2 or encoded.lower() != encoded:
        raise AdapterProtocolError(f"{label} source is not lowercase hexadecimal")
    try:
        raw = bytes.fromhex(encoded)
    except ValueError as exc:
        raise AdapterProtocolError(f"{label} source is not hexadecimal") from exc
    if raw.hex() != encoded:
        raise AdapterProtocolError(f"{label} source hexadecimal mismatch")
    if _raw_digest(RAW_DOMAIN, raw) != value["retained_raw_digest"]:
        raise AdapterProtocolError(f"{label} retained raw digest mismatch")
    return raw


def _exact_json(label: str, raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterProtocolError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AdapterProtocolError(f"{label} must be an object")
    return value


def _recognized(label: str, value: Any, contract: str) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != RECOGNIZED_FIELDS:
        raise AdapterProtocolError(f"{label} recognized wrapper fields do not match")
    if value.get("contract") != contract:
        raise AdapterProtocolError(f"{label} recognized contract mismatch")
    canonical_json = value.get("canonical_json")
    if not isinstance(canonical_json, str):
        raise AdapterProtocolError(f"{label} recognized JSON is absent")
    parsed = _exact_json(f"{label} recognized", canonical_json.encode("utf-8"))
    if _canonical(parsed).decode("utf-8") != canonical_json:
        raise AdapterProtocolError(f"{label} recognized JSON is not canonical")
    return parsed


def _verify_packet_digest(packet: dict[str, Any], expected: str) -> None:
    if packet.get("schema") != "nightshift.orientation-packet/v1":
        raise AdapterProtocolError("foreign retained packet schema")
    if packet.get("packet_digest") != expected:
        raise AdapterProtocolError("retained packet identity mismatch")
    preimage = json.loads(_canonical(packet), object_pairs_hook=_unique_object)
    preimage.pop("packet_digest", None)
    switchyard = preimage.get("switchyard")
    if not isinstance(switchyard, dict):
        raise AdapterProtocolError("retained packet switchyard record absent")
    switchyard.pop("plan_ref", None)
    if _digest(PACKET_DOMAIN, preimage) != expected:
        raise AdapterProtocolError("retained packet digest mismatch")
    expected_ref = "nightshift-packet://" + expected.removeprefix("sha256:")
    original_switchyard = packet.get("switchyard")
    if not isinstance(original_switchyard, dict) or original_switchyard.get("plan_ref") != expected_ref:
        raise AdapterProtocolError("retained packet plan reference mismatch")


def _require_rfc3339(field: str, value: Any) -> tuple[datetime, int]:
    if not isinstance(value, str):
        raise AdapterProtocolError(f"invalid {field}")
    matched = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.((?:(?!000)\d{3}|\d{3}(?!000)\d{3}|\d{6}(?!000)\d{3})))?Z",
        value,
    )
    if matched is None:
        raise AdapterProtocolError(f"invalid {field}")
    try:
        seconds = datetime.strptime(matched.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise AdapterProtocolError(f"invalid {field}") from exc
    fraction = matched.group(2) or ""
    nanoseconds = int(fraction.ljust(9, "0")) if fraction else 0
    return seconds, nanoseconds


def _validate_question(value: Any) -> None:
    fields = frozenset({
        "question_id", "question", "exhausted_evidence", "safe_default",
        "consequences", "resume_point",
    })
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise AdapterProtocolError("invalid receipt human question")
    _require_id("question_id", value["question_id"])
    for field in fields - {"question_id"}:
        _bounded_text(field, value[field])


def _validate_interoperable_extension(value: Any) -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if abs(value) > 9_007_199_254_740_991:
            raise AdapterProtocolError("invalid RFC8785 number")
        return
    if isinstance(value, float):
        if not math.isfinite(value) or abs(value) > 9_007_199_254_740_991:
            raise AdapterProtocolError("invalid RFC8785 number")
        return
    if isinstance(value, list):
        for member in value:
            _validate_interoperable_extension(member)
        return
    if isinstance(value, dict):
        if len(value) > 64:
            raise AdapterProtocolError("invalid receipt extensions")
        for key, member in value.items():
            _require_id("RFC8785 object key", key)
            _validate_interoperable_extension(member)
        return
    raise AdapterProtocolError("invalid RFC8785 extension value")


def _validate_receipt_common(value: dict[str, Any], domain: bytes) -> None:
    _require_digest("receipt_digest", value.get("receipt_digest"))
    if _digest(domain, _without(value, "receipt_digest")) != value["receipt_digest"]:
        raise AdapterProtocolError("predecessor receipt digest mismatch")
    _require_digest("packet_digest", value.get("packet_digest"))
    for field in ("run_id", "work_item_id"):
        _require_id(field, value.get(field))
    for field in ("state", "result_classification", "remaining_trigger", "next_lawful_action"):
        _bounded_text(field, value.get(field))
    questions = value.get("human_questions")
    if not isinstance(questions, list):
        raise AdapterProtocolError("invalid receipt human questions")
    for question in questions:
        _validate_question(question)
    extensions = value.get("extensions")
    if not isinstance(extensions, dict) or len(extensions) > 64:
        raise AdapterProtocolError("invalid receipt extensions")
    _validate_interoperable_extension(extensions)


def _receipt_string_list(field: str, value: Any) -> None:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or len(item) > 65_536 for item in value
    ):
        raise AdapterProtocolError(f"invalid receipt {field}")


def _validate_terminal_predecessor(value: dict[str, Any]) -> None:
    if frozenset(value) != RECEIPT_FIELDS or value.get("schema") != RECEIPT_SCHEMA:
        raise AdapterProtocolError("terminal predecessor receipt fields do not match")
    _validate_receipt_common(value, RECEIPT_DOMAIN)
    for field in (
        "attempt_id", "adapter_id", "adapter_version", "provider_identity", "model_identity",
    ):
        _require_id(field, value.get(field))
    for field in ("session_identity", "thread_identity", "turn_identity", "queue_identity"):
        optional = value.get(field)
        if optional is not None:
            _require_id(field, optional)
    started = _require_rfc3339("started_at", value.get("started_at"))
    ended = _require_rfc3339("ended_at", value.get("ended_at"))
    if started > ended:
        raise AdapterProtocolError("invalid receipt timestamps")
    for field in ("tests", "evidence", "live_or_production_mutations"):
        _receipt_string_list(field, value.get(field))
    repositories = value.get("repositories")
    repository_fields = frozenset({"repository", "branch", "head", "push_status"})
    if not isinstance(repositories, list) or any(
        not isinstance(repository, dict)
        or frozenset(repository) != repository_fields
        or any(not isinstance(member, str) for member in repository.values())
        for repository in repositories
    ):
        raise AdapterProtocolError("invalid receipt repositories")
    teardown = value.get("teardown")
    teardown_fields = frozenset({"live_runtime", "secrets", "teardown"})
    if (
        not isinstance(teardown, dict)
        or frozenset(teardown) != teardown_fields
        or any(not isinstance(member, str) for member in teardown.values())
    ):
        raise AdapterProtocolError("invalid receipt teardown")


def _validate_not_started_predecessor(value: dict[str, Any]) -> None:
    if (
        frozenset(value) != NOT_STARTED_FIELDS
        or value.get("schema") != "nightshift.work-item-not-started-receipt/v1"
    ):
        raise AdapterProtocolError("not-started predecessor receipt fields do not match")
    _validate_receipt_common(value, NOT_STARTED_DOMAIN)
    _require_rfc3339("recorded_at", value.get("recorded_at"))
    _receipt_string_list("evidence", value.get("evidence"))


def validate_brief(value: dict[str, Any], brief_raw: bytes, start: dict[str, Any]) -> None:
    if len(brief_raw) > MAXIMUM_BRIEF_BYTES:
        raise AdapterProtocolError("worker brief exceeds total bound")
    if not isinstance(value, dict) or frozenset(value) != BRIEF_FIELDS:
        raise AdapterProtocolError("closed worker brief fields do not match")
    if value.get("schema") != BRIEF_SCHEMA:
        raise AdapterProtocolError("foreign worker brief schema")
    if value.get("packet_digest") != start["packet_digest"]:
        raise AdapterProtocolError("worker brief packet identity mismatch")
    packet_raw = _exact_source("packet", value.get("packet_source"), SOURCE_FIELDS)
    packet = _exact_json("retained packet", packet_raw)
    _verify_packet_digest(packet, start["packet_digest"])
    work_items = packet.get("work_items")
    if not isinstance(work_items, list):
        raise AdapterProtocolError("retained packet work items absent")
    selected = [item for item in work_items if isinstance(item, dict) and item.get("id") == start["work_item_id"]]
    if len(selected) != 1:
        raise AdapterProtocolError("retained packet work item identity mismatch")
    work_item = selected[0]
    recognized_work = _recognized(
        "work item", value.get("work_item"),
        "nightshift.orientation-packet/v1#work-item",
    )
    if recognized_work != work_item:
        raise AdapterProtocolError("recognized work item differs from retained packet")
    recognized_global = _recognized(
        "global constraints", value.get("global_constraints"),
        "nightshift.orientation-packet/v1#global-constraints",
    )
    if recognized_global != packet.get("global_constraints"):
        raise AdapterProtocolError("recognized global constraints differ from retained packet")
    execution = _recognized(
        "execution", value.get("execution"),
        "nightshift.foreman-execution-profile/v2#work-item",
    )
    if frozenset(execution) != frozenset({
        "adapter_id", "workspace_identity", "resource_lock_keys", "provider_model_class",
    }):
        raise AdapterProtocolError("execution profile work-item fields do not match")
    for field in ("adapter_id", "workspace_identity", "provider_model_class"):
        if execution.get(field) != start[field]:
            raise AdapterProtocolError(f"execution {field} mismatch")
    locks = execution.get("resource_lock_keys")
    if not isinstance(locks, list) or not locks or len(locks) != len(set(locks)):
        raise AdapterProtocolError("execution resource locks invalid")
    for lock in locks:
        _require_id("resource lock", lock)
    dependencies = work_item.get("dependencies")
    if not isinstance(dependencies, list) or any(not isinstance(item, str) for item in dependencies):
        raise AdapterProtocolError("work item dependencies invalid")
    predecessors = value.get("predecessor_receipts")
    if isinstance(predecessors, dict) and len(predecessors) > 1024:
        raise AdapterProtocolError("predecessor receipt count exceeds bound")
    if not isinstance(predecessors, dict) or set(predecessors) != set(dependencies):
        raise AdapterProtocolError("predecessor receipt set differs from dependencies")
    for dependency, source in predecessors.items():
        raw = _exact_source(f"predecessor {dependency}", source, PREDECESSOR_FIELDS)
        receipt = _exact_json(f"predecessor {dependency}", raw)
        kind = source.get("receipt_kind")
        if kind == "terminal":
            _validate_terminal_predecessor(receipt)
        elif kind == "not_started":
            _validate_not_started_predecessor(receipt)
        else:
            raise AdapterProtocolError(f"predecessor {dependency} receipt kind mismatch")
        if (
            receipt.get("packet_digest") != start["packet_digest"]
            or receipt.get("run_id") != start["run_id"]
            or receipt.get("work_item_id") != dependency
        ):
            raise AdapterProtocolError(f"predecessor {dependency} receipt binding mismatch")


def validate_start(
    value: dict[str, Any], brief_raw: bytes, *,
    adapter_protocol: str = ADAPTER_PROTOCOL, adapter_version: str = ADAPTER_VERSION,
) -> None:
    if frozenset(value) != START_FIELDS:
        raise AdapterProtocolError("closed start request fields do not match")
    if value["schema"] != START_SCHEMA:
        raise AdapterProtocolError("foreign start schema")
    if value["adapter_id"] != ADAPTER_ID:
        raise AdapterProtocolError("adapter_id mismatch")
    if value["adapter_protocol"] != adapter_protocol:
        raise AdapterProtocolError("adapter_protocol mismatch")
    if value["adapter_version"] != adapter_version:
        raise AdapterProtocolError("adapter_version mismatch")
    for field in (
        "run_id", "work_item_id", "attempt_id", "workspace_identity",
        "provider_model_class",
    ):
        _require_id(field, value[field])
    for field in ("request_digest", "packet_digest", "worker_brief_digest"):
        _require_digest(field, value[field])
    if _digest(START_DOMAIN, _without(value, "request_digest")) != value["request_digest"]:
        raise AdapterProtocolError("request_digest mismatch")
    try:
        brief = json.loads(brief_raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterProtocolError(f"invalid worker brief: {exc}") from exc
    if _canonical(brief) != brief_raw:
        raise AdapterProtocolError("worker brief is not exact canonical JSON")
    if _raw_digest(BRIEF_DOMAIN, brief_raw) != value["worker_brief_digest"]:
        raise AdapterProtocolError("worker_brief_digest mismatch")
    validate_brief(brief, brief_raw, value)
    if (
        not isinstance(value["timeout_seconds"], int)
        or value["timeout_seconds"] < 1
        or value["timeout_seconds"] > 86_400
        or not isinstance(value["maximum_output_bytes"], int)
        or value["maximum_output_bytes"] < 1024
        or value["maximum_output_bytes"] > 16 * 1024 * 1024
        or value["recursive_worker_swarms_forbidden"] is not True
        or value["approval_policy"] != "SURFACE_ONLY_NO_RESPONSE"
        or value["expected_receipt_schema"] != RECEIPT_SCHEMA
    ):
        raise AdapterProtocolError("start boundary mismatch")


def binding_from_start(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": BINDING_SCHEMA,
        "request_digest": value["request_digest"],
        "packet_digest": value["packet_digest"],
        "run_id": value["run_id"],
        "work_item_id": value["work_item_id"],
        "attempt_id": value["attempt_id"],
        "adapter_id": value["adapter_id"],
        "adapter_version": value["adapter_version"],
    }


def validate_binding(value: dict[str, Any]) -> None:
    if value["schema"] != BINDING_SCHEMA:
        raise AdapterProtocolError("foreign binding schema")
    for field in ("request_digest", "packet_digest"):
        _require_digest(field, value[field])
    for field in ("run_id", "work_item_id", "attempt_id", "adapter_id", "adapter_version"):
        _require_id(field, value[field])
    if value["adapter_id"] != ADAPTER_ID or value["adapter_version"] != ADAPTER_VERSION:
        raise AdapterProtocolError("adapter binding mismatch")


def _now() -> str:
    current = datetime.now(timezone.utc)
    base = current.strftime("%Y-%m-%dT%H:%M:%S")
    if current.microsecond == 0:
        return base + "Z"
    if current.microsecond % 1000 == 0:
        return f"{base}.{current.microsecond // 1000:03d}Z"
    return f"{base}.{current.microsecond:06d}Z"


def capabilities() -> dict[str, Any]:
    source_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return {
        "schema": CAPABILITIES_SCHEMA,
        "adapter_id": ADAPTER_ID,
        "adapter_protocol": ADAPTER_PROTOCOL,
        "adapter_version": ADAPTER_VERSION,
        "adapter_executable_identity": f"sha256:{source_digest}",
        "provider_kind": "openai.codex-app-server",
        "commands": ["capabilities", "start", "resume", "status", "collect"],
        "approval_policy": "SURFACE_ONLY_NO_RESPONSE",
        "expected_start_request_schema": START_SCHEMA,
        "event_schema": EVENT_SCHEMA,
        "terminal_receipt_schema": RECEIPT_SCHEMA,
        "target_effects_authorized": False,
    }


@dataclass(frozen=True)
class Attempt:
    binding: dict[str, Any]
    request: dict[str, Any]
    brief_raw: bytes
    backend: dict[str, str]
    account_class: str
    provider_identity: str
    model_identity: str
    session_identity: str
    thread_id: str | None
    turn_id: str | None
    queue_id: str | None
    client_message_id: str
    status: str
    started_at: str
    final_message: str | None
    terminal_receipt: dict[str, Any] | None


def _preflight_existing_store(path: Path, binding: dict[str, Any]) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise AdapterProtocolError("adapter state descriptor boundary unavailable")
    candidate = path if path.is_absolute() else Path.cwd() / path
    parts = candidate.parts
    if len(parts) < 2 or any(part in {"", ".", ".."} for part in parts[1:]):
        raise AdapterProtocolError("invalid adapter state path")
    directory_descriptor = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    )
    descriptor: int | None = None
    try:
        for component in parts[1:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        descriptor = os.open(
            parts[-1],
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_descriptor,
        )
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise AdapterProtocolError(
            f"unable to open exact existing adapter state: {exc}"
        ) from exc
    finally:
        os.close(directory_descriptor)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AdapterProtocolError("adapter state is not a regular file")
        connection = sqlite3.connect(
            f"file:/proc/self/fd/{descriptor}?mode=ro", uri=True
        )
        try:
            row = connection.execute(
                "SELECT binding_json FROM attempts WHERE attempt_id=?",
                (binding["attempt_id"],),
            ).fetchone()
        except sqlite3.Error as exc:
            raise AdapterProtocolError(f"invalid existing adapter state: {exc}") from exc
        finally:
            connection.close()
        if row is None:
            raise AdapterProtocolError("unknown attempt")
        retained = bytes(row[0])
        if retained != _canonical(binding):
            raise AdapterProtocolError("attempt binding substitution")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


class AdapterStore:
    def __init__(self, path: Path, admitted_descriptor: int | None = None):
        self._admitted_descriptor = admitted_descriptor
        self._occurrence_active = False
        if admitted_descriptor is None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.connection = sqlite3.connect(path)
        else:
            self.connection = sqlite3.connect(
                f"file:/proc/self/fd/{admitted_descriptor}?mode=rw", uri=True
            )
        self.connection.row_factory = sqlite3.Row
        if admitted_descriptor is None:
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.executescript(
                """
            CREATE TABLE IF NOT EXISTS attempts (
                attempt_id TEXT PRIMARY KEY, binding_json BLOB NOT NULL,
                request_json BLOB NOT NULL, brief_raw BLOB NOT NULL,
                backend_json BLOB NOT NULL, account_class TEXT NOT NULL,
                provider_identity TEXT NOT NULL, model_identity TEXT NOT NULL,
                session_identity TEXT NOT NULL, thread_id TEXT, turn_id TEXT,
                queue_id TEXT, client_message_id TEXT NOT NULL, status TEXT NOT NULL,
                started_at TEXT NOT NULL, final_message TEXT, terminal_receipt_json BLOB
            );
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, attempt_id TEXT NOT NULL,
                event_digest TEXT NOT NULL UNIQUE, raw_json BLOB NOT NULL
            );
            """
        )

    def begin_existing_occurrence(self, binding: dict[str, Any]) -> Attempt:
        """Atomically retain the exact binding under one occurrence writer lock."""
        if self._occurrence_active:
            raise AdapterProtocolError("adapter occurrence is already admitted")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            attempt = self.load(binding)
        except Exception:
            self.connection.rollback()
            raise
        self._occurrence_active = True
        return attempt

    def finish_existing_occurrence(self) -> None:
        if self._occurrence_active:
            self.connection.commit()
            self._occurrence_active = False

    def admit(self, attempt: Attempt) -> None:
        with self.connection:
            self.connection.execute(
                """INSERT INTO attempts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    attempt.binding["attempt_id"], _canonical(attempt.binding),
                    _canonical(attempt.request), attempt.brief_raw, _canonical(attempt.backend),
                    attempt.account_class, attempt.provider_identity, attempt.model_identity,
                    attempt.session_identity, attempt.thread_id, attempt.turn_id, attempt.queue_id,
                    attempt.client_message_id, attempt.status, attempt.started_at,
                    attempt.final_message, None,
                ),
            )

    def update(self, attempt_id: str, **values: Any) -> None:
        allowed = {"thread_id", "turn_id", "queue_id", "status", "final_message", "terminal_receipt_json"}
        if not values or not set(values) <= allowed:
            raise AdapterProtocolError("invalid attempt materialization update")
        assignments = ",".join(f"{key}=?" for key in values)
        prohibited_from_indeterminate = (
            values.get("status", "INDETERMINATE") != "INDETERMINATE"
            or values.get("terminal_receipt_json") is not None
        )
        guard = (
            "status NOT IN ('INDETERMINATE','TERMINAL')"
            if prohibited_from_indeterminate
            else "status != 'TERMINAL'"
        )

        def apply() -> None:
            cursor = self.connection.execute(
                f"UPDATE attempts SET {assignments} WHERE attempt_id=? AND {guard}",
                [*values.values(), attempt_id],
            )
            if cursor.rowcount != 1:
                current = self.connection.execute(
                    "SELECT status FROM attempts WHERE attempt_id=?", (attempt_id,)
                ).fetchone()
                if current is None:
                    raise AdapterProtocolError("unknown attempt")
                raise AdapterProtocolError(
                    f"{current['status'].lower()} attempt transition is terminally prohibited"
                )

        if self._occurrence_active:
            apply()
        else:
            with self.connection:
                apply()

    def append_event(self, attempt_id: str, event: dict[str, Any]) -> None:
        def apply() -> None:
            self.connection.execute(
                "INSERT OR IGNORE INTO events(attempt_id,event_digest,raw_json) VALUES (?,?,?)",
                (attempt_id, event["event_digest"], _canonical(event)),
            )

        if self._occurrence_active:
            apply()
        else:
            with self.connection:
                apply()

    def events(self, attempt_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT raw_json FROM events WHERE attempt_id=? ORDER BY sequence",
            (attempt_id,),
        ).fetchall()
        return [json.loads(row["raw_json"]) for row in rows]

    def load(self, binding: dict[str, Any]) -> Attempt:
        validate_binding(binding)
        row = self.connection.execute(
            "SELECT * FROM attempts WHERE attempt_id=?", (binding["attempt_id"],),
        ).fetchone()
        if row is None:
            raise AdapterProtocolError("unknown attempt")
        retained = json.loads(row["binding_json"])
        if retained != binding:
            raise AdapterProtocolError("attempt binding substitution")
        receipt = json.loads(row["terminal_receipt_json"]) if row["terminal_receipt_json"] else None
        return Attempt(
            binding=retained, request=json.loads(row["request_json"]),
            brief_raw=bytes(row["brief_raw"]), backend=json.loads(row["backend_json"]),
            account_class=row["account_class"], provider_identity=row["provider_identity"],
            model_identity=row["model_identity"], session_identity=row["session_identity"],
            thread_id=row["thread_id"], turn_id=row["turn_id"], queue_id=row["queue_id"],
            client_message_id=row["client_message_id"], status=row["status"],
            started_at=row["started_at"], final_message=row["final_message"],
            terminal_receipt=receipt,
        )


def _provider_id(identity: BackendIdentity) -> str:
    return f"codex-app-server:{identity.sha256[:24]}"


def _session_id(identity: BackendIdentity) -> str:
    digest = hashlib.sha256(str(identity.home).encode()).hexdigest()[:24]
    return f"codex-home:{digest}"


def _custody_extensions(attempt: Attempt) -> dict[str, Any]:
    return {
        "codex_executable": attempt.backend["executable"],
        "codex_version": attempt.backend["version"],
        "codex_sha256": attempt.backend["sha256"],
        "codex_home": attempt.backend["home"],
        "account_class": attempt.account_class,
        "requested_provider_model_class": attempt.request["provider_model_class"],
    }


def _message_raw(message: ServerMessage) -> bytes:
    raw = message.raw_bytes if message.raw_bytes is not None else _canonical(message.raw)
    if len(raw) > MAXIMUM_RAW_APP_SERVER_EVENT_BYTES:
        raise AdapterProtocolError("App Server event exceeds retained raw byte bound")
    try:
        parsed = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterProtocolError(f"invalid retained App Server event: {exc}") from exc
    if parsed != message.raw:
        raise AdapterProtocolError("retained App Server event differs from parsed message")
    return raw



def _event(attempt: Attempt, kind: str, **changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": EVENT_SCHEMA, "event_digest": "sha256:" + "0" * 64,
        "event_id": f"{attempt.binding['attempt_id']}:{uuid.uuid4()}",
        "packet_digest": attempt.binding["packet_digest"],
        "run_id": attempt.binding["run_id"], "work_item_id": attempt.binding["work_item_id"],
        "attempt_id": attempt.binding["attempt_id"], "adapter_id": ADAPTER_ID,
        "adapter_version": ADAPTER_VERSION, "occurred_at": _now(), "kind": kind,
        "provider_identity": attempt.provider_identity, "model_identity": attempt.model_identity,
        "session_identity": attempt.session_identity, "thread_identity": attempt.thread_id,
        "turn_identity": attempt.turn_id, "queue_identity": attempt.queue_id,
        "message": None, "human_question": None,
        "extensions": _custody_extensions(attempt),
    }
    value.update(changes)
    value["event_digest"] = _digest(EVENT_DOMAIN, _without(value, "event_digest"))
    return value


def _prompt(attempt: Attempt) -> str:
    brief = json.loads(attempt.brief_raw)
    return json.dumps(
        {
            "protocol": ADAPTER_PROTOCOL, "binding": attempt.binding,
            "workspace_identity": attempt.request["workspace_identity"],
            "provider_model_class": attempt.request["provider_model_class"],
            "timeout_seconds": attempt.request["timeout_seconds"],
            "maximum_output_bytes": attempt.request["maximum_output_bytes"],
            "recursive_worker_swarms_forbidden": True,
            "approval_policy": "SURFACE_ONLY_NO_RESPONSE",
            "expected_receipt_schema": RECEIPT_SCHEMA, "worker_outcome_schema": OUTCOME_SCHEMA,
            "worker_brief": brief,
            "instruction": (
                "Perform only the bounded worker brief. Never answer an approval request. "
                "Return one exact canonical switchyard.codex-worker-outcome/v1 JSON object "
                "as the final agent message. The adapter adds only retained custody identities and seals the exact terminal receipt; process exit alone is not a result."
            ),
        },
        sort_keys=True, ensure_ascii=False,
    )


class NightshiftAdapter:
    def __init__(self, identity: BackendIdentity, account_class: str, appserver: AppServerClient, store: AdapterStore, config: Config):
        _require_id("account_class", account_class)
        if config.allow_approval_responses or config.allow_interrupt:
            raise AdapterProtocolError("adapter requires approval responses and interrupts disabled")
        self.identity = identity
        self.account_class = account_class
        self.appserver = appserver
        self.store = store
        self.config = config
        self.process_occurrence_identity = f"appserver-process:{uuid.uuid4()}"

    def start(self, request: dict[str, Any], brief_raw: bytes) -> dict[str, Any]:
        validate_start(request, brief_raw)
        workspace = self.config.validate_cwd(request["workspace_identity"])
        binding = binding_from_start(request)
        attempt = Attempt(
            binding=binding, request=request, brief_raw=brief_raw, backend=self.identity.as_dict(),
            account_class=self.account_class, provider_identity=_provider_id(self.identity),
            model_identity=f"class:{request['provider_model_class']}",
            session_identity=_session_id(self.identity), thread_id=None, turn_id=None, queue_id=None,
            client_message_id=str(uuid.uuid4()), status="ADMITTED", started_at=_now(),
            final_message=None, terminal_receipt=None,
        )
        self.store.admit(attempt)
        self._record(attempt, "adapter_accepted")
        try:
            thread_result = self.appserver.request("thread/start", {"cwd": str(workspace)})
            thread = thread_result.get("thread") or {}
            thread_id = _require_id("thread_id", thread.get("id"))
            self.store.update(binding["attempt_id"], thread_id=thread_id, status="STARTING")
            attempt = self.store.load(binding)
            turn_result = self.appserver.request(
                "turn/start",
                {
                    "threadId": thread_id,
                    "input": [{"type": "text", "text": _prompt(attempt)}],
                    "clientUserMessageId": attempt.client_message_id,
                },
            )
            turn = turn_result.get("turn") or {}
            turn_id = _require_id("turn_id", turn.get("id"))
            self.store.update(binding["attempt_id"], turn_id=turn_id, status="RUNNING")
            attempt = self.store.load(binding)
            self._record(attempt, "provider_identity", evidence_raw=_canonical(thread_result), evidence_kind="thread_start_response")
            self._record(attempt, "worker_started", evidence_raw=_canonical(turn_result), evidence_kind="turn_start_response")
        except Exception as exc:
            attempt = self.store.load(binding)
            self.store.update(binding["attempt_id"], status="INDETERMINATE")
            self._record(attempt, "mechanism_indeterminate", message=str(exc)[:4096])
        return self.result(binding)

    def _mark_indeterminate(self, binding: dict[str, Any], message: str) -> None:
        attempt = self.store.load(binding)
        self.store.update(binding["attempt_id"], status="INDETERMINATE")
        self._record(attempt, "mechanism_indeterminate", message=message[:4096])

    def resume(self, binding: dict[str, Any]) -> dict[str, Any]:
        attempt = self.store.load(binding)
        if attempt.status == "INDETERMINATE":
            return self.result(binding)
        if attempt.terminal_receipt is not None:
            raise AdapterProtocolError("terminal attempt cannot resume")
        if attempt.thread_id is None:
            self._mark_indeterminate(binding, "no retained thread identity")
            return self.result(binding)
        result = self.appserver.request(
            "thread/read", {"threadId": attempt.thread_id, "includeTurns": True}
        )
        thread = result.get("thread") or {}
        if thread.get("id") != attempt.thread_id:
            raise AdapterProtocolError("thread identity substitution")
        status = thread.get("status") or {}
        if status.get("type") == "notLoaded":
            self.appserver.request("thread/resume", {"threadId": attempt.thread_id})
        elif status.get("type") not in {"idle", "active"}:
            self._mark_indeterminate(binding, "unsupported thread status")
            return self.result(binding)
        evidence_raw = _canonical(result)
        if len(evidence_raw) > MAXIMUM_RAW_APP_SERVER_EVENT_BYTES:
            self._mark_indeterminate(binding, "thread/read response exceeds retained raw byte bound")
            self._drain(binding)
            return self.result(binding)
        self._ingest_thread(attempt, thread, evidence_raw)
        self._record(self.store.load(binding), "checkpoint")
        self._drain(binding)
        return self.result(binding)

    def status(self, binding: dict[str, Any]) -> dict[str, Any]:
        attempt = self.store.load(binding)
        if attempt.status == "INDETERMINATE":
            return self.result(binding)
        if attempt.thread_id is not None:
            result = self.appserver.request(
                "thread/read", {"threadId": attempt.thread_id, "includeTurns": True}
            )
            thread = result.get("thread") or {}
            if thread.get("id") != attempt.thread_id:
                raise AdapterProtocolError("thread identity substitution")
            evidence_raw = _canonical(result)
            if len(evidence_raw) > MAXIMUM_RAW_APP_SERVER_EVENT_BYTES:
                self._mark_indeterminate(binding, "thread/read response exceeds retained raw byte bound")
            else:
                self._ingest_thread(attempt, thread, evidence_raw)
        self._drain(binding)
        return self.result(binding)

    def _finalize_acquisition(self, binding: dict[str, Any]) -> bool:
        quiesce = getattr(self.appserver, "quiesce_acquisition", None)
        if quiesce is None:
            self._mark_indeterminate(binding, "App Server cannot establish terminal acquisition cut")
            return False
        try:
            cut = quiesce()
        except Exception as exc:
            self._mark_indeterminate(
                binding, f"App Server terminal acquisition cut failed: {exc}"
            )
            return False
        if not isinstance(cut, AcquisitionCut):
            self._mark_indeterminate(
                binding, "App Server returned foreign terminal acquisition cut"
            )
            return False
        try:
            self._drain(binding)
        except AdapterProtocolError as exc:
            self._mark_indeterminate(
                binding, f"App Server retained frame validation failed: {exc}"
            )
            return False
        attempt = self.store.load(binding)
        if (
            not cut.stream_quiesced
            or cut.loss_generation
            or cut.process_disposition not in {
                "EXITED", "EXITED_AFTER_TERMINATE", "EXITED_AFTER_KILL",
            }
        ) and attempt.status != "INDETERMINATE":
            self._mark_indeterminate(
                binding,
                "App Server acquisition loss preceded terminal evidence cut "
                "or unconfirmed process exit prevented terminality"
            )
            attempt = self.store.load(binding)
        return attempt.status != "INDETERMINATE"

    def finalize_occurrence(self, binding: dict[str, Any]) -> dict[str, Any]:
        self._finalize_acquisition(binding)
        return self.result(binding)

    def collect(self, binding: dict[str, Any]) -> dict[str, Any]:
        attempt = self.store.load(binding)
        if attempt.terminal_receipt is not None:
            return self.result(binding)
        self.status(binding)
        attempt = self.store.load(binding)
        if attempt.final_message:
            if not self._finalize_acquisition(binding):
                return self.result(binding)
            attempt = self.store.load(binding)
            if attempt.status == "INDETERMINATE":
                return self.result(binding)
            if attempt.status != "PROVIDER_COMPLETED":
                return self.result(binding)

            try:
                outcome = json.loads(attempt.final_message, object_pairs_hook=_unique_object)
                if not isinstance(outcome, dict) or frozenset(outcome) != OUTCOME_FIELDS:
                    raise AdapterProtocolError("closed worker outcome fields do not match")
                if _canonical(outcome) != attempt.final_message.encode("utf-8"):
                    raise AdapterProtocolError("worker outcome is not exact canonical JSON")
                receipt = receipt_from_outcome(outcome, attempt)
            except (json.JSONDecodeError, AdapterProtocolError) as exc:
                self._mark_indeterminate(binding, str(exc))
            else:
                self.store.update(
                    binding["attempt_id"], status="TERMINAL",
                    terminal_receipt_json=_canonical(receipt),
                )
        return self.result(binding)

    def observe(self, binding: dict[str, Any], seconds: float) -> dict[str, Any]:
        deadline = time.monotonic() + max(0.0, seconds)
        while time.monotonic() < deadline:
            self._drain(binding)
            time.sleep(0.05)
        return self.result(binding)

    def result(self, binding: dict[str, Any]) -> dict[str, Any]:
        attempt = self.store.load(binding)
        return {
            "schema": RESULT_SCHEMA, "binding": attempt.binding,
            "mechanism_state": attempt.status, "events": self.store.events(binding["attempt_id"]),
            "terminal_receipt": attempt.terminal_receipt,
        }

    def _record(
        self, attempt: Attempt, kind: str, *,
        appserver_message: ServerMessage | None = None,
        evidence_raw: bytes | None = None, evidence_kind: str | None = None,
        extension_fields: dict[str, Any] | None = None, **changes: Any,
    ) -> None:
        extensions = _custody_extensions(attempt)
        extensions["appserver_process_occurrence_identity"] = self.process_occurrence_identity
        raw = _message_raw(appserver_message) if appserver_message is not None else evidence_raw
        representation = (
            "exact_wire_bytes_including_line_terminator"
            if appserver_message is not None and appserver_message.raw_bytes is not None
            else "canonicalized_parsed_response"
        )
        if raw is not None:
            if len(raw) > MAXIMUM_RAW_APP_SERVER_EVENT_BYTES:
                raise AdapterProtocolError("App Server event exceeds retained raw byte bound")
            extensions.update({
                "appserver_evidence_kind": evidence_kind or "wire_message",
                "appserver_evidence_representation": representation,
                "appserver_evidence_digest": _raw_digest(RAW_APP_SERVER_EVENT_DOMAIN, raw),
                "appserver_evidence_encoding": "hex",
                "appserver_evidence_bytes_hex": raw.hex(),
            })
        if extension_fields:
            extensions.update(extension_fields)
        changes["extensions"] = extensions
        self.store.append_event(attempt.binding["attempt_id"], _event(attempt, kind, **changes))

    def _drain(self, binding: dict[str, Any]) -> None:
        drain_diagnostics = getattr(self.appserver, "drain_acquisition_diagnostics", None)
        diagnostics = drain_diagnostics() if drain_diagnostics is not None else []
        if diagnostics:
            attempt = self.store.load(binding)
            self.store.update(binding["attempt_id"], status="INDETERMINATE")
            for diagnostic in diagnostics:
                self._record(attempt, "mechanism_indeterminate", message=diagnostic[:4096])
            for target in (self.appserver.server_requests, self.appserver.notifications):
                while True:
                    try:
                        target.get_nowait()
                    except queue.Empty:
                        break
            return
        if self.store.load(binding).status == "INDETERMINATE":
            return
        while True:
            try:
                message = self.appserver.server_requests.get_nowait()
            except queue.Empty:
                break
            attempt = self.store.load(binding)
            thread_id, turn_id = _message_ids(message)
            if thread_id is None or thread_id != attempt.thread_id:
                raise AdapterProtocolError("approval request lacks exact retained thread binding")
            try:
                _message_raw(message)
            except AdapterProtocolError as exc:
                self._mark_indeterminate(binding, str(exc))
                return
            if turn_id is None or turn_id != attempt.turn_id:
                raise AdapterProtocolError("approval request lacks exact retained turn binding")
            self.store.update(binding["attempt_id"], status="WAITING_APPROVAL")
            self._record(
                attempt, "waiting_approval", appserver_message=message, evidence_kind="approval_server_request",
                message=f"approval request surfaced without response: {message.method}",
                extension_fields={
                    "approval_method": message.method,
                    "approval_response_sent": False,
                    "protected_effect_absent": True,
                },
            )
        while True:
            try:
                message = self.appserver.notifications.get_nowait()
            except queue.Empty:
                break
            try:
                self._notification(binding, message)
            except AdapterProtocolError as exc:
                self._mark_indeterminate(binding, str(exc))
                return

    def _notification(self, binding: dict[str, Any], message: ServerMessage) -> None:
        _message_raw(message)
        attempt = self.store.load(binding)
        if attempt.status == "INDETERMINATE":
            return
        thread_id, turn_id = _message_ids(message)
        if thread_id is not None and thread_id != attempt.thread_id:
            return
        params = message.params
        item = params.get("item") if isinstance(params.get("item"), dict) else {}
        if message.method in {"item/started", "item/completed"} and item.get("type") == "userMessage":
            if item.get("clientId") == attempt.client_message_id and turn_id == attempt.turn_id:
                self.store.update(binding["attempt_id"], status="RUNNING")
        if message.method == "turn/completed":
            if thread_id != attempt.thread_id or turn_id != attempt.turn_id:
                return
            raw = _message_raw(message)
            text = _final_agent_message(params.get("turn") or {})
            bounded, truncated = _bounded_utf8(text, attempt.request["maximum_output_bytes"])
            status = "INDETERMINATE" if truncated else "PROVIDER_COMPLETED"
            self.store.update(binding["attempt_id"], status=status, final_message=bounded)
            kind = "mechanism_indeterminate" if truncated else "provider_completion_observation"
            detail = "provider final message exceeded byte bound" if truncated else None
            self._record(
                self.store.load(binding), kind, appserver_message=message,
                evidence_kind="turn_completed_notification", message=detail,
            )

    def _ingest_thread(
        self, attempt: Attempt, thread: dict[str, Any], evidence_raw: bytes | None = None,
    ) -> None:
        if attempt.status == "INDETERMINATE":
            return
        turns = thread.get("turns") if isinstance(thread.get("turns"), list) else []
        selected = None
        if attempt.turn_id:
            selected = next((turn for turn in turns if turn.get("id") == attempt.turn_id), None)
        if isinstance(selected, dict):
            turn_id = _require_id("turn_id", selected.get("id"))
            if turn_id != attempt.turn_id:
                raise AdapterProtocolError("thread history turn identity substitution")
            text = _final_agent_message(selected)
            bounded, truncated = _bounded_utf8(text, attempt.request["maximum_output_bytes"])
            completed = selected.get("status") in {"completed", "failed", "interrupted"}

            status = "INDETERMINATE" if truncated else "PROVIDER_COMPLETED" if completed else "RUNNING"
            self.store.update(attempt.binding["attempt_id"], status=status, final_message=bounded)
            if completed:
                kind = "mechanism_indeterminate" if truncated else "provider_completion_observation"
                detail = "provider final message exceeded byte bound" if truncated else None
                self._record(
                    self.store.load(attempt.binding), kind, evidence_raw=evidence_raw,
                    evidence_kind="thread_read_response", message=detail,
                )


def _bounded_utf8(text: str | None, maximum_bytes: int) -> tuple[str | None, bool]:
    if text is None:
        return None, False
    raw = text.encode("utf-8")
    if len(raw) <= maximum_bytes:
        return text, False
    return raw[:maximum_bytes].decode("utf-8", errors="ignore"), True


def _message_ids(message: ServerMessage) -> tuple[str | None, str | None]:
    params = message.params
    thread_id = params.get("threadId")
    turn_id = params.get("turnId")
    turn = params.get("turn")
    if not isinstance(turn_id, str) and isinstance(turn, dict):
        turn_id = turn.get("id")
    return (thread_id if isinstance(thread_id, str) else None, turn_id if isinstance(turn_id, str) else None)


def _final_agent_message(turn: dict[str, Any]) -> str | None:
    items = turn.get("items") if isinstance(turn.get("items"), list) else []
    messages = [item.get("text") for item in items if isinstance(item, dict) and item.get("type") == "agentMessage" and isinstance(item.get("text"), str)]
    return messages[-1] if messages else None


def _bounded_text(field: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 65536:
        raise AdapterProtocolError(f"invalid worker outcome {field}")
    return value


def _string_list(field: str, value: Any) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or len(item) > 65536 for item in value
    ):
        raise AdapterProtocolError(f"invalid worker outcome {field}")
    return value


def receipt_from_outcome(outcome: dict[str, Any], attempt: Attempt) -> dict[str, Any]:
    if outcome.get("schema") != OUTCOME_SCHEMA:
        raise AdapterProtocolError("foreign worker outcome schema")
    for field in ("state", "result_classification", "remaining_trigger", "next_lawful_action"):
        _bounded_text(field, outcome.get(field))
    for field in ("tests", "evidence", "live_or_production_mutations"):
        _string_list(field, outcome.get(field))
    repositories = outcome.get("repositories")
    if not isinstance(repositories, list):
        raise AdapterProtocolError("invalid worker outcome repositories")
    for repository in repositories:
        if not isinstance(repository, dict) or frozenset(repository) != frozenset({
            "repository", "branch", "head", "push_status",
        }):
            raise AdapterProtocolError("invalid worker outcome repository custody")
        for field, value in repository.items():
            _bounded_text(f"repository {field}", value)
    questions = outcome.get("human_questions")
    question_fields = frozenset({
        "question_id", "question", "exhausted_evidence", "safe_default",
        "consequences", "resume_point",
    })
    if not isinstance(questions, list):
        raise AdapterProtocolError("invalid worker outcome human questions")
    for question in questions:
        if not isinstance(question, dict) or frozenset(question) != question_fields:
            raise AdapterProtocolError("invalid worker outcome human question")
        _require_id("question_id", question["question_id"])
        for field in question_fields - {"question_id"}:
            _bounded_text(f"question {field}", question[field])
    if outcome["live_or_production_mutations"]:
        raise AdapterProtocolError("worker outcome declares protected effect")
    teardown = outcome.get("teardown")
    if not isinstance(teardown, dict) or frozenset(teardown) != frozenset({
        "live_runtime", "secrets", "teardown",
    }):
        raise AdapterProtocolError("invalid worker outcome teardown")
    for field, value in teardown.items():
        _bounded_text(f"teardown {field}", value)
    extensions = outcome.get("extensions")
    if not isinstance(extensions, dict) or len(extensions) > 64:
        raise AdapterProtocolError("invalid worker outcome extensions")
    _validate_interoperable_extension(extensions)
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA, "receipt_digest": "sha256:" + "0" * 64,
        "packet_digest": attempt.binding["packet_digest"],
        "run_id": attempt.binding["run_id"],
        "work_item_id": attempt.binding["work_item_id"],
        "attempt_id": attempt.binding["attempt_id"],
        "adapter_id": ADAPTER_ID, "adapter_version": ADAPTER_VERSION,
        "provider_identity": attempt.provider_identity,
        "model_identity": attempt.model_identity,
        "session_identity": attempt.session_identity,
        "thread_identity": attempt.thread_id,
        "turn_identity": attempt.turn_id,
        "queue_identity": attempt.queue_id,
        "started_at": attempt.started_at, "ended_at": _now(),
    }
    receipt.update({key: value for key, value in outcome.items() if key != "schema"})
    receipt["receipt_digest"] = _digest(RECEIPT_DOMAIN, _without(receipt, "receipt_digest"))
    validate_receipt(receipt, attempt)
    return receipt


def validate_receipt(value: dict[str, Any], attempt: Attempt) -> None:
    _validate_terminal_predecessor(value)
    expected = {
        "packet_digest": attempt.binding["packet_digest"],
        "run_id": attempt.binding["run_id"], "work_item_id": attempt.binding["work_item_id"],
        "attempt_id": attempt.binding["attempt_id"], "adapter_id": ADAPTER_ID,
        "adapter_version": ADAPTER_VERSION, "provider_identity": attempt.provider_identity,
        "model_identity": attempt.model_identity, "session_identity": attempt.session_identity,
        "thread_identity": attempt.thread_id, "turn_identity": attempt.turn_id,
        "queue_identity": attempt.queue_id,
    }
    for field, expected_value in expected.items():
        if value[field] != expected_value:
            raise AdapterProtocolError(f"terminal {field} substitution")
    if value["live_or_production_mutations"]:
        raise AdapterProtocolError("live or production mutation declared")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="switchyard-nightshift-adapter")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--account-class")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capabilities")
    start = sub.add_parser("start")
    start.add_argument("--request", type=Path, required=True)
    start.add_argument("--brief", type=Path, required=True)
    start.add_argument("--observe-seconds", type=float, default=0.25)
    for name in ("resume", "status", "collect"):
        command = sub.add_parser(name)
        command.add_argument("--binding", type=Path, required=True)
        command.add_argument("--observe-seconds", type=float, default=0.25)
    return parser


def main() -> None:
    args = _parser().parse_args()
    if args.command == "capabilities":
        print(_canonical(capabilities()).decode())
        return
    if args.config is None or args.state is None or args.account_class is None:
        raise SystemExit("non-capability commands require --config, --state, and --account-class")
    admitted_descriptor = None
    if args.command == "start":
        request, _ = _load_closed(args.request, START_FIELDS)
        brief_raw = _read_bounded_regular(args.brief, MAXIMUM_BRIEF_BYTES, "worker brief")
        validate_start(request, brief_raw)
        binding = binding_from_start(request)
    else:
        binding, _ = _load_closed(args.binding, BINDING_FIELDS)
        validate_binding(binding)
        admitted_descriptor = _preflight_existing_store(args.state, binding)
    store = AdapterStore(args.state, admitted_descriptor)
    existing_occurrence = args.command != "start"
    try:
        if existing_occurrence:
            store.begin_existing_occurrence(binding)
        config = Config.load(args.config)
        identity = config.verify_backend()
        appserver = AppServerClient(identity.command, environment=identity.environment)
        adapter = NightshiftAdapter(identity, args.account_class, appserver, store, config)
        try:
            appserver.start()
            if args.command == "start":
                adapter.start(request, brief_raw)
            elif args.command == "resume":
                adapter.resume(binding)
            elif args.command == "status":
                adapter.status(binding)
            else:
                adapter.collect(binding)
            if args.observe_seconds:
                adapter.observe(binding, args.observe_seconds)
        except Exception:
            if existing_occurrence:
                adapter.finalize_occurrence(binding)
            else:
                appserver.quiesce_acquisition()
            raise
        result = adapter.finalize_occurrence(binding)
        store.finish_existing_occurrence()
        print(_canonical(result).decode())
    finally:
        store.finish_existing_occurrence()
        store.connection.close()
        if admitted_descriptor is not None:
            os.close(admitted_descriptor)


if __name__ == "__main__":
    main()
