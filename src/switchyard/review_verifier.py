"""Authenticate one AG plan review from pinned Nightshift/Switchyard custody."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import resource
import signal
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from ._vendor import rfc8785
from .provider_admission import replay_snapshot
from .provider_runner import capture_verified_executable, capture_contract_for_request, validate_dispatch, validate_request

CONFIG_SCHEMA = "switchyard.shared-review-verifier-config/v1"
REQUEST_SCHEMA = "ag.governed-loop.review-verification-request/v1"
RESULT_SCHEMA = "switchyard.shared-source-review/v1"
CUSTODY_SCHEMA = "switchyard.shared-source-review-custody/v1"
RESPONSE_SCHEMA = "ag.governed-loop.owner-verification-response/v1"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[A-Za-z0-9._:/-]{1,512}\Z")
CONFIG_FIELDS = {"schema", "reviewer_id", "author_principal", "excluded_thread_ids",
    "switchyard_state_path", "nightshift_foreman_program", "nightshift_foreman_sha256",
    "nightshift_state_path", "nightshift_run_id", "brief_manifest_pointer", "brief_contract",
    "route", "limits"}
ROUTE_FIELDS = {"codex_source_head", "app_server_executable_sha256", "provider", "model",
    "adapter_id", "adapter_version", "adapter_protocol"}
LIMIT_FIELDS = {"max_result_bytes", "max_custody_bytes", "max_events_bytes", "foreman_timeout_seconds"}
MANIFEST_FIELDS = {"schema", "binding_id", "binding_bytes_base64", "author_principal"}
RESULT_FIELDS = {"schema", "binding_id", "verdict", "findings"}
FINDING_FIELDS = {"code", "summary"}
BINDING_SCHEMA = "maude.governed-plan-binding/v1"
BINDING_FIELDS = {"schema", "binding_id", "campaign", "occurrence", "subject", "scope",
    "work_schema", "work", "compiler_contract", "plan_document_digest", "lock_id",
    "compilation_id", "artifacts"}
ARTIFACT_NAMES = {"plan_document", "lock_receipt", "compiler_inputs", "compiled_handoff",
    "compilation_receipt", "executor_plan"}
ARTIFACT_FIELDS = {"sha256", "byte_length", "bytes_base64"}


class VerificationError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        raise VerificationError("value is outside canonical JSON") from exc


def plain_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def worker_brief_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(b"nightshift.worker-brief.digest/v2\0" + raw).hexdigest()


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise VerificationError("duplicate JSON key")
        out[key] = value
    return out


def parse(raw: bytes, label: str, *, canonical_required: bool = True) -> Any:
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid {label} JSON") from exc
    if canonical_required and canonical(value) != raw:
        raise VerificationError(f"{label} is not canonical JSON")
    return value


def closed(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise VerificationError(f"{label} fields do not match")
    return value


def token(value: Any, label: str) -> str:
    if not isinstance(value, str) or TOKEN.fullmatch(value) is None:
        raise VerificationError(f"invalid {label}")
    return value


def digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise VerificationError(f"invalid {label}")
    return value


def read_regular(path: Path, limit: int, label: str) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise VerificationError(f"{label} is not a bounded regular file")
        chunks, total = [], 0
        while True:
            part = os.read(fd, min(65536, limit + 1 - total))
            if not part:
                break
            total += len(part)
            if total > limit:
                raise VerificationError(f"{label} exceeds bound")
            chunks.append(part)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != \
           (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise VerificationError(f"{label} changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_config(path: Path) -> tuple[dict[str, Any], str]:
    raw = read_regular(path, 1024 * 1024, "config")
    raw = raw[:-1] if raw.endswith(b"\n") else raw
    value = closed(parse(raw, "config"), CONFIG_FIELDS, "config")
    if value["schema"] != CONFIG_SCHEMA:
        raise VerificationError("config schema mismatch")
    token(value["reviewer_id"], "reviewer_id"); token(value["author_principal"], "author_principal")
    if value["reviewer_id"] == value["author_principal"]:
        raise VerificationError("reviewer and author principal are not distinct")
    if not isinstance(value["excluded_thread_ids"], list) or len(value["excluded_thread_ids"]) > 64:
        raise VerificationError("invalid excluded thread list")
    for item in value["excluded_thread_ids"]: token(item, "excluded thread")
    closed(value["route"], ROUTE_FIELDS, "route")
    for key, item in value["route"].items(): (digest if key.endswith("sha256") else token)(item, key)
    limits = closed(value["limits"], LIMIT_FIELDS, "limits")
    if any(not isinstance(limits[k], int) for k in limits) or not (1 <= limits["foreman_timeout_seconds"] <= 60):
        raise VerificationError("invalid limits")
    if any(not 1 <= limits[k] <= 16 * 1024 * 1024 for k in ("max_result_bytes", "max_custody_bytes", "max_events_bytes")):
        raise VerificationError("invalid byte limits")
    if not isinstance(value["brief_manifest_pointer"], list) or not value["brief_manifest_pointer"]:
        raise VerificationError("invalid brief manifest pointer")
    for item in value["brief_manifest_pointer"]: token(item, "brief pointer component")
    token(value["brief_contract"], "brief contract")
    for key in ("switchyard_state_path", "nightshift_foreman_program", "nightshift_state_path"):
        if not isinstance(value[key], str) or not Path(value[key]).is_absolute():
            raise VerificationError(f"{key} is not absolute")
    digest(value["nightshift_foreman_sha256"], "foreman identity")
    token(value["nightshift_run_id"], "nightshift run")
    return value, plain_digest(raw)


def decode_artifact(text: Any, limit: int, label: str) -> bytes:
    if not isinstance(text, str) or len(text) > ((limit + 2) // 3) * 4:
        raise VerificationError(f"invalid {label} encoding")
    try: raw = base64.b64decode(text, validate=True)
    except Exception as exc: raise VerificationError(f"invalid {label} encoding") from exc
    if len(raw) > limit or base64.b64encode(raw).decode() != text:
        raise VerificationError(f"invalid {label} bound")
    return raw


def validate_binding(raw: bytes) -> str:
    value = closed(parse(raw, "binding"), BINDING_FIELDS, "binding")
    if value["schema"] != BINDING_SCHEMA:
        raise VerificationError("binding schema mismatch")
    for key in ("campaign", "subject", "scope", "work", "plan_document_digest", "lock_id", "compilation_id"):
        digest(value[key], f"binding {key}")
    for key in ("work_schema", "compiler_contract"):
        token(value[key], f"binding {key}")
    try: occurrence = uuid.UUID(value["occurrence"])
    except (ValueError, AttributeError) as exc: raise VerificationError("invalid binding occurrence") from exc
    if str(occurrence) != value["occurrence"]:
        raise VerificationError("binding occurrence is not canonical")
    artifacts = closed(value["artifacts"], ARTIFACT_NAMES, "binding artifacts")
    decoded: dict[str, bytes] = {}
    for name, artifact in artifacts.items():
        closed(artifact, ARTIFACT_FIELDS, f"binding artifact {name}")
        raw_artifact = decode_artifact(artifact["bytes_base64"],
            1024 * 1024 if name == "plan_document" else 16 * 1024 * 1024, name)
        if artifact["byte_length"] != len(raw_artifact) or artifact["sha256"] != plain_digest(raw_artifact):
            raise VerificationError(f"binding artifact {name} identity mismatch")
        decoded[name] = raw_artifact
    if plain_digest(decoded["plan_document"]) != value["plan_document_digest"]:
        raise VerificationError("binding PlanDocument identity mismatch")
    unsigned = {key: item for key, item in value.items() if key != "binding_id"}
    identity = plain_digest(BINDING_SCHEMA.encode() + b"\0" + canonical(unsigned))
    if value["binding_id"] != identity:
        raise VerificationError("binding domain identity mismatch")
    return identity


def run_foreman(config: dict[str, Any]) -> list[Any]:
    program = Path(config["nightshift_foreman_program"])
    maximum = config["limits"]["max_events_bytes"]
    def child_limits() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        captured = capture_verified_executable(program, config["nightshift_foreman_sha256"])
        try:
            proc = subprocess.Popen([f"/proc/self/fd/{captured}", "events", "--db", config["nightshift_state_path"],
                "--run-id", config["nightshift_run_id"]], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                close_fds=True, pass_fds=(captured,), env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                start_new_session=True, preexec_fn=child_limits)
        finally:
            os.close(captured)
        deadline = time.monotonic() + config["limits"]["foreman_timeout_seconds"]
        try:
            while proc.poll() is None:
                if stdout.tell() >= maximum or stderr.tell() >= maximum:
                    raise VerificationError("foreman output reached bound")
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(str(program), config["limits"]["foreman_timeout_seconds"])
                time.sleep(.01)
        except BaseException:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait()
            raise
        # The query executable is not allowed to leave descendant producers.
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        if proc.returncode != 0:
            raise VerificationError("foreman read-only query failed")
        if stdout.tell() > maximum or stderr.tell() > 65536:
            raise VerificationError("foreman output exceeds bound")
        stdout.seek(0); events = parse(stdout.read(), "foreman events", canonical_required=False)
    if not isinstance(events, list) or len(events) > 4096:
        raise VerificationError("invalid foreman event set")
    return events


def switchyard_row(config: dict[str, Any], dispatch_digest: str) -> tuple[dict, dict, bytes, dict]:
    uri = Path(config["switchyard_state_path"]).resolve().as_uri() + "?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    limit = 16 * 1024 * 1024
    try:
        cursor = db.execute("SELECT request,brief,backend,record FROM provider_runs "
            "WHERE length(request)<=? AND length(brief)<=? AND length(backend)<=? AND length(record)<=? LIMIT 4097",
            (limit, limit, limit, limit))
        rows = []
        for row in cursor:
            rows.append(row)
            if len(rows) > 4096: break
    finally: db.close()
    if len(rows) > 4096: raise VerificationError("provider store exceeds review scan bound")
    found = []
    for req_raw, brief, backend_raw, record_raw in rows:
        record = parse(record_raw, "provider record")
        if record.get("dispatch_record", {}).get("dispatch_digest") == dispatch_digest:
            found.append((parse(req_raw, "provider request"), record, brief, parse(backend_raw, "provider backend")))
    if len(found) != 1: raise VerificationError("exact provider dispatch is not unique")
    return found[0]


def extract_manifest(brief: bytes, config: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    basis = parse(brief, "worker brief")
    try: value = parse(basis["work_item"]["canonical_json"].encode(), "work item")
    except (KeyError, AttributeError) as exc: raise VerificationError("worker brief lacks canonical work item") from exc
    for component in config["brief_manifest_pointer"]:
        if isinstance(value, dict) and component in value:
            value = value[component]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", component) and int(component) < len(value):
            value = value[int(component)]
        else:
            raise VerificationError("review manifest pointer missing")
    # Shared review caller convention: acceptance_tests[0] carries this closed
    # canonical manifest string; subsequent acceptance tests specify the bounded
    # independent review and exact result contract. The owner brief digest binds
    # the string bytes. This requires no orientation-packet schema extension.
    if not isinstance(value, str):
        raise VerificationError("review manifest must be a canonical JSON string")
    value = parse(value.encode(), "review manifest")
    manifest = closed(value, MANIFEST_FIELDS, "review manifest")
    if manifest["schema"] != config["brief_contract"]: raise VerificationError("review manifest contract mismatch")
    digest(manifest["binding_id"], "manifest binding")
    binding_raw = decode_artifact(manifest["binding_bytes_base64"], 16 * 1024 * 1024, "binding")
    if validate_binding(binding_raw) != manifest["binding_id"]:
        raise VerificationError("manifest binding bytes do not match binding identity")
    if manifest["author_principal"] != config["author_principal"]: raise VerificationError("author principal mismatch")
    return manifest, binding_raw


def verify_nightshift_snapshot(disposition: dict[str, Any], snapshot: dict[str, Any]) -> None:
    retained = closed(disposition.get("mapper_snapshot"),
        {"representation", "byte_length", "sha256", "encoding", "bytes_hex"}, "Nightshift mapper snapshot")
    raw = canonical(snapshot)
    if (retained["representation"] != "RFC8785_SWITCHYARD_MAPPER_SNAPSHOT"
            or retained["encoding"] != "hex" or type(retained["byte_length"]) is not int
            or retained["byte_length"] != len(raw) or retained["sha256"] != plain_digest(raw)
            or retained["bytes_hex"] != raw.hex()
            or disposition.get("mapper_snapshot_schema") != snapshot["schema"]
            or disposition.get("mapper_snapshot_digest") != snapshot["snapshot_digest"]):
        raise VerificationError("Nightshift mapper snapshot differs from Switchyard custody")


def replayed_worker_output(snapshot: dict[str, Any], maximum: int) -> str | None:
    """Project the runner's final output from already replay-validated frames."""
    binding = snapshot["binding"]
    output, total = None, 0
    for evidence in snapshot["records"]:
        if evidence["raw"] is None:
            continue
        message = parse(bytes.fromhex(evidence["raw"]["bytes_hex"]), "provider frame", canonical_required=False)
        method, params = message.get("method"), message.get("params", {})
        if method not in {"thread/tokenUsage/updated", "item/completed"}:
            continue
        if params.get("threadId") != binding["thread_id"]:
            continue
        if params.get("turnId") != binding["turn_id"]:
            raise VerificationError("provider output turn attribution mismatch")
        if method == "item/completed":
            item = params.get("item", {})
            if item.get("type") == "agentMessage" and isinstance(item.get("text"), str):
                total += len(item["text"].encode())
                if total > maximum:
                    raise VerificationError("provider output exceeds admitted bound")
                output = item["text"]
    return output


def validate_review_result(raw: bytes, binding_id: str, expected_verdict: Any) -> dict[str, Any]:
    """Parse the closed result shape before any custody-store lookup."""
    result = closed(parse(raw, "review result"), RESULT_FIELDS, "review result")
    if result["schema"] != RESULT_SCHEMA or result["binding_id"] != binding_id or result["verdict"] != expected_verdict:
        raise VerificationError("review result binding mismatch")
    if result["verdict"] not in {"accepted", "rejected"} or not isinstance(result["findings"], list) or len(result["findings"]) > 64:
        raise VerificationError("invalid review result")
    for finding in result["findings"]:
        closed(finding, FINDING_FIELDS, "finding"); token(finding["code"], "finding code")
        if not isinstance(finding["summary"], str) or not 1 <= len(finding["summary"].encode()) <= 4096:
            raise VerificationError("invalid finding summary")
    return result


def verify(config: dict[str, Any], config_digest: str, request: dict[str, Any]) -> dict[str, Any]:
    closed(request, {"schema", "requirement", "review", "artifacts"}, "verification request")
    if request["schema"] != REQUEST_SCHEMA: raise VerificationError("request schema mismatch")
    requirement, review, artifacts = request["requirement"], request["review"], request["artifacts"]
    if requirement.get("reviewer_id") != config["reviewer_id"] or requirement.get("route_enrollment_digest") != config_digest:
        raise VerificationError("review route enrollment mismatch")
    if review.get("reviewer_id") != config["reviewer_id"]: raise VerificationError("reviewer mismatch")
    binding_id = digest(review.get("binding_id"), "binding_id"); dispatch_id = digest(review.get("dispatch_id"), "dispatch_id")
    result_raw = decode_artifact(artifacts.get("result_bytes_base64"), config["limits"]["max_result_bytes"], "result")
    custody_raw = decode_artifact(artifacts.get("custody_receipt_bytes_base64"), config["limits"]["max_custody_bytes"], "custody")
    if plain_digest(result_raw) != review.get("result_digest") or plain_digest(custody_raw) != review.get("custody_receipt_digest"):
        raise VerificationError("artifact digest mismatch")
    result = validate_review_result(result_raw, binding_id, review.get("verdict"))
    req, record, brief, backend = switchyard_row(config, dispatch_id)
    manifest, _binding_raw = extract_manifest(brief, config)
    if manifest["binding_id"] != binding_id: raise VerificationError("reviewer did not receive exact binding")
    route = config["route"]
    dispatch = record.get("dispatch_record", {})
    validate_request(req, brief)
    validate_dispatch(dispatch, req, backend)
    if any(backend.get(k) != route[k] for k in ("codex_source_head", "provider", "model")) or backend.get("executable_sha256") != route["app_server_executable_sha256"]:
        raise VerificationError("provider route mismatch")
    if any(dispatch.get(k) != route[k] for k in ("adapter_id", "adapter_version", "adapter_protocol")):
        raise VerificationError("adapter route mismatch")
    snapshot = record.get("provider_admission")
    replayed = replay_snapshot(snapshot, capture_contract=capture_contract_for_request(req))
    if replayed.snapshot() != snapshot:
        raise VerificationError("provider snapshot replay mismatch")
    provider_binding = snapshot.get("binding", {})
    expected_binding = {
        "work_attempt_id": record.get("work_attempt_id"),
        "dispatch_occurrence_id": record.get("dispatch_occurrence_id"),
        "adapter_process_occurrence_id": dispatch.get("adapter_process_occurrence_id"),
        "app_server_session_identity": dispatch.get("app_server_session_identity"),
        "thread_id": record.get("thread_id"), "turn_id": record.get("turn_id"),
        "provider": route["provider"], "model": route["model"],
        "codex_source_head": route["codex_source_head"],
        "app_server_executable_sha256": route["app_server_executable_sha256"],
        "internal_provider_request_retries": 0,
    }
    if any(provider_binding.get(key) != value for key, value in expected_binding.items()):
        raise VerificationError("provider snapshot binding differs from retained dispatch")
    if record.get("state") != "PROVIDER_COMPLETED" or record.get("turn_status") != "completed" or record.get("worker_output") != result_raw.decode():
        raise VerificationError("provider result is not exact completed output")
    if replayed_worker_output(snapshot, req["maximum_output_bytes"]) != result_raw.decode():
        raise VerificationError("review result differs from replayed provider output")
    if snapshot.get("mechanism_state") != "PROVIDER_COMPLETED" or not snapshot.get("acquisition_cut", {}).get("clean"):
        raise VerificationError("provider acquisition is not cleanly complete")
    if record.get("semantic_retry") or record.get("approval_response_sent") or dispatch.get("internal_provider_retry_count") != 0:
        raise VerificationError("provider route used retry or approval response")
    if record.get("thread_id") in config["excluded_thread_ids"]:
        raise VerificationError("review used excluded author thread")
    ended = record.get("ended_at_unix_ms")
    expiry = review.get("expires_at_unix_ms")
    maximum_age = requirement.get("max_age_ms")
    if (not isinstance(ended, int) or not isinstance(expiry, int) or not isinstance(maximum_age, int)
            or review.get("reviewed_at_unix_ms") != ended or not ended < expiry <= ended + maximum_age):
        raise VerificationError("review time is not bound to provider completion")
    events = run_foreman(config)
    opens = [e for e in events if e.get("payload", {}).get("kind") == "provider_dispatch_opened" and e["payload"].get("dispatch", {}).get("dispatch_digest") == dispatch_id]
    dispositions = [e for e in events if e.get("payload", {}).get("kind") == "provider_disposition_recorded" and e["payload"].get("disposition", {}).get("dispatch_digest") == dispatch_id]
    if len(opens) != 1 or len(dispositions) != 1: raise VerificationError("Nightshift custody is not unique")
    opened, disposition = opens[0]["payload"]["dispatch"], dispositions[0]["payload"]["disposition"]
    if opened != dispatch or disposition.get("mechanism_state") != "PROVIDER_COMPLETED" or not disposition.get("acquisition_complete") or disposition.get("will_retry"):
        raise VerificationError("Nightshift disposition does not authenticate completion")
    if opened.get("worker_brief_digest") != req.get("worker_brief_digest") or opened.get("dispatch_occurrence_id") != record.get("dispatch_occurrence_id"):
        raise VerificationError("Nightshift/Switchyard dispatch mismatch")
    if worker_brief_digest(brief) != opened.get("worker_brief_digest"):
        raise VerificationError("retained worker brief digest mismatch")
    verify_nightshift_snapshot(disposition, snapshot)
    custody = {"schema": CUSTODY_SCHEMA, "binding_id": binding_id,
        "dispatch_id": dispatch_id, "dispatch_occurrence_id": record["dispatch_occurrence_id"],
        "nightshift_run_id": config["nightshift_run_id"], "work_attempt_id": record["work_attempt_id"],
        "thread_id": record["thread_id"], "turn_id": record["turn_id"], "reviewer_id": config["reviewer_id"],
        "author_principal": config["author_principal"], "worker_brief_digest": opened["worker_brief_digest"],
        "worker_output_digest": plain_digest(result_raw), "provider_disposition_digest": disposition["disposition_digest"]}
    if canonical(custody) != custody_raw: raise VerificationError("custody projection mismatch")
    return {"schema": RESPONSE_SCHEMA, "accepted": True, "binding_id": binding_id,
        "configuration_digest": config_digest, "evidence_digest": plain_digest(custody_raw)}


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--config", type=Path, required=True); args = parser.parse_args()
    try:
        config, identity = load_config(args.config)
        chunks, total = [], 0
        while True:
            part = os.read(0, min(65536, 16 * 1024 * 1024 + 1 - total))
            if not part: break
            chunks.append(part); total += len(part)
            if total > 16 * 1024 * 1024: break
        raw = b"".join(chunks)
        if len(raw) > 16 * 1024 * 1024: raise VerificationError("request exceeds bound")
        response = verify(config, identity, parse(raw, "request"))
    except Exception as exc:
        raise SystemExit(f"review verification refused: {type(exc).__name__}")
    view = memoryview(canonical(response) + b"\n")
    while view:
        view = view[os.write(1, view):]
