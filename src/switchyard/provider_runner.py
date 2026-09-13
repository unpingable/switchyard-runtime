"""One durable Nightshift V3 dispatch through the existing admission mapper.

This adapter does not schedule, retry, grant effects, or decide worker correctness.
The enrolled Nightshift caller owns complete profile/requirement/dispatch admission.
"""
from __future__ import annotations

import argparse
import calendar
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import sqlite3
import stat
import time
from datetime import datetime, timezone

from jsonschema import Draft202012Validator

from .appserver import (AppServerClient, request_wire, client_request_byte_bound,
    LEGACY_CAPTURE_CONTRACT, BOUNDED_TURN_CAPTURE_CONTRACT, BOUNDED_TURN_ECHO_CAPTURE_CONTRACT,
    MAXIMUM_USER_INPUT_ECHO_BYTES, normalized_bounded_turn_input)
from .nightshift_adapter import (
    AdapterProtocolError, MAXIMUM_BRIEF_BYTES, _canonical, _read_bounded_regular,
    _unique_object, validate_start,
)
from .provider_admission import ProviderAdmissionMapper, replay_snapshot, seal_binding
from . import provider_admission
from .fd_custody import FdCustodyError, HeldSqlite, read_bounded_regular_at

PROTOCOL = "switchyard.codex-app-server/v2"
VERSION = "2.0.0"
V3_DOMAIN = b"nightshift.worker-start-request.digest/v3\0"
DISPATCH_DOMAIN = b"nightshift.provider-dispatch-occurrence.digest/v1\0"
PRELAUNCH_DOMAIN = b"switchyard.provider-prelaunch-closure.digest/v1\0"
PRELAUNCH_SCHEMA = "switchyard.provider-prelaunch-closure/v1"
PROVENANCE_SCHEMA = "switchyard.runtime-source-export/v1"
RUNNER_SOURCE_CLOSURE = (
    "src/switchyard/__init__.py",
    "src/switchyard/appserver.py",
    "src/switchyard/config.py",
    "src/switchyard/fd_custody.py",
    "src/switchyard/nightshift_adapter.py",
    "src/switchyard/provider_admission.py",
    "src/switchyard/provider_runner.py",
    "src/switchyard/_vendor/__init__.py",
    "src/switchyard/_vendor/rfc8785/__init__.py",
    "src/switchyard/_vendor/rfc8785/_impl.py",
    "src/switchyard/schemas/nightshift.provider-dispatch-occurrence.v1.schema.json",
    "src/switchyard/schemas/nightshift.worker-start-request.v3.schema.json",
    "src/switchyard/schemas/switchyard.codex-provider-admission.v1.schema.json",
    "src/switchyard/schemas/switchyard.codex-provider-admission.beta.v1.schema.json",
    "src/switchyard/schemas/switchyard.codex-provider-admission.beta-final.v1.schema.json",
    "src/switchyard/schemas/switchyard.codex-provider-admission.bounded-turn.v1.schema.json",
    "src/switchyard/schemas/switchyard.codex-provider-admission.bounded-turn-echo.v1.schema.json",
)
BOUNDED_BASE_INSTRUCTIONS = (
    "You are a read-only source reviewer. Use only the supplied workspace and return "
    "the requested explanation. Do not initiate effects, network access, or other workers."
)
BOUNDED_DEVELOPER_INSTRUCTIONS = (
    "The worker output is testimony, not factual qualification or authorization. "
    "Report uncertainty and stay within the single bounded source-explanation task."
)


def bounded_turn_start(thread_id: str, backend: dict, brief: bytes) -> dict:
    if not isinstance(thread_id, str) or not 1 <= len(thread_id) <= 512:
        raise AdapterProtocolError("thread identity exceeds retained identity bound")
    prompt = "Perform only the bounded work in this Nightshift worker brief. Do not spawn agents, change provider/model, or perform protected effects. Report evidence and uncertainty; your answer is not qualification.\n" + brief.decode()
    return {"threadId": thread_id, "model": backend["model"], "input": [{"type": "text", "text": prompt}]}


def preflight_request(request: dict, brief: bytes, backend: dict) -> dict:
    """No backend/store use. Reserve the largest supported thread/request IDs."""
    validate_request(request, brief)
    params = bounded_turn_start("\0" * 512, backend, brief)
    wire = request_wire({"id": 9007199254740991, "method": "turn/start", "params": params})
    maximum = client_request_byte_bound("turn/start", capture_contract_for_request(request))
    if len(wire) > maximum:
        raise AdapterProtocolError("worker brief exceeds bounded turn/start wire before backend start")
    if capture_contract_for_request(request) == BOUNDED_TURN_ECHO_CAPTURE_CONTRACT:
        expected_input = normalized_bounded_turn_input(params["input"])
        # Codex97 attaches exact selected text to a lifecycle item. Reserve its
        # largest closed envelope before the backend starts; a raw 256KiB
        # turn/start request that cannot fit its own echo is refused here.
        reserved_id = "\0" * 512
        echo_item = {"type": "userMessage", "id": reserved_id, "clientId": None,
            "content": expected_input}
        for method, timestamp in (("item/started", "startedAtMs"), ("item/completed", "completedAtMs")):
            echo = {"method": method, "params": {"threadId": reserved_id, "turnId": reserved_id,
                "item": echo_item, timestamp: 9_007_199_254_740_991}}
            if len(request_wire(echo)) > MAXIMUM_USER_INPUT_ECHO_BYTES:
                raise AdapterProtocolError("worker brief exceeds bounded user input echo before backend start")
    return {"schema": "switchyard.provider-request-preflight/v1", "request_digest": request["request_digest"],
        "worker_brief_digest": request["worker_brief_digest"], "worker_brief_bytes": len(brief),
        "maximum_reserved_turn_start_wire_bytes": len(wire),
        "maximum_turn_start_wire_bytes": maximum,
        "maximum_output_bytes": request["maximum_output_bytes"], "provider_contact": False}


def capture_contract_for_request(request: dict) -> str:
    """Context from an already validated retained request, never from a snapshot."""
    schemas = Path(__file__).parent / "schemas"
    echo = (schemas / "switchyard.codex-provider-admission.bounded-turn-echo.v1.schema.json").read_bytes()
    bounded = (schemas / "switchyard.codex-provider-admission.bounded-turn.v1.schema.json").read_bytes()
    if request["switchyard_schema_sha256"] == digest(echo):
        return BOUNDED_TURN_ECHO_CAPTURE_CONTRACT
    return BOUNDED_TURN_CAPTURE_CONTRACT if request["switchyard_schema_sha256"] == digest(bounded) else LEGACY_CAPTURE_CONTRACT


def bounded_thread_start(workspace: Path, backend: dict) -> dict:
    """Return the closed thread configuration for the provider qualification."""
    backend_executable = Path(backend["executable"]).resolve(strict=True)
    return {
        "cwd": str(workspace),
        # The qualified App Server reports an empty runtime-root set even when
        # the experimental request field is supplied. Bind the permission
        # profile directly to the one exact workspace path instead.
        "runtimeWorkspaceRoots": [],
        "model": backend["model"],
        "modelProvider": backend["provider"],
        "allowProviderModelFallback": False,
        "approvalPolicy": "untrusted",
        "permissions": "provider-bounded-read",
        "config": {
            "permissions": {
                "provider-bounded-read": {
                    "filesystem": {
                        ":minimal": "read",
                        str(workspace): "read",
                        # Named helper execution needs the exact sealed source
                        # pathname visible; never admit its artifact parent.
                        str(backend_executable): "read",
                    },
                    "network": {"enabled": False},
                }
            },
            "project_doc_max_bytes": 0,
            "include_permissions_instructions": False,
            "include_apps_instructions": False,
            "shell_environment_policy": {
                "inherit": "none",
                "ignore_default_excludes": False,
                "set": {
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                },
            },
            "analytics.enabled": False,
            "check_for_update_on_startup": False,
            "agents.enabled": False,
            "features.multi_agent": False,
            "features.multi_agent_v2": False,
            "features.apps": False,
            "features.enable_mcp_apps": False,
            "features.plugins": False,
            "features.recommended_plugins": False,
            "features.executor_capability_discovery": False,
            "features.skip_host_skill_discovery": True,
            "features.hooks": False,
            "features.standalone_web_search": False,
            "features.web_search_request": False,
            "features.web_search_cached": False,
            "features.view_image": False,
            "features.memory_tool": False,
            "features.external_agent_memory_import": False,
            "features.unbounded_connection_retries": False,
        },
        "baseInstructions": BOUNDED_BASE_INSTRUCTIONS,
        "developerInstructions": BOUNDED_DEVELOPER_INSTRUCTIONS,
        "dynamicTools": [],
        "selectedCapabilityRoots": [],
        "environments": [],
        "ephemeral": True,
    }


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def verify_runner_provenance(path: Path | str, request: dict, *, root_fd: int | None = None) -> None:
    """Check trusted enrolled deployment metadata against the installed runner closure.

    This consistency check does not authenticate a caller or grant dispatch authority.
    Under descriptor-root custody, the provenance record is an existing bounded
    relative file beneath that held root.
    """
    value, _ = (load(Path(path), 1024 * 1024) if root_fd is None
                else load_at(root_fd, str(path), 1024 * 1024))
    expected = {
        "schema", "canonical_source", "canonical_revision", "export_procedure",
        "authored_material_license", "third_party_notices_retained", "files",
    }
    if set(value) != expected or value["schema"] != PROVENANCE_SCHEMA:
        raise AdapterProtocolError("runner source provenance schema differs")
    if value["canonical_source"] != "Switchyard" or value["canonical_revision"] != request["switchyard_owner_head"]:
        raise AdapterProtocolError("runner source provenance revision differs")
    files = value["files"]
    if not isinstance(files, dict):
        raise AdapterProtocolError("runner source provenance files differ")
    package_root = Path(__file__).resolve().parent
    for relative in RUNNER_SOURCE_CLOSURE:
        item = files.get(relative)
        if not isinstance(item, dict) or set(item) != {"canonical_path", "bytes", "sha256"}:
            raise AdapterProtocolError("runner source provenance closure differs")
        if item["canonical_path"] != relative or type(item["bytes"]) is not int or not isinstance(item["sha256"], str):
            raise AdapterProtocolError("runner source provenance entry differs")
        prefix = "src/switchyard/"
        if not relative.startswith(prefix):
            raise AdapterProtocolError("runner source closure is outside the installed package")
        installed_relative = relative.removeprefix(prefix)
        raw = _read_bounded_regular(
            package_root / installed_relative,
            16 * 1024 * 1024,
            "installed runner source",
        )
        if item["bytes"] != len(raw) or item["sha256"] != hashlib.sha256(raw).hexdigest():
            raise AdapterProtocolError("installed runner source differs from provenance")


def load(path: Path, maximum: int = 1024 * 1024) -> tuple[dict, bytes]:
    raw = _read_bounded_regular(path, maximum, "provider input")
    value = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(value, dict):
        raise AdapterProtocolError("provider input must be an object")
    return value, raw


def load_at(root_fd: int, relative: str, maximum: int = 1024 * 1024) -> tuple[dict, bytes]:
    try:
        raw = read_bounded_regular_at(root_fd, relative, maximum, "provider input")
    except (FdCustodyError, OSError) as error:
        raise AdapterProtocolError("fd-relative provider input refused") from error
    value = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(value, dict):
        raise AdapterProtocolError("provider input must be an object")
    return value, raw


def validate_request(request: dict, brief: bytes) -> None:
    schema = json.loads((Path(__file__).parent / "schemas/nightshift.worker-start-request.v3.schema.json").read_text())
    Draft202012Validator(schema).validate(request)
    owner_schema = {
        provider_admission.CODEX_SOURCE_HEAD: "switchyard.codex-provider-admission.v1.schema.json",
        provider_admission.BETA_CODEX_SOURCE_HEAD: "switchyard.codex-provider-admission.beta.v1.schema.json",
        provider_admission.FINAL_CODEX_SOURCE_HEAD: "switchyard.codex-provider-admission.beta-final.v1.schema.json",
    }[request["codex_owner_head"]]
    owner_schemas = [owner_schema]
    if request["codex_owner_head"] == provider_admission.FINAL_CODEX_SOURCE_HEAD:
        owner_schemas.append("switchyard.codex-provider-admission.bounded-turn.v1.schema.json")
        owner_schemas.append("switchyard.codex-provider-admission.bounded-turn-echo.v1.schema.json")
    if request["switchyard_schema_sha256"] not in {
            digest((Path(__file__).parent / "schemas" / name).read_bytes()) for name in owner_schemas}:
        raise AdapterProtocolError("request owner/schema tuple differs")
    basis = {k: v for k, v in request.items() if k != "request_digest"}
    if request["request_digest"] != digest(V3_DOMAIN + _canonical(basis)):
        raise AdapterProtocolError("V3 request digest mismatch")
    predecessor_raw = bytes.fromhex(request["predecessor_bytes_hex"])
    predecessor = json.loads(predecessor_raw, object_pairs_hook=_unique_object)
    if _canonical(predecessor) != predecessor_raw or digest(predecessor_raw) != request["predecessor_sha256"]:
        raise AdapterProtocolError("exact V2 predecessor mismatch")
    validate_start(predecessor, brief, adapter_protocol=PROTOCOL, adapter_version=VERSION)
    for key in predecessor:
        if key not in {"schema", "request_digest"} and request.get(key) != predecessor[key]:
            raise AdapterProtocolError(f"V3 predecessor projection mismatch: {key}")
    if (request["predecessor_request_digest"] != predecessor["request_digest"]
        or request["work_attempt_id"] != request["attempt_id"]
        or request["dispatch_occurrence_id"] == request["work_attempt_id"]
        or request["codex_owner_head"] not in {provider_admission.CODEX_SOURCE_HEAD, provider_admission.BETA_CODEX_SOURCE_HEAD, provider_admission.FINAL_CODEX_SOURCE_HEAD}):
        raise AdapterProtocolError("V3 dispatch/owner identity mismatch")


class ExecutableCaptureError(AdapterProtocolError):
    """The runner observed executable capture fail before claim or backend start."""


def validate_backend_spec(spec: dict, request: dict) -> None:
    fields = {"schema", "executable", "executable_sha256", "executable_shape", "codex_source_head", "codex_home", "provider", "model"}
    if set(spec) != fields or spec["schema"] != "switchyard.provider-backend/v1":
        raise AdapterProtocolError("closed backend configuration mismatch")
    if (spec["codex_source_head"] != provider_admission.FINAL_CODEX_SOURCE_HEAD
        or spec["codex_source_head"] != request["codex_owner_head"]
        or spec["provider"] != request["provider_id"] or spec["model"] != request["model_id"]
        or spec["provider"] != "openai"):
        raise AdapterProtocolError("explicit provider/model/source selection mismatch")


def verify_backend(spec: dict, request: dict) -> tuple[list[str], int]:
    validate_backend_spec(spec, request)
    path = Path(spec["executable"])
    if not path.is_absolute() or not os.access(path, os.X_OK):
        raise AdapterProtocolError("backend executable must be absolute and executable")
    home = Path(spec["codex_home"])
    if not home.is_absolute() or not home.is_dir() or home.resolve() == Path.home() / ".codex":
        raise AdapterProtocolError("an enrolled existing isolated Codex home is required")
    if spec["executable_shape"] == "standalone-app-server":
        command = [str(path), "--listen", "stdio://"]
    elif spec["executable_shape"] == "codex-cli":
        command = [str(path), "app-server", "--listen", "stdio://"]
    else:
        raise AdapterProtocolError("unknown executable shape")
    try:
        captured = capture_verified_executable(path, spec["executable_sha256"])
    except (OSError, AdapterProtocolError) as error:
        raise ExecutableCaptureError("backend executable capture failed before provider claim") from error
    command[0] = f"/proc/self/fd/{captured}"
    return command + ["-c", 'provider_retry_policy="disabled"'], captured


def capture_verified_executable(path: Path, expected_sha256: str) -> int:
    # Hash and execute the same sealed captured ELF; pathname/content changes
    # after capture cannot select a different executable. Dynamic runtime stays
    # within the declared trusted installed-runtime boundary.
    source_fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    captured = None
    try:
        if not stat.S_ISREG(os.fstat(source_fd).st_mode):
            raise AdapterProtocolError("backend executable is not regular")
        captured = os.memfd_create("switchyard-provider", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        hasher = hashlib.sha256(); total = 0; first = True
        while chunk := os.read(source_fd, 1024 * 1024):
            if first and not chunk.startswith(b"\x7fELF"):
                raise AdapterProtocolError("backend executable is not ELF")
            first = False; total += len(chunk)
            if total > 1024 * 1024 * 1024:
                raise AdapterProtocolError("backend executable exceeds bound")
            hasher.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(captured, view):]
        if first or 'sha256:' + hasher.hexdigest() != expected_sha256:
            raise AdapterProtocolError("backend executable identity mismatch")
        fcntl.fcntl(captured, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        return captured
    except BaseException:
        if captured is not None:
            os.close(captured)
        raise
    finally:
        os.close(source_fd)


def validate_dispatch(dispatch: dict, request: dict, backend: dict) -> None:
    schema = json.loads((Path(__file__).parent / "schemas/nightshift.provider-dispatch-occurrence.v1.schema.json").read_text())
    Draft202012Validator(schema).validate(dispatch)
    if dispatch["dispatch_digest"] != digest(DISPATCH_DOMAIN + _canonical({k:v for k,v in dispatch.items() if k != "dispatch_digest"})):
        raise AdapterProtocolError("dispatch digest mismatch")
    for key in ("packet_digest", "run_id", "work_item_id", "work_attempt_id", "dispatch_occurrence_id",
        "selected_model_ordinal", "adapter_id", "adapter_version", "adapter_protocol", "worker_brief_digest",
        "internal_provider_retry_count", "provider_execution_id", "authority_effect"):
        if dispatch[key] != request[key]:
            raise AdapterProtocolError(f"dispatch request mismatch: {key}")
    if (dispatch["worker_start_request_schema"] != request["schema"]
        or dispatch["worker_start_request_digest"] != request["request_digest"]
        or dispatch["selection"] != {key:request[key] for key in ("provider_id", "model_id", "model_class")}
        or dispatch["app_server_session_identity"] != digest(str(Path(backend["codex_home"]).resolve()).encode())):
        raise AdapterProtocolError("dispatch execution identity mismatch")


def prelaunch_binding(request: dict, brief: bytes, backend: dict, dispatch: dict) -> dict:
    """Exact original inputs, including source identities; no provider observations."""
    return {**{key: request[key] for key in (
        "packet_digest", "run_id", "work_item_id", "work_attempt_id", "dispatch_occurrence_id",
        "request_digest", "worker_brief_digest", "switchyard_owner_head", "codex_owner_head")},
        "adapter_process_occurrence_id": dispatch["adapter_process_occurrence_id"],
        "request_sha256": digest(_canonical(request)), "brief_sha256": digest(brief),
        "backend_sha256": digest(_canonical(backend)), "dispatch_digest": dispatch["dispatch_digest"],
        "dispatch_sha256": digest(_canonical(dispatch))}


def _hexadecimal(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def _sha256_identity(value: object) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and _hexadecimal(value[7:], 64)


def _timestamp(value: object) -> int:
    """Native chrono-compatible RFC3339 UTC spelling, compared without truncation."""
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{3}|\d{6}|\d{9}))?Z", value) if isinstance(value, str) else None
    if match is None:
        raise AdapterProtocolError("prelaunch timestamp must be canonical RFC3339 UTC")
    fraction = match[2] or ""
    if fraction and (int(fraction) == 0 or (len(fraction) > 3 and fraction.endswith("000"))):
        raise AdapterProtocolError("prelaunch timestamp precision differs from canonical chrono")
    try:
        parsed = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S")
    except ValueError as error:
        raise AdapterProtocolError("prelaunch timestamp must be canonical RFC3339 UTC") from error
    return calendar.timegm(parsed.timetuple()) * 1_000_000_000 + int(fraction.ljust(9, "0") or "0")


def _utc_now() -> str:
    seconds, nanos = divmod(time.time_ns(), 1_000_000_000)
    basis = datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    fraction = "" if nanos == 0 else (f".{nanos // 1_000_000:03}" if nanos % 1_000_000 == 0
        else f".{nanos // 1_000:06}" if nanos % 1_000 == 0 else f".{nanos:09}")
    return basis + fraction + "Z"


def _bounded_identifier(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value.encode()) <= 256 and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def validate_prelaunch_closure(closure: dict) -> None:
    fields = {"schema", "closure_digest", "binding", "closed_at", "evidence_mode", "failure_code",
        "supervisor_attestation", "observer_source_head", "observer_runner_sha256", "state",
        "provider_claim_absent", "backend_started", "authority_effect"}
    if not isinstance(closure, dict) or set(closure) != fields or len(_canonical(closure)) > 32 * 1024:
        raise AdapterProtocolError("closed prelaunch receipt schema differs")
    binding = closure["binding"]
    ids = {"run_id", "work_item_id", "work_attempt_id", "dispatch_occurrence_id", "adapter_process_occurrence_id"}
    hashes = {"packet_digest", "request_digest", "request_sha256", "worker_brief_digest", "brief_sha256",
        "backend_sha256", "dispatch_digest", "dispatch_sha256"}
    heads = {"switchyard_owner_head", "codex_owner_head"}
    if (not isinstance(binding, dict) or set(binding) != ids | hashes | heads
        or any(not _bounded_identifier(binding[k]) for k in ids)
        or any(not _sha256_identity(binding[k]) for k in hashes)
        or any(not _hexadecimal(binding[k], 40) for k in heads)
        or closure["schema"] != PRELAUNCH_SCHEMA or closure["state"] != "PRELAUNCH_CLOSED"
        or closure["failure_code"] not in {"EXECUTABLE_CAPTURE_FAILED", "REQUEST_PREFLIGHT_FAILED"}
        or closure["provider_claim_absent"] is not True or closure["backend_started"] is not False
        or closure["authority_effect"] != "LOCAL_PRELAUNCH_CLOSURE_ONLY"
        or not _hexadecimal(closure["observer_source_head"], 40)
        or not _sha256_identity(closure["observer_runner_sha256"])):
        raise AdapterProtocolError("prelaunch receipt boundary differs")
    closed_at = _timestamp(closure["closed_at"])
    proof = closure["supervisor_attestation"]
    if (closure["failure_code"] == "EXECUTABLE_CAPTURE_FAILED"
        and closure["evidence_mode"] == "OBSERVED_CAPTURE_FAILURE" and proof is None):
        pass
    elif closure["evidence_mode"] == "SUPERVISOR_ATTESTED_PRECLAIM_FAILURE" and isinstance(proof, dict):
        proof_fields = {"schema", "binding", "supervisor_identity", "host", "unit", "invocation_id",
            "active_state", "result", "exit_code", "observed_at", "original_runner_sha256",
            "unit_evidence_sha256", "failure_evidence_sha256", "boundary", "original_producer_terminated",
            "alternate_writers_excluded", "trust_basis"}
        if (set(proof) != proof_fields or proof["schema"] != "switchyard.prelaunch-supervisor-attestation/v1"
            or proof["binding"] != binding or proof["active_state"] not in {"inactive", "failed"}
            or proof["result"] != "exit-code" or type(proof["exit_code"]) is not int
            or not 0 < proof["exit_code"] <= 2**32 - 1
            or proof["boundary"] != "BEFORE_PROVIDER_CLAIM" or proof["original_producer_terminated"] is not True
            or proof["alternate_writers_excluded"] is not True
            or proof["trust_basis"] != "OWNER_ATTESTATION_NOT_INDEPENDENT_PROCESS_PROOF"
            or not _hexadecimal(proof["invocation_id"], 32)
            or any(not _bounded_identifier(proof[k]) for k in ("supervisor_identity", "host", "unit"))
            or any(not _sha256_identity(proof[k]) for k in ("original_runner_sha256", "unit_evidence_sha256", "failure_evidence_sha256"))
            or _timestamp(proof["observed_at"]) > closed_at):
            raise AdapterProtocolError("terminal supervisor attestation differs from exact preclaim closure")
    else:
        raise AdapterProtocolError("unknown prelaunch evidence mode")
    basis = {k: v for k, v in closure.items() if k != "closure_digest"}
    if closure["closure_digest"] != digest(PRELAUNCH_DOMAIN + _canonical(basis)):
        raise AdapterProtocolError("prelaunch closure digest mismatch")


def _new_prelaunch_closure(request: dict, brief: bytes, backend: dict, dispatch: dict,
                          source_head: str, proof: dict | None, closed_at: str,
                          failure_code: str = "EXECUTABLE_CAPTURE_FAILED") -> dict:
    closure = {"schema": PRELAUNCH_SCHEMA, "binding": prelaunch_binding(request, brief, backend, dispatch),
        "closed_at": closed_at, "evidence_mode": "OBSERVED_CAPTURE_FAILURE" if proof is None else "SUPERVISOR_ATTESTED_PRECLAIM_FAILURE",
        "failure_code": failure_code, "supervisor_attestation": proof,
        "observer_source_head": source_head, "observer_runner_sha256": digest(Path(__file__).read_bytes()),
        "state": "PRELAUNCH_CLOSED", "provider_claim_absent": True, "backend_started": False,
        "authority_effect": "LOCAL_PRELAUNCH_CLOSURE_ONLY"}
    closure["closure_digest"] = digest(PRELAUNCH_DOMAIN + _canonical(closure))
    validate_prelaunch_closure(closure)
    if _timestamp(closed_at) < _timestamp(dispatch["opened_at"]):
        raise AdapterProtocolError("prelaunch closure precedes dispatch")
    return closure


def close_prelaunch(request: dict, brief: bytes, backend: dict, dispatch: dict, store: "RunStore",
                    proof: dict, source_head: str, closed_at: str,
                    failure_code: str = "EXECUTABLE_CAPTURE_FAILED") -> dict:
    """Owner-attested recovery only. Never infer producer death from missing custody."""
    closure = prepare_prelaunch_closure(request, brief, backend, dispatch, proof, source_head, closed_at,
        failure_code)
    return store.close_prelaunch(request, brief, backend, dispatch, closure)


def prepare_prelaunch_closure(request: dict, brief: bytes, backend: dict, dispatch: dict,
                              proof: dict, source_head: str, closed_at: str,
                              failure_code: str = "EXECUTABLE_CAPTURE_FAILED") -> dict:
    """Validate an exact closure before allocating or mutating adapter custody."""
    validate_request(request, brief)
    validate_backend_spec(backend, request)
    validate_dispatch(dispatch, request, backend)
    if not isinstance(proof, dict):
        raise AdapterProtocolError("terminal supervisor attestation required")
    return _new_prelaunch_closure(request, brief, backend, dispatch, source_head, proof, closed_at,
        failure_code)


class PrelaunchStoreExists(AdapterProtocolError):
    """Exclusive prelaunch-store initialization observed an existing pathname."""


class RunStore:
    """Additive adapter custody in the existing Switchyard SQLite state file."""
    def __init__(self, path: Path | None = None, *, root_fd: int | None = None,
                 relative: str | None = None, existing_only: bool = False,
                 exclusive_create: bool = False):
        if existing_only and exclusive_create:
            raise AdapterProtocolError("exclusive provider state creation conflicts with existing-only custody")
        self._held: HeldSqlite | None = None
        if root_fd is None:
            if path is None or relative is not None:
                raise AdapterProtocolError("one pathname or fd-relative state location required")
            if existing_only:
                self.db = sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True)
            elif exclusive_create:
                descriptor = None
                try:
                    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                except FileExistsError as error:
                    raise PrelaunchStoreExists("prelaunch provider state already exists") from error
                try:
                    self.db = sqlite3.connect(path)
                finally:
                    os.close(descriptor)
            else:
                self.db = sqlite3.connect(path)
        else:
            if path is not None or relative is None:
                raise AdapterProtocolError("fd-relative state requires one relative name")
            try:
                self._held = HeldSqlite(root_fd, relative, create=not existing_only,
                    exclusive_create=exclusive_create)
                self.db = self._held.connect()
            except FileExistsError as error:
                raise PrelaunchStoreExists("prelaunch provider state already exists") from error
            except (FdCustodyError, OSError, sqlite3.Error) as error:
                if self._held is not None:
                    self._held.close()
                    self._held = None
                raise AdapterProtocolError("fd-relative provider state refused") from error
        try:
            if existing_only and self.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='provider_runs'").fetchone() is None:
                raise AdapterProtocolError("recovery requires an existing provider custody table")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("CREATE TABLE IF NOT EXISTS provider_runs (dispatch TEXT PRIMARY KEY, request BLOB NOT NULL, brief BLOB NOT NULL, backend BLOB NOT NULL, record BLOB NOT NULL)")
            self.db.commit()
        except BaseException:
            self.close()
            raise

    def claim(self, request: dict, brief: bytes, backend: dict, dispatch: dict) -> tuple[dict, bool]:
        key = request["dispatch_occurrence_id"]
        exact = (_canonical(request), brief, _canonical(backend))
        self.db.execute("BEGIN IMMEDIATE")
        try:
            old = self.db.execute("SELECT request,brief,backend,record FROM provider_runs WHERE dispatch=?", (key,)).fetchone()
            if old:
                if old[:3] != exact:
                    raise AdapterProtocolError("dispatch reuse with different admitted inputs")
                value = json.loads(old[3])
                if value.get("dispatch_record") != dispatch:
                    raise AdapterProtocolError("dispatch custody substitution")
                self.db.commit()
                return value, False
            record = {"schema": "switchyard.provider-run/v1", "dispatch_occurrence_id": key,
                "work_attempt_id": request["work_attempt_id"], "request_digest": request["request_digest"],
                "backend": backend, "state": "OUTCOME_UNKNOWN", "thread_id": None, "turn_id": None,
                "requested_execution": {
                    "provider_id": request["provider_id"], "model_id": request["model_id"],
                    "request_digest": request["request_digest"],
                    "work_attempt_id": request["work_attempt_id"],
                    "dispatch_occurrence_id": request["dispatch_occurrence_id"]},
                "observed_execution": {"state": "NOT_OBSERVABLE", "provider_id": None,
                    "model_id": None, "source": None},
                "provider_admission": None, "turn_status": None, "usage": None,
                "usage_state": "NOT_OBSERVABLE", "usage_scope": "NOT_OBSERVABLE", "usage_turn_id": None,
                "cost": None, "cost_state": "NOT_OBSERVABLE", "cost_scope": "NOT_OBSERVABLE",
                "worker_output": None,
                "acceptance_state": "NOT_EVALUATED_BY_SWITCHYARD",
                "authority_effect": "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY",
                "approval_response_sent": False, "semantic_retry": False,
                "operator_note": "durable claim precedes contact; absent terminal record never redispatches",
                "dispatch_record": dispatch,
                "process_occurrence": dispatch["adapter_process_occurrence_id"],
                "adapter_pid": os.getpid(), "started_at_unix_ms": time.time_ns() // 1_000_000}
            self.db.execute("INSERT INTO provider_runs VALUES (?,?,?,?,?)", (key, *exact, _canonical(record)))
            self.db.commit()
            return record, True
        except BaseException:
            self.db.rollback()
            raise

    def lookup(self, request: dict, brief: bytes, backend: dict, dispatch: dict) -> dict | None:
        row = self.db.execute("SELECT request,brief,backend,record FROM provider_runs WHERE dispatch=?", (request["dispatch_occurrence_id"],)).fetchone()
        if row is None:
            return None
        if row[:3] != (_canonical(request), brief, _canonical(backend)):
            raise AdapterProtocolError("dispatch reuse with different admitted inputs")
        record = json.loads(row[3])
        if record.get("dispatch_record") != dispatch:
            raise AdapterProtocolError("dispatch custody substitution")
        return record

    def close_prelaunch(self, request: dict, brief: bytes, backend: dict, dispatch: dict, closure: dict) -> dict:
        validate_prelaunch_closure(closure)
        if closure["binding"] != prelaunch_binding(request, brief, backend, dispatch):
            raise AdapterProtocolError("prelaunch closure input binding differs")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            prior = self.lookup(request, brief, backend, dispatch)
            if prior is not None:
                if prior.get("state") != "PRELAUNCH_CLOSED" or prior.get("prelaunch_closure") != closure:
                    raise AdapterProtocolError("existing provider claim or conflicting prelaunch closure")
                self.db.commit()
                return closure
            # The existing exact-dispatch slot also fences older runners: their
            # lookup/claim returns a retained record and never starts a backend.
            record = {"schema": "switchyard.provider-run/v1", "state": "PRELAUNCH_CLOSED",
                "dispatch_occurrence_id": request["dispatch_occurrence_id"],
                "work_attempt_id": request["work_attempt_id"], "request_digest": request["request_digest"],
                "dispatch_record": dispatch, "backend": backend, "provider_admission": None,
                "thread_id": None, "turn_id": None, "provider_execution": None,
                "worker_output": None, "usage": None, "cost": None,
                "acceptance_state": "LOCAL_PRELAUNCH_CLOSURE_ONLY", "prelaunch_closure": closure,
                "approval_response_sent": False, "semantic_retry": False,
                "authority_effect": "LOCAL_PRELAUNCH_CLOSURE_ONLY"}
            self.db.execute("INSERT INTO provider_runs VALUES (?,?,?,?,?)", (
                request["dispatch_occurrence_id"], _canonical(request), brief, _canonical(backend), _canonical(record)))
            self.db.commit()
            return closure
        except BaseException:
            self.db.rollback()
            raise

    def update(self, record: dict) -> None:
        self.db.execute("UPDATE provider_runs SET record=? WHERE dispatch=?", (_canonical(record), record["dispatch_occurrence_id"]))
        self.db.commit()

    def close(self) -> None:
        self.db.close()
        if self._held is not None:
            self._held.close()
            self._held = None


def _read_store(path: Path | str, query: str, values: tuple, *, root_fd: int | None = None):
    held = None
    try:
        if root_fd is None:
            db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
        else:
            held = HeldSqlite(root_fd, str(path), create=False)
            db = held.connect(readonly=True)
        try:
            return db.execute(query, values).fetchone()
        finally:
            db.close()
    except (FdCustodyError, OSError, sqlite3.Error) as error:
        raise AdapterProtocolError("fd-relative provider state refused") from error
    finally:
        if held is not None:
            held.close()


def inspect(path: Path | str, dispatch: str, *, root_fd: int | None = None) -> dict:
    # Does not open a backend, initialize a missing store, or mutate existing custody.
    row = _read_store(path, "SELECT record,request,brief,backend FROM provider_runs WHERE dispatch=?", (dispatch,), root_fd=root_fd)
    if row is None:
        raise AdapterProtocolError("unknown dispatch")
    record = json.loads(row[0])
    if record["provider_admission"] is not None:
        request = json.loads(row[1]); backend = json.loads(row[3])
        validate_request(request, row[2])
        validate_dispatch(record["dispatch_record"], request, backend)
        replay_snapshot(record["provider_admission"], capture_contract=capture_contract_for_request(request))
    return record


def inspect_prelaunch(path: Path | str, dispatch: str, *, root_fd: int | None = None) -> dict:
    record = inspect(path, dispatch, root_fd=root_fd)
    if record.get("state") != "PRELAUNCH_CLOSED":
        raise AdapterProtocolError("dispatch is not a retained prelaunch closure")
    closure = record.get("prelaunch_closure")
    validate_prelaunch_closure(closure)
    row = _read_store(path, "SELECT request,brief,backend FROM provider_runs WHERE dispatch=?", (dispatch,), root_fd=root_fd)
    if row is None or closure["binding"] != prelaunch_binding(json.loads(row[0]), row[1], json.loads(row[2]), record["dispatch_record"]):
        raise AdapterProtocolError("retained prelaunch closure input binding differs")
    return closure


def reconcile(path: Path | str, dispatch: str, *, root_fd: int | None = None,
              client_factory=AppServerClient) -> dict:
    """Read the same retained thread/turn through a fresh App Server process.

    This never replaces the original acquisition or emits a new turn. A later
    terminal observation is source testimony, not repaired admission evidence.
    """
    prior = inspect(path, dispatch, root_fd=root_fd)
    if not prior["thread_id"] or not prior["turn_id"]:
        raise AdapterProtocolError("dispatch lacks exact thread/turn for read-only reconciliation")
    request_row = _read_store(path, "SELECT request FROM provider_runs WHERE dispatch=?", (dispatch,), root_fd=root_fd)
    if request_row is None:
        raise AdapterProtocolError("unknown dispatch")
    request = json.loads(request_row[0])
    command, fd = verify_backend(prior["backend"], request)
    client = client_factory(command, request_timeout=30,
        environment={"CODEX_HOME": prior["backend"]["codex_home"]}, pass_fds=(fd,))
    result = {"schema":"switchyard.provider-reconciliation/v1", "dispatch_occurrence_id":dispatch,
        "work_attempt_id":prior["work_attempt_id"], "thread_id":prior["thread_id"], "turn_id":prior["turn_id"],
        "original_state":prior["state"], "observed_turn_status":None, "state":"NOT_OBSERVABLE",
        "new_turn_started":False, "original_evidence_replaced":False}
    try:
        client.start()
        observed = client.request("thread/read", {"threadId":prior["thread_id"],"includeTurns":True})
        raw = _canonical(observed)
        if len(raw) > 16 * 1024 * 1024:
            raise AdapterProtocolError("reconciled thread exceeds bound")
        thread = observed.get("thread", {})
        if thread.get("id") != prior["thread_id"]:
            raise AdapterProtocolError("reconciled thread substitution")
        matching = [turn for turn in thread.get("turns", []) if turn.get("id") == prior["turn_id"]]
        if len(matching) != 1:
            raise AdapterProtocolError("exact prior turn unavailable")
        result.update(state="OBSERVED_SAME_TURN", observed_turn_status=matching[0].get("status"),
            source_sha256=digest(raw), source=observed)
    except Exception as error:
        result["local_error_class"] = type(error).__name__
    finally:
        cut = client.quiesce_acquisition(timeout=5)
        result["process_disposition"] = cut.process_disposition
        if not cut.stream_quiesced or cut.loss_generation:
            result["state"] = "NOT_OBSERVABLE"
        os.close(fd)
    return result


def run(request: dict, brief: bytes, backend: dict, store: RunStore, *, dispatch_record: dict,
        source_provenance: Path | str | None = None, source_provenance_root_fd: int | None = None,
        client_factory=AppServerClient) -> dict:
    validate_request(request, brief)
    if source_provenance is not None:
        verify_runner_provenance(source_provenance, request, root_fd=source_provenance_root_fd)
    validate_dispatch(dispatch_record, request, backend)
    prior = store.lookup(request, brief, backend, dispatch_record)
    if prior is not None:
        return prior
    preflight_request(request, brief, backend)
    workspace = Path(request["workspace_identity"])
    if not workspace.is_absolute() or not workspace.is_dir():
        raise AdapterProtocolError("enrolled workspace is not an existing absolute directory")
    try:
        command, executable_fd = verify_backend(backend, request)
    except ExecutableCaptureError:
        closed_at = _utc_now()
        closure = _new_prelaunch_closure(request, brief, backend, dispatch_record,
            request["switchyard_owner_head"], None, closed_at)
        store.close_prelaunch(request, brief, backend, dispatch_record, closure)
        return store.lookup(request, brief, backend, dispatch_record)
    try:
        record, fresh = store.claim(request, brief, backend, dispatch_record)
    except BaseException:
        os.close(executable_fd)
        raise
    if not fresh:
        os.close(executable_fd)
        return record
    estate = dispatch_record["app_server_session_identity"]
    client = client_factory(command, request_timeout=min(30, request["timeout_seconds"]),
        environment={"CODEX_HOME": backend["codex_home"]}, enable_ordered_acquisition=True,
        capture_contract=capture_contract_for_request(request),
        adapter_process_occurrence_id=record["process_occurrence"], app_server_session_identity=estate,
        pass_fds=(executable_fd,))
    mapper = None
    pending = []
    deadline = time.monotonic() + request["timeout_seconds"]
    output_bytes = 0
    attribution_failed = False

    def drain() -> None:
        nonlocal output_bytes, attribution_failed
        events = client.drain_ordered_acquisition()
        if mapper is None:
            pending.extend(events)
            return
        events = pending[:] + events
        pending.clear()
        for envelope in events:
            mapper.consume_envelope(envelope)
            message = envelope.message
            if message is None:
                continue
            params = message.params
            if (message.method in {"thread/tokenUsage/updated", "item/completed"}
                and params.get("threadId") == record["thread_id"]
                and params.get("turnId") != record["turn_id"]):
                attribution_failed = True
                record.update(usage=None, usage_state="NOT_OBSERVABLE", usage_scope="NOT_OBSERVABLE",
                    usage_turn_id=None, worker_output=None)
                mapper.mark_acquisition_loss("output/usage turn attribution mismatch")
                continue
            if message.method == "thread/tokenUsage/updated" and params.get("threadId") == record["thread_id"]:
                if not attribution_failed:
                    record["usage"] = params.get("tokenUsage")
                    record["usage_state"] = "OBSERVED" if record["usage"] is not None else "NOT_OBSERVABLE"
                    record["usage_scope"] = "THREAD_CUMULATIVE_AND_LAST_PROVIDER_USAGE" if record["usage"] is not None else "NOT_OBSERVABLE"
                    record["usage_turn_id"] = params["turnId"] if record["usage"] is not None else None
            if message.method == "turn/completed" and params.get("threadId") == record["thread_id"]:
                turn = params.get("turn", {})
                if turn.get("id") == record["turn_id"]:
                    record["turn_status"] = turn.get("status")
            if message.method == "item/completed" and params.get("threadId") == record["thread_id"] and not attribution_failed:
                item = params.get("item", {})
                if item.get("type") == "agentMessage" and isinstance(item.get("text"), str):
                    output_bytes += len(item["text"].encode())
                    if output_bytes > request["maximum_output_bytes"]:
                        mapper.mark_acquisition_loss("worker output exceeds admitted bound")
                    else:
                        record["worker_output"] = item["text"]
        record["provider_admission"] = mapper.snapshot()
        store.update(record)

    try:
        client.start()
        thread = client.request("thread/start", bounded_thread_start(workspace, backend))
        if (thread.get("model") != backend["model"]
            or thread.get("modelProvider") != backend["provider"]
            or thread.get("cwd") != str(workspace)
            or thread.get("runtimeWorkspaceRoots") != []
            or thread.get("instructionSources") != []
            or thread.get("activePermissionProfile") != {"id": "provider-bounded-read", "extends": None}):
            raise AdapterProtocolError("effective provider thread context differs from bounded request")
        record["observed_execution"] = {"state": "OBSERVED_THREAD_CONTEXT",
            "provider_id": thread["modelProvider"], "model_id": thread["model"],
            "source": "CODEX_APP_SERVER_THREAD_START"}
        record["thread_id"] = thread["thread"]["id"]
        store.update(record)
        turn = client.request("turn/start", bounded_turn_start(record["thread_id"], backend, brief))
        record["turn_id"] = turn["turn"]["id"]
        store.update(record)
        mapper = ProviderAdmissionMapper(seal_binding({
            "work_attempt_id": request["work_attempt_id"], "dispatch_occurrence_id": request["dispatch_occurrence_id"],
            "adapter_process_occurrence_id": record["process_occurrence"], "app_server_session_identity": estate,
            "thread_id": record["thread_id"], "turn_id": record["turn_id"], "provider": backend["provider"],
            "model": backend["model"], "codex_source_head": backend["codex_source_head"],
            "executable_kind": "CAMPAIGN_CODEX_BUILD", "app_server_executable_identity": backend["executable"],
            "app_server_executable_sha256": backend["executable_sha256"], "internal_provider_request_retries": 0}),
            capture_contract=capture_contract_for_request(request))
        while time.monotonic() < deadline:
            drain()
            if mapper.mechanism_state in {"PROVIDER_COMPLETED", "PARKED_NOT_ADMITTED", "WAITING_APPROVAL", "ADMISSION_INDETERMINATE", "POST_ADMISSION_INTERRUPTED"}:
                break
            time.sleep(0.02)
        else:
            mapper.mark_acquisition_loss("admitted execution deadline elapsed")
    except Exception as error:
        # Exception type only: provider diagnostics and local config can contain secrets.
        record["local_error_class"] = type(error).__name__
        if mapper is not None:
            mapper.mark_acquisition_loss("adapter operation failed")
    finally:
        record["pre_cleanup_mechanism_state"] = mapper.mechanism_state if mapper else "NOT_OBSERVABLE"
        cut = client.quiesce_acquisition(timeout=5)
        if mapper is not None:
            drain()
            mapper.consume_cut(cut)
            record["provider_admission"] = mapper.snapshot()
            clean = bool(mapper.acquisition_cut and mapper.acquisition_cut["clean"])
            if mapper.mechanism_state in {"PROVIDER_COMPLETED", "POST_ADMISSION_INTERRUPTED"}:
                record["observed_execution"] = {"state": "OBSERVED_PROVIDER_BOUNDARY",
                    "provider_id": backend["provider"], "model_id": backend["model"],
                    "source": "ORDERED_PROVIDER_ADMISSION_EVIDENCE"}
            if clean and mapper.mechanism_state == "PROVIDER_COMPLETED":
                record["state"] = {"completed": "PROVIDER_COMPLETED", "failed": "PROVIDER_FAILED", "interrupted": "PROVIDER_INTERRUPTED"}.get(record["turn_status"], "OUTCOME_UNKNOWN")
            elif clean and mapper.mechanism_state == "PARKED_NOT_ADMITTED":
                record["state"] = "NOT_ADMITTED_MODEL_AT_CAPACITY"
            else:
                record["state"] = "OUTCOME_UNKNOWN"
        record["ended_at_unix_ms"] = time.time_ns() // 1_000_000
        store.update(record)
        os.close(executable_fd)
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state")
    parser.add_argument("--root-fd", type=int,
        help="inherited directory descriptor; state and run inputs become strict relative names")
    sub = parser.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("preflight-request")
    for name in ("request", "brief", "backend"):
        preflight.add_argument("--" + name, type=Path, required=True)
    start = sub.add_parser("run")
    start.add_argument("--source-provenance", type=Path, required=True)
    for name in ("request", "brief", "backend", "dispatch-record"):
        start.add_argument("--" + name, type=Path, required=True)
    close = sub.add_parser("close-prelaunch", help="retain exact preclaim closure from trusted supervisor testimony; never launches")
    close.add_argument("--source-provenance", type=Path, required=True)
    close.add_argument("--source-head", required=True, help="explicitly enrolled recovery source revision, independent of the original request")
    close.add_argument("--supervisor-attestation", type=Path, required=True)
    close.add_argument("--closed-at", required=True)
    close.add_argument("--failure-code", choices=("EXECUTABLE_CAPTURE_FAILED", "REQUEST_PREFLIGHT_FAILED"),
        default="EXECUTABLE_CAPTURE_FAILED")
    for name in ("request", "brief", "backend", "dispatch-record"):
        close.add_argument("--" + name, type=Path, required=True)
    for name in ("inspect", "inspect-prelaunch", "reconcile"):
        read = sub.add_parser(name)
        read.add_argument("--dispatch", required=True)
    args = parser.parse_args()
    if args.command == "preflight-request":
        if args.root_fd is not None or args.state is not None:
            parser.error("preflight-request has no store or root-fd surface")
        request, _ = load(args.request); backend, _ = load(args.backend)
        brief = _read_bounded_regular(args.brief, MAXIMUM_BRIEF_BYTES, "worker brief")
        print(_canonical(preflight_request(request, brief, backend)).decode())
        return
    if args.state is None:
        parser.error("--state is required for durable operations")
    state: Path | str = args.state if args.root_fd is not None else Path(args.state)
    if args.command == "inspect":
        result = inspect(state, args.dispatch, root_fd=args.root_fd)
    elif args.command == "inspect-prelaunch":
        result = inspect_prelaunch(state, args.dispatch, root_fd=args.root_fd)
    elif args.command == "reconcile":
        result = reconcile(state, args.dispatch, root_fd=args.root_fd)
    else:
        if args.root_fd is None:
            request, _ = load(args.request); backend, _ = load(args.backend)
            dispatch, dispatch_raw = load(args.dispatch_record)
            brief = _read_bounded_regular(args.brief, MAXIMUM_BRIEF_BYTES, "worker brief")
        else:
            request, _ = load_at(args.root_fd, str(args.request)); backend, _ = load_at(args.root_fd, str(args.backend))
            dispatch, dispatch_raw = load_at(args.root_fd, str(args.dispatch_record))
            try:
                brief = read_bounded_regular_at(args.root_fd, str(args.brief), MAXIMUM_BRIEF_BYTES, "worker brief")
            except (FdCustodyError, OSError) as error:
                raise AdapterProtocolError("fd-relative worker brief refused") from error
        if _canonical(dispatch) != dispatch_raw:
            raise AdapterProtocolError("dispatch record must be exact canonical owner output")
        closure = None
        if args.command == "close-prelaunch":
            # Recovery is enrolled separately; do not rewrite the original
            # request's source pin or require a fabricated provider snapshot.
            # All exact records validate before an absent closure store exists.
            verify_runner_provenance(args.source_provenance,
                {"switchyard_owner_head": args.source_head}, root_fd=args.root_fd)
            proof, proof_raw = (load(args.supervisor_attestation, 32 * 1024) if args.root_fd is None
                else load_at(args.root_fd, str(args.supervisor_attestation), 32 * 1024))
            if _canonical(proof) != proof_raw.removesuffix(b"\n"):
                raise AdapterProtocolError("supervisor attestation must be canonical")
            closure = prepare_prelaunch_closure(request, brief, backend, dispatch, proof,
                args.source_head, args.closed_at, args.failure_code)
        if args.root_fd is None:
            if args.command == "close-prelaunch" and args.failure_code == "REQUEST_PREFLIGHT_FAILED":
                try:
                    store = RunStore(Path(args.state), exclusive_create=True)
                except PrelaunchStoreExists:
                    store = RunStore(Path(args.state), existing_only=True)
            else:
                store = RunStore(Path(args.state), existing_only=args.command == "close-prelaunch")
        else:
            if args.command == "close-prelaunch" and args.failure_code == "REQUEST_PREFLIGHT_FAILED":
                try:
                    store = RunStore(root_fd=args.root_fd, relative=args.state, exclusive_create=True)
                except PrelaunchStoreExists:
                    store = RunStore(root_fd=args.root_fd, relative=args.state, existing_only=True)
            else:
                store = RunStore(root_fd=args.root_fd, relative=args.state,
                    existing_only=args.command == "close-prelaunch")
        try:
            if args.command == "close-prelaunch":
                result = store.close_prelaunch(request, brief, backend, dispatch, closure)
            else:
                result = run(request, brief, backend, store, dispatch_record=dispatch,
                             source_provenance=args.source_provenance,
                             source_provenance_root_fd=args.root_fd)
        finally:
            store.close()
    print(_canonical(result).decode())


if __name__ == "__main__":
    main()
