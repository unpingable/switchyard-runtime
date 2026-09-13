from __future__ import annotations

import copy
import itertools
import json
import logging
import os
import queue
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

LOG = logging.getLogger(__name__)
MAXIMUM_APP_SERVER_LINE_BYTES = 32 * 1024 * 1024
MAXIMUM_RETAINED_ADAPTER_EVENT_BYTES = 16 * 1024
MAXIMUM_TURN_START_REQUEST_BYTES = 256 * 1024
LEGACY_CAPTURE_CONTRACT = "LEGACY_V1"
BOUNDED_TURN_CAPTURE_CONTRACT = "BOUNDED_TURN_V1"
MAXIMUM_APP_SERVER_MESSAGE_QUEUE_ITEMS = 256
MAXIMUM_APP_SERVER_MESSAGE_QUEUE_BYTES = 16 * 1024 * 1024
MAXIMUM_APP_SERVER_STDERR_LINE_BYTES = 16 * 1024
MAXIMUM_APP_SERVER_STDERR_QUEUE_ITEMS = 256
MAXIMUM_APP_SERVER_STDERR_QUEUE_BYTES = 1024 * 1024
MAXIMUM_APP_SERVER_DIAGNOSTIC_ITEMS = 64


class AppServerError(RuntimeError):
    pass


def request_wire(message: dict[str, Any]) -> bytes:
    """The single serialization used for both pre-send checking and transmission."""
    return json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def client_request_byte_bound(method: str | None, capture_contract: str = LEGACY_CAPTURE_CONTRACT) -> int:
    if capture_contract not in {LEGACY_CAPTURE_CONTRACT, BOUNDED_TURN_CAPTURE_CONTRACT}:
        raise ValueError("unknown provider capture contract")
    return (MAXIMUM_TURN_START_REQUEST_BYTES
            if method == "turn/start" and capture_contract == BOUNDED_TURN_CAPTURE_CONTRACT
            else MAXIMUM_RETAINED_ADAPTER_EVENT_BYTES)


@dataclass(frozen=True)
class AcquisitionCut:
    stream_quiesced: bool
    loss_generation: int
    process_disposition: str = "UNKNOWN"
    ordered_high_water: int = 0
    adapter_process_occurrence_id: str | None = None
    app_server_session_identity: str | None = None


@dataclass(frozen=True)
class ServerMessage:
    raw: dict[str, Any]
    raw_bytes: bytes | None = None

    @property
    def method(self) -> str | None:
        value = self.raw.get("method")
        return value if isinstance(value, str) else None

    @property
    def params(self) -> dict[str, Any]:
        value = self.raw.get("params")
        return value if isinstance(value, dict) else {}


@dataclass(frozen=True)
class AcquisitionEnvelope:
    ordinal: int
    kind: str
    message: ServerMessage | None = None
    diagnostic: str | None = None
    raw_bytes: bytes | None = None
    request_method: str | None = None


QueueValue = TypeVar("QueueValue")


class ByteBoundedQueue(queue.Queue[QueueValue], Generic[QueueValue]):
    def __init__(
        self,
        max_items: int,
        max_bytes: int,
        size: Callable[[QueueValue], int],
    ) -> None:
        super().__init__(maxsize=max_items)
        self.max_bytes = max_bytes
        self._size = size
        self._queued_bytes = 0

    def _put(self, item: QueueValue) -> None:
        item_bytes = self._size(item)
        if item_bytes < 0 or item_bytes > self.max_bytes - self._queued_bytes:
            raise queue.Full
        self.queue.append((item_bytes, item))
        self._queued_bytes += item_bytes

    def _get(self) -> QueueValue:
        item_bytes, item = self.queue.popleft()
        self._queued_bytes -= item_bytes
        return item

    @property
    def queued_bytes(self) -> int:
        with self.mutex:
            return self._queued_bytes


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate App Server JSON key: {key}")
        value[key] = item
    return value


def _message_bytes(message: ServerMessage) -> int:
    if message.raw_bytes is not None:
        return len(message.raw_bytes)
    canonical = json.dumps(message.raw, separators=(",", ":"), ensure_ascii=False)
    return len(canonical.encode("utf-8"))


def _envelope_bytes(envelope: AcquisitionEnvelope) -> int:
    total = 64
    if envelope.message is not None:
        total += _message_bytes(envelope.message)
    if envelope.diagnostic is not None:
        total += len(envelope.diagnostic.encode("utf-8"))
    if envelope.raw_bytes is not None:
        total += len(envelope.raw_bytes)
    if envelope.request_method is not None:
        total += len(envelope.request_method.encode("utf-8"))
    return total


class AppServerClient:
    """Small, dependency-free client for `codex app-server --listen stdio://`.

    The reader thread is the sole consumer of stdout. Client responses are routed
    to per-request queues; notifications and server-initiated requests are
    exposed on separate queues for the foreman event pump.
    """

    def __init__(
        self,
        command: list[str],
        request_timeout: float = 30.0,
        environment: dict[str, str] | None = None,
        maximum_line_bytes: int = MAXIMUM_APP_SERVER_LINE_BYTES,
        maximum_message_queue_items: int = MAXIMUM_APP_SERVER_MESSAGE_QUEUE_ITEMS,
        maximum_message_queue_bytes: int = MAXIMUM_APP_SERVER_MESSAGE_QUEUE_BYTES,
        maximum_stderr_line_bytes: int = MAXIMUM_APP_SERVER_STDERR_LINE_BYTES,
        maximum_stderr_queue_items: int = MAXIMUM_APP_SERVER_STDERR_QUEUE_ITEMS,
        maximum_stderr_queue_bytes: int = MAXIMUM_APP_SERVER_STDERR_QUEUE_BYTES,
        enable_ordered_acquisition: bool = False,
        capture_contract: str = LEGACY_CAPTURE_CONTRACT,
        maximum_ordered_queue_items: int = MAXIMUM_APP_SERVER_MESSAGE_QUEUE_ITEMS,
        maximum_ordered_queue_bytes: int = MAXIMUM_APP_SERVER_MESSAGE_QUEUE_BYTES,
        adapter_process_occurrence_id: str | None = None,
        app_server_session_identity: str | None = None,
        pass_fds: tuple[int, ...] = (),
    ):
        if not command:
            raise ValueError("an explicit qualified App Server command is required")
        self.command = list(command)
        self.pass_fds = pass_fds
        self.environment = dict(environment or {})
        self.request_timeout = request_timeout
        if not 1 <= maximum_line_bytes <= MAXIMUM_APP_SERVER_LINE_BYTES:
            raise ValueError("maximum_line_bytes is outside the App Server frame boundary")
        self.maximum_line_bytes = maximum_line_bytes
        if not 1 <= maximum_message_queue_items <= MAXIMUM_APP_SERVER_MESSAGE_QUEUE_ITEMS:
            raise ValueError("maximum_message_queue_items is outside the queue boundary")
        if not 1 <= maximum_message_queue_bytes <= MAXIMUM_APP_SERVER_MESSAGE_QUEUE_BYTES:
            raise ValueError("maximum_message_queue_bytes is outside the queue boundary")
        if not 1 <= maximum_stderr_line_bytes <= MAXIMUM_APP_SERVER_STDERR_LINE_BYTES:
            raise ValueError("maximum_stderr_line_bytes is outside the stderr frame boundary")
        if not 1 <= maximum_stderr_queue_items <= MAXIMUM_APP_SERVER_STDERR_QUEUE_ITEMS:
            raise ValueError("maximum_stderr_queue_items is outside the stderr queue boundary")
        if not 1 <= maximum_stderr_queue_bytes <= MAXIMUM_APP_SERVER_STDERR_QUEUE_BYTES:
            raise ValueError("maximum_stderr_queue_bytes is outside the stderr queue boundary")
        self.maximum_stderr_line_bytes = maximum_stderr_line_bytes
        if not 1 <= maximum_ordered_queue_items <= MAXIMUM_APP_SERVER_MESSAGE_QUEUE_ITEMS:
            raise ValueError("maximum_ordered_queue_items is outside the queue boundary")
        if not 1 <= maximum_ordered_queue_bytes <= MAXIMUM_APP_SERVER_MESSAGE_QUEUE_BYTES:
            raise ValueError("maximum_ordered_queue_bytes is outside the queue boundary")
        self.enable_ordered_acquisition = enable_ordered_acquisition
        client_request_byte_bound(None, capture_contract)
        self.capture_contract = capture_contract
        if (adapter_process_occurrence_id is None) != (app_server_session_identity is None):
            raise ValueError("cut identities must be supplied together")
        if enable_ordered_acquisition and adapter_process_occurrence_id is None:
            raise ValueError("ordered acquisition requires exact cut identities")
        for field, value in (
            ("adapter_process_occurrence_id", adapter_process_occurrence_id),
            ("app_server_session_identity", app_server_session_identity),
        ):
            if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 512):
                raise ValueError(f"{field} is outside the identity boundary")
        self.adapter_process_occurrence_id = adapter_process_occurrence_id
        self.app_server_session_identity = app_server_session_identity
        self._proc: subprocess.Popen[bytes] | None = None
        self._ids = itertools.count(1)
        self._pending: dict[int, queue.Queue[dict[str, Any]]] = {}
        self._pending_methods: dict[int, str] = {}
        self._pending_lock = threading.Lock()
        self.notifications: ByteBoundedQueue[ServerMessage] = ByteBoundedQueue(
            maximum_message_queue_items, maximum_message_queue_bytes, _message_bytes
        )
        self.server_requests: ByteBoundedQueue[ServerMessage] = ByteBoundedQueue(
            maximum_message_queue_items, maximum_message_queue_bytes, _message_bytes
        )
        self.stderr_lines: ByteBoundedQueue[str] = ByteBoundedQueue(
            maximum_stderr_queue_items,
            maximum_stderr_queue_bytes,
            lambda value: len(value.encode("utf-8")),
        )
        self.acquisition_diagnostics: ByteBoundedQueue[str] = ByteBoundedQueue(
            MAXIMUM_APP_SERVER_DIAGNOSTIC_ITEMS,
            65536,
            lambda value: len(value.encode("utf-8")),
        )
        self.ordered_acquisition: ByteBoundedQueue[AcquisitionEnvelope] | None = (
            ByteBoundedQueue(
                maximum_ordered_queue_items, maximum_ordered_queue_bytes, _envelope_bytes
            )
            if enable_ordered_acquisition
            else None
        )
        self._acquisition_ordinal = 0
        self.stdout_refused_frames = 0
        self.notification_overflows = 0
        self.server_request_overflows = 0
        self.stderr_refused_frames = 0
        self.stderr_queue_overflows = 0
        self._reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None
        self._write_lock = threading.Lock()
        self._acquisition_lock = threading.Lock()
        self._loss_generation = 0
        self._acquisition_quiesced = False
        self._stdout_reader_disposition = "NOT_STARTED"
        self._stderr_reader_disposition = "NOT_STARTED"

    def start(self) -> None:
        if self._proc is not None:
            return
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            env={**os.environ, **self.environment},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0,
            pass_fds=self.pass_fds,
        )
        if not self._proc.stdin or not self._proc.stdout or not self._proc.stderr:
            raise AppServerError("failed to open app-server pipes")
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._stdout_reader_disposition = "RUNNING"
        self._stderr_reader_disposition = "RUNNING"
        self._reader.start()
        self._stderr_reader.start()

        try:
            self.request(
                "initialize",
                {
                    "clientInfo": {
                        "name": "switchyard_foreman",
                        "title": "Switchyard Codex Foreman",
                        "version": "0.1.0",
                    },
                    "capabilities": {"experimentalApi": True},
                },
            )
            self.notify("initialized", {})
        except Exception:
            self.quiesce_acquisition(timeout=self.request_timeout)
            raise

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _write(
        self,
        message: dict[str, Any],
        *,
        acquisition_kind: str | None = None,
        request_method: str | None = None,
    ) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise AppServerError("app-server is not running")
        wire = request_wire(message)
        if (self.enable_ordered_acquisition and acquisition_kind == "CLIENT_REQUEST"
                and (message.get("method") != request_method
                     or len(wire) > client_request_byte_bound(request_method, self.capture_contract))):
            raise AppServerError("client request exceeds exact pre-send custody bound")
        with self._write_lock:
            if acquisition_kind is not None:
                with self._acquisition_lock:
                    if not self._next_ordered_locked(
                        acquisition_kind,
                        message=ServerMessage(copy.deepcopy(message), raw_bytes=wire),
                        request_method=request_method,
                    ):
                        self._record_loss_locked(
                            "App Server ordered client request refused by bounded queue"
                        )
                        raise AppServerError("client request custody queue refused before send")
            view = memoryview(wire)
            while view:
                written = self._proc.stdin.write(view)
                if written is None or written <= 0:
                    raise AppServerError("App Server request write made no progress")
                view = view[written:]
            self._proc.stdin.flush()

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = next(self._ids)
        response_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
        with self._pending_lock:
            self._pending[request_id] = response_queue
            self._pending_methods[request_id] = method
        message: dict[str, Any] = {"id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        try:
            self._write(
                message, acquisition_kind="CLIENT_REQUEST", request_method=method
            )
            try:
                response = response_queue.get(timeout=self.request_timeout)
            except queue.Empty as exc:
                raise AppServerError(f"timeout waiting for {method}") from exc
        finally:
            with self._pending_lock:
                self._pending.pop(request_id, None)
                self._pending_methods.pop(request_id, None)

        if "error" in response:
            raise AppServerError(f"{method} failed: {response['error']}")
        result = response.get("result")
        return result if isinstance(result, dict) else {}

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"method": method}
        if params:
            message["params"] = params
        self._write(message)

    def respond(self, request_id: Any, result: dict[str, Any]) -> None:
        self._write({"id": request_id, "result": result})

    def _next_ordered_locked(
        self, kind: str, *, message: ServerMessage | None = None,
        diagnostic: str | None = None, raw_bytes: bytes | None = None,
        request_method: str | None = None,
    ) -> bool:
        target = self.ordered_acquisition
        if target is None:
            return True
        ordinal = self._acquisition_ordinal
        self._acquisition_ordinal += 1
        retained_raw = (
            raw_bytes
            if raw_bytes is not None and len(raw_bytes) <= MAXIMUM_RETAINED_ADAPTER_EVENT_BYTES
            else None
        )
        retained_message = (
            ServerMessage(copy.deepcopy(message.raw), message.raw_bytes)
            if message is not None
            else None
        )
        try:
            target.put_nowait(
                AcquisitionEnvelope(
                    ordinal, kind, retained_message, diagnostic, retained_raw, request_method
                )
            )
            return True
        except queue.Full:
            return False

    def _record_loss_locked(self, message: str, raw_bytes: bytes | None = None) -> None:
        self._loss_generation += 1
        try:
            self.acquisition_diagnostics.put_nowait(message)
        except queue.Full:
            pass
        self._next_ordered_locked(
            "LOSS", diagnostic=message[:4096], raw_bytes=raw_bytes
        )

    def _record_acquisition_loss(
        self, message: str, raw_bytes: bytes | None = None
    ) -> None:
        with self._acquisition_lock:
            self._record_loss_locked(message, raw_bytes)

    def quiesce_acquisition(self, timeout: float = 5.0) -> AcquisitionCut:
        """Create a bounded stream-defined cut; every cleanup failure becomes loss."""
        proc = self._proc
        if proc is None:
            self._record_acquisition_loss("App Server absent at terminal evidence boundary")
            return AcquisitionCut(
                False, self._loss_generation, "ABSENT", self._acquisition_ordinal,
                self.adapter_process_occurrence_id, self.app_server_session_identity,
            )
        stream_quiesced = True
        process_disposition = "RUNNING"
        writer_lock_acquired = False
        try:
            writer_lock_acquired = self._write_lock.acquire(timeout=max(0.0, timeout))
            if not writer_lock_acquired:
                stream_quiesced = False
                self._record_acquisition_loss(
                    "App Server writer lock did not quiesce at terminal evidence boundary"
                )
            elif proc.stdin is not None and not proc.stdin.closed:
                proc.stdin.close()
        except Exception as exc:
            stream_quiesced = False
            self._record_acquisition_loss(
                f"App Server input close failed at terminal evidence boundary: {exc}"
            )
        finally:
            if writer_lock_acquired:
                self._write_lock.release()

        process_exited = False
        try:
            proc.wait(timeout=timeout)
            process_exited = True
            process_disposition = "EXITED"
        except subprocess.TimeoutExpired:
            stream_quiesced = False
            self._record_acquisition_loss(
                "App Server did not quiesce at terminal evidence boundary"
            )
        except Exception as exc:
            stream_quiesced = False
            self._record_acquisition_loss(
                f"App Server wait failed at terminal evidence boundary: {exc}"
            )

        if not process_exited:
            try:
                proc.terminate()
            except Exception as exc:
                stream_quiesced = False
                self._record_acquisition_loss(
                    f"App Server terminate failed at terminal evidence boundary: {exc}"
                )
            try:
                proc.wait(timeout=min(timeout, 3.0))
                process_exited = True
                process_disposition = "EXITED_AFTER_TERMINATE"
            except subprocess.TimeoutExpired:
                stream_quiesced = False
                self._record_acquisition_loss(
                    "App Server did not exit after terminate at terminal evidence boundary"
                )
            except Exception as exc:
                stream_quiesced = False
                self._record_acquisition_loss(
                    f"App Server terminate wait failed at terminal evidence boundary: {exc}"
                )

        if not process_exited:
            try:
                proc.kill()
            except Exception as exc:
                stream_quiesced = False
                self._record_acquisition_loss(
                    f"App Server kill failed at terminal evidence boundary: {exc}"
                )
            try:
                proc.wait(timeout=min(timeout, 3.0))
                process_exited = True
                process_disposition = "EXITED_AFTER_KILL"
            except Exception as exc:
                stream_quiesced = False
                process_disposition = "EXIT_UNCONFIRMED"
                self._record_acquisition_loss(
                    f"App Server final wait failed at terminal evidence boundary: {exc}"
                )
        if not process_exited:
            stream_quiesced = False
            process_disposition = "EXIT_UNCONFIRMED"

        for reader, disposition_field in (
            (self._reader, "_stdout_reader_disposition"),
            (self._stderr_reader, "_stderr_reader_disposition"),
        ):
            if reader is None:
                stream_quiesced = False
                self._record_acquisition_loss(
                    "App Server reader absent at terminal evidence boundary"
                )
                continue
            try:
                reader.join(timeout=timeout)
                if reader.is_alive():
                    stream_quiesced = False
                    self._record_acquisition_loss(
                        "App Server reader did not reach EOF at terminal evidence boundary"
                    )
                    continue
            except Exception as exc:
                stream_quiesced = False
                self._record_acquisition_loss(
                    f"App Server reader join failed at terminal evidence boundary: {exc}"
                )
                continue
            with self._acquisition_lock:
                disposition = getattr(self, disposition_field)
            if disposition != "CLEAN_EOF":
                stream_quiesced = False
                self._record_acquisition_loss(
                    f"App Server reader ended without clean EOF: {disposition}"
                )
        with self._acquisition_lock:
            self._acquisition_quiesced = stream_quiesced
            return AcquisitionCut(
                stream_quiesced, self._loss_generation, process_disposition,
                self._acquisition_ordinal,
                self.adapter_process_occurrence_id,
                self.app_server_session_identity,
            )

    def drain_acquisition_diagnostics(self) -> list[str]:
        messages: list[str] = []
        while True:
            try:
                messages.append(self.acquisition_diagnostics.get_nowait())
            except queue.Empty:
                return messages

    def drain_ordered_acquisition(self) -> list[AcquisitionEnvelope]:
        target = self.ordered_acquisition
        if target is None:
            raise AppServerError("ordered acquisition is not enabled")
        envelopes: list[AcquisitionEnvelope] = []
        while True:
            try:
                envelopes.append(target.get_nowait())
            except queue.Empty:
                return envelopes

    def _offer_message(
        self,
        target: ByteBoundedQueue[ServerMessage],
        message: ServerMessage,
        kind: str,
    ) -> None:
        with self._acquisition_lock:
            try:
                target.put_nowait(message)
            except queue.Full:
                if kind == "notification":
                    self.notification_overflows += 1
                else:
                    self.server_request_overflows += 1
                self._record_loss_locked(
                    f"App Server {kind} refused by bounded acquisition queue",
                    message.raw_bytes,
                )
                return
            ordered_kind = "NOTIFICATION" if kind == "notification" else "SERVER_REQUEST"
            if not self._next_ordered_locked(ordered_kind, message=message):
                self._record_loss_locked(
                    "App Server ordered acquisition envelope refused by bounded queue"
                )

    def _read_stdout(self) -> None:
        try:
            self._read_stdout_loop()
        except Exception as exc:
            with self._acquisition_lock:
                self._stdout_reader_disposition = "FAILURE"
            self._record_acquisition_loss(f"App Server stdout reader failed: {exc}")
        else:
            with self._acquisition_lock:
                self._stdout_reader_disposition = "CLEAN_EOF"

    def _read_stdout_loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        while True:
            raw_line = self._proc.stdout.readline(self.maximum_line_bytes + 1)
            if not raw_line:
                return
            oversized = len(raw_line) > self.maximum_line_bytes
            terminated = raw_line.endswith(b"\n")
            if oversized or not terminated:
                while raw_line and not raw_line.endswith(b"\n"):
                    raw_line = self._proc.stdout.readline(self.maximum_line_bytes + 1)
                self.stdout_refused_frames += 1
                self._record_acquisition_loss("App Server stdout frame refused by bounded acquisition")
                LOG.warning("App Server stdout frame exceeded bound or lacked terminator")
                continue
            try:
                line = raw_line.decode("utf-8")
                message = json.loads(line, object_pairs_hook=_unique_json_object)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                self.stdout_refused_frames += 1
                self._record_acquisition_loss("App Server stdout frame refused as invalid JSON", raw_line)
                LOG.warning("non-JSON App Server stdout frame")
                continue
            if not isinstance(message, dict):
                self.stdout_refused_frames += 1
                self._record_acquisition_loss(
                    "App Server stdout JSON frame refused as a non-object", raw_line
                )
                continue
            has_method = "method" in message
            has_id = "id" in message
            if has_method:
                method = message.get("method")
                params = message.get("params")
                if (
                    not isinstance(method, str)
                    or not method
                    or ("params" in message and not isinstance(params, dict))
                    or (has_id and (not isinstance(message.get("id"), int) or isinstance(message.get("id"), bool)))
                ):
                    self.stdout_refused_frames += 1
                    self._record_acquisition_loss(
                        "App Server method frame refused as malformed protocol shape", raw_line
                    )
                    continue
                if len(raw_line) > MAXIMUM_RETAINED_ADAPTER_EVENT_BYTES:
                    self.stdout_refused_frames += 1
                    self._record_acquisition_loss(
                        "App Server notification or server request refused by retained-event byte bound"
                    )
                    continue
                wrapped = ServerMessage(message, raw_bytes=raw_line)
                target = self.server_requests if has_id else self.notifications
                self._offer_message(
                    target, wrapped, "server request" if has_id else "notification"
                )
                continue
            if has_id:
                request_id = message.get("id")
                if not isinstance(request_id, int) or isinstance(request_id, bool):
                    self.stdout_refused_frames += 1
                    self._record_acquisition_loss(
                        "App Server response refused with noninteger request identity", raw_line
                    )
                    continue
                with self._pending_lock:
                    pending = self._pending.get(request_id)
                    request_method = self._pending_methods.get(request_id)
                if pending is None:
                    self.stdout_refused_frames += 1
                    self._record_acquisition_loss(
                        "App Server response refused for unknown request identity", raw_line
                    )
                    continue
                if request_method is None:
                    self.stdout_refused_frames += 1
                    self._record_acquisition_loss(
                        "App Server response refused without exact request-method custody",
                        raw_line,
                    )
                    continue
                wrapped = ServerMessage(message, raw_bytes=raw_line)
                with self._acquisition_lock:
                    if len(raw_line) > MAXIMUM_RETAINED_ADAPTER_EVENT_BYTES:
                        self.stdout_refused_frames += 1
                        self._record_loss_locked(
                            "App Server response refused by retained-event byte bound"
                        )
                    elif not self._next_ordered_locked(
                        "CLIENT_RESPONSE",
                        message=wrapped,
                        request_method=request_method,
                    ):
                        self._record_loss_locked(
                            "App Server ordered acquisition envelope refused by bounded queue"
                        )
                    try:
                        pending.put_nowait(message)
                    except queue.Full:
                        self.stdout_refused_frames += 1
                        self._record_loss_locked(
                            "duplicate App Server response refused", raw_line
                        )
                continue
            self.stdout_refused_frames += 1
            self._record_acquisition_loss(
                "App Server stdout object refused as unclassified protocol frame", raw_line
            )

    def _read_stderr(self) -> None:
        try:
            self._read_stderr_loop()
        except Exception as exc:
            with self._acquisition_lock:
                self._stderr_reader_disposition = "FAILURE"
            self._record_acquisition_loss(f"App Server stderr reader failed: {exc}")
        else:
            with self._acquisition_lock:
                self._stderr_reader_disposition = "CLEAN_EOF"

    def _read_stderr_loop(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        while True:
            raw_line = self._proc.stderr.readline(self.maximum_stderr_line_bytes + 1)
            if not raw_line:
                return
            oversized = len(raw_line) > self.maximum_stderr_line_bytes
            terminated = raw_line.endswith(b"\n")
            if oversized or not terminated:
                while raw_line and not raw_line.endswith(b"\n"):
                    raw_line = self._proc.stderr.readline(self.maximum_stderr_line_bytes + 1)
                self.stderr_refused_frames += 1
                self._record_acquisition_loss("App Server stderr frame refused by bounded acquisition")
                continue
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            try:
                self.stderr_lines.put_nowait(line)
            except queue.Full:
                self.stderr_queue_overflows += 1
                self._record_acquisition_loss("App Server stderr line refused by bounded acquisition queue")
