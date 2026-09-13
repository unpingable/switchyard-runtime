# Local pre-launch closure V1

This bounded recovery closes one exact prepared provider dispatch after a local
failure before Switchyard claimed or started the backend. `EXECUTABLE_CAPTURE_FAILED`
records a runner-side executable capture failure. The additive
`REQUEST_PREFLIGHT_FAILED` reason records a request-preflight failure only from
terminal owner testimony at that same boundary.
It creates no worker result, provider admission, model response, retry authority,
or replacement request.

Two evidence modes are distinct:

- `OBSERVED_CAPTURE_FAILURE`: the runner caught executable capture failure at
  its own boundary before claim. Future failures retain this record directly.
- `SUPERVISOR_ATTESTED_PRECLAIM_FAILURE`: an enrolled local supervisor attests
  the original producer's terminal invocation and exclusion of alternate
  writers. This is explicitly
  `OWNER_ATTESTATION_NOT_INDEPENDENT_PROCESS_PROOF`. Missing provider custody
  alone never establishes producer death or permission to close.

The approved local transport and protected deployment/store paths authenticate
the owner operationally. Canonical hashes establish identity and consistency;
they do not independently authenticate the supervisor or prove process facts.
Recovery source enrollment is separate from the original request's source pin.
The approved provider route is not changed by using a recovery binary.

## Exact records

`switchyard.provider-prelaunch-closure/v1` is closed and bounded to 32 KiB.
Its fields are `schema`, `closure_digest`, `binding`, `closed_at`,
`evidence_mode`, `failure_code`, `supervisor_attestation`,
`observer_source_head`, `observer_runner_sha256`, `state`,
`provider_claim_absent`, `backend_started`, and `authority_effect`.
The failure-code enum is `EXECUTABLE_CAPTURE_FAILED` or
`REQUEST_PREFLIGHT_FAILED`; the remaining fixed values are `PRELAUNCH_CLOSED`,
true, false, and `LOCAL_PRELAUNCH_CLOSURE_ONLY`, respectively. The latter
reason requires `SUPERVISOR_ATTESTED_PRECLAIM_FAILURE`; observed-capture mode
is limited to the runner-side executable-capture reason.
The closure digest is SHA-256 over
`switchyard.provider-prelaunch-closure.digest/v1\0` plus RFC 8785 bytes
with the `closure_digest` member omitted.

The closed `binding` contains:

- `packet_digest`, `run_id`, `work_item_id`, `work_attempt_id`,
  `dispatch_occurrence_id`, `adapter_process_occurrence_id`;
- `request_digest`, `request_sha256`, `worker_brief_digest`,
  `brief_sha256`, `backend_sha256`, `dispatch_digest`, `dispatch_sha256`;
- original `switchyard_owner_head` and `codex_owner_head`.

The SHA-256 fields hash the canonical request/backend/dispatch and literal brief
bytes. Original request and dispatch semantic digests remain unchanged.
The public pure `provider_runner.prelaunch_binding` function derives this
binding from the four original inputs without touching a store or provider.

The supervisor attestation is null only in observed-capture mode. Otherwise its
closed schema is `switchyard.prelaunch-supervisor-attestation/v1`, containing:
`schema`, exact `binding`, `supervisor_identity`, `host`, `unit`,
`invocation_id`, `active_state`, `result`, `exit_code`, `observed_at`,
`original_runner_sha256`, `unit_evidence_sha256`, `failure_evidence_sha256`,
`boundary`, `original_producer_terminated`, `alternate_writers_excluded`,
and `trust_basis`. It requires a 32-digit lowercase hexadecimal invocation,
`inactive` or `failed`, `exit-code`, positive exit code,
`BEFORE_PROVIDER_CLAIM`, both booleans true, and the testimony label above.
The owner retains the exact unit and failure evidence referenced by the hashes;
Switchyard does not query a service manager or infer those claims from absence.

Timestamps preserve canonical chrono UTC RFC3339 precision (seconds or 3/6/9
fractional digits). Comparisons do not truncate nanoseconds. Original dispatch
timestamps are never rewritten. Neither record contains observed provider,
thread, turn, response, credential, or worker-output fields.

## Native recovery sequence

Inspect and reconcile the original producer and retained inputs first. An
uncertain invocation, alternate writer, existing provider claim, wrong binding,
or conflicting closure must refuse. `EXECUTABLE_CAPTURE_FAILED` requires the
original provider-custody store. For a `REQUEST_PREFLIGHT_FAILED` closure only,
an absent adapter store may be initialized solely to retain the exact closure:
the required owner attestation still binds `BEFORE_PROVIDER_CLAIM`, and the new
store contains the closure rather than a provider claim. Switchyard validates
the canonical inputs, enrolled recovery provenance, and exact attestation before
that allocation, then uses exclusive creation; a concurrently present pathname
is reopened existing-only and unknown custody refuses.

Using an explicitly enrolled recovery source export:

```text
python3 -m switchyard.provider_runner --state ORIGINAL_ADAPTER_DB close-prelaunch \
  --request ORIGINAL_REQUEST --brief ORIGINAL_BRIEF --backend ORIGINAL_BACKEND \
  --dispatch-record ORIGINAL_DISPATCH --supervisor-attestation OWNER_ATTESTATION \
  --source-provenance RECOVERY_SOURCE_PROVENANCE --source-head RECOVERY_FULL_SHA \
  --closed-at EXACT_CLOSURE_TIME --failure-code REQUEST_PREFLIGHT_FAILED
python3 -m switchyard.provider_runner --state ORIGINAL_ADAPTER_DB inspect-prelaunch \
  --dispatch ORIGINAL_DISPATCH_ID
nightshift-foreman accept-prelaunch-closure --db ORIGINAL_FOREMAN_DB \
  --receipt RETAINED_SWITCHYARD_CLOSURE
nightshift-foreman replay --db ORIGINAL_FOREMAN_DB --run-id ORIGINAL_RUN
```

Retain the exact closure emitted by Switchyard through the campaign's normal
owner-controlled artifact mechanism. Foreman accepts that mechanism-owned
record through the existing trusted local input boundary; an arbitrary
caller-written document is not independently authenticated by its digest.
One terminal LF from native stdout is accepted.

Switchyard uses an immediate transaction to require custody absence and occupy
the original `provider_runs` dispatch slot with `PRELAUNCH_CLOSED`, retaining
original request/brief/backend and dispatch bytes. Existing claims cannot be
overwritten. Exact duplicate closure is idempotent; changed evidence refuses.
Both new and prior runners return the retained record before backend launch,
including prior runners that do not understand the new closure subtype.

Foreman requires the exact active `DISPATCHING` attempt, its retained prepared
request and dispatch, and no provider disposition. It atomically retains an
attempt-bound `PrelaunchClosureAccepted` event and releases resource claims.
The existing final receipt shape reports `NOT_STARTED` with
`LOCAL_PRELAUNCH_FAILURE`, explicitly says that the prepared attempt is
retained, and embeds the exact closure plus `prepared_attempt_id`. The original
attempt and dispatch history remain intact. Existing V1 `accept-not-started`
and provider-terminal gates are unchanged. Older Foreman readers refuse the
new journal event; use the recovery binary to inspect the recovered store.

This Foreman change does not enroll a new provider route. A separately approved
new dispatch may still use its unchanged prior runtime tuple in a distinct
store. Closure never dispatches or schedules that work.
