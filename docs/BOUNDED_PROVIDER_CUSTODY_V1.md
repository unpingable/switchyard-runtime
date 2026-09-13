# Bounded provider custody V1 and Foreman profile V3

This is a local size-control contract, not provider contact, review acceptance,
execution authority, or permission to reuse an earlier approved source route.

## Separate limits

- Worker brief input remains bounded at 16 MiB by its existing reader. A valid
  brief can nevertheless be too large for the selected request wire contract.
- The separately pinned `bounded-turn` Switchyard schema permits at most 262144
  exact UTF-8 bytes (including JSON framing and newline) for an outbound
  `CLIENT_REQUEST` whose method is exactly `turn/start`. No other method or lane
  receives this increase. Historical owner/schema tuples retain 16384 bytes.
- Other retained source frames remain capped at 16384 bytes. A server frame can
  therefore be refused even when total model text is below the 32768-byte output
  budget. The output budget is not a guarantee that every possible frame fits.
- `BOUNDED_TURN_ECHO_V1` is a separate, schema-selected experimental context.
  It retains at most 262144 raw bytes only for closed Codex97 lifecycle forms:
  the exact selected text-input echo, and source-shaped agent-message output,
  delta, or final summary frames. It does not enlarge arbitrary `item/*`,
  server-request, response, or provider-boundary traffic. The agent text in
  those forms remains limited to 32768 decoded UTF-8 bytes in total across
  completed sequential items; the final summary must repeat the last completed
  item. This raw framing allowance does not increase the worker-output budget.
- Ordered acquisition retains its existing 256-item / 16-MiB queue, 4096-record
  limit, and 16-MiB cumulative snapshot-record bound. No raw frame is truncated,
  omitted to manufacture a clean cut, or replaced with a summary digest.
- Foreman execution-profile/v3 separates `maximum_worker_output_bytes` from
  `maximum_event_bytes`. The former is mandatory, an integer in 1024..16777216,
  and becomes the unchanged V2/V3 worker-start `maximum_output_bytes` field.
  The bounded review selects 32768 output bytes, 120 seconds, and zero internal
  retries. A larger journal ceiling does not increase the selected output budget.
- Per-event journal storage and aggregate verifier-query output are distinct
  ceilings. The candidate fixture uses 16 MiB for each and measures both full
  serialized event and full aggregate query. Native qualification must establish
  headroom before selecting a real route; a 16-MiB event alone would not fit a
  16-MiB aggregate query with other events. Future output volume remains bounded
  but is not predicted by a mandatory-request feasibility check.

## Pre-send boundary

`switchyard-provider-runner preflight-request --request REQUEST --brief BRIEF
--backend BACKEND` is a no-store, no-backend-start command. It validates the
request/brief and reserves the worst supported 512-codepoint thread identity and
safe-integer request ID when measuring the mandatory turn request. It does not
verify provider availability or produce provider execution evidence. Run it
before provider launch. Obtaining the exact V3 request normally requires a
Foreman scheduler reservation first; a refusal retains that reservation for
supported native recovery, without inferring provider execution. `run` repeats this feasibility
check after retained-occurrence lookup and before backend capture or claim.
A refused feasibility check is not a completed worker or an automatic closure.

The actual AppServer transport serializes each request once, checks those exact
bytes against the method-specific bound and retains them in the bounded queue
before the first stdin write. Queue refusal stops before sending. Short writes
advance through the same byte buffer, not a reserialized request. A partial-write
failure or missing response remains uncertain; it is never retried automatically.
The durable runner still returns an existing occurrence before new preflight,
backend capture, or request transmission. Response-loss recovery inspects that
original occurrence; it does not open a replacement.

The bounded `thread/start` request sets `ephemeral: true`. The runner's
`reconcile` command starts a fresh App Server process and asks `thread/read` for
the exact retained thread and turn. It cannot make the provider-side thread
survive the original process, so post-exit reconciliation can honestly remain
`NOT_OBSERVABLE`. An `OBSERVED_SAME_TURN` result is later provider-source
testimony, not a transition that rewrites the retained occurrence or repairs
admission, completion, review acceptance, usage, cost, or effect permission.

## Compatibility and identity

V2 execution profiles omit `maximum_worker_output_bytes`, retain their original
serialization/digest, and continue using `maximum_event_bytes` as their output
bound. Explicit null is rejected on every serde ingress. V2 with a numeric new
field and V3 without a valid numeric field are refused. V3 uses schema
`nightshift.foreman-execution-profile/v3` and domain
`nightshift.foreman-execution-profile.digest/v3\0`; old readers reject it.
The work-item execution projection remains the unchanged V2 work-item shape.

Worker-start, binding, evidence, snapshot, and disposition record schemas and
identity domains retain their existing versions. The new separately content-pinned
`switchyard.codex-provider-admission.bounded-turn.v1.schema.json` is a closed
schema source cut, not a caller-supplied arbitrary cap. The native graph selects
this source only for the explicit new owner tuple. Historical source/schema pins
are preserved; an old pinned graph refuses the large-frame fixture even on a
new binary. No unknown cap field is accepted. Exact raw bytes, record digests,
mapper snapshot digest, typed disposition and duplicate byte custody remain
fully retained and replayed.

Mapper, transport, and replay default to the closed `LEGACY_V1` capture context.
`BOUNDED_TURN_V1` is selected explicitly from the validated retained request's
schema digest, including runner startup, read-only inspection/reconciliation,
and review-verifier replay. Unknown selectors refuse. Context is not inferred
from a snapshot or from the Codex head alone. No binding or snapshot field is
added. Standalone native disposition validation accepts the structural union
of supported source formats; this is not scheduling admission. The complete
native graph additionally selects the enrolled requirement's exact source/schema
limits and refuses a large snapshot under an old tuple. Consequently structural
validation alone cannot advance an old enrolled dispatch.

`BOUNDED_TURN_ECHO_V1` is likewise selected only by the new pinned
`switchyard.codex-provider-admission.bounded-turn-echo.v1.schema.json` digest.
It does not reinterpret `LEGACY_V1` or `BOUNDED_TURN_V1` records: those retained
tuples keep their original 16384-byte incoming-frame limits, and a mismatched or
unknown selector fails closed.

## Offline qualification only

`tests/test_size_controls.py` constructs synthetic request bytes independently;
no campaign IDs, actual review material, credentials, or real provider response
are included. The shared compact `bounded-turn-synthetic.json` recipe expands to
an exact 118500-byte request and has a cross-language snapshot identity assertion.
The native Foreman `bounded_turn` tests use temporary fixture stores and CLI
admit/prepare/derive/record/events, measure event/query sizes, reopen retained
custody, and refuse duplicate recording without another dispatch. Synthetic
`EXECUTION_ADMITTED` frames establish only local mapper/contract behavior, never
that a provider request occurred. The optional `BOUNDED_TURN_LEGACY_FOREMAN`
variable selects a frozen old binary solely for an offline V3 refusal check.
`tests/test_bounded_turn_echo.py` and its generic vector exercise the selected
echo forms, escaped raw framing, sequential completed-item accounting, and old
context refusal. They are component qualification only, not real-review
qualification or evidence of provider execution.
