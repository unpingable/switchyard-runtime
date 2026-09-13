# Bounded direct OpenRouter transport

Status: **implemented and deterministically fixture-tested**. One bounded live
v2 response was observed; Maude refused its Markdown-fenced JSON. A later,
separately authorized v3 response was accepted by Maude's closed parser as one
scope-bound description-only proposal for review. It remains unaccepted. These
records establish bounded provider contact and one proposed/diff result, not a
full authoring walkthrough, human approval, or downstream authority.
This module adds one explicit API acquisition route. It does not replace the
Codex App Server adapter, admit work, authorize effects, evaluate model output,
or establish provider availability.

## Ownership and boundary

`switchyard.direct_api` owns transport custody for one already owner-bound
request. Its closed request and owner-binding records identify:

- request, work attempt, and dispatch occurrence separately;
- SHA-256 of the exact admitted UTF-8 input and its maximum byte size;
- the fixed HTTPS endpoint
  `https://openrouter.ai/api/v1/chat/completions`;
- provider `openrouter`, the exact requested model, and a nonsecret enrolled
  account identity;
- credential source `environment:OPENROUTER_API_KEY` without retaining its value;
- one total monotonic local-acquisition duration, response/output bounds, no
  retry/fallback, and the authority effect
  `LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY`.

The original `direct-api-request/v1` remains inspectable for retained v1
occurrences. Enrolled callers use `direct-api-request/v2` with closed
maximum prompt, completion, and total-token values. V2 sends the completion
ceiling as OpenRouter's `max_tokens`, retains the three limits and enrolled
owner/profile/proposal identities, and treats observed token overage as
`TOKEN_USAGE_OVER_BOUND`, never an acceptable completion. Prompt/total figures
are response evidence, so a missing usage record is not proof that those two
limits were met; a caller requiring an enforceable proposal budget must refuse
such a result. To avoid assuming a model tokenizer, v2 requires the admitted
UTF-8 input-byte ceiling plus a fixed 512-token chat-wrapper reserve not exceed
the prompt-token ceiling (one byte is the conservative upper-bound input unit;
the selected upstream model must still honor declared limits). V2 does not estimate tokens locally or invent
spend accounting.

V2 also carries a caller/account-scoped spend-budget identity, a fixed
micro-unit budget, a conservative per-dispatch reservation, and a maximum
concurrent request count. The reservation must exactly equal the admitted
maximum prompt tokens times the approved fixed prompt micro-price plus maximum
completion tokens times the approved fixed completion micro-price; OpenRouter's
`max_price` units are dollars per million tokens, numerically equal to those
micro-dollars per token (for example, 3 maps to 3, not 0.000003). The profile
therefore fixes both the model and its price card. The SQLite claim transaction checks both the active
slot count and all retained reservations for that owner/account/budget scope
before contact, then commits the dispatch and reservation together. Completion
releases only the concurrency slot; it never releases the reservation based on
a provider-reported cost. This is intentionally conservative: uncertain and
completed occurrences stay precharged until the owner performs a separately
reviewed budget reconciliation. No response-cost-only path can create spend
headroom.

Known terminal outcomes before contact (including cancellation or an unavailable
credential) also release their active concurrency slot while retaining the
conservative monetary reservation. An outcome that may have contacted the
provider keeps both its reservation and concurrency slot pinned for inspection;
this adapter does not invent reconciliation or release authority.

For v2, the outbound OpenRouter `provider` object also sets
`require_parameters=true` and `max_price.prompt`, `.completion`, and `.request`
(`0`) from that fixed price card. This asks the provider to enforce the same
price envelope; local arithmetic is a reservation control, not evidence of
external billing. The dedicated provider-key cap remains the final spend
boundary.

### Structured responses: additive v3

`direct-api-request/v3` and `direct-api-owner-binding/v3` retain the enrolled
limits and add caller-issued `response_format`. Its strict JSON Schema is
covered by the exact request digest and forwarded unchanged. It is bounded to
64 KiB, with depth, node-count and string-length checks before contact. V1 and
V2 do not acquire a new response format implicitly.

The conservative prompt check includes admitted input bytes, canonical response
format bytes and the 512-token wrapper allowance. A format that would exceed
the prompt ceiling is refused before the dispatch claim or provider contact.
The fixed token-price reservation is not raised to accommodate a schema.

This is a transport constraint, not semantic validation. Maude supplies its
closed proposal envelope and allowed operation shapes, then still validates
the actual response, exact base and scope, and semantic diff. Unsupported
provider parameters or malformed output refuse; no automatic route switch,
Markdown-fence removal, retry or plan acceptance follows. Provider-side schema
support remains an external dependency and must be checked for a live model.

The caller owns the authenticity and authority of the owner-binding record.
Switchyard validates its closed fields, digest, and exact projection; it does
not turn a self-consistent caller document into authorization. Docket/Foreman or
another enrolled owner must claim/admit the surrounding attempt before invoking
this adapter. A model response never grants AG authority or target effects.

## One-use lifecycle

The SQLite claim commits before credential lookup or network contact. An exact
duplicate returns the retained record and never calls the provider again.
Reuse of a dispatch identity with different request, input, or owner binding
refuses. After contact starts, timeout, transport loss, cancellation, malformed
response, or process interruption remains uncertain and permits inspect/reconcile
only—never regeneration under the same dispatch.

The production HTTP call runs the existing redirect-disabled urllib transport in
one isolated child. The parent owns the monotonic duration, local cancellation,
and durable record. On deadline or a cancellation observed while the child is
running, the parent terminates that local transport process and records an
uncertain contacted outcome without retry. The credential crosses only the
private child stdin pipe; it is not placed in argv, environment, logs, or durable
state. The child receives no SQLite path or authority object.

The launcher uses Python isolated-path mode and prepends the exact installed
source parent derived from this module's resolved pathname. It does not inherit
`PYTHONPATH`, so the child cannot select a different ambient Switchyard tree.
Only proxy, certificate, and executable-search variables needed by the existing
urllib transport are allowlisted into the child environment. The canonical child
itself reads at most one bounded input envelope and emits at most the admitted
response bound plus its fixed base64/JSON envelope; the parent rejects a larger
result after collection. This output-memory claim depends on executing that
exact pinned child, not an arbitrary injected test command.

This is active **local acquisition cancellation**, not provider-side
cancellation. The remote service may already have received or completed the
request, so the outcome remains unknown and no replacement call is allowed.

The request contains one `model`, no `models` fallback list, no tools, and
`provider.allow_fallbacks=false`. OpenRouter documents that provider fallbacks
default to enabled and are disabled with this field:
<https://openrouter.ai/docs/guides/routing/provider-selection>. This source
inspection does not establish what a future external occurrence actually does;
reported model and upstream provider remain response evidence.

HTTP 401/403, 402, 429, 503, 408/504, and other non-200 responses retain typed
authentication, quota, rate/capacity, provider-capacity, timeout-uncertain, and
generic refusal states. When a bounded JSON error envelope supplies a scalar
`error.code`, `error.type`, `error.metadata.error_type`, or
`error.metadata.provider_code`, the adapter retains only values matching its
1–128 character diagnostic-token grammar. The fields are
`provider_error_code`, `provider_error_type`, and
`upstream_provider_error_code`; documented `metadata.error_type` takes
precedence over the legacy top-level `error.type`. Numeric codes are normalized
to strings. A value containing the active credential or beginning with a
recognized secret prefix is omitted. These optional identifiers improve
refusal inspection without changing its disposition.
Messages, raw response bodies, headers, request echoes, nested metadata, and
exception text are not persisted; malformed, prose-like, or overlong diagnostic
values are omitted.
The credential value is passed only to the one transport call and is never
placed in request, owner binding, result, or SQLite state.

`PROVIDER_COMPLETED` means one bounded response with the exact requested model
and output was observed. `acceptance_state` remains
`NOT_EVALUATED_BY_SWITCHYARD`. Missing usage and cost are explicitly
`NOT_OBSERVABLE`. A numeric provider-reported cost is retained with currency
`NOT_OBSERVABLE`; this adapter does not infer a bill or campaign spend.

## CLI

Install the project normally, then supply canonical JSON request/binding files
and an absolute bounded regular input file:

```sh
switchyard-direct-api --state /absolute/campaign/direct-api.sqlite run \
  --request /absolute/campaign/request.json \
  --admitted-input /absolute/campaign/input.txt \
  --owner-binding /absolute/campaign/owner-binding.json
```

The CLI obtains only `OPENROUTER_API_KEY` from its environment. Do not pass a
credential in argv, JSON, logs, or fixtures. Inspect without contact:

```sh
switchyard-direct-api --state /absolute/campaign/direct-api.sqlite inspect \
  --dispatch exact-dispatch-occurrence-id
```

The request and binding files must be canonical JSON. The input reader is
absolute-path, regular-file, `O_NOFOLLOW`, nonblocking, and byte-bounded. The
SQLite path and its containing campaign custody remain the launcher/owner's
responsibility; this module does not create another supervisor or directory
authority mechanism.

## Qualification and nonclaims

`tests/test_direct_api.py` uses only deterministic transports and failure
injection. It covers completion-versus-acceptance, exact duplicate recovery,
changed-input/selection refusal, endpoint/account/credential-source custody,
missing credentials, pre/post-contact cancellation, interruption, timeout,
transport loss, malformed output, model mismatch, response/output bounds,
typed HTTP dispositions, usage/cost availability, and credential redaction.

The tests make no external request and use no real credential. They do not
establish live OpenRouter access, model availability, account ownership,
provider-side cancellation, upstream generation count, provider enforcement of
the declared token ceiling, monetary budget enforcement, response truth, or
independent acceptance.
