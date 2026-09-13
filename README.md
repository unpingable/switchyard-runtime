# Switchyard runtime

A source-only distribution of Switchyard's bounded direct OpenRouter provider
path. It is the canonical implementation, not a second provider framework.
The supported entry points are `switchyard-direct-api`, the bounded
`switchyard-provider-runner`, and `switchyard-review-verifier`; internal modules
included as dependencies do not establish support for other Switchyard services.

Use it when an enrolled caller needs one durable, bounded model request and an
inspectable result. It does not validate or accept plans, authorize downstream
work, or execute a proposed plan. Maude keeps those proposal-review decisions.
For a small script without durable custody needs, this may be more than you need.

## Install and check without provider access

Requires Python 3.11 or later. Use a separate environment: this distribution
preserves the canonical package/import names and must not be installed over a
different Switchyard distribution in the same environment.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[test]'
.venv/bin/python -m pytest -q
.venv/bin/switchyard-direct-api --help
.venv/bin/switchyard-provider-runner --help
.venv/bin/switchyard-review-verifier --help
```

Tests use deterministic local transports, not billable provider calls. See
[the direct API contract and HOWTO](docs/DIRECT_API_OPENROUTER.md) for request
records, enrollment, limits, cancellation and inspection. Installing this package
does not enroll a caller or provision a provider account.

The provider runner is also available as
`python -m switchyard.provider_runner`. Its `run` operation requires an exact
`--source-provenance SOURCE-PROVENANCE.json` alongside the closed worker-start,
brief, backend and dispatch inputs. The runner verifies the manifest's canonical
revision and complete declared source closure against the request before any
component dispatch. Supplying a manifest does not enroll its owner tuple; the
calling Foreman must separately accept that exact revision/schema tuple.

`switchyard-review-verifier` verifies one supplied, closed review-verification
request against already-retained local Switchyard and Foreman custody. It reads
its closed `--config` and request JSON from standard input, then emits a
canonical owner-verification response. It does not create a model request,
accept a plan, or authorize downstream work. The caller remains responsible for
selecting the review route, retaining the matching custody stores, and deciding
what an authenticated accepted or rejected review means.

The source supports retained v1 requests, enrolled budget-bounded v2 requests,
and additive v3 requests with a caller-bound strict JSON response schema.
Structured output does not replace the caller's validation or human review.
One separately authorized bounded v3 response was accepted by Maude's closed
parser as a scope-bound description-only proposal for review. The plan remains
unaccepted; this establishes no downstream effects or complete authoring
walkthrough. The earlier bounded v2 response was refused as Markdown-fenced JSON.
Install the source revision selected by your caller’s guide, not an unrelated
Switchyard distribution with the same import name.

The provider runner also supports exact local pre-launch failure closure through
`close-prelaunch` and `inspect-prelaunch`. An enrolled local supervisor may attest
a failed original invocation before provider claim; this owner testimony is not
independent process proof. The retained closure prevents a later launch of that
same dispatch, creates no provider result, and grants no retry. See the
[pre-launch closure contract](docs/PROVIDER_PRELAUNCH_CLOSURE_V1.md). Using a
recovery binary does not retarget a separately approved provider route.

## Trust and limits

The caller admits the exact input, model, account and budget. The local SQLite
store claims an occurrence before contact; repeats inspect the same record.
The host, credential provisioning and provider-side limit enforcement remain
trusted. A caller able to bypass the runtime can contact a provider independently.
There is no claim of OS isolation, universal exactly-once provider execution,
formal verification of the HTTP adapter, or downstream authority.

A timeout after contact can leave the result unknown. Do not resend the same
work or silently choose another billable route. Preserve the record and its
reservation and reconcile it; supervisor recovery does not recover provider
execution. Missing usage/cost remains unobservable, not zero.

The provider runner starts its bounded thread with `ephemeral: true`.
`reconcile` opens a fresh App Server process and performs read-only
`thread/read` for the retained thread and turn; it does not make an ephemeral
thread durable. After the original process exits, that read may return
`NOT_OBSERVABLE` or a local error. Even `OBSERVED_SAME_TURN` is later source
testimony only: it neither replaces the retained original evidence nor repairs
provider admission, usage, cost, review acceptance, or downstream permission.

## One implementation and reproducible export

`SOURCE-PROVENANCE.json` records the exact canonical revision, each exported
source path and SHA-256. Maintainers export with:

```sh
node tools/export-runtime.mjs /absolute/canonical/switchyard FULL_COMMIT_SHA /absolute/new-output-directory
```

The output directory must not exist. The exporter reads the pinned Git objects,
not uncommitted files, and uses a closed allowlist. Two exports from the same
revision have identical file bytes and provenance. No private Git history,
credentials, session databases, private configuration or campaign records are
copied. The canonical repository remains private, so outsiders can verify the
published file hashes and build this distribution, but cannot independently
retrieve the private canonical revision. Maintainers must record the two-export
comparison at release. Fix implementation in canonical source, then re-export;
never maintain a patched public fork.

The user's authored exported material is Apache-2.0. The vendored RFC8785
implementation retains its own license and notice; see [NOTICE](NOTICE).
