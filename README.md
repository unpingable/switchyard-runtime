# Switchyard runtime

A source-only distribution of Switchyard's bounded direct OpenRouter provider
path. It is the canonical implementation, not a second provider framework.
The supported entry point is `switchyard-direct-api`; internal modules included
as dependencies do not establish support for other Switchyard services.

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
```

Tests use deterministic local transports, not billable provider calls. See
[the direct API contract and HOWTO](docs/DIRECT_API_OPENROUTER.md) for request
records, enrollment, limits, cancellation and inspection. Installing this package
does not enroll a caller or provision a provider account.

The source supports retained v1 requests, enrolled budget-bounded v2 requests,
and additive v3 requests with a caller-bound strict JSON response schema.
Structured output does not replace the caller's validation or human review.
The v3 repair is locally tested; a successful live Maude authoring walkthrough
is still pending. Install the source revision selected by your caller's guide,
not an unrelated Switchyard distribution with the same import name.

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
