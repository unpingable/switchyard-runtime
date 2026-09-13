# Working on the source-only runtime distribution

This repository distributes a closed source cut of canonical Switchyard. Make
runtime changes in canonical source and re-export; do not create an independent
provider implementation here. Keep SOURCE-PROVENANCE.json and third-party notices.
Use `python -m pytest -q` for deterministic tests; they do not require credentials.

Use durable request custody when a campaign needs resumption and reconciliation;
small documentation edits need no model provider. Before long execution, record
the exact occurrence/store/source revision and durable producer/log locations.
After interruption inspect the existing occurrence before any successor request.
Unknown provider outcomes stay unknown until evidence resolves them. Tool or
credential availability does not grant permission for downstream effects.
Durable local custody does not make an ephemeral provider thread recoverable.
Read-only reconciliation may remain `NOT_OBSERVABLE`, and same-turn testimony
does not replace the original evidence or repair admission.

No credentials, real provider responses, private campaign records or canonical
Git history belong in this public repository. Do not use legacy project secrets.
Live tests require an enrolled caller, explicitly selected model and bounded
budget, dedicated locally provisioned credentials and approved test inputs.
