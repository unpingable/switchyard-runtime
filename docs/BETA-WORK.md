# switchyard-runtime beta work

Planning only, recorded 2026-10-01. Work below is not started by publication of this plan. Source, package, installation, runtime and composition standing remain separate.

## Current state

Start from [`dev/operator-beta`](https://github.com/unpingable/switchyard-runtime/tree/dev/operator-beta), canonical product reconciliation at `0906e55ecde54b8ec944d595d1afbf325e13772b`. Documentation commits after that point do not select a different product base or transfer predecessor qualification.

The closed public runtime export includes provider receipt projection and worker-outcome validation. Implementation changes belong in canonical Switchyard and are re-exported; this repository does not own an independent provider implementation.

## Scope and exclusions

This plan routes current requirements and evidence needed for future bounded work. It does not resume alpha qualification, launch providers, mutate a deployment or implement product changes. Target-specific configuration and operational facts belong in program/application records; component documentation describes abstract interfaces only.

`agent_gov`, Classic NQ (`nq-classic`), retired monorepos, predecessor product lines and historical application implementations are historical/migration evidence only. They are not forward source donors, dependencies or instructions to restore removed APIs. Retired WLP compatibility remains excluded. Record a current requirement if old evidence suggests missing functionality; require an explicit owner decision before any revival.

## SW-01: Plan Switchyard runtime export and provider recovery contract

`RELEASE_ENGINEERING` · **Required for operator-beta** · Project: Ready.

Problem: Reusable receipt projection and worker outcome validation are exported source; canonical implementation and public distribution remain distinct.

Intended outcome: Document current receipt enrollment, dependency/runtime floor, package/source export identity, cancellation and recovery limits; implementation changes remain canonical and are re-exported.

Scope/exclusions: Do not fork provider implementation in the public cut or publish canonical private history/provider occurrences.

Dependencies: Foreman exact receipt tuple; [PA-11](https://github.com/unpingable/unpingable-site/issues/12) and [PA-12](https://github.com/unpingable/unpingable-site/issues/13) release closure.

Acceptance/evidence: Closed export hashes/licenses and deterministic contract vectors, package/ABI evidence and bounded separately admitted lifecycle tests; unknown provider outcome remains unknown.

Owner decisions: Caller supplies provider/model/enrollment; exporter owner approves new payload boundaries.

Owning issue: [SW-01](https://github.com/unpingable/switchyard-runtime/issues/2).
