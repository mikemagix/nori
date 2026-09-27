# Opinionated deployment templates implementation plan

**Repository:** `tomusdrw/nori`  
**Issue:** [#35](https://github.com/tomusdrw/nori/issues/35)  
**Branch:** `feat/deployment-templates`  
**Status:** approved for implementation

## Goal

Let operators deploy services through a safe, typed template instead of only
authoring arbitrary Bash. The initial templates cover a single-container app
and an app paired with a persistent PostgreSQL database. Existing custom
deploy scripts remain fully supported and are not rewritten.

This plan preserves the requirements in the issue/spec, including Dashboard
and MCP parity, explicit conversion to Custom, digest-pinned app images,
bounded readiness, safe rollback, write-only secrets, and human-gated OAuth
and database migrations.

## Chosen design

Use a **native typed Docker driver** for template-mode services. A shared,
secret-free deployment `Plan` is compiled from stored template configuration,
the resolved target image, and the service identity. It powers three surfaces:

1. The native Docker lifecycle executor for template deployments.
2. A value-free Dashboard/MCP preview of the operations and resources.
3. A deterministic Bash renderer when the operator explicitly converts a
   template back to Custom mode.

Custom-mode services continue through the existing Bash executor unchanged.
This avoids making generated shell a second runtime while still leaving every
service on the existing documented escape hatch.

The runtime plan will own only resources bearing all of these exact labels:

```
nori.service=<service name>
nori.template=1
nori.service-id=<immutable service id>
nori.role=<app|candidate|db|internal-network|data-volume>
```

`nori.service` remains for compatibility with the existing dashboard and
monitoring behavior. The additional labels make adoption, cleanup, and
rollback fail closed when a name conflicts with an unowned Docker resource.

The plan derives deterministic Nori-owned names from the immutable service ID.
The public proxy network is explicit and attach-only: Nori verifies it and may
connect the app candidate to it, but never creates, adopts, changes, or deletes
it. PostgreSQL uses a private Nori-owned bridge network and named data volume.

## Data and public contract

### Service persistence

Extend `store.Service` and the `services` table with:

- `deployment_mode`, defaulting to `custom` for new and existing rows.
- `template_config`, a validated JSON document; it is `{}` for Custom mode.

Update every service read/write, `SaveServiceConfig`, and its optimistic stale
write predicate in one migration-backed change. Saving a Dashboard form and
saving through MCP therefore have the same atomicity and conflict semantics.
`deploy_script` remains the source of truth only for Custom mode.

Add a small template-state record keyed by service ID after a managed database
is successfully initialized. It stores a non-secret identity fingerprint, not
the password. A later attempt to change the database name, user, image major
version, or other data identity while the managed volume exists fails with a
clear migration-required error. Operators can explicitly convert to Custom and
perform a documented migration, rather than silently reusing or replacing
stateful data.

### Template configuration

Define a versioned typed configuration in an internal deployment-template
package. It has exactly these initial modes:

- `custom` — the existing raw Bash contract.
- `single_container` — one managed app container.
- `postgres` — one managed app container plus managed PostgreSQL.

Configuration contains only non-secret values: app port, optional proxy
network and hostname settings, health-check kind and bounded timeout, named
volume mount declarations, and PostgreSQL image/database/user plus the names
of required dotenv keys. Values from the encrypted dotenv file are resolved
only in the executor; previews, database rows, logs, and ordinary reads never
show them.

The Postgres template uses a clear environment contract:

- `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` are present in the
  encrypted service dotenv file.
- `DATABASE_URL` is present and is checked against the planned private database
  host, database, and user before deployment.
- The configured database name/user and image must agree with those bindings.

Reject mutable PostgreSQL tags, duplicate or unsafe volume targets, duplicate
proxy variables, invalid resource names, unbounded health checks, and template
configuration on Nori's self-service. Preserve arbitrary additional application
environment variables without rendering their values.

## Runtime model

```mermaid
sequenceDiagram
    participant UI as Dashboard or MCP
    participant Store as SQLite + encrypted dotenv
    participant Exec as Executor lock
    participant Plan as Template planner
    participant Docker as Typed Docker client

    UI->>Store: save typed mode/config and encrypted env
    Exec->>Plan: compile plan with resolved digest
    Plan-->>Exec: secret-free resources and safe actions
    Exec->>Docker: verify exact ownership; pre-pull images
    alt postgres template
        Exec->>Docker: ensure private network, volume, and database
        Exec->>Docker: probe PostgreSQL across private network
    end
    Exec->>Docker: create/start app candidate
    Exec->>Docker: poll bounded health check
    alt healthy
        Exec->>Docker: retire previous owned app
    else unhealthy or failed
        Exec->>Docker: remove candidate and retain prior app/data
    end
```

The current per-service executor lock remains the serialization boundary. The
template path uses it just as Custom does, so a second deployment cannot race
candidate promotion or rollback within the process.

### Docker lifecycle

Extend the narrow Docker interface with typed operations for image pulls,
container inspect/create/start/stop/remove, network/volume inspect/create,
network attachment, and short-lived readiness probes. Keep Docker SDK types at
the adapter boundary; the plan package exposes Nori types rather than raw SDK
objects.

Before changing runtime state, the driver will:

1. Resolve and pre-pull the digest-pinned app image and explicitly tagged
   PostgreSQL image.
2. Inspect every deterministic resource name. It may reuse only an exact
   label match; a missing or conflicting label is an actionable ownership
   conflict and stops the deployment before the old app is changed.
3. Create only the private network and data volume when missing. It never
   manages the configured public proxy network.

The app is started as an owned candidate. Its non-secret configured environment
and required secrets are passed through Docker API configuration, never command
arguments or logs. It receives the resolved digest-pinned target image.

Health checks are either a bounded HTTP(S) request or a bounded container-local
command. The driver polls to the configured deadline; it does not confuse a
container wait with a health signal. On success it promotes the candidate and
then retires the prior owned app. On failure it removes the candidate, restores
the prior app when necessary, and never removes the database container or data
volume.

For PostgreSQL, the driver starts the owned database on the private network and
uses a short-lived client/probe container attached to that network. The probe
uses `PGPASSWORD` through the Docker API environment rather than an argument.
This verifies the actual app-to-database network path without leaking a
password. If PostgreSQL cannot become ready, the app candidate is never
promoted and persistent data is retained.

All template logs, operation descriptions, Docker errors, Dashboard output,
and MCP results pass through the existing dotenv redactor. Action previews are
deliberately value-free.

### Conversion to Custom

The Dashboard and MCP each provide an explicit, confirmed
`convert_service_to_custom` action. It compiles the same plan and renders the
equivalent documented Bash contract using `$SERVICE`, `$TARGET_IMAGE`, and
`$ENV_FILE`; it does not interpolate dotenv values. The conversion atomically
saves the generated script, sets `deployment_mode=custom`, and clears template
configuration. No automatic conversion or silent template fallback occurs.

## Implementation units

### U1 — Store mode/config/state migration

Touch `internal/store/models.go`, `store.go`, `service.go`, and
`service_config.go`.

- Add typed service fields, schema defaults, additive migrations, and complete
  scans/inserts/updates.
- Make mode/config participate in service+dotenv transactions and stale-write
  detection.
- Add template-state persistence and migration-safe identity update methods.
- Add store tests for legacy migration to Custom, round trips, atomicity, stale
  updates, and state fingerprint behavior.

### U2 — Shared template schema and planner

Add an internal package for versioned config decoding, validation, deterministic
resource naming, plan compilation, preview actions, and Custom Bash rendering.

- Keep the plan free of secret values and Docker SDK objects.
- Validate the constraints above before any Docker call.
- Make `Template -> Plan -> Custom Bash` deterministic; use stable operation
  fixtures as conversion tests.
- Unit-test invalid configuration, label/name generation, previews, redaction
  invariants, conversion output, and the single/Postgres plans.

### U3 — Typed Docker adapter and stateful fake

Expand `internal/docker/docker.go` only with operations U4/U5 need and mirror
them in `internal/docker/fake.go`.

- Model resource labels and operation results explicitly.
- Preserve current list/log/start/stop behavior for existing services.
- Make the fake record calls and permit tests to simulate ownership conflicts,
  pull failures, container readiness, probe failure, cleanup errors, and
  rollback paths.
- Add Docker adapter unit tests; retain tagged integration coverage for a real
  daemon where available.

### U4 — Template executor path and safe app promotion

Refactor `internal/executor/executor.go` behind a mode dispatch while keeping
the Custom Bash path behavior and environment-file lifetime intact.

- Build the plan only after image digest resolution and under the existing
  per-service lock.
- Implement preflight, candidate lifecycle, bounded health checks, promotion,
  cleanup, and rollback using the typed adapter.
- Reject non-template resources and do not touch the old app until preflight
  succeeds.
- Redact all template deployment output at the boundary used by records,
  Dashboard logs, and MCP.
- Add executor tests for single-container success, health failure, timeout,
  rollback, non-overlap, foreign-resource conflict, image digest usage, and
  absence of dotenv values from visible output.

### U5 — PostgreSQL lifecycle and data safety

Implement the Postgres portion of the template driver.

- Create/reuse only the exact-owned private network, database container, and
  named volume.
- Probe authentication/readiness across the private network with a short-lived
  client and a context deadline.
- Persist the managed database identity only after successful initialization;
  reject unsafe identity changes later.
- Preserve data and the old app on app/probe/promotion failure.
- Add tests for first boot, persistence across redeploys, probe/auth failure,
  retry, image/version/database-identity rejection, and safe cleanup.

### U6 — Dashboard service editor, preview, and conversion

Update `internal/web/forms.go`, `server.go`, and the relevant `.templ` views.

- Add mode selection and typed fields with server-side validation shared with
  MCP rather than parallel rules.
- Retain the raw Bash editor for Custom mode only.
- Provide a non-secret preview before saving/deploying and a clear conversion
  warning/confirmation.
- Surface ownership, readiness, migration-required, and rollback outcomes as
  actionable non-secret messages.
- Add form/server tests for mode round trips, validation, preview, conversion,
  and never rendering dotenv values; regenerate templ output.

### U7 — MCP parity without Docker primitives

Update `internal/web/mcp.go` and MCP tests.

- Extend typed create/update/get service operations with mode/config data.
- Add equivalent plan preview and explicit conversion capabilities.
- Return structured, redacted phase/status/rollback data.
- Keep scope checks, OAuth consent, and the write-only encrypted environment
  contract intact. Do not add raw Docker command or socket primitives.
- Test Dashboard/MCP parity, tool schemas, redaction, and conversion behavior.

### U8 — Documentation and quality pass

Update `README.md` and `docs/mcp.md` with template configuration, secret
handling, external proxy-network ownership, health checks, PostgreSQL
persistence/recovery, and converting to Custom for exceptional cases.

Run the focused and full verification suite, inspect the complete diff for
scope drift, and apply small in-scope maintainability or test improvements
identified during reflection.

## Test-first execution order

For each unit, add a focused failing test before production behavior. Build in
dependency order: U1 -> U2 -> U3 -> U4 -> U5 -> U6/U7 -> U8. Keep the first
working Custom service test as a regression guard before routing any service
through the new template executor.

The critical behavior matrix is:

| Scenario | Expected result |
| --- | --- |
| Existing service after migration | Runs its unchanged Custom Bash script |
| Single template deployment | Exact-owned candidate starts from the digest image and promotes after health |
| Foreign same-name resource | Deployment stops before replacing the old app |
| Candidate health failure | Candidate is removed; old app remains/restarts; no data is deleted |
| Postgres first deployment | Owned network/volume/database are created and cross-network auth probe succeeds |
| Postgres redeployment | Existing exact-owned volume is reused |
| DB identity/major-version change | Fails with an explicit migration-required error |
| Preview/log/MCP output | Contains action/status metadata but no dotenv values |
| Dashboard vs MCP save/convert | Same validation, stored state, and generated Custom script |

## Verification

Run, in addition to focused package tests:

```bash
gofmt -w <changed Go files>
make generate
make test
go vet ./...
go test -race ./...
make build
```

If a local Docker daemon is available, run the relevant tagged integration test
suite as additional evidence. Do not treat its absence as permission to skip
the fake-backed lifecycle tests.

Before opening the pull request, inspect the final diff against this plan and
the issue; confirm that OAuth configuration and database migrations remain
human-controlled, no Custom script was silently transformed, no raw Docker
primitive was exposed to MCP, and no test fixture or UI/log response contains a
dotenv secret.

## Scope boundaries

This change does not add arbitrary Docker control to MCP, create or manage the
operator's proxy network, auto-migrate application or PostgreSQL data, change
existing Custom scripts, or turn Nori into a general container orchestrator.

## References

- [Nori issue #35](https://github.com/tomusdrw/nori/issues/35)
- [Existing deployment contract](../../README.md)
- [Docker resource labels](https://docs.docker.com/engine/manage-resources/labels/)
- [Docker Engine API reference](https://docs.docker.com/reference/api/engine/)
- [Docker environment-variable caveats](https://docs.docker.com/reference/cli/docker/)
