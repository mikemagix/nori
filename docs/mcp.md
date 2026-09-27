# MCP maintenance notes

Nori owns its authorization server because this feature must work with the
existing administrator login, without an external identity provider. The
official Go MCP SDK owns protocol parsing, tool schemas and Streamable HTTP.
Keep those responsibilities separate. The MCP transport is stateless: every
HTTP request passes through bearer-token validation, including requests made
on an already initialized client connection.

## Code map

| Area | Entry points |
|------|--------------|
| Public OAuth routes, metadata and rate limits | `internal/mcpauth/server.go` |
| Registration and public/confidential client authentication | `internal/mcpauth/clients.go` |
| Admin consent, exact redirects and PKCE challenges | `internal/mcpauth/authorization.go`, embedded `consent.html` |
| Code exchange, refresh rotation and token-family revocation | `internal/mcpauth/tokens.go` |
| Bearer validation and per-tool scope checks | `internal/mcpauth/resource.go` |
| Credential consumption and revocation markers | `internal/store/mcp_oauth.go` |
| Instance toggle, public origin and revocation epoch | `internal/store/mcp_settings.go` |
| Tools and input validation | `internal/web/mcp.go` |
| Atomic service saves and conflict detection | `internal/store/service_config.go` |
| Bounded deployment-log reads | `internal/store/deployment_read.go` |
| Live scheduled-service configuration | `internal/scheduler/scheduler.go`, `internal/store/schedule.go` |

## Security boundaries to preserve

- The configured public origin supplies issuer, resource and allowed Host.
  Never derive these from arbitrary forwarding headers. HTTP is allowed only
  for loopback development. Proxy TLS termination is supported by the secure
  cookie context set in `web.Server.mcpSecureCookies`.
- Browser sessions authorize consent, not MCP requests. Consent requires an
  authenticated admin session, CSRF token, matching Origin and explicit POST.
  GET navigation from OAuth clients may have an external, loopback, absent or
  `null` Origin; it opens login or renders consent and never grants access.
  The consent GET uses `Referrer-Policy: same-origin`: `no-referrer` suppresses
  the Origin on browser form POSTs and breaks approval with `invalid_origin`.
  Do not add CORS read access to the consent page. Keep the template escaped,
  its parameter whitelist, and its CSP/frame restrictions when changing it.
- Codes bind client, exact registered redirect, S256 challenge, resource,
  scope and current epoch. Tokens bind client, resource, scope and epoch.
  Refresh may narrow scopes but cannot add permissions or extend the original
  grant deadline.
- `ConsumeOAuth` is a conditional database write, not a read followed by an
  unconditional update. It must remain single-use across separate Store and
  Server instances. A process-local mutex is insufficient.
- Replay revokes the whole token family. Its persisted revocation marker also
  prevents an exchange already in flight from inserting new usable tokens.
  Keep that marker longer than the maximum grant lifetime: currently 31 days
  versus 30 days. Never delete used refresh records early; they detect replay.
- Settings receives a dedicated, safe projection of approved client
  registrations and grants. It must never receive generic OAuth records: they
  contain credential hashes and protocol-private metadata. A one-grant revoke
  tombstones only that token family and preserves the client registration and
  every other family. Safe grant projections are retained through the same
  post-expiry revocation window so a recent revoked connection is not shown as
  active after a restart.
- Credentials are hashed before they reach storage. Do not log credentials,
  authorization query strings, deploy scripts or environment contents.
- Disabling MCP, changing its public URL or revoking all access changes the
  epoch and removes registrations and grants in one transaction. An ordinary
  settings save must never restore an old epoch. A request already admitted
  may finish, and a deployment already launched continues running.
- All tools go through `addNoriTool` and its scope check before side effects.
  `WithIdentity` is for trusted internal callers/tests; it must not replace
  `Protect` on an HTTP route. Environment reads return only
  variable names and fixed placeholders. `nori:secrets` permits only setting a
  declared variable, together with `nori:write`; no scope reveals values.
- Write access can run arbitrary Bash with Nori's permissions and Docker
  socket. It can read host secrets and affect Nori itself. The explicit
  self-service guards prevent accidental edits through service tools; they
  are not a sandbox against a client granted write access. Known current dotenv values are
  redacted from MCP output, including scripts and logs. Unknown, encoded and
  historical credentials are outside that redaction guarantee.
- Logs must be bounded at the read boundary, not only after loading the full
  output. Container logs must belong to the selected service; preserve byte,
  tail and timeout limits and Docker multiplex-frame validation. Reads include
  at most one maximum-value-length of extra context to redact secrets crossing
  the 256 KiB output window. Redaction happens before the final output cap.
- The MCP wrapper snapshots dotenv values before each tool operation, including
  legacy and self-service values, refreshes after reads, and redacts decoded
  response strings with both snapshots. A longer newly written value makes a
  truncated log read fail closed if its captured context is insufficient.
  Multiline values also redact individual nonempty lines because Docker applies
  its line tail before the server receives logs. Failure
  to load/parse the values fails closed. The environment template response is
  constructed separately from names and markers so redaction cannot corrupt it.

## Public URL setup and settings checks

On the Settings page, an empty public URL input is filled from
`window.location.origin`. This is an editable browser-side suggestion, not the
canonical issuer until the administrator saves it and server validation passes.
Existing input values are preserved. Behind a reverse proxy, open Settings at
the intended public HTTPS address or correct the suggestion before saving.
See the [user setup instructions](../README.md#mcp-agent-access).

When verifying changes to this page:

- With no configured URL, open `/settings` and check that the suggestion contains
  only the browser's scheme, host and port. MCP must remain disabled until saved.
- With a saved URL that differs from the browser's origin, confirm that the saved
  value remains in the input. Confirm that a manually edited value can be saved.
- After enabling and saving, verify that the connection notes show the saved
  URL plus `/mcp`, alongside the read/write access explanation. Check note padding
  and the separate revoke-access section at desktop and mobile widths.
- The Connected OAuth clients section lists only approved connections. Its
  rows show the original approved scopes, approval and expiry times, and
  lifecycle status; they must not reveal codes, tokens, credential hashes,
  client secrets, redirect URLs, or token-family identifiers. Check long,
  untrusted client names at desktop and narrow widths.
- Individual revocation starts with a confirmation page that names the selected
  client and scope. A confirmed revoke must leave sibling grants usable. It
  requires the signed administrator session, CSRF proof, a body no larger than
  16 KiB, the saved public Host, and exactly one matching non-null Origin. The
  server deliberately ignores forwarding headers. An instance without a saved
  public URL may complete first-time Settings setup with the existing session
  and CSRF protections.
- Confirm that disabling access or revoking all access requires clients to
  authorize again, as described in the form notes.

## Persistence and concurrency

`SaveServiceConfig` encrypts environment contents and commits configuration and
environment together. Updates compare the configuration snapshot read by the
operation against the current database fields. A mismatch aborts with
`ErrServiceConflict`; neither configuration nor environment may partially save.
This detects overlapping MCP mutations, not stale client-side drafts: the tool
does not expose a client-supplied version token. MCP template saves resolve placeholders against the current encrypted
values within that transaction. Omitted environment fields are preserved;
omitted keys in an explicitly supplied template are removed.

The environment tools use transactional `SetEnvTemplate` / `SetEnvSecret`
operations so they cannot restore an earlier service configuration or silently
restore a stale secret value. Concurrent SQLite write conflicts fail without
partial writes; clients can retry. Templates normalize dotenv syntax and omit
comments; values are always quoted to retain leading zeros and literal dollars. Names and managed status are immutable through MCP.
The existing dashboard still uses its older save/validation path; do not assume
its writes have the same conflict protection. Unifying those paths is a
separate follow-up below.

The scheduler reads only scheduled IDs, names and cron expressions once per
second. It preserves unchanged entries, removes stale entries and rechecks a
job's policy/expression when it fires. Invalid legacy expressions are remembered
until edited to avoid logging the same error every second. Do not replace this
with remove-and-recreate polling: that resets `@every` schedules.

## Lifetimes and capacity

OAuth lifetime constants live together in `mcpauth/server.go`. Pending client
registrations expire after 10 minutes; explicit consent extends them to one
year. Codes expire after 5 minutes. Access tokens expire after at most 10 minutes
and never outlive the grant. Refresh tokens retain the grant's original 30-day
deadline even as they rotate.

Storage is bounded at 1,000 client records and 20,000 total OAuth records,
including used tokens and revocation markers. Inserts remove expired records;
pending registrations cannot persist indefinitely without admin consent.
Registration has its own budget of 10 requests/minute. Valid credential
exchanges have a separate budget of 120 requests/client/minute. These budgets
are process-local; database consumption and revocation are persistent.

On a `503 temporarily_unavailable`, first check database availability. To inspect
capacity without exposing credentials, query counts only:

```sql
SELECT kind, used, count(*) AS records
FROM mcp_oauth
GROUP BY kind, used;
```

Global revocation in Settings clears capacity but also disconnects every client
and requires new registration/consent. Do not silently evict approved clients
or replay-detection records to make room.

## Verification

Run `make test` and `go vet ./...`; for concurrency or OAuth-storage changes,
also run:

```sh
go test -race ./internal/mcpauth ./internal/store ./internal/web ./internal/scheduler
```

The MCP tests use temporary SQLite databases, fake Docker and a real MCP SDK
client. They do not deploy containers on a live host.

- `mcpauth/server_test.go`: consent and denial, PKCE/resource/redirect checks,
  scopes, anonymous registration isolation, refresh replay, confidential
  clients, expiry, Host/Origin checks and epoch invalidation.
- `mcpauth/tokens_test.go`: advertised/stored access expiry, concurrent code and
  refresh exchange through two independent stores, live grants and revoked
  families across restart, and scope-escalation rejection.
- `web/mcp_settings_test.go`: real OAuth-to-MCP HTTP flow, default write access,
  write-only secret protection, Settings CSRF/origin/body limits, global and
  individual revocation isolation, safe rendered inventory, and Secure cookie
  upgrade behind a proxy.
- `web/mcp_test.go`: tool lifecycle, partial updates, scopes, self-service guards,
  and validation.
- `docker/logs_test.go`: bounded container log decoding, oversized frames and
  malformed streams.
- Store tests cover encryption, rollback, conflicting writes and bounded log
  reads. Scheduler tests cover creation, changes, deletion and invalid-then-fixed
  schedules without restart.

No browser UI test or independent external security audit is represented by
these checks. A rendered consent page and an actual supported OAuth client's
registration/refresh behavior still need release-level compatibility checks.

## Follow-up GitHub issues

### [Share service mutation and validation between the dashboard and MCP](https://github.com/tomusdrw/nori/issues/24)

Move ordinary service writes behind a common operation layer while retaining
the launcher's special self-service workflow. Apply consistent validation,
atomic config/environment saves and conflict handling to both interfaces.
Acceptance: dashboard/MCP parity tests; overlapping writes cannot silently
restore old configuration; invalid input never partially saves.

### [Verify OAuth interoperability and browser consent before release](https://github.com/tomusdrw/nori/issues/26)

Exercise discovery, registration, consent/denial, redirect return, refresh and
reauthorization with the intended native or backend MCP clients. Add browser
coverage at narrow/wide viewports, including long untrusted client names and
redirect URLs. Arrange a focused independent review of the built-in OAuth
boundaries; test-suite success alone is not an external audit.
