---
title: "feat: Manage individual OAuth grants"
date: 2026-09-27T21:52:00+02:00
type: feat
target_repo: tomusdrw/nori
source_issue_url: https://github.com/tomusdrw/nori/issues/25
artifact_contract: ce-unified-plan/v1
product_contract_source: github-issue-25
execution: code
plan_depth: deep
deepened: 2026-09-27
---

# feat: Manage individual OAuth grants

## Goal Capsule

**Objective:** An administrator can identify and disconnect one connected OAuth client grant without interrupting other approved clients or grants.

**Means:** Persist a browser-safe grant-management projection alongside OAuth credential records, then revoke one family through the existing transactional tombstone mechanism. (KTD1, KTD2)

**Authority:** This plan implements [Issue #25](https://github.com/tomusdrw/nori/issues/25) and the existing OAuth security boundaries documented in `docs/mcp.md`. The issue scope overrides optional historical/audit features.

**Stop conditions:** Do not add MCP administration tools, display credentials or redirect URLs, rotate the global epoch for a selected grant, or change the separate global revoke-all semantics.

**Execution profile:** Security-sensitive, test-first implementation. Keep the work on one isolated branch and open a PR when the verification contract passes.

---

## Product Contract

### Summary

Add an authenticated Settings inventory of approved client registrations and their authorization grants. Administrators can inspect safe grant metadata and explicitly revoke exactly one grant; the existing broad revoke-all remains separate.

### Problem Frame

The current Settings page can revoke every OAuth client and registration, but cannot disconnect one compromised or unwanted connection. Existing token rows are intentionally unsuitable for a browser-facing inventory: they rotate, expire, and contain credential-adjacent data.

### Actors

- **A1 — Administrator:** uses the authenticated Settings page to inspect and revoke one connection.
- **A2 — OAuth client:** remains registered and can create multiple authorization grants through consent.
- **A3 — OAuth resource/token server:** validates and invalidates every credential in a grant family.

### Requirements

- **R1.** Settings lists approved OAuth client registrations and their grants using a safe, understandable identity; pending registrations never appear.
- **R2.** Each listed grant shows originally approved scopes, approval time, expiry time, and one current state: Active, Expired, or Revoked. The Settings response and rendered page must not contain access tokens, refresh tokens, authorization codes, client secrets, credential hashes, raw OAuth storage data, raw family values, or redirect URLs/query strings.
- **R3.** A client registration and authorization grant remain separate. Revoking one grant preserves its client registration and every other grant.
- **R4.** A selected active grant has a dedicated confirmation page/state that identifies the safe client/grant details. The destructive POST is bound to a single opaque, non-credential management identifier; cancellation makes no change.
- **R5.** Individual and global MCP-revocation mutations require the existing administrator session and CSRF proof, and enforce the configured public origin's exact Host and Origin without trusting forwarding headers.
- **R6.** A successful individual revocation makes the selected grant family's access tokens, refresh tokens, and outstanding codes unusable immediately. A refresh, replay, or exchange already in flight cannot create a usable credential after revocation commits.
- **R7.** Individual revocation never changes another family, another registration, a pending registration, the global epoch, or MCP enablement/public URL. The global revoke-all control remains visible and performs its existing broad reset.
- **R8.** Grant status and revocation survive a store reopen. A still-registered client can reauthorize normally, producing a new, distinct active grant rather than reviving the old family.
- **R9.** Inventory read failures show no partial/stale grant list. A failed revoke reports that the connection may still be active and does not present success.
- **R10.** The responsive Settings UI keeps client identity, scopes, dates, state, confirmation, and success/failure states understandable at wide and narrow widths.
- **R11.** Automated coverage proves authorization, CSRF/Origin/Host rejection, isolation, invalidation, concurrent safety, restart persistence, reauthorization, secret non-disclosure, and responsive markup behavior.

### Acceptance Examples

- **AE1.** With two active client grants, revoking A invalidates A's current access and refresh credentials while B continues to call MCP and refresh.
- **AE2.** With two grants for one registered client, revoking one preserves the other grant and the registration.
- **AE3.** After restart, a revoked grant's old credentials still fail and the inventory does not describe it as Active.
- **AE4.** Reauthorization by the still-registered client creates a new Active grant; no old credential becomes valid.
- **AE5.** A forged, cross-origin, missing-Origin, Host-mismatched, or CSRF-invalid mutation changes no grant.
- **AE6.** Rendered Settings HTML contains approved scopes and dates but no credential or secret-bearing URI material.

### Scope Boundaries

**In scope:** safe Settings inventory, one-family revocation, legacy active-family projection/bootstrap, origin-bound destructive routes, focused documentation, and verification.

**Out of scope:** editing scopes in place, deleting a registration during individual revoke, bulk revocation, recovering credentials, changing OAuth client self-revocation, or a general audit-log system.

### Deferred to Follow-Up Work

- Agent-visible administration requires a distinct owner/admin authorization model and must not be added under `nori:read`, `nori:write`, or `nori:secrets`.
- Long-lived OAuth audit retention, pagination, and operator audit entries are not needed for this connection-management feature.

### Assumptions

- Management data uses new, namespaced `kind` values in the existing `mcp_oauth` table. It therefore shares the current 20,000-record capacity, transactional expiry cleanup, database migration path, and `DELETE FROM mcp_oauth` global reset; there is no second table or quota to keep in sync. A management lookup derives a storage key from a browser-facing random opaque ID, so neither the ID nor a raw OAuth row is enumerated from storage.
- A safe registration record contains only a display label and lifecycle timestamps. A safe grant record contains only its registration relation, display label, originally approved scopes, timestamps, and the internal family relation needed by Store. It never contains a client ID, secret/hash, redirect, code, token, PKCE data, or generic serialized OAuth record.
- An Active or Expired safe grant remains visible until `grant expiry + 31 days`. An individual revoke shortens that summary's expiry to `revoked_at + 31 days`, matching its tombstone window; `Revoked` takes precedence over `Expired`, and expiry cleanup purges the safe record thereafter. The feature does not reconstruct old expired/revoked families as audit history.
- Existing active credential families are bootstrapped only by a narrow `mcpauth` facade before Settings inventory reads. It derives safe data from private OAuth types, atomically upserts records only when the persisted epoch remains current and the client/family is still approved, live, non-tombstoned, and has immutable original-scope data. Families whose surviving data only reflects a narrowed refresh scope are omitted rather than displayed with an invented approval scope; web never receives raw OAuth rows. Global revoke-all continues to clear all OAuth records and summaries.

---

## Planning Contract

### Key Technical Decisions

- **KTD1 — Store a dedicated grant-management projection in bounded OAuth record kinds, not a token-derived UI view.** Add typed `mcp_oauth` record kinds for browser-safe registrations and grants, with namespaced/digested keys derived from opaque random management IDs. They share the table's 20,000-record limit, cleanup, migration, and global delete. Active/Expired grants expire from the projection at `grant expiry + 31 days`; a revoke replaces that with `revoked_at + 31 days`; `used` means Revoked and wins over natural expiry. Token rows rotate and include redirects, PKCE data, hashes, and credentials, so they cannot be rendered or used as the inventory source. Governs R1, R2, R3, R8, R9.
- **KTD2 — Use one shared family-revocation transaction for every revoke path.** That primitive writes/checks the existing 31-day tombstone, marks only that family's credential and grant-management rows used, sets a revoked management record's expiry to the tombstone expiry, and refuses stale or non-active selected grants. The managed endpoint, client self-revocation, refresh/code replay, and token-issuance rollback all call it, so a displayed state can never remain Active after any family revoke. It never calls `SetMCPConfig(..., revoke=true)`. Governs R3, R4, R6, R7, R8, R9.
- **KTD3 — Make future consent issuance atomic with its management records.** A Store operation accepts serialized OAuth records plus Store-owned safe DTOs (not private `mcpauth` types), verifies a live, current-epoch, unconsumed raw client, performs its approval/expiry extension, updates the safe registration, inserts the grant and authorization code after the tombstone/capacity checks, then commits as one transaction. Storage failure returns the existing OAuth failure rather than a usable-but-unlisted family. The `mcpauth` facade owns idempotent live-family bootstrap so Store never imports private OAuth decoders. Governs R1, R2, R8, R9.
- **KTD4 — Keep grant administration Settings-only and human-confirmed.** MCP callers are the principals being managed; the existing service scopes are not owner control-plane authority. Destructive Settings routes use `session → bounded body → persisted configured Host/Origin → CSRF → handler`; the origin guard requires exactly one non-`null` Origin and an exact configured scheme/host/port match, ignores forwarding headers, and fails closed when configuration cannot be read. It protects individual revoke, global revoke, and an existing Settings POST that would rotate the epoch; first-time configuration has no prior public origin to enforce. Governs R4, R5, R7.
- **KTD5 — Preserve broad-reset behavior and bounded retention.** Global revoke/disable/public-origin change still rotates epoch and clears registrations, credentials, and management summaries. Individual revocation retains only the safe status summary long enough to show the revoked connection while the existing tombstone is relevant. Governs R2, R7, R8.

### High-Level Technical Design

```mermaid
sequenceDiagram
    participant Admin as Administrator
    participant Web as Settings handlers
    participant Store as SQLite OAuth store
    participant OAuth as Token/resource server

    Admin->>Web: GET /settings
    Web->>Store: List safe approved registrations + grants
    Store-->>Web: Safe projection only
    Web-->>Admin: Inventory with opaque grant management IDs

    Admin->>Web: GET confirmation for one grant
    Web->>Store: Load safe active grant by opaque ID
    Store-->>Web: Client label, scopes, approved/expiry times
    Web-->>Admin: Confirmation page

    Admin->>Web: POST confirmed revoke (session, CSRF, exact Host/Origin)
    Web->>Store: Resolve ID; tombstone family; mark family revoked
    Store-->>Web: Transaction committed
    Web-->>Admin: Settings shows Revoked
    OAuth->>Store: Validate existing token or issue refresh/code exchange
    Store-->>OAuth: Family marked used / tombstone blocks issuance
```

### System-Wide Impact

- The OAuth data model gains nonsecret administrative records, but the existing `mcp_oauth` capacity, epoch reset, credential hashing, refresh rotation, and tombstone lifetime stay authoritative.
- Every Settings mutation that can revoke MCP access has one canonical persisted-origin guard; it uses the previous saved public URL, so disabling or changing that URL cannot bypass the check.
- The new summary gives operators safer visibility without granting MCP clients visibility into other clients or their grants.

### Alternatives Considered

- **Derive the page from live access/refresh rows:** rejected because rotation, expiration, replay, and serialized credential context make the result incomplete and unsafe.
- **Use epoch rotation for a selected revoke:** rejected because it invalidates unrelated grants and registrations.
- **Expose inventory/revoke as MCP tools:** deferred because a bearer token for one client must not administer other OAuth principals.

### Sources & Research

- `docs/mcp.md` documents current OAuth ownership, storage, family tombstones, lifecycle, and required verification.
- `internal/store/mcp_oauth.go`, `internal/mcpauth/authorization.go`, `internal/mcpauth/tokens.go`, and `internal/mcpauth/resource.go` establish the current family lifecycle.
- [RFC 7009](https://www.rfc-editor.org/info/rfc7009/) supports immediate revocation of a token and related authorization-grant tokens.
- [RFC 9700](https://www.rfc-editor.org/info/rfc9700/) requires refresh-token replay detection through rotation or sender-constraining; Nori already implements rotation plus family revocation.

---

## Implementation Units

### U1. Add safe, durable OAuth registration and grant management records

**Goal:** Make approved registrations and individual grant families queryable and revocable without exposing or deriving browser data from credential records.

**Requirements:** R1, R2, R3, R6, R7, R8, R9.

**Dependencies:** None.

**Files:** `internal/store/mcp_oauth.go`, `internal/store/models.go` (if a shared view type is warranted), `internal/store/store.go`, `internal/store/mcp_settings.go`, `internal/store/mcp_oauth_test.go`, `internal/store/mcp_settings_test.go`, `internal/store/store_test.go`.

**Approach:**

1. Define Store-owned, nonsecret registration/grant projection DTOs and opaque random management IDs. Persist registration/grant projections as new namespaced `mcp_oauth.kind` values with digested keys; grant data excludes every credential-adjacent field, while its raw family relation remains only in Store columns.
2. Use the existing table's 20,000-record bound and expiry cleanup for the record kinds. Set an Active/Expired grant projection expiry to `grant expiry + 31 days`; the shared family revoke transaction sets it to `revoked_at + 31 days`, and Revoked wins over Expired. Let the existing global `DELETE FROM mcp_oauth` remove all projections atomically with raw credentials. Validate fresh and pre-feature database open paths.
3. Add one Store transaction for approved consent: check a live, current-epoch, unconsumed raw client; perform its approval/expiry extension; upsert the safe registration; insert the safe grant; check the family tombstone/capacity; insert the authorization code; then commit. It receives serialized OAuth records and safe Store DTOs, never private `mcpauth` values.
4. Add atomic Store operations to enumerate a safe ordered projection, fetch one confirmation-safe active grant by its opaque ID, and revoke exactly one grant ID. Factor one family tombstone/used-row transaction which is also called by client self-revocation, refresh/code replay, and token-issuance rollback, so all revocation paths mark the management grant Revoked.

**Execution note:** Start with store-level tests that fail for exact-one family selection and post-revoke token insertion before changing the web surface.

**Patterns to follow:** `OAuthRecord`, `PutOAuth`, and `RevokeOAuthFamily` in `internal/store/mcp_oauth.go`; transaction and migration conventions in `internal/store/mcp_settings.go` and `internal/store/store.go`.

**Test scenarios:**

- A safe list includes approved registrations and two distinct grant IDs, scopes, timestamps, and statuses without any stored credential fields.
- Revoking one active management ID tombstones and marks only that family, preserves its registration and a sibling family, and leaves MCP configuration/epoch unchanged. Covers AE1 and AE2.
- Unknown, tampered, expired, or already-revoked IDs cannot select a different family or report success.
- Two Store instances race an exchange/insert path and managed revocation; no credential in the revoked family remains usable or becomes insertable. Covers AE1.
- Closing and reopening the SQLite store preserves a revoked state and credential invalidation. Covers AE3.
- A self-revocation, refresh/code replay, and issuance rollback each make their matching safe grant Revoked rather than Active.
- Active/Expired grants purge at `grant expiry + 31 days`, revoked grants at `revoked_at + 31 days`, and status precedence is covered without unbounded summary retention.
- Opening a pre-feature database follows the idempotent migration/bootstrap path without destroying valid OAuth rows.
- A global epoch revoke still clears safe records and all live OAuth state.

**Verification:** The store returns only typed safe projections, maintains the 20,000-record bound, and proves targeted tombstoning across separate database connections.

### U2. Make consent create and maintain the grant projection atomically

**Goal:** Ensure every newly approved authorization becomes a distinct, safely listed grant without changing OAuth protocol semantics.

**Requirements:** R1, R2, R3, R6, R8, R9.

**Dependencies:** U1.

**Files:** `internal/mcpauth/authorization.go`, `internal/mcpauth/clients.go`, `internal/mcpauth/tokens.go`, `internal/mcpauth/server_test.go`, `internal/mcpauth/tokens_test.go`.

**Approach:**

1. At `decision=allow`, create the family once, capture immutable approval metadata, and call U1's exact combined Store operation that commits the approved registration, safe grant record, and authorization code together.
2. Retain a narrow `mcpauth` management facade on `web.Server`; before inventory reads it idempotently bootstraps only current-epoch, approved-client, non-tombstoned live legacy families with immutable original-scope data. Its Store transaction verifies the persisted epoch before upserting so a concurrent global reset cannot restore old access or a summary. Omit families whose only surviving scope was narrowed during refresh; do not invent historic expired/revoked entries.
3. Update the existing self-revocation, refresh/code replay, and token-issuance rollback callers in `tokens.go` to invoke U1's shared family-revocation primitive.
4. Preserve exact redirect/PKCE validation, scope normalization, client authentication, refresh narrowing, token hashes, token response shape, and the existing self-revocation endpoint.

**Execution note:** Add the OAuth flow assertions before changing consent persistence; keep tests on real temporary SQLite rather than process-local mocks.

**Patterns to follow:** Consent validation in `internal/mcpauth/authorization.go`; independent-store race coverage in `internal/mcpauth/tokens_test.go`.

**Test scenarios:**

- An approved client creates one safe Active grant with the originally approved scopes and a fixed expiry; a second authorization for the same client creates a different grant/family. Covers AE2 and AE4.
- Pending registrations remain absent from the approved inventory.
- Narrowing scope on refresh leaves the inventory's approved scopes unchanged.
- Store failure while approving returns the existing safe OAuth failure and does not leave a code/usable grant without its required management state.
- Bootstrap remains idempotent when a Settings read races global reset and never returns raw OAuth data to web.
- A legacy family whose only remaining scope is narrowed by refresh is omitted rather than represented as an original approval.
- Existing exact redirect, PKCE, Host/Origin, refresh replay, and client self-revocation behavior remains covered after the persistence change.

**Verification:** A real authorization-code flow creates a safe projection and no OAuth endpoint starts returning new management or credential fields.

### U3. Add protected confirmation and exact-one revocation handlers

**Goal:** Give an administrator a server-bound confirmation flow that revokes only the chosen grant and fails closed.

**Requirements:** R3, R4, R5, R6, R7, R8, R9.

**Dependencies:** U1, U2.

**Files:** `internal/web/server.go`, `internal/web/mcp_settings_test.go`, `internal/web/settings_test.go`.

**Approach:**

1. Retain one `mcpauth.Server` on `web.Server` or expose an equivalent narrow façade so Settings handlers receive only safe inventory/confirmation data and cannot decode generic OAuth records.
2. Load the safe projection for Settings and provide explicit empty and unavailable states. A read failure must not substitute an empty list.
3. Register an authenticated GET confirmation route and separate POST revoke/global routes. The POST reloads the opaque ID inside U1's transaction and handles cancellation, stale/not-active selection, success, and uncertain storage failure distinctly.
4. Put every destructive route in a dedicated chain ordered `session → MaxBytesReader → persisted-origin guard → CSRF → handler`. The guard reads the prior saved configuration, requires exactly one non-`null` Origin and exact configured scheme/host/port plus matching request Host, ignores `Forwarded`/`X-Forwarded-*`, and rejects missing configuration reads. Apply it to individual/global routes and a persisted-configured Settings POST whose submitted change would rotate the epoch; deliberately allow first-time configuration without a prior configured origin.

**Patterns to follow:** Settings routing and error handling in `internal/web/server.go`; double-submit CSRF tests in `internal/web/mcp_settings_test.go`; canonical-origin rules in `internal/mcpauth/server.go` and `internal/mcpauth/resource.go`.

**Test scenarios:**

- An unauthenticated Settings inventory/confirmation request redirects to login and no unauthenticated POST mutates storage.
- Missing/invalid CSRF, missing/foreign/duplicate/`null` Origin, Host/port mismatch, forwarding-header spoofing, oversized body, and malformed/unknown opaque IDs are rejected without changing a selected or global grant. Covers AE5.
- Disabling MCP or changing the configured public URL is equally origin-protected after initial setup.
- The confirmation page identifies only safe client/grant metadata; cancel does not mutate; a confirmed opaque ID revokes exactly one family. Covers AE1 and AE2.
- A write error returns a non-success response that says the connection may still be active and does not redirect with the normal saved success state.
- The existing global revoke-all remains available, correctly labeled, exact-origin protected, and broad in effect.
- An active MCP session/token for the target family fails after confirmation while a sibling family continues to operate. Covers AE1 and AE3.

**Verification:** Every destructive transition is auth + CSRF + exact-origin protected and its response accurately reflects certainty.

### U4. Render an accessible responsive grant inventory and confirmation

**Goal:** Make safe grant state understandable on desktop and mobile without nesting destructive forms or leaking sensitive metadata.

**Requirements:** R1, R2, R4, R9, R10.

**Dependencies:** U3.

**Files:** `internal/web/settings.templ`, `internal/web/static/app.css`, `internal/web/settings_test.go`, `internal/web/mcp_settings_test.go`.

**Approach:**

1. Extend the typed Settings view with safe inventory, unavailable, empty, individual-revocation success, and uncertain-error state. Keep the existing Settings-save form separate from grant actions.
2. Render one semantic registration group with a labelled heading and table per approved registration; order registrations by original approval time and grants within each registration by newest approval time, with an internal-key tie-breaker. Render client label, approved scopes, approval/expiry times, and status. Use safe opaque IDs only in action URLs/forms; do not render raw families, client IDs, redirects, or generic storage values. Treat a client label as untrusted text: rely on normal templ escaping and never interpolate it into JavaScript, a URL, or log output.
3. Use table headers/cells at wide widths and labelled field/value associations at narrow widths. Give each revoke control an accessible name containing safe client/grant context, so repeated actions remain unambiguous without visual table context.
4. Render confirmation as a focused Settings page/state with the same safe identifying fields and explicit cancel/confirm actions. Render success through an announced status and uncertain failure through an announced alert, both with a focused result heading and an explicit return-to-inventory action. Keep the global revoke-all panel visibly separate.
5. Use `.table-wrap` plus purpose-specific classes and a narrow breakpoint that turns each row into labelled, wrapping fields with a reachable action. Long client names and scopes must not force horizontal or off-screen critical content.

**Patterns to follow:** `SettingsPage` in `internal/web/settings.templ`, `.table-wrap`, `.danger-zone`, and responsive rules in `internal/web/static/app.css`; the repository's `templ` source/generation workflow.

**Test scenarios:**

- Empty inventory, active/revoked/expired status, confirmation identity, success, and uncertain failure copy are present and unambiguous.
- Rendered HTML contains no token, refresh token, code, secret, secret hash, raw family, redirect query, or credential JSON even when underlying OAuth records do. Covers AE6.
- Attacker-controlled client labels render as text, not markup or executable content.
- Multiple grants are visibly and semantically grouped under their registration; keyboard and screen-reader checks verify action context, confirmation, and success/uncertain-error announcements.
- Long client names and scope strings use wrapping/labelled responsive markup; narrow-layout classes retain value labels and a reachable action. Covers R10.
- Generated templates compile from source and existing Settings fields/global revoke controls remain rendered.

**Verification:** The page tells the administrator what will be revoked at both layout widths and all values reaching the browser are explicitly safe projections.

### U5. Document the lifecycle and run the focused verification matrix

**Goal:** Keep operational documentation aligned with individual-grant behavior and prove the finished branch across persistence, protocol, web, and race boundaries.

**Requirements:** R5, R6, R7, R8, R10, R11.

**Dependencies:** U1, U2, U3, U4.

**Files:** `docs/mcp.md`, `README.md`, `internal/store/mcp_settings_test.go`, `internal/mcpauth/server_test.go`, `internal/mcpauth/tokens_test.go`, `internal/web/mcp_settings_test.go`, `internal/web/settings_test.go`.

**Approach:**

1. Update user-facing MCP Settings documentation to distinguish disconnecting one grant from globally revoking all access, reauthorization behavior, and the fact that the UI exposes no credentials.
2. Update maintenance/security notes with the safe projection boundary, targeted tombstone invariant, origin guard, retention boundary, and verification locations.
3. Use the existing temporary SQLite, two-Store, real OAuth/MCP client, and rendered-HTML test seams rather than adding a browser-test framework solely for this issue. Perform the documented desktop/mobile visual check before PR creation.

**Patterns to follow:** The OAuth maintenance and verification sections in `docs/mcp.md`; `mcpSettingsServer`, `seedTokenGrant`, and server-rendered Settings helpers in existing tests.

**Test scenarios:**

- The complete two-client/two-family flow proves isolation, restart persistence, replay/in-flight safety, and reauthorization. Covers AE1 through AE4.
- Origin/Host/CSRF/auth rejection and uncertain-storage behavior remain non-mutating. Covers AE5.
- The rendered inventory/confirmation verifies non-disclosure and narrow/wide affordances. Covers AE6.
- Documentation statements match the final public UI labels and broad versus individual revoke behavior.

**Verification:** Documentation and targeted tests describe and prove the same credential lifecycle; no required check depends on a live Docker host.

---

## Verification Contract

- Run `make test` to regenerate templates and execute the full Go suite.
- Run `go vet ./...`.
- Run `go test -race ./internal/mcpauth ./internal/store ./internal/web ./internal/scheduler` for storage/OAuth concurrency coverage.
- Inspect the Settings inventory and confirmation at desktop and narrow mobile widths with long untrusted client labels/scopes; confirm the global revoke-all and individual revoke actions remain distinct.
- Before opening the PR, verify that the diff contains no generated `*_templ.go` files, credentials, local database files, or private planning/coordination references.

---

## Risks & Mitigation

- **Credential resurrection under a concurrent exchange:** use the established persisted tombstone predicate and prove it through two Store instances, not a process-local lock.
- **Projection status drift:** make every family-revocation path share the tombstone/used-row primitive; assert self-revocation, replay, and failed issuance each become Revoked in the safe list.
- **Cross-grant/global invalidation:** resolve a server-side opaque management ID to exactly one family inside the revoke transaction; do not use the epoch-reset API.
- **Origin-check ordering or bypass:** cap request bodies before CSRF form parsing, use the persisted configuration rather than forwarding headers, and cover duplicate/`null` Origins and Settings-driven epoch changes.
- **Browser disclosure of internal OAuth data:** create a narrow safe DTO and assert page output against every prohibited category, including redirect queries and hashes.
- **Migration/legacy data loss:** make storage setup idempotent and bootstrap only reconstructable live legacy data; test opening an old shape without deleting valid OAuth records.
- **False success on storage errors:** separate successful revoked, stale/no-active, and uncertain-error responses; the last explicitly says the connection may still be active.
- **Mobile ambiguity:** use labelled narrow rows and test wrapping with long untrusted strings before release.

---

## Definition of Done

- U1–U5 are implemented in dependency order with no abandoned metadata path, unused route, or speculative MCP tool left in the branch.
- The Settings page shows only safe approved-registration/grant metadata and provides explicit, exact-one human confirmation.
- Targeted revocation persists, is race-safe, and leaves sibling grants, registrations, pending registrations, MCP configuration, and global epoch untouched.
- Global revoke-all remains separate, broad, and protected by the same canonical mutation boundary.
- All Verification Contract commands pass and manual desktop/narrow layout inspection confirms readable values and reachable actions.
- The PR explains individual versus global revocation, links Issue #25 with the repository's normal closing syntax, and contains no private spec, automation, or local-path references.
