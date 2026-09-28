# Nori

Self-hosted deployment control panel for Docker-based services. Watches container
registries for new images, runs your bash deploy scripts, and provides a dashboard to
manage services.

## Why Nori?

Nori is for operators whose CI already produces container images and who want the last
mile of deployment to stay small, explicit, and easy to inspect. The registry digest
selects exactly what should run, a Bash script describes how it should be deployed, and
the dashboard or MCP interface provides a focused operational view.

- **Small and predictable** — one Go application, SQLite, and the Docker daemon you
  already operate.
- **Explicit deployments** — use ordinary Bash for container replacement, migrations,
  backups, or any service-specific step without learning a platform-specific workflow.
- **Useful automation without a platform layer** — deploy manually, immediately after
  an image update, or on a schedule.
- **Operator and agent friendly** — the same focused service model is available through
  the dashboard and the OAuth-protected MCP interface.
- **Easy to leave and easy to debug** — services remain normal Docker containers, and
  deployment behavior is visible in scripts and logs.

### Nori and Coolify

Nori and [Coolify](https://coolify.io/) both help run containerized software on your own
infrastructure, but they optimize for different operating styles. Coolify is a broad
self-hosted platform for managing the application lifecycle. Nori deliberately focuses
on the shorter path from a published image to a running service on one Docker host.

| | Nori | Coolify |
|---|---|---|
| Primary goal | A focused, transparent deployment controller | A comprehensive self-hosted application platform |
| Starting point | A container image already built by CI | Source code, Compose definitions, or container images |
| Deployment model | An explicit Bash script owned by the operator | Standardized workflows managed by the platform |
| Operational model | One Docker host with minimal supporting infrastructure | A control plane coordinating application infrastructure |
| Best fit | Operators who value simplicity, direct control, and a small trusted surface | Teams who want a platform to own more of the application lifecycle |

Choose Nori when simplicity is part of the reliability model: the build happens in CI,
the deployment remains understandable end to end, and the tool does not try to become
the infrastructure itself.

## Requirements

- Docker socket access (`/var/run/docker.sock`)
- Go 1.25+ (for building from source)
- Bash and tmux (for the browser terminal)

## Quick start

For a local binary, set the application secrets yourself:

```bash
# Generate secrets
export NORI_KEY=$(head -c 32 /dev/urandom | base64)
export NORI_SESSION_KEY=$(head -c 32 /dev/urandom | base64)
export NORI_ADMIN_HASH=$(go run ./cmd/nori hash-password 'your-password')

make build
./bin/nori
```

Open http://localhost:8080 and log in with your password.

## Docker (recommended)

The published image talks to the **host Docker daemon** via a mounted socket. This is
intentional — Nori orchestrates containers on the host by running your bash scripts
(which call `docker`). The socket mount makes Nori root-equivalent on that host, so
keep auth enabled and put Cloudflare Access (or similar) in front.

### Choose an application image

```bash
export NORI_IMAGE=registry.example.com/your-org/nori:latest
docker pull "$NORI_IMAGE"
```

### docker compose

```bash
docker compose run --rm -it launcher up \
  --image "$NORI_IMAGE" \
  --port "${NORI_PORT:-8080}:8080"
```

The first run asks for an admin password, generates the encryption and session
keys, writes them to the `nori-config` volume, and creates the long-running
`nori` container. Later `up` invocations read that saved configuration and
recreate the container without prompting or changing any secrets.

For a scripted first boot, generate the admin password hash without a local Go
install and pass it to `up`:

```bash
export NORI_ADMIN_HASH=$(docker run --rm "$NORI_IMAGE" \
  hash-password 'your-password')
docker compose run --rm launcher up \
  --image "$NORI_IMAGE" \
  --port "${NORI_PORT:-8080}:8080" \
  --admin-password-hash "$NORI_ADMIN_HASH"
```

### docker run

```bash
export IMAGE=registry.example.com/your-org/nori:latest
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v nori-config:/config \
  "$IMAGE" \
  up --image "$IMAGE"
```

Use `--data-volume`, `--config-volume`, `--container-name`, repeat `--port`,
`--no-port`, `--network`, or repeat `--env`/`--volume` at first boot to change
the defaults. The port, network, volume, and environment options can also
intentionally update an existing launch configuration. The launcher stores a
human-editable `run.json` and `nori.env` on the config volume;
`nori.env` contains plaintext secrets, so it has the same sensitive trust
boundary as `docker.sock`.

### Private-image authentication

Watching a **private** package needs registry credentials. Both the in-process
digest poll and your deploy script's `docker pull` run *inside* the Nori
container, which does not see the host user's `docker login`. Give the container
access to those credentials by mounting your Docker config with `--volume`:

```bash
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v nori-config:/config \
  "$IMAGE" up \
  --image "$IMAGE" \
  --volume "$HOME/.docker/config.json:/root/.docker/config.json:ro"
```

The mount is persisted in `run.json` and survives self-updates. This works when
`~/.docker/config.json` holds an inline `auths` token (the default after a `docker login`
on a Linux host). It does **not** work if your host uses a
credential *helper* (`credsStore`/`credHelpers`, e.g. Docker Desktop's
`desktop`), because the mounted file only references a helper binary that is
absent from the container — in that case generate a config with an inline token
and mount that instead.

### Reverse proxy

Nori serves an unauthenticated `GET /healthz` returning `200 ok` for proxy
and uptime checks.

If a Docker-aware reverse proxy routes containers using `VIRTUAL_HOST` and
`VIRTUAL_PORT`, let it own external port exposure. For an nginx-proxy
certificate companion, also set `LETSENCRYPT_HOST`. On first boot, omit the host
port mapping and persist the proxy variables with the launcher:

```bash
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v nori-config:/config \
  "$IMAGE" up \
  --image "$IMAGE" \
  --no-port \
  --env VIRTUAL_HOST=nori.example.com \
  --env VIRTUAL_PORT=8080 \
  --env LETSENCRYPT_HOST=nori.example.com
```

Add `--network your-proxy-network` when the proxy requires Nori to join a
specific Docker network. The `--env`, `--port`/`--no-port`, `--network`, and
`--volume` options also update an existing launcher configuration without
regenerating its secrets, so the same command repairs a first boot that failed
because port 8080 was already in use. These settings are retained for every
self-update.

The image ships `bash`, `tmux`, and the `docker` CLI so your deploy scripts,
launcher, and browser terminal can call Docker against the host daemon through
the mounted socket.

### Existing installations

Nori only reads `NORI_*` configuration, the `nori.env` launcher-environment
filename, and the `nori.service` container label; former `DEPLOYBOT_*` names
are not recognized. To reuse volumes created with the old defaults, select them
explicitly before running the new Compose configuration:

```bash
export NORI_CONFIG_VOLUME=deploybot-config
export NORI_DATA_VOLUME=deploybot-data
docker compose run --rm -it launcher up --image "$NORI_IMAGE"
```

Update stored service deployment scripts from
`deploybot.service` to `nori.service` and redeploy those services so Nori can
discover their containers.

An existing container started directly with `docker run` has no launcher config
volume and therefore cannot safely self-update yet. Re-bootstrap through `up`
once, passing its existing encryption key, session key, and admin hash as
`--key`, `--session-key`, and `--admin-password-hash`. This preserves encrypted
service environment values; the launcher never guesses a container's run
configuration.

## Browser terminal

The **Terminal** link opens an interactive Bash shell in the app container. It is backed
by one named tmux session, so closing the tab or losing the WebSocket connection only
detaches the browser: commands keep running and the next connection reattaches to the
same shell. Type `exit` when you intentionally want to end the session. Restarting or
replacing the container ends the shell process, while files written under `/data` remain
on the persistent volume.

The shell starts in `NORI_TERMINAL_DIR` (`.` by default and `/data` in the supplied
Docker image). Reverse proxies must support WebSocket upgrades for `/terminal/ws`.

The terminal is protected by the same admin session as the rest of the app and rejects
cross-origin WebSocket connections. It can run arbitrary commands with the app's
permissions, including use of the mounted Docker socket, so treat terminal access as
root access to the Docker host.

## Per-service configuration

Each service is configured with a watched image, one complete `.env` document, and a
Bash deployment script. The form uses code editors with syntax highlighting, line
numbers, and live validation. Invalid dotenv or Bash syntax cannot be saved, and Bash
is checked again immediately before every deployment.

The `.env` document is kept exactly as entered, including comments and blank lines. The
complete document is encrypted at rest in SQLite because any value may be sensitive.

Both editors have **Version history** with dated snapshots of saved changes. Select a
version to preview it, **Use in editor** to restore its contents into the current
form, **Copy contents** for the clipboard, or **Use in new service** to start an
unnamed service with that script or envfile. Nothing is applied until you save.
Restoring older contents creates a new version; unchanged saves do not add duplicates.
Environment history is encrypted too. Existing installations start with their current
configuration as the first version, and deleting a service removes its history.
The managed self-service versions only editable launcher environment values.

### Deployment templates

Alongside **Custom deployment script**, ordinary services can use two managed
templates: **Single container** and **Application with PostgreSQL**. Template
configuration is a versioned, non-secret JSON object stored separately from the
encrypted `.env` document. The Dashboard provides a read-only action preview;
MCP provides the same structure through `template_config` and
`preview_service_template`.

For a single container, configure an internal port, restart policy, optional
serving/proxy network, named-volume mounts, and exactly one bounded health URL
or container-local health command. Nori pulls the exact digest before changing
runtime state, verifies every deterministic resource name is already owned by
the same service, starts a candidate, and only promotes it after health passes.
On a failed start or health check it removes the candidate and leaves the
serving container in place.

The PostgreSQL template adds an explicit, non-`latest` PostgreSQL image, a
private labeled network, a persistent labeled data volume, database/user
bindings, and a bounded authenticated probe using `DATABASE_URL`. Both
`POSTGRES_DB`/`POSTGRES_USER` and the URL must agree with the structured
configuration. Nori reuses a healthy owned database on application redeploys;
it never removes its volume during application rollback. Changing the database
identity or PostgreSQL major version after initialization is a migration, not
an ordinary template edit: convert to Custom and perform that migration
deliberately.

Nori creates or adopts only resources carrying the service, template, immutable
service-ID, and role ownership labels. The configured external proxy network is
attach-only: it must already exist and is never created or deleted by Nori.
Environment values travel to Docker through its API boundary and never appear
in the preview, deployment output, or MCP responses.

**Convert to Custom** is an explicit one-way action in the service form and
through `convert_service_to_custom` in MCP. It materializes an inspectable
Bash script while preserving the encrypted environment, then stops structured
template management. Prefer Custom whenever the service needs behavior beyond
these two intentionally bounded layouts.

## Per-service contract

Each service requires two declarations in your deploy script:

1. **Watched image** — configured in the UI (e.g. `registry.example.com/you/app:latest`). This image's
   digest drives "update available" and auto-deploy.
2. **Container label** — add `--label nori.service=$SERVICE` to every `docker run`.

The app injects these variables into your script's environment on every deploy:

| Variable | Value |
|----------|-------|
| `$SERVICE` | The service name. |
| `$IMAGE` | The watched image reference, e.g. `registry.example.com/you/app:latest`. |
| `$TARGET_DIGEST` | The digest being deployed, e.g. `sha256:…`. |
| `$TARGET_IMAGE` | The digest-pinned reference `repo@sha256:…`. Pull this to deploy the exact digest. |
| `$ENV_FILE` | Path to the service's `.env`, materialized for `docker run --env-file "$ENV_FILE"`. |

Every variable from the service's `.env` document is also exported directly into the
script's shell. `$ENV_FILE` is written `0600`, holds only the service env (not the
variables above), and is removed once the deploy finishes — so pass it to the container
with `--env-file` rather than forwarding each value with `-e` by hand. Because the docker
CLI reads `--env-file` locally, this works whether Nori runs as a container or a
local binary; it does **not** write a file inside the deployed container.

Example deploy script snippet:

```bash
docker pull "$TARGET_IMAGE"
# ... backup steps ...
docker rm -f "$SERVICE" 2>/dev/null || true
docker run -d --name "$SERVICE" \
  --label nori.service="$SERVICE" \
  --env-file "$ENV_FILE" \
  "$TARGET_IMAGE"
```

## Auto-deploy policies

| Policy | Behavior |
|--------|----------|
| `manual` | Deploy only via dashboard button |
| `immediate` | Auto-deploy when registry digest changes (polled every 60s) |
| `scheduled` | Deploy on cron schedule (e.g. `0 3 * * *`) |

Schedule changes saved through the dashboard or MCP take effect on the next
scheduler refresh, normally within one second, without restarting Nori. Creating
a scheduled service adds its job; changing its cron expression replaces the job;
switching to another policy or deleting the service removes it. Unchanged jobs
keep their timing, including `@every` intervals.

If a schedule does not run, check Nori's logs for `scheduler: bad cron` and correct
the service's expression. Invalid expressions saved by older dashboard versions
are skipped and logged once per change. `scheduler: reload` indicates that the
scheduler could not read configuration; it retries on the next refresh.

## Notifications (optional)

Nori can notify external channels about four kinds of events:

- successful deployments;
- failed deployments;
- services detected as down or unhealthy by the monitor;
- service recovery after a down alert.

Messages use a distinct event marker so their status is recognizable at a
glance: ❌ for a failed deployment, 🚨 for a service outage, ✅ for a recovery,
and 🚀 for a successful deployment. SMS messages keep the operational details
compact, while Telegram messages use labeled fields for the Nori instance,
service, trigger, shortened image digest, and failure reason when applicable.
Deployment logs and environment values are never included.

Twilio SMS and Telegram are independent channels; either or both can be
enabled at the same time. The **Settings** page shows whether each channel is
configured and lets you choose per channel which events it receives. Send
failures are logged but never fail or delay a deployment, and requests to
notification providers use bounded timeouts.

### Twilio SMS

Nori sends an SMS to a preconfigured number when a deploy script exits non-zero.
A built-in monitor checks every managed service's containers (the same
`nori.service` label used by the dashboard) every `NORI_MONITOR_INTERVAL`
(default 60s). A service counts as down when no container for the service is
running and healthy (a container whose Docker HEALTHCHECK reports `unhealthy`
counts as down even while running) for two consecutive checks — so a single
transient restart does not alert, but a crash loop does. Nori then sends an SMS
when the service goes down and one recovery SMS when it comes back up. A service
that is already down when Nori starts alerts once shortly after startup.
Per-service alerts are throttled to at most one per 15 minutes. Stopping a
service from the dashboard also counts as down (it is, after all, down);
starting it again sends the recovery. Monitor down/recovery events honor the
same per-channel event routing as deploy alerts.

Each service may also set an optional **Health URL** in its service form. When
set, the monitor GETs that URL on every check and the service only counts as
up when both a container is running and the endpoint answers with a 2xx
status; an unreachable endpoint or a non-2xx response counts as down after the
same two consecutive checks, with the same alert, recovery, and throttling
rules as container state. Leave it empty to disable probing for that service.
The URL is probed from inside Nori's own container and network, so it must be
reachable from there — for example a container address on a shared Docker
network, or a port published on the host.

Configure all four env vars; leaving any blank disables SMS entirely, and a
partial set is rejected at startup:

```
NORI_TWILIO_ACCOUNT_SID=AC...
NORI_TWILIO_AUTH_TOKEN=...
NORI_TWILIO_FROM=+15551234567
NORI_TWILIO_TO=+15559876543
```

The per-service failure cooldown already prevents SMS spam during repeated
auto-deploy retries of the same digest; manual deploys are not rate-limited.

### Telegram

Telegram is the low-friction channel for routine operational updates, including
successful deployments that would be too chatty as SMS. Create a bot with
[@BotFather](https://t.me/BotFather) to get a bot token, then set:

```
NORI_TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
NORI_TELEGRAM_CHAT_ID=-1001234567890
```

The chat ID identifies the conversation that receives the messages. To find it,
message the bot once and open
`https://api.telegram.org/bot<token>/getUpdates` in a browser — the response
includes the chat's `id`. For a group or channel, add the bot as a member
(admin for channels) first; IDs of group and channel chats are negative. A
partial configuration is rejected at startup, mirroring Twilio.

Messages are delivered through Telegram's `sendMessage` Bot API with a bounded
HTTP timeout. The bot token and chat ID are never written to logs, and API
errors are logged without their secret material.

When **Settings → Public instance URL** is configured, Telegram deployment
messages include a link to the deployment details and health messages link to
the affected service. The destination still requires normal Nori login. Links
are omitted cleanly when the public URL is empty; changing it takes effect on
the next notification without restarting Nori. MCP access does not need to be
enabled for notification links.

### Event routing

The **Settings** page shows whether each channel is configured (channels are
wired through environment variables at startup, so this is read-only status)
and a checkbox matrix that routes each event kind — deploy failed, service
down or unhealthy, service recovered, deploy succeeded — to each channel
independently. For example,
keep the chatty deploy-success messages on Telegram only, while failures and
recoveries also go out as SMS. Changes take effect on the next event; no
restart needed. Clearing every checkbox for a channel silences it completely.
(The distinction matters only when editing the stored table by hand: a channel
missing from it delivers all events, while one present with every event off
delivers none.)

Channels configured but never touched in Settings deliver all events (the
historical default). A channel that appears later — say you add the Telegram
env vars after running with Twilio for a while — also starts with all events
enabled. If an installation had previously used the old `notify_mode` toggle,
its value is honored until the routing matrix is saved for the first time:
`never` keeps everything silenced, `always` and `auto-only` map to all events
enabled (the manual/auto distinction is retired).

## MCP agent access

The instance-wide **Settings → Agent access (MCP)** option enables a Streamable
HTTP MCP server at `/mcp`. It is **disabled by default**. When **Public instance
URL** is empty, the browser fills it with the current page's origin: the scheme,
hostname and port, without the path or query string. An existing value is left
unchanged. Check that this is the address both your browser and agents use to
reach Nori, especially if you opened Settings through a local address or an
alternate proxy hostname. You can edit the suggestion; with JavaScript disabled,
enter the address manually.

Select **Enabled** and click **Save settings** to persist the URL and enable MCP;
the suggestion alone does not save settings or enable access. No restart is
required. The URL must be an HTTPS origin without a path (for example
`https://nori.example.com`). HTTP is allowed only on loopback addresses for local
development.

Once enabled, the connection notes below the fields show the saved URL with
`/mcp` appended. Add that endpoint (for example `https://nori.example.com/mcp`)
to an OAuth-capable MCP client. Review the adjacent access notes and approve
only clients you trust. The client
discovers the authorization endpoints, registers itself, and opens Nori in your
browser. Sign in with the existing administrator password and approve or deny
the requested permissions. Public clients use Authorization Code with mandatory
S256 PKCE; confidential clients can use `client_secret_basic`, also with PKCE.
The `resource` parameter must be the exact public URL followed by `/mcp` during
authorization, code exchange, and refresh.

| Scope | Access |
|-------|--------|
| `nori:read` | Service configuration and status, deployment history, explicitly requested logs |
| `nori:write` | Create/update/delete services, replace environment configuration, start/stop containers, deploy |
| `nori:secrets` | Set a value for an existing environment variable; also requires `nori:write`. Never permits reading values. |

The default connection requests read and write access. Clients can explicitly
request only `nori:read` for inspection, or additionally request `nori:secrets`
to insert environment values. No scope allows reading plaintext dotenv values.
Environment files remain encrypted in SQLite.

`get_service_environment` returns a normalized dotenv template such as
`API_KEY="[REDACTED]"`. All values, including empty and non-sensitive ones, use
this placeholder; comments are omitted because they may contain secrets.
`set_service_environment` and the `env_file` fields on create/update accept only
placeholders. Saving preserves current values by variable name, removes omitted
keys, and initializes new keys to empty strings. Then use
`set_service_secret` with `service_id`, `key` (the exact variable name), and
`value` to insert a literal value. It rejects undeclared keys and returns only
success, never the value. Declare renamed keys and set their values explicitly.

MCP responses, including deployment and container logs, redact known current
dotenv values from all services. Redaction covers multiline and overlapping
values and secrets crossing the log byte limit. It cannot identify unknown,
encoded, or previously removed/rotated credentials; avoid logging credentials.
Write access can execute scripts with Nori's permissions, including control of
the Docker host. These tools do not sandbox a client granted write access.

Available tools: `list_services`, `get_service`, `create_service`,
`update_service`, `delete_service`, `start_service`, `stop_service`,
`deploy_service`, `list_deployments`, `get_deployment`, `get_container_logs`,
`get_service_environment`, `set_service_environment`, and `set_service_secret`. Tools use numeric
service IDs, validate configuration, and save service/environment changes
atomically. Creating a service defaults to manual deployment.
Concurrent configuration edits return a conflict instead of overwriting a newer
configuration; read the service again before retrying. Scheduled-service
changes are picked up within one second without restarting Nori. Deleting a
service removes its configuration/history but does not remove its containers.
The launcher-managed Nori self-service cannot be modified through MCP.

Authorization codes expire after five minutes and can be exchanged only once.
Access tokens expire after at most ten minutes, or when the grant expires if
that is sooner. Refresh tokens rotate on every use,
expire with their grant after 30 days, and reuse revokes the entire token family.
Credentials are stored as hashes. OAuth grants survive normal restarts.
**Revoke all agent access**, disabling MCP, or changing its public URL
invalidates every grant and registration; reconnect/re-register clients and
authorize again afterward. Clients can also revoke their token family through
`/oauth/revoke`. Disabling MCP stops subsequent requests; deployments already
started continue running.

Finish initial authorization within ten minutes of client registration. If it
expires, reconnect the client to register again. Approved registrations are
retained for one year from the latest consent. Concurrent refresh attempts can
trigger replay protection: the client must serialize refreshes and retain the
new refresh token before using it again.

If connection fails, check the response:

| Response | What to check |
|----------|---------------|
| `404` on `/mcp` or OAuth endpoints | MCP is enabled and the proxy routes the path to Nori. |
| `403 invalid_host` | The request's `Host`, as preserved by the proxy, must match the configured public URL. |
| `403 invalid_origin` | Consent approval/denial POSTs must originate from Nori's configured public URL. MCP requests with an `Origin` header must also use that origin. Opening the consent page with GET from another app is allowed. If a consent form sends `Origin: null`, check that a proxy has not replaced its `Referrer-Policy: same-origin` header with `no-referrer`. |
| `400 invalid_grant` | Exact resource URL, redirect URI and PKCE verifier; expired/replayed credentials require fresh authorization. |
| `401 invalid_client` | Client registration and credentials; after global revocation, register again. |
| `429 slow_down` | Respect `Retry-After`. Anonymous registration is limited separately from existing grants. |
| `503 temporarily_unavailable` | Check database health and OAuth storage capacity in the [maintenance notes](docs/mcp.md). |

When using a reverse proxy, preserve the public `Host` header and route `/mcp`,
`/oauth/*`, `/.well-known/oauth-authorization-server`, and
`/.well-known/oauth-protected-resource[/mcp]` to Nori. The configured URL is the
canonical issuer and token audience; forwarded headers do not determine it.
MCP rejects a mismatched Host and browser Origins other than the configured
origin. OAuth clients should call MCP from their backend or native process.
The configured HTTPS origin also enables Secure login cookies behind a TLS
terminating proxy. An additional proxy login must not intercept the OAuth
discovery, registration, token, or MCP requests made by the client.

The implementation uses the [official Go MCP SDK](https://github.com/modelcontextprotocol/go-sdk)
and [MCP authorization discovery and resource binding](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
For implementation boundaries, regression tests and proposed follow-ups, see
[MCP maintenance notes](docs/mcp.md).

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `NORI_KEY` | yes | Base64-encoded 32-byte AES key for encrypting secret env vars |
| `NORI_SESSION_KEY` | yes | Base64-encoded 32+ byte key for signing session cookies |
| `NORI_ADMIN_HASH` | yes | Bcrypt hash of admin password (`nori hash-password`) |
| `NORI_DB` | no | SQLite path (default: `nori.db`) |
| `NORI_LISTEN` | no | Listen address (default: `:8080`) |
| `NORI_DOCKER_HOST` | no | Docker host override |
| `NORI_TERMINAL_DIR` | no | Initial terminal directory (default: current directory; Docker image: `/data`) |
| `NORI_POLL_INTERVAL` | no | Registry poll interval (default: `60s`) |
| `NORI_MONITOR_INTERVAL` | no | Container health check interval (default: `60s`) |
| `NORI_TWILIO_ACCOUNT_SID` | no | Twilio Account SID. Set all four `NORI_TWILIO_*` to enable SMS notifications. |
| `NORI_TWILIO_AUTH_TOKEN` | no | Twilio auth token. |
| `NORI_TWILIO_FROM` | no | Sender number (Twilio-owned, E.164, e.g. `+15551234567`). |
| `NORI_TWILIO_TO` | no | Recipient number (E.164). Partial config is an error. |
| `NORI_TELEGRAM_BOT_TOKEN` | no | Bot API token from [@BotFather](https://t.me/BotFather). Set both `NORI_TELEGRAM_*` to enable Telegram notifications. |
| `NORI_TELEGRAM_CHAT_ID` | no | Target chat, group, or channel ID. Partial config is an error. |

When started by the launcher, `NORI_KEY`, `NORI_SESSION_KEY`, and
`NORI_ADMIN_HASH` are generated once and read from `/config/nori.env`.
The launcher also sets `NORI_CONFIG_VOLUME`, `NORI_SELF_CONTAINER`,
and `NORI_SELF_IMAGE`; do not set only some of these manually.

## Self-updates

Launcher-managed installations automatically add a protected **nori**
service to the dashboard. Its policy defaults to manual, so a newly published
image appears as an update that you deploy while watching. The normal deploy
history is used: after the handoff starts, the row remains `running` until the
new instance starts and verifies its own digest.

The service's **Configure** page also exposes the editable portion of
`/config/nori.env`. Launcher-managed values — `NORI_KEY`,
`NORI_SESSION_KEY`, `NORI_ADMIN_HASH`, and the self-identity variables
— are hidden, rejected if submitted, and preserved when the editable values are
saved. Other launcher environment values can be added, changed, or removed
using Docker env-file syntax. Save the configuration and then use
**Re-deploy** on the service page to restart Nori at the current image digest
with the new environment.

Deploying this service deliberately interrupts the browser connection, including
any browser terminal session. Wait for Nori to return at the same address,
then refresh its deployment history; that is when the handoff is resolved to
`success` or `failed`.

### Launcher configuration

The `nori-config` volume is the source of truth for a launcher-managed
installation:

| File | Purpose | Editing guidance |
|---|---|---|
| `/config/run.json` | Image, container name, ports, volumes, labels, restart policy, and current/previous digests | Edit only to intentionally change the launcher-owned container configuration; then run `nori up` from a detached launcher to apply it. |
| `/config/nori.env` | Application configuration and generated secrets | Treat as a secret. Do not regenerate `NORI_KEY` after the first start, or encrypted service environments become unreadable. |

Do not replace the managed self-service script or its launcher identity
variables. The launcher must remain outside Nori's container so it can
survive the container swap.

There is intentionally no health check or automatic rollback. If a self-update
leaves Nori unavailable, run a detached launcher manually with the saved
config volume, for example:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v nori-config:/config \
  "$NORI_IMAGE" rollback
```

## Maintainer notes

Start with the [approved self-update design](docs/superpowers/specs/2026-07-15-nori-self-update-design.md)
before changing this feature. The implementation is intentionally split as follows:

- `internal/launcher`: persistent config, first boot, Docker CLI swap, and rollback.
- `internal/store`: the managed `is_self` service and startup reconciliation.
- `internal/executor`: handoff-only success for the self-service; it must leave the deployment `running`.
- `cmd/nori/self.go`: startup seeding and the final digest comparison.

The non-negotiable invariants are that the launcher config remains canonical,
`NORI_KEY` is never regenerated after bootstrap, and only the replacement
instance may resolve a successful self-deployment. Keep tests around these
boundaries when extending the feature.

## Security

This app mounts `docker.sock`, making it **root-equivalent on the host**. Requirements:

- Always use authentication (enabled by default)
- Put **Cloudflare Access** (or similar) in front as a second layer
- Never expose without TLS in production
- Treat browser terminal access as unrestricted administrator access to the host

## CI recommendation

Stamp images with a readable version for the dashboard:

```yaml
- run: docker build -t registry.example.com/your-org/your-app:${VERSION} .
- run: docker tag ... :latest
```

Or set the OCI label `org.opencontainers.image.version`.

## Commands

```bash
nori                    # start server
nori hash-password PWD  # generate bcrypt hash for NORI_ADMIN_HASH
nori seed-demo          # insert a demo service row
nori up --image IMAGE   # bootstrap/recreate from launcher config
nori update --target-digest sha256:...  # swap to an image digest
nori rollback            # swap to the previous recorded digest
```

The browser editor and terminal bundles are committed, so building the Go binary does
not require a JavaScript toolchain. If you change `internal/web/editor.js` or
`internal/web/terminal.js`, rebuild them with Bun:

```bash
make assets
```
