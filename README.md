# Remnawave DNS Guard RU agent

Standalone Go worker for [DNS Guard backend](https://github.com/mitetenov/remnawave-dns-guard-backend).
The [frontend](https://github.com/mitetenov/remnawave-dns-guard-frontend) is maintained separately.

## Run with Docker Hub images

For a new installation, download only `docker-compose.yaml` and `.env`:

```sh
umask 077
mkdir -p /opt/remnawave-dns-guard-agent
cd /opt/remnawave-dns-guard-agent
curl -fsSLo docker-compose.yaml https://raw.githubusercontent.com/mitetenov/remnawave-dns-guard-agent/main/docker-compose.yaml
curl -fsSLo .env https://raw.githubusercontent.com/mitetenov/remnawave-dns-guard-agent/main/.env.example
chmod 600 .env
# Fill CONTROL_PLANE_URL and AGENT_TOKEN before starting.
docker compose config --quiet
docker compose pull
docker compose up -d
docker compose logs --tail=100 agent
```

The Compose file uses `mitetenov/remnawave-dns-guard-agent:latest` directly.
For reproducible deployment or rollback, replace the tag in `image:` with a
`sha-<full commit SHA>` tag. The published image targets Linux AMD64.

The worker loads settings through `env_file: .env`; the path is relative to
`docker-compose.yaml`. Compose checks that the file exists, and the worker
validates required values at startup. Preserve the existing `.env` when updating
an installation instead of downloading the example over it.

## RU probe worker

Run on a Linux Docker host with a Russian egress connection. The worker polls
the backend with its dedicated bearer token, validates leased jobs, and runs up
to four separate Xray processes concurrently. Auto-excluded targets remain
assigned by the backend and are probed normally. No incoming public ports,
Remnawave token, or Cloudflare token are needed.

Required environment: `CONTROL_PLANE_URL=https://guard.example.com` and
`AGENT_TOKEN` (at least 32 characters, matching backend). Optional settings:
`AGENT_ID=ru-1`, `XRAY_BIN=/usr/local/bin/xray`, comma-separated `CONTROL_URLS`
and `PROBE_URLS`. Defaults are documented in the [backend contract](https://github.com/mitetenov/remnawave-dns-guard-backend/blob/main/CONTRACT.md). Both URL
lists are explicit operator-configured allowlists of one to four HTTPS URLs.
URLs cannot contain credentials or fragments. `ALLOW_INSECURE_HTTP=true` permits
a private/plain-HTTP backend endpoint for development only; control and tunneled
probe URLs must remain HTTPS. Production direct requests validate all DNS
answers as public, connect to a validated address, and preserve certificate
verification and SNI. No redirects are followed, and bearer tokens are sent
only to the configured backend.

Every batch checks direct controls before polling and again before posting
results. At least one control must return 2xx/3xx. If the RU connection goes
unhealthy, the worker updates the backend control heartbeat and discards that
batch's results; leased jobs eventually expire without target failures. Target
results are never submitted based solely on a tunnel-independent TCP connection.
Each target must carry an HTTP(S) request through its exact IPv4 VLESS outbound.
The backend heartbeat freshness is 90 seconds, and the normal bounded batch
takes at most approximately 40 seconds after the initial heartbeat.

Supported profiles: VLESS over TCP/RAW or XHTTP, using TLS or REALITY. TCP maps to
Xray `network: raw`; contract `public_key` maps to the current REALITY `password`
key. TLS certificate verification stays enabled. XHTTP supports `auto`,
`packet-up`, `stream-up`, and `stream-one`; Vision flow is supported only for
TCP/RAW. UUID, public IPv4, port, SNI/host, REALITY key, short ID, fingerprint,
path, and mode are validated. There is no raw configuration or command endpoint.

Agent **1.1.0+** accepts optional `xhttp_extra` (a JSON object up to 16 KiB)
and passes it unchanged to `xhttpSettings.extra`. Supported fields follow the
pinned Xray v26.10.21 `SplitHTTPConfig`: padding/obfuscation, headers, upload/post
parameters and xmux. Unknown fields and non-null `downloadSettings` are rejected:
a separate download connection could bypass the job IP. Outer path/host/mode
keep their upstream Xray precedence. Legacy profiles omit `xhttp_extra`.
Upgrade the agent before the backend/frontend; updated backends lease profiles
with extra only to stable agents >=1.1.0. Pure config tests cover all eight
XHTTP TLS/REALITY modes with padding, headers and xmux.

Agent **1.2.0+** accepts optional TLS `alpn` as an ordered list and passes it
to `tlsSettings.alpn`. Empty/missing lists keep Xray defaults. Protocol IDs are
bounded printable ASCII strings; `fromMitm` and nonempty REALITY ALPN are rejected.
Updated backends lease profiles with ALPN only to stable workers >=1.2.0.
Pure config tests include Firefox + XHTTP packet-up + GET/header upload
extra + `h2,http/1.1`, using synthetic credentials and addresses. TLS certificate
verification remains enabled.

Xray configs are private temporary files (0600); each process is terminated and
waited for, with forced kill fallback, before its config is deleted. Only
enumerated reasons are submitted to the backend; Xray stdout/stderr are suppressed.
The worker handles SIGTERM/SIGINT and reaps its Xray child processes itself.
A read-only root filesystem is supported when `/tmp` is writable (e.g. a tmpfs);
no persistent volume is needed.

`dns-guard-agent --healthcheck` verifies an authenticated backend poll
completed within 180 seconds. This verifies worker progress; RU control-health
status is reported separately in the backend/UI. The healthcheck never polls or
leases extra jobs. Network failures are retried at the next polling interval.

## Request failure logs

Failed direct control checks and backend API requests emit one JSON record per
request to the container log. Successful requests are quiet. A failed control
is logged even when another control succeeds and the agent remains healthy.

```json
{"event":"request_failed","time":"2026-10-22T12:29:13Z","kind":"control","method":"GET","url":"https://ya.ru","duration_ms":5000,"phase":"dns","reason":"timeout"}
```

`kind` distinguishes `control` and `backend`; `phase` identifies DNS resolution,
TCP connection, TLS handshake, HTTP response, response-body parsing, or address
policy rejection. `reason` distinguishes timeouts, DNS lookup failures, refused
or reset connections, certificate failures, and invalid backend responses.
`http_status` is included when a response was received, for example 403 or 503.
The logs omit URL credentials, query strings, fragments, headers, request/response
bodies, and raw error text. Existing backend error codes and control-health
decisions are unchanged.

On the RU host, inspect failures with:

```sh
docker compose logs --timestamps --since 1h agent
```

## Build and checks

Build context is the repository root:

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dns-guard-agent ./cmd/agent
docker build --platform linux/amd64 -t dns-guard-agent .
```

Go 1.27.3 builds a static worker with no third-party Go dependencies. The
multi-stage build downloads only the official Linux AMD64 Xray archive and
checks the official `.dgst` SHA2-256 value before extracting only `xray`.
The default is pinned to `XRAY_VERSION=v26.10.21`. Override with a deliberately reviewed release via
`--build-arg XRAY_VERSION=v...`; prereleases are not selected automatically.

The Alpine Go toolchain is shared with the backend build. Xray is downloaded in
an independent stage containing only its downloader and the reviewed version;
worker source changes reuse this stage. The stable Xray binary is copied before
the worker in independent `COPY --link` layers. BuildKit caches Go compilation
on the same builder, while CI exports ordinary layers with `type=gha,mode=max`;
cache-mount contents themselves are not exported by that layer cache. Tests and
documentation are excluded from the build context.

The Go suite keeps isolated profile/schema, protocol and allowlist checks, release checksum tests with injected downloads, heartbeat file checks and local in-process fake HTTP/TLS adapters. Child-process/proxy tests and native Xray runtime test harnesses are removed.
The runtime starts from `scratch` and contains only the static worker, official
static Xray executable, CA certificates, and writable temporary directory. It
has no shell or package manager and runs as numeric UID/GID `10001:10001`.
Production images and Xray downloads are AMD64-only. Native developer builds can
run on other hosts for local tests, but no ARM images are published. The agent
has no Python runtime, package installer, UI, or listener.

Official sources:

- Stable release: https://github.com/XTLS/Xray-core/releases/tag/v26.10.21
- Transport: https://xtls.github.io/en/config/transport.html
- REALITY: https://xtls.github.io/en/config/transports/reality.html
- RAW: https://xtls.github.io/en/config/transports/raw.html
- XHTTP: https://xtls.github.io/en/config/transports/xhttp.html

## CI

Every push and pull request verifies modules, formatting, vet, golangci-lint, unit/race tests, production builds and Compose, then builds the AMD64 Docker image. The build downloads and verifies the pinned Xray archive but does not execute native runtime integration tests. After validation main publishes the existing latest and sha-<full commit SHA> tags. PRs do not publish or deploy.

Repository variables: `DOCKERHUB_USERNAME`, `DOCKERHUB_IMAGE`.
Repository secret: `DOCKERHUB_TOKEN` with Read & Write permissions.
Backend and agent have independent unit tests; neither service requires the other checkout for CI.

Go checks use Go 1.27.3, module verification/tidy, gofmt, vet, golangci-lint v2.15.0, unit/race tests and production builds. CI uses Ubuntu 26.04; Actions are pinned to reviewed release commits. Dependabot checks Go, Actions and Docker weekly. PR image validation never publishes; publication remains gated on the existing checks.
