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

Xray configs are private temporary files (0600); each process is terminated and
waited for, with forced kill fallback, before its config is deleted. Only
enumerated reasons are logged/submitted; Xray stdout/stderr are suppressed.
The worker handles SIGTERM/SIGINT and reaps its Xray child processes itself.
A read-only root filesystem is supported when `/tmp` is writable (e.g. a tmpfs);
no persistent volume is needed.

`dns-guard-agent --healthcheck` verifies an authenticated backend poll
completed within 180 seconds. This verifies worker progress; RU control-health
status is reported separately in the backend/UI. The healthcheck never polls or
leases extra jobs. Network failures are retried at the next polling interval.

## Build and checks

Build context is the repository root:

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dns-guard-agent ./cmd/agent
docker build --platform linux/amd64 -t dns-guard-agent .
docker run --rm --platform linux/amd64 --network none --read-only --tmpfs /tmp dns-guard-agent --self-test
```

Go 1.27.2 builds a static worker with no third-party Go dependencies. The
multi-stage build downloads only the official Linux AMD64 Xray archive and
checks the official `.dgst` SHA2-256 value before extracting only `xray`.
The default is pinned to `XRAY_VERSION=v26.3.27`. Override with a deliberately reviewed release via
`--build-arg XRAY_VERSION=v...`; prereleases are not selected automatically.
The runtime stage executes `dns-guard-agent --self-test` with the downloaded binary to check
all ten synthetic transport/security/mode profiles using `xray run -test`.
This parses configs only and does not dial the synthetic node.

The Alpine Go toolchain is shared with the backend build. Xray is downloaded in
an independent stage containing only its downloader and the reviewed version;
worker source changes reuse this stage. The stable Xray binary is copied before
the worker in independent `COPY --link` layers. BuildKit caches Go compilation
on the same builder, while CI exports ordinary layers with `type=gha,mode=max`;
cache-mount contents themselves are not exported by that layer cache. Tests and
documentation are excluded from the build context. Container self-test files
live in a build-time tmpfs and do not enter the final image.

The Go suite exercises the protocol through local HTTP servers, pinned HTTPS
connections with certificate verification and SNI, malformed and oversized
responses, control-outage result suppression, four-job concurrency, HTTPS
through a real local CONNECT proxy, private config permissions, child-process
termination and forced kill, heartbeat safety, and release checksums. The
container self-test uses the actual pinned Xray executable; generated synthetic
profiles validate configuration compatibility without contacting real nodes.
The runtime starts from `scratch` and contains only the static worker, official
static Xray executable, CA certificates, and writable temporary directory. It
has no shell or package manager and runs as numeric UID/GID `10001:10001`.
Production images and Xray downloads are AMD64-only. Native developer builds can
run on other hosts for local tests, but no ARM images are published. The agent
has no Python runtime, package installer, UI, or listener.

Official sources:

- Stable release: https://github.com/XTLS/Xray-core/releases/tag/v26.3.27
- Transport: https://xtls.github.io/en/config/transport.html
- REALITY: https://xtls.github.io/en/config/transports/reality.html
- RAW: https://xtls.github.io/en/config/transports/raw.html
- XHTTP: https://xtls.github.io/en/config/transports/xhttp.html

## CI

Every push and pull request runs Go tests and static checks, validates Compose, builds
the Docker image, and checks ten generated profiles with the actual pinned Xray
binary in a container with networking disabled. After these checks pass, `main`
publishes `latest` and `sha-<full commit SHA>` to Docker Hub. Pull requests do not
publish images. CI does not deploy to an RU host or contact production nodes.

Repository variables: `DOCKERHUB_USERNAME`, `DOCKERHUB_IMAGE`.
Repository secret: `DOCKERHUB_TOKEN` with Read & Write permissions.
Backend CI separately checks the same wire contract over HTTP. The optional
Go-to-Go suite in the backend checkout accepts an explicit local Go agent source
path; neither service needs the other repository as a runtime dependency.
