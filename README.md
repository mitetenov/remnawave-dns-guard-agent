# Remnawave DNS Guard RU agent

Standalone worker for [DNS Guard backend](https://github.com/mitetenov/remnawave-dns-guard-backend).
The [frontend](https://github.com/mitetenov/remnawave-dns-guard-frontend) is maintained separately.

## Run with Docker Hub images

```sh
cp .env.example .env
chmod 600 .env
# Fill CONTROL_PLANE_URL and AGENT_TOKEN before starting.
docker compose config --quiet
docker compose pull
docker compose up -d
docker compose logs --tail=100 agent
```

Default image: `mitetenov/remnawave-dns-guard-agent:latest`. Set `AGENT_IMAGE`
in `.env` to a `sha-<full commit SHA>` tag for reproducible deployment or rollback.
The published image targets Linux AMD64.

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
Use Docker `init: true` for subprocess reaping. A read-only root filesystem is
supported when `/tmp` is writable (e.g. a tmpfs); no persistent volume is needed.

`python /app/probe_agent.py --healthcheck` verifies an authenticated backend poll
completed within 180 seconds. This verifies worker progress; RU control-health
status is reported separately in the backend/UI. The healthcheck never polls or
leases extra jobs. Network failures are retried at the next polling interval.

## Build and checks

Build context is the repository root:

```sh
docker build -t dns-guard-agent .
python -m pip install -r requirements-dev.txt
python -m pytest tests -q
```

The multi-stage build downloads the official amd64 or arm64 Xray archive and
checks the official `.dgst` SHA2-256 value before extracting only `xray`.
Default `XRAY_VERSION=v26.3.27` was verified against the official latest stable
release on 2026-10-14. Override with a deliberately reviewed release via
`--build-arg XRAY_VERSION=v...`; prereleases are not selected automatically.
The runtime stage executes `verify_xray.py` with the downloaded binary to check
all ten synthetic transport/security/mode profiles using `xray run -test`.
This parses configs only and does not dial the synthetic node.

Local verification passed 17 mocked unit tests. Docker was unavailable in the
development environment and the complete release download was blocked; actual
Xray binary config validation and image build were therefore not run locally.
The Docker build's self-test is a required executable check on a Docker-capable
host. No live tunnel, Russian network, or DNS mutation was tested.

Official sources:

- Stable release: https://github.com/XTLS/Xray-core/releases/tag/v26.3.27
- Transport: https://xtls.github.io/en/config/transport.html
- REALITY: https://xtls.github.io/en/config/transports/reality.html
- RAW: https://xtls.github.io/en/config/transports/raw.html
- XHTTP: https://xtls.github.io/en/config/transports/xhttp.html

## CI

Every push and pull request runs isolated Python tests, validates Compose, builds
the Docker image, and checks ten generated profiles with the actual pinned Xray
binary in a container with networking disabled. After these checks pass, `main`
publishes `latest` and `sha-<full commit SHA>` to Docker Hub. Pull requests do not
publish images. CI does not deploy to an RU host or contact production nodes.

Repository variables: `DOCKERHUB_USERNAME`, `DOCKERHUB_IMAGE`.
Repository secret: `DOCKERHUB_TOKEN` with Read & Write permissions.
Backend CI additionally checks the agent-to-backend protocol using this repository.
