# syntax=docker/dockerfile:1.28.0
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24 AS toolchain
ARG TARGETARCH
ENV GOTOOLCHAIN=local
WORKDIR /src
# The runtime and official Xray release are deliberately AMD64 only.
RUN test "$TARGETARCH" = amd64 || (echo 'Only linux/amd64 images are supported' >&2; exit 1)
COPY go.mod ./

# Downloading the reviewed release depends only on the downloader and version.
# Worker source changes must not download Xray again.
FROM toolchain AS xray
COPY cmd/fetch-xray ./cmd/fetch-xray
COPY internal/xraydownload ./internal/xraydownload
ARG XRAY_VERSION=v26.10.21
RUN --mount=type=cache,id=guard-agent-go-build,target=/root/.cache/go-build \
    go run -mod=readonly ./cmd/fetch-xray --version "$XRAY_VERSION" --arch "$TARGETARCH" --destination /out/xray

FROM toolchain AS build
COPY *.go ./
COPY cmd/agent ./cmd/agent
RUN --mount=type=cache,id=guard-agent-go-build,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w -buildid=' -o /out/dns-guard-agent ./cmd/agent \
    && mkdir -p /out/tmp \
    && chmod 1777 /out/tmp

FROM scratch AS runtime
COPY --link --from=toolchain /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --link --from=build --chmod=1777 /out/tmp /tmp
COPY --link --from=xray /out/xray /usr/local/bin/xray
COPY --link --from=build /out/dns-guard-agent /usr/local/bin/dns-guard-agent
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 CMD ["/usr/local/bin/dns-guard-agent", "--healthcheck"]
# No inbound public ports. /tmp can be a tmpfs with a read-only root filesystem.
ENTRYPOINT ["/usr/local/bin/dns-guard-agent"]
