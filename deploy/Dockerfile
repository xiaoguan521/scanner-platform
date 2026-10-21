# syntax=docker/dockerfile:1.7
#
# Build one of the three runtime targets with BuildKit:
#   docker buildx build --target server  -t <server-image>  -f deploy/Dockerfile .
#   docker buildx build --target worker  -t <worker-image>  -f deploy/Dockerfile .
#   docker buildx build --target updater -t <updater-image> -f deploy/Dockerfile .
#
# The deployment Compose file consumes the resulting image digests. It never
# builds images at runtime.

FROM golang:1.26.0-bookworm AS go-builder
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -p /out && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/sec-server ./cmd/server && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/sec-worker ./cmd/worker && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/sec-updater ./cmd/updater && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/sec-fence-launcher ./cmd/fence-launcher && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/sec-worker-supervisor ./cmd/worker-supervisor

FROM node:22.14.0-bookworm-slim AS web-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

FROM python:3.13.1-slim-bookworm AS engine-builder
ARG TARGETARCH
WORKDIR /build
COPY config/engines.lock.json config/engines.lock.json
COPY scripts/install_engines.py scripts/install_engines.py
RUN python3 scripts/install_engines.py --engine core --platform linux --arch ${TARGETARCH} --destination /opt/sec/bin

FROM debian:bookworm-slim AS runtime-base
ARG TARGETARCH
RUN apt-get update && \
    apt-get install --no-install-recommends --yes ca-certificates nftables util-linux && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system --gid 10001 sec && \
    useradd --system --uid 10001 --gid 10001 --home-dir /runtime --no-create-home sec && \
    install -d -o 10001 -g 10001 -m 0700 /runtime /runtime/worker /runtime/inputs /runtime/reports /vuln-data /opt/sec/bin /opt/sec/web
COPY --from=go-builder /out/ /opt/sec/bin/
COPY --from=engine-builder /opt/sec/bin/ /opt/sec/bin/
COPY --from=web-builder /src/web/dist/ /opt/sec/web/dist/
RUN chmod 0755 /opt/sec/bin/sec-* /opt/sec/bin/nuclei /opt/sec/bin/trivy

FROM runtime-base AS server
USER 10001:10001
ENTRYPOINT ["/opt/sec/bin/sec-server"]

FROM runtime-base AS worker
# The supervisor needs root only to create the one-shot namespace and cgroup;
# the Worker drops to uid 10001 before starting an engine.
ENTRYPOINT ["/opt/sec/bin/sec-worker-supervisor"]

FROM runtime-base AS updater
USER 10001:10001
ENTRYPOINT ["/opt/sec/bin/sec-updater"]
