# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$TARGETPLATFORM golang:1.26-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build

WORKDIR /src
RUN apt-get update && \
    apt-get install -y --no-install-recommends libssl-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    go build -trimpath \
      -ldflags "-s -w" \
      -o /out/snagline-control ./cmd/snagline-control && \
    CGO_ENABLED=0 \
    go build -trimpath \
      -ldflags "-s -w" \
      -o /out/snagline-delivery ./cmd/snagline-delivery && \
    CGO_ENABLED=1 \
    go build -trimpath \
      -ldflags "-s -w" \
      -o /out/snagline-edge ./cmd/snagline-edge && \
    CGO_ENABLED=0 \
    go build -trimpath \
      -ldflags "-s -w" \
      -o /out/snagline-front ./cmd/snagline-front && \
    CGO_ENABLED=0 \
    go build -trimpath \
      -ldflags "-s -w" \
      -o /out/snagline-case ./cmd/snagline-case && \
    CGO_ENABLED=1 \
    go build -trimpath \
      -ldflags "-s -w" \
      -o /out/snagline-dispatcher ./cmd/snagline-dispatcher && \
    CGO_ENABLED=0 \
    go build -trimpath \
      -ldflags "-s -w" \
      -o /out/snagline-buzz-projector ./cmd/snagline-buzz-projector && \
    CGO_ENABLED=0 \
    go build -trimpath \
      -ldflags "-s -w" \
      -o /out/snagline-ssp-verify ./cmd/snagline-ssp-verify

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35 AS runtime-static
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
LABEL org.opencontainers.image.source="https://github.com/avivsinai/snagline" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.licenses="MIT"
USER nonroot:nonroot

FROM gcr.io/distroless/base-debian12:nonroot@sha256:63f52bd27b6aa6555f5d56500b70d7bb0afe51c654905be88a2c1cf967a77b1a AS runtime-sqlcipher
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
LABEL org.opencontainers.image.source="https://github.com/avivsinai/snagline" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.licenses="MIT"
USER nonroot:nonroot

FROM runtime-static AS control
COPY --from=build /out/snagline-control /usr/local/bin/snagline-control
ENTRYPOINT ["/usr/local/bin/snagline-control"]

FROM runtime-static AS delivery
COPY --from=build /out/snagline-delivery /usr/local/bin/snagline-delivery
ENTRYPOINT ["/usr/local/bin/snagline-delivery"]

FROM runtime-sqlcipher AS edge
COPY --from=build /out/snagline-edge /usr/local/bin/snagline-edge
ENTRYPOINT ["/usr/local/bin/snagline-edge"]

# snagline-front is intentionally not a container target. It must run beside
# the edge as the matching host service UID and, in AMQ mode, execute the
# operator-pinned host AMQ binary. It remains available in release archives.

FROM runtime-static AS case
COPY --from=build /out/snagline-case /usr/local/bin/snagline-case
ENTRYPOINT ["/usr/local/bin/snagline-case"]

FROM runtime-sqlcipher AS dispatcher
COPY --from=build /out/snagline-dispatcher /usr/local/bin/snagline-dispatcher
ENTRYPOINT ["/usr/local/bin/snagline-dispatcher"]

FROM runtime-static AS buzz-projector
COPY --from=build /out/snagline-buzz-projector /usr/local/bin/snagline-buzz-projector
ENTRYPOINT ["/usr/local/bin/snagline-buzz-projector"]

FROM runtime-static AS ssp-verify
COPY --from=build /out/snagline-ssp-verify /usr/local/bin/snagline-ssp-verify
ENTRYPOINT ["/usr/local/bin/snagline-ssp-verify"]
