# multi-stage build.
# Final image: scratch + statically-linked Go binary + CA certs.

FROM golang:1.22-alpine AS builder

WORKDIR /build

# Cache deps separately from source for faster rebuilds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produces a fully static binary suitable for scratch.
# Trimpath strips local file paths from the binary (smaller + non-leaky).
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /opa-adapter \
    ./cmd/opa-adapter

# ── Final image ─────────────────────────────────────────────────────

FROM scratch

COPY --from=builder /opa-adapter /opa-adapter
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Default config path; mount your own via -v / configMap.
EXPOSE 8181 9090

ENTRYPOINT ["/opa-adapter"]
CMD ["-config", "/etc/opa-adapter.yaml"]
