# Go build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source. This includes the committed internal/web/dist, which is the
# embedded UI (go:embed in internal/web/spa.go).
#
# IMPORTANT: the UI is NOT rebuilt in this image — it embeds the dist committed
# to the repo. When @cloistr/ui or any ui/ source changes, you MUST rebuild the
# UI locally (`cd ui && npm run build`) and commit internal/web/dist, or the
# deployed signer will ship a STALE frontend. (An in-image React+WASM build
# needs a Rust toolchain for the frost-wasm crate; wiring rustup+wasm32 into the
# build image reliably is a separate hardening task — see cloistr-signer README.)
COPY . .

# Build signer and migrate binaries
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /signer ./cmd/signer
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /migrate ./cmd/migrate

# Runtime stage
FROM alpine:3.20

# Retry logic for transient network errors
RUN for i in 1 2 3 4 5; do \
      apk add --no-cache ca-certificates tzdata && break || \
      echo "Attempt $i failed, retrying in 5s..." && sleep 5; \
    done

# Create non-root user
RUN adduser -D -u 1000 signer
USER signer

WORKDIR /app

COPY --from=builder /signer /app/signer
COPY --from=builder /migrate /app/migrate

EXPOSE 7777

ENTRYPOINT ["/app/signer"]
