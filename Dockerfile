# frost WASM stage: the browser-side FROST module, built from source with the
# same pinned toolchain and path remapping as CI (ui/frost-wasm/build.sh), so
# the module in the image is byte-identical to test:frost-wasm's build.
FROM rust:1.99.0-slim-bookworm AS wasm
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates curl >/dev/null \
 && rustup target add wasm32-unknown-unknown \
 && curl -sSfL https://github.com/rustwasm/wasm-pack/releases/download/v0.15.0/wasm-pack-v0.15.0-x86_64-unknown-linux-musl.tar.gz \
    | tar xz -C /usr/local/bin --strip-components=1 wasm-pack-v0.15.0-x86_64-unknown-linux-musl/wasm-pack
COPY ui/frost-wasm /src/ui/frost-wasm
RUN /src/ui/frost-wasm/build.sh

# UI stage: build the React SPA from ui/package-lock.json (npm ci fails if the
# lock and package.json disagree). The built dist is what the signer embeds, so
# a dependency bump in the lock changes what ships.
FROM node:20.20.2-bookworm-slim AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
# The @cloistr registry is public-read; no token is needed to install.
RUN printf '@cloistr:registry=https://git.aegis-hq.xyz/api/v4/groups/9/-/packages/npm/\n' > .npmrc \
 && npm ci --ignore-scripts --no-audit --no-fund
COPY ui/ ./
COPY --from=wasm /src/ui/frost-wasm/pkg ./frost-wasm/pkg
RUN npx tsc && npx vite build \
 && test -f /src/internal/web/dist/index.html \
 && printf '{"lockSha256":"%s"}\n' "$(sha256sum package-lock.json | cut -d' ' -f1)" > /src/internal/web/dist/ui-build.json

# Go build stage
FROM golang:1.27-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source, then the UI built above into internal/web/dist (go:embed in
# internal/web/spa.go). internal/web/dist is excluded from the build context
# (.dockerignore), so nothing committed can shadow the fresh build.
COPY . .
COPY --from=ui /src/internal/web/dist ./internal/web/dist

# Build signer and migrate binaries
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /signer ./cmd/signer
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /migrate ./cmd/migrate

# Runtime stage
FROM alpine:3.24

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
