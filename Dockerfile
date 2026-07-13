# UI build stage - build the React + WASM frontend
FROM node:22-alpine AS uibuilder

WORKDIR /ui

# wasm-pack for the frost-wasm crate
RUN apk add --no-cache curl
RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Build arg for private @cloistr registry auth
ARG NPM_AEGIS_TOKEN

# Install dependencies from lockfile first for layer caching
COPY ui/package.json ui/package-lock.json ui/.npmrc ./
RUN NPM_AEGIS_TOKEN=${NPM_AEGIS_TOKEN} npm ci

# Copy source and build
COPY ui/ ./
RUN NPM_AEGIS_TOKEN=${NPM_AEGIS_TOKEN} npm run build

# Go build stage
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Copy freshly built UI dist over anything committed in the repo
# vite.config.ts outputs to ../internal/web/dist relative to ui/ → /internal/web/dist in container
COPY --from=uibuilder /internal/web/dist ./internal/web/dist

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
