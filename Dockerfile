# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Copy icons from submodule to static directory
RUN cp assets/icons/cloistr-signer.svg internal/web/static/favicon.svg && \
    cp assets/icons/favicon/cloistr-signer-16.svg internal/web/static/favicon-16.svg

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /signer ./cmd/signer

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -u 1000 signer
USER signer

WORKDIR /app

COPY --from=builder /signer /app/signer

EXPOSE 7777

ENTRYPOINT ["/app/signer"]
