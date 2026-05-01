# Load Testing Infrastructure

k6-based load tests for cloistr-signer performance validation.

## Prerequisites

Install k6:
```bash
# macOS
brew install k6

# Linux (Debian/Ubuntu)
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6

# Docker
docker pull grafana/k6
```

## Test Scenarios

### HTTP API Tests

These test the management API (key listing, status, etc.):

```bash
# Run API health check test
k6 run scenarios/api-health.js

# Run API endpoints test (requires auth token)
AUTH_TOKEN=your-jwt-token k6 run scenarios/api-endpoints.js
```

### NIP-46 Signing Tests

These test the actual signing performance:

```bash
# Prerequisites: Set up test environment
export SIGNER_URL=http://localhost:8080
export TEST_PUBKEY=your-test-pubkey
export TEST_PRIVKEY=your-test-privkey  # Only for local testing!

# Run single signing test
k6 run scenarios/sign-event.js

# Run batch signing test
k6 run scenarios/batch-sign.js

# Run concurrent sessions test
k6 run scenarios/concurrent.js
```

## Configuration

Default configuration in each test can be overridden:

```bash
# Custom VUs and duration
k6 run --vus 50 --duration 60s scenarios/sign-event.js

# Output to JSON
k6 run --out json=results.json scenarios/sign-event.js

# Output to Prometheus
k6 run --out experimental-prometheus-rw scenarios/sign-event.js
```

## Success Criteria (from Phase 13 roadmap)

| Metric | Target |
|--------|--------|
| Concurrent signing sessions | 100 |
| Events/second sustained | 50 |
| P99 latency (single sign) | < 500ms |
| Batch vs sequential improvement | > 50% reduction in round-trips |

## Test Categories

1. **API Health** (`api-health.js`)
   - Tests /health, /health/live, /health/ready
   - Validates basic service availability

2. **API Endpoints** (`api-endpoints.js`)
   - Tests authenticated endpoints
   - Measures response times for key operations

3. **Sign Event** (`sign-event.js`)
   - Simulates NIP-46 sign_event requests via HTTP
   - Measures P50/P95/P99 latency

4. **Batch Sign** (`batch-sign.js`)
   - Tests batch_sign with varying batch sizes
   - Compares against sequential signing

5. **Concurrent Sessions** (`concurrent.js`)
   - Ramps up to 100 concurrent sessions
   - Validates system under load

## Notes

- NIP-46 tests require a running signer with keys loaded
- For accurate NIP-46 testing, use the relay-based tests (requires relay setup)
- HTTP-based tests provide simpler but less realistic measurements
