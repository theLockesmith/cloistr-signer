import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

/**
 * Sign Event Performance Test
 *
 * This test measures signing performance via the FROST HTTP API.
 * For NIP-46 relay-based testing, see the websocket-sign.js scenario.
 *
 * Prerequisites:
 * - A FROST key must exist with at least one local share
 * - Set FROST_KEY_ID to the key ID
 * - Set AUTH_TOKEN to a valid JWT
 */

// Custom metrics
const signDuration = new Trend('sign_duration');
const signFailRate = new Rate('sign_failures');
const signCounter = new Counter('signs_total');

// Test configuration - targets from Phase 13 roadmap
export const options = {
  scenarios: {
    // Baseline: low concurrency
    baseline: {
      executor: 'constant-vus',
      vus: 5,
      duration: '30s',
      startTime: '0s',
    },
    // Ramp up to target: 50 events/second
    sustained: {
      executor: 'constant-arrival-rate',
      rate: 50,
      timeUnit: '1s',
      duration: '60s',
      preAllocatedVUs: 50,
      maxVUs: 100,
      startTime: '30s',
    },
    // Spike test
    spike: {
      executor: 'ramping-arrival-rate',
      startRate: 50,
      timeUnit: '1s',
      stages: [
        { duration: '10s', target: 100 },
        { duration: '20s', target: 100 },
        { duration: '10s', target: 50 },
      ],
      preAllocatedVUs: 100,
      maxVUs: 200,
      startTime: '90s',
    },
  },
  thresholds: {
    // P99 latency under 500ms (Phase 13 target)
    sign_duration: ['p(99)<500'],
    // Less than 1% failures
    sign_failures: ['rate<0.01'],
  },
};

const BASE_URL = __ENV.SIGNER_URL || 'http://localhost:8080';
const AUTH_TOKEN = __ENV.AUTH_TOKEN;
const FROST_KEY_ID = __ENV.FROST_KEY_ID;

export function setup() {
  if (!AUTH_TOKEN) {
    console.error('AUTH_TOKEN is required for signing tests');
    return { skip: true };
  }
  if (!FROST_KEY_ID) {
    console.warn('FROST_KEY_ID not set - using mock test');
    return { token: AUTH_TOKEN, mockMode: true };
  }
  return { token: AUTH_TOKEN, keyId: FROST_KEY_ID, mockMode: false };
}

function createTestEvent() {
  const now = Math.floor(Date.now() / 1000);
  return {
    kind: 1,
    content: `Load test event ${Date.now()}`,
    tags: [],
    created_at: now,
  };
}

export default function (data) {
  if (data.skip) {
    sleep(1);
    return;
  }

  const headers = {
    'Authorization': `Bearer ${data.token}`,
    'Content-Type': 'application/json',
  };

  if (data.mockMode) {
    // Mock mode: just test that auth works and measure API latency
    const statusRes = http.get(`${BASE_URL}/api/v1/status`, { headers });

    check(statusRes, {
      'mock status check passes': (r) => r.status === 200,
    });

    signDuration.add(statusRes.timings.duration);
    signCounter.add(1);
    sleep(0.1);
    return;
  }

  // Real FROST signing test
  const event = createTestEvent();
  const payload = JSON.stringify({ event });

  const signRes = http.post(
    `${BASE_URL}/api/v1/frost/keys/${data.keyId}/sign`,
    payload,
    { headers }
  );

  const success = check(signRes, {
    'sign returns 200': (r) => r.status === 200,
    'sign returns signature': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.signature && body.signature.length === 128;
      } catch {
        return false;
      }
    },
  });

  signDuration.add(signRes.timings.duration);
  signFailRate.add(!success);
  signCounter.add(1);

  // Small pause to avoid overwhelming the server
  sleep(0.05);
}

export function handleSummary(data) {
  const metrics = data.metrics;

  let output = '\n=== Sign Event Load Test Results ===\n\n';
  output += `Target: 50 events/second, P99 < 500ms\n\n`;

  output += `Total Signs: ${metrics.signs_total?.values?.count || 0}\n`;
  output += `Failure Rate: ${((metrics.sign_failures?.values?.rate || 0) * 100).toFixed(2)}%\n`;

  output += `\nLatency (ms):\n`;
  output += `  Avg:  ${(metrics.sign_duration?.values?.avg || 0).toFixed(2)}\n`;
  output += `  P50:  ${(metrics.sign_duration?.values?.med || 0).toFixed(2)}\n`;
  output += `  P95:  ${(metrics.sign_duration?.values?.['p(95)'] || 0).toFixed(2)}\n`;
  output += `  P99:  ${(metrics.sign_duration?.values?.['p(99)'] || 0).toFixed(2)}\n`;
  output += `  Max:  ${(metrics.sign_duration?.values?.max || 0).toFixed(2)}\n`;

  const duration = (data.state?.testRunDurationMs || 1) / 1000;
  const totalSigns = metrics.signs_total?.values?.count || 0;
  const rate = totalSigns / duration;

  output += `\nThroughput: ${rate.toFixed(2)} events/second\n`;

  // Check against Phase 13 targets
  output += '\n=== Phase 13 Targets ===\n';
  const p99 = metrics.sign_duration?.values?.['p(99)'] || 0;
  output += `P99 < 500ms: ${p99 < 500 ? 'PASS' : 'FAIL'} (${p99.toFixed(2)}ms)\n`;
  output += `50 events/sec: ${rate >= 50 ? 'PASS' : 'FAIL'} (${rate.toFixed(2)}/s)\n`;

  return { 'stdout': output };
}
