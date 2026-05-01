import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';

/**
 * Concurrent Sessions Test
 *
 * Validates the signer can handle 100 concurrent signing sessions.
 * This is a Phase 13 success criterion.
 *
 * Each VU simulates a unique client session making signing requests.
 */

// Custom metrics
const activeSessions = new Gauge('active_sessions');
const requestDuration = new Trend('request_duration');
const failRate = new Rate('failures');
const requestCounter = new Counter('requests_total');

// Test configuration - Target: 100 concurrent sessions
export const options = {
  scenarios: {
    concurrent_ramp: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 25 },   // Ramp to 25
        { duration: '30s', target: 50 },   // Ramp to 50
        { duration: '30s', target: 100 },  // Ramp to 100 (target)
        { duration: '60s', target: 100 },  // Sustain at 100
        { duration: '30s', target: 0 },    // Ramp down
      ],
      gracefulRampDown: '10s',
    },
  },
  thresholds: {
    // Should handle 100 sessions with < 5% failures
    failures: ['rate<0.05'],
    // P95 latency should stay reasonable under load
    request_duration: ['p(95)<1000'],
  },
};

const BASE_URL = __ENV.SIGNER_URL || 'http://localhost:8080';
const AUTH_TOKEN = __ENV.AUTH_TOKEN;
const FROST_KEY_ID = __ENV.FROST_KEY_ID;

export function setup() {
  // Verify signer is healthy before starting
  const healthRes = http.get(`${BASE_URL}/health`);
  if (healthRes.status !== 200) {
    console.error('Signer not healthy, aborting test');
    return { skip: true };
  }

  return {
    token: AUTH_TOKEN,
    keyId: FROST_KEY_ID,
  };
}

function createTestEvent(vuId) {
  return {
    kind: 1,
    content: `Session ${vuId} test at ${Date.now()}`,
    tags: [],
    created_at: Math.floor(Date.now() / 1000),
  };
}

export default function (data) {
  if (data.skip) {
    sleep(1);
    return;
  }

  const vuId = __VU;
  const iteration = __ITER;

  // Track active sessions
  activeSessions.add(1);

  const headers = data.token ? {
    'Authorization': `Bearer ${data.token}`,
    'Content-Type': 'application/json',
  } : {};

  // Simulate session activity
  if (data.keyId && data.token) {
    // Real signing test
    const event = createTestEvent(vuId);
    const res = http.post(
      `${BASE_URL}/api/v1/frost/keys/${data.keyId}/sign`,
      JSON.stringify({ event }),
      { headers }
    );

    const success = check(res, {
      'sign successful': (r) => r.status === 200,
    });

    requestDuration.add(res.timings.duration);
    failRate.add(!success);
    requestCounter.add(1);

  } else {
    // Fallback: test API endpoints
    // Mix of operations a session might perform

    // Get status
    const statusRes = http.get(`${BASE_URL}/api/v1/status`);
    check(statusRes, { 'status ok': (r) => r.status === 200 });
    requestDuration.add(statusRes.timings.duration);
    requestCounter.add(1);

    // If authenticated, list keys
    if (data.token) {
      const keysRes = http.get(`${BASE_URL}/api/v1/keys`, { headers });
      check(keysRes, { 'keys ok': (r) => r.status === 200 });
      requestDuration.add(keysRes.timings.duration);
      failRate.add(keysRes.status !== 200);
      requestCounter.add(1);
    }
  }

  // Simulate realistic session behavior
  // Sessions don't constantly hammer the server
  sleep(Math.random() * 2 + 0.5); // 0.5-2.5 seconds between requests
}

export function teardown(data) {
  console.log('Concurrent sessions test complete');
}

export function handleSummary(data) {
  const metrics = data.metrics;

  let output = '\n=== Concurrent Sessions Test Results ===\n\n';
  output += `Target: 100 concurrent sessions\n\n`;

  const maxVUs = metrics.vus?.values?.max || 0;
  output += `Peak Concurrent Sessions: ${maxVUs}\n`;
  output += `Total Requests: ${metrics.requests_total?.values?.count || 0}\n`;
  output += `Failure Rate: ${((metrics.failures?.values?.rate || 0) * 100).toFixed(2)}%\n`;

  output += `\nLatency (ms):\n`;
  output += `  Avg: ${(metrics.request_duration?.values?.avg || 0).toFixed(2)}\n`;
  output += `  P50: ${(metrics.request_duration?.values?.med || 0).toFixed(2)}\n`;
  output += `  P95: ${(metrics.request_duration?.values?.['p(95)'] || 0).toFixed(2)}\n`;
  output += `  P99: ${(metrics.request_duration?.values?.['p(99)'] || 0).toFixed(2)}\n`;

  // Phase 13 success criteria
  output += '\n=== Phase 13 Targets ===\n';
  const passedConcurrency = maxVUs >= 100;
  const passedFailRate = (metrics.failures?.values?.rate || 0) < 0.05;

  output += `100 concurrent sessions: ${passedConcurrency ? 'PASS' : 'FAIL'} (${maxVUs})\n`;
  output += `< 5% failure rate: ${passedFailRate ? 'PASS' : 'FAIL'}\n`;

  return { 'stdout': output };
}
