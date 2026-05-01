import http from 'k6/http';
import { check, sleep, fail } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const keyListDuration = new Trend('key_list_duration');
const keyGetDuration = new Trend('key_get_duration');
const statusDuration = new Trend('status_duration');
const apiFailRate = new Rate('api_failures');

// Test configuration
export const options = {
  stages: [
    { duration: '10s', target: 5 },   // Ramp up
    { duration: '60s', target: 5 },   // Sustained load
    { duration: '10s', target: 20 },  // Spike
    { duration: '30s', target: 20 },  // Sustained spike
    { duration: '10s', target: 0 },   // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],  // 95% under 500ms
    api_failures: ['rate<0.05'],        // Less than 5% failures
  },
};

const BASE_URL = __ENV.SIGNER_URL || 'http://localhost:8080';
const AUTH_TOKEN = __ENV.AUTH_TOKEN;

export function setup() {
  if (!AUTH_TOKEN) {
    console.warn('AUTH_TOKEN not set - some tests will be skipped');
  }
  return { token: AUTH_TOKEN };
}

export default function (data) {
  const headers = data.token ? { 'Authorization': `Bearer ${data.token}` } : {};

  // Test /api/v1/status (no auth required)
  const statusRes = http.get(`${BASE_URL}/api/v1/status`);

  check(statusRes, {
    'status endpoint returns 200': (r) => r.status === 200,
    'status has keys count': (r) => {
      try {
        const body = JSON.parse(r.body);
        return typeof body.keys === 'number';
      } catch {
        return false;
      }
    },
  });

  statusDuration.add(statusRes.timings.duration);
  apiFailRate.add(statusRes.status !== 200);

  // Authenticated endpoints
  if (data.token) {
    // Test /api/v1/keys
    const keysRes = http.get(`${BASE_URL}/api/v1/keys`, { headers });

    check(keysRes, {
      'keys list returns 200': (r) => r.status === 200,
      'keys response is array': (r) => {
        try {
          return Array.isArray(JSON.parse(r.body));
        } catch {
          return false;
        }
      },
    });

    keyListDuration.add(keysRes.timings.duration);
    apiFailRate.add(keysRes.status !== 200);

    // If we have keys, test getting one
    try {
      const keys = JSON.parse(keysRes.body);
      if (keys.length > 0) {
        const keyId = keys[0].id;
        const keyRes = http.get(`${BASE_URL}/api/v1/keys/${keyId}`, { headers });

        check(keyRes, {
          'get key returns 200': (r) => r.status === 200,
          'key has pubkey': (r) => {
            try {
              return JSON.parse(r.body).pubkey !== undefined;
            } catch {
              return false;
            }
          },
        });

        keyGetDuration.add(keyRes.timings.duration);
      }
    } catch (e) {
      // Ignore JSON parse errors
    }

    // Test /api/v1/requests (pending approvals)
    const requestsRes = http.get(`${BASE_URL}/api/v1/requests`, { headers });

    check(requestsRes, {
      'requests returns 200': (r) => r.status === 200,
    });
  }

  sleep(0.5);
}

export function handleSummary(data) {
  const metrics = data.metrics;
  let output = '\n=== API Endpoints Load Test Results ===\n\n';

  output += `Total Requests: ${metrics.http_reqs?.values?.count || 0}\n`;
  output += `Failed Requests: ${((metrics.api_failures?.values?.rate || 0) * 100).toFixed(2)}%\n`;
  output += `\nLatency (ms):\n`;
  output += `  Avg: ${(metrics.http_req_duration?.values?.avg || 0).toFixed(2)}\n`;
  output += `  P50: ${(metrics.http_req_duration?.values?.med || 0).toFixed(2)}\n`;
  output += `  P95: ${(metrics.http_req_duration?.values?.['p(95)'] || 0).toFixed(2)}\n`;
  output += `  P99: ${(metrics.http_req_duration?.values?.['p(99)'] || 0).toFixed(2)}\n`;

  if (metrics.key_list_duration) {
    output += `\nKey List Latency:\n`;
    output += `  Avg: ${(metrics.key_list_duration?.values?.avg || 0).toFixed(2)}ms\n`;
  }

  if (metrics.status_duration) {
    output += `\nStatus Latency:\n`;
    output += `  Avg: ${(metrics.status_duration?.values?.avg || 0).toFixed(2)}ms\n`;
  }

  return { 'stdout': output };
}
