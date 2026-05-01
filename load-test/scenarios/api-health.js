import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const healthCheckDuration = new Trend('health_check_duration');
const healthCheckFailRate = new Rate('health_check_failures');

// Test configuration
export const options = {
  stages: [
    { duration: '10s', target: 10 },  // Ramp up
    { duration: '30s', target: 10 },  // Stay at 10 VUs
    { duration: '10s', target: 0 },   // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<100'],  // 95% of requests under 100ms
    health_check_failures: ['rate<0.01'], // Less than 1% failures
  },
};

const BASE_URL = __ENV.SIGNER_URL || 'http://localhost:8080';

export default function () {
  // Test /health endpoint
  const healthRes = http.get(`${BASE_URL}/health`);

  check(healthRes, {
    'health status is 200': (r) => r.status === 200,
    'health response is OK': (r) => r.body === 'OK',
  });

  healthCheckDuration.add(healthRes.timings.duration);
  healthCheckFailRate.add(healthRes.status !== 200);

  // Test /health/live endpoint
  const liveRes = http.get(`${BASE_URL}/health/live`);

  check(liveRes, {
    'live status is 200': (r) => r.status === 200,
  });

  // Test /health/ready endpoint
  const readyRes = http.get(`${BASE_URL}/health/ready`);

  check(readyRes, {
    'ready status is 200': (r) => r.status === 200,
  });

  // Test /metrics endpoint (Prometheus)
  const metricsRes = http.get(`${BASE_URL}/metrics`);

  check(metricsRes, {
    'metrics status is 200': (r) => r.status === 200,
    'metrics contains coldforge': (r) => r.body.includes('coldforge_signer'),
  });

  sleep(1);
}

export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: '  ', enableColors: true }),
  };
}

function textSummary(data, opts) {
  const metrics = data.metrics;
  let output = '\n=== Health Check Load Test Results ===\n\n';

  output += `Total Requests: ${metrics.http_reqs?.values?.count || 0}\n`;
  output += `Failed Requests: ${metrics.http_req_failed?.values?.passes || 0}\n`;
  output += `Avg Duration: ${(metrics.http_req_duration?.values?.avg || 0).toFixed(2)}ms\n`;
  output += `P95 Duration: ${(metrics.http_req_duration?.values?.['p(95)'] || 0).toFixed(2)}ms\n`;
  output += `P99 Duration: ${(metrics.http_req_duration?.values?.['p(99)'] || 0).toFixed(2)}ms\n`;

  return output;
}
