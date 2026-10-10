import { afterEach, describe, expect, it, vi } from 'vitest';
import apiClient, { ApiRequestError } from './client';

afterEach(() => vi.unstubAllGlobals());

describe('ApiClient errors', () => {
  it('carries the server error code, so the UI can act on key_locked', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: 'Your signing key is locked on this server.', code: 'key_locked' }), {
          status: 409,
        }),
      ),
    );
    const err = await apiClient.nostrConnect({ uri: 'nostrconnect://x', key_id: 'k' }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiRequestError);
    expect(err.code).toBe('key_locked');
    expect(err.status).toBe(409);
    expect(err.message).toBe('Your signing key is locked on this server.');
  });

  it('still reads a plain error without a code', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'nope' }), { status: 400 })));
    const err = await apiClient.listKeys().catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toBe('nope');
    expect(err.code).toBeUndefined();
  });
});
