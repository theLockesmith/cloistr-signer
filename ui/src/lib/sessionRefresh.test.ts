import { describe, it, expect } from 'vitest';
import { ApiRequestError } from '../api/client';
import { refreshOnce, runRefreshTick } from './sessionRefresh';

describe('refreshOnce', () => {
  it('returns the new token and expiry', async () => {
    const o = await refreshOnce(async () => ({ token: 't2', expires_at: '2026-11-01T00:00:00Z' }));
    expect(o).toEqual({ kind: 'renewed', token: 't2', expiresAt: '2026-11-01T00:00:00Z' });
  });
  it('stops for a fixed-lifetime sign-in', async () => {
    const o = await refreshOnce(async () => { throw new ApiRequestError('fixed', 409, 'not_sliding'); });
    expect(o.kind).toBe('fixed');
  });
  it('stops when the sign-in has ended', async () => {
    const o = await refreshOnce(async () => { throw new ApiRequestError('unauthorized', 401); });
    expect(o.kind).toBe('ended');
  });
  it('retries on any other failure, including a 409 with another code', async () => {
    for (const err of [new ApiRequestError('boom', 500), new ApiRequestError('x', 409, 'other'), new TypeError('network')]) {
      expect((await refreshOnce(async () => { throw err; })).kind).toBe('retry');
    }
    expect((await refreshOnce(async () => ({}) as never)).kind).toBe('retry');
  });
});

describe('runRefreshTick', () => {
  const deps = (refresh: () => Promise<{ token: string; expires_at: string }>) => {
    const saved: [string, string][] = [];
    let stopped = 0;
    return { saved, stops: () => stopped, d: { refresh, save: (t: string, e: string) => { saved.push([t, e]); }, stop: () => { stopped++; } } };
  };
  it('saves the renewed token and expiry, keeps running', async () => {
    const x = deps(async () => ({ token: 't2', expires_at: 'e2' }));
    await runRefreshTick(x.d);
    expect(x.saved).toEqual([['t2', 'e2']]);
    expect(x.stops()).toBe(0);
  });
  it('stops on not_sliding and on 401, saving nothing', async () => {
    for (const err of [new ApiRequestError('fixed', 409, 'not_sliding'), new ApiRequestError('gone', 401)]) {
      const x = deps(async () => { throw err; });
      await runRefreshTick(x.d);
      expect(x.saved).toEqual([]);
      expect(x.stops()).toBe(1);
    }
  });
  it('neither saves nor stops on a transient failure', async () => {
    const x = deps(async () => { throw new ApiRequestError('boom', 503); });
    await runRefreshTick(x.d);
    expect(x.saved).toEqual([]);
    expect(x.stops()).toBe(0);
  });
});
