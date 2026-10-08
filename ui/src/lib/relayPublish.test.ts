import { describe, it, expect, vi, afterEach } from 'vitest';
import type { Event } from 'nostr-tools';
import { PUBLISH_TIMEOUT_MS } from '@cloistr/collab-common/relay';
import { publishToRelays, RELAY_CONNECT_TIMEOUT_MS } from './relayPublish';

const event = { id: 'e', kind: 1, pubkey: 'p', sig: 's', content: '', tags: [], created_at: 0 } as Event;

function fakePool(behaviour: Record<string, 'ok' | 'hang' | 'reject' | 'noconnect'>) {
  const calls: { url: string; params?: { connectionTimeout?: number } }[] = [];
  return {
    calls,
    ensureRelay: vi.fn(async (url: string, params?: { connectionTimeout?: number }) => {
      calls.push({ url, params });
      if (behaviour[url] === 'noconnect') throw new Error('connection timed out');
      return {
        url,
        publish: () => {
          if (behaviour[url] === 'ok') return Promise.resolve('');
          if (behaviour[url] === 'reject') return Promise.reject(new Error('blocked: nope'));
          return new Promise<string>(() => {}); // never settles
        },
      };
    }),
  };
}

afterEach(() => vi.useRealTimers());

describe('publishToRelays', () => {
  it('passes a connection timeout to every relay connection', async () => {
    const pool = fakePool({ 'wss://a': 'ok' });
    await publishToRelays(pool as never, ['wss://a'], event);
    expect(pool.calls[0].params?.connectionTimeout).toBe(RELAY_CONNECT_TIMEOUT_MS);
  });

  it('gives up on a relay that never answers the publish, instead of hanging', async () => {
    vi.useFakeTimers();
    const pool = fakePool({ 'wss://ok': 'ok', 'wss://hang': 'hang' });
    const pending = publishToRelays(pool as never, ['wss://ok', 'wss://hang'], event);
    await vi.advanceTimersByTimeAsync(PUBLISH_TIMEOUT_MS + 1);
    const result = await pending;
    expect(result.published).toEqual(['wss://ok']);
    expect(result.failed.map((f) => f.relay)).toEqual(['wss://hang']);
  });

  it('reports rejected and unreachable relays as failed', async () => {
    const pool = fakePool({ 'wss://ok': 'ok', 'wss://no': 'reject', 'wss://down': 'noconnect' });
    const result = await publishToRelays(pool as never, ['wss://ok', 'wss://no', 'wss://down'], event);
    expect(result.published).toEqual(['wss://ok']);
    expect(result.failed.map((f) => f.relay).sort()).toEqual(['wss://down', 'wss://no']);
  });
});
