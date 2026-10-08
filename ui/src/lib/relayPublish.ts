/**
 * Publish one event to several relays with every step bounded in time.
 *
 * Raw `pool.ensureRelay(url)` + `relay.publish(event)` has no timeout: a relay
 * that accepts the socket but never answers OK leaves the caller waiting
 * forever. Here the connection is bounded by RELAY_CONNECT_TIMEOUT_MS and the
 * publish by collab-common's boundedPublish (PUBLISH_TIMEOUT_MS), so the
 * worst case per relay is the sum of the two, and relays run in parallel.
 */
import type { Event } from 'nostr-tools';
import type { Relay } from 'nostr-tools/relay';
import { boundedPublish, PUBLISH_TIMEOUT_MS } from '@cloistr/collab-common/relay';

export const RELAY_CONNECT_TIMEOUT_MS = 10_000;

export interface RelayConnector {
  ensureRelay(url: string, params?: { connectionTimeout?: number }): Promise<unknown>;
}

export interface RelayPublishResult {
  published: string[];
  failed: { relay: string; reason: string }[];
}

export async function publishToRelays(
  pool: RelayConnector,
  relays: string[],
  event: Event,
  timeoutMs: number = PUBLISH_TIMEOUT_MS,
): Promise<RelayPublishResult> {
  const result: RelayPublishResult = { published: [], failed: [] };
  await Promise.all(
    relays.map(async (url) => {
      try {
        const relay = (await pool.ensureRelay(url, { connectionTimeout: RELAY_CONNECT_TIMEOUT_MS })) as Relay;
        await boundedPublish(relay, event, timeoutMs);
        result.published.push(url);
      } catch (e) {
        result.failed.push({ relay: url, reason: e instanceof Error ? e.message : String(e) });
      }
    }),
  );
  return result;
}
