import { useEffect, useRef, useState } from 'react';
import { SimplePool } from 'nostr-tools';

/**
 * Parsed fields from a kind:0 (profile metadata) event.
 */
export interface NostrProfile {
  nip05?: string;
  name?: string;
  picture?: string;
}

const DEFAULT_RELAYS = ['wss://relay.damus.io', 'wss://relay.nostr.band', 'wss://nos.lol'];

// Module-level cache: pubkey -> parsed profile. Survives re-renders and
// component remounts so we never re-fetch a profile we already have.
const profileCache = new Map<string, NostrProfile>();

/**
 * Fetch the kind:0 profile for a pubkey from relays.
 *
 * Returns the parsed content (nip05, name, picture) or null while loading.
 * The result is cached per pubkey so repeated calls with the same key
 * don't open new subscriptions.
 */
export function useNostrProfile(
  pubkey: string | undefined,
  relays: string[],
): NostrProfile | null {
  const [profile, setProfile] = useState<NostrProfile | null>(() =>
    pubkey ? profileCache.get(pubkey) ?? null : null,
  );
  const poolRef = useRef<SimplePool | null>(null);

  useEffect(() => {
    if (!pubkey) return;

    // Already cached — use it immediately.
    const cached = profileCache.get(pubkey);
    if (cached) {
      setProfile(cached);
      return;
    }

    const pool = new SimplePool();
    poolRef.current = pool;

    const effectiveRelays = relays.length > 0 ? relays : DEFAULT_RELAYS;

    // Subscribe for kind:0 authored by this pubkey. We only need the most
    // recent one (limit: 1), and we close the sub after the first EOSE.
    const sub = pool.subscribeMany(
      effectiveRelays,
      [{ kinds: [0], authors: [pubkey], limit: 1 }] as any,
      {
        onevent(event) {
          try {
            const content = JSON.parse(event.content);
            const parsed: NostrProfile = {
              nip05: content.nip05,
              name: content.name ?? content.display_name,
              picture: content.picture,
            };
            profileCache.set(pubkey, parsed);
            setProfile(parsed);
          } catch {
            // Malformed content — ignore.
          }
        },
        oneose() {
          sub.close();
        },
      },
    );

    return () => {
      sub.close();
      poolRef.current = null;
    };
  }, [pubkey, relays.join(',')]);

  return profile;
}
