// Wires the browser-side FROST cosign channel into the admin UI.
//
// Lifecycle:
//   1. On mount, generates (or reuses from sessionStorage) an ephemeral
//      Nostr keypair that the signer publishes cosign requests to.
//   2. Registers the ephemeral pubkey with the signer via POST
//      /api/v1/frost/cosign-listener/register so the signer knows
//      where to p-tag its kind:24135 events.
//   3. Starts the FrostCosignListener on the user's FROST-key relays.
//   4. Queues incoming approval handles for UI rendering.
//   5. On unmount / logout, stops the listener + clears the queue.

import { useEffect, useRef, useState, useCallback } from 'react';
import { generateSecretKey, getPublicKey } from 'nostr-tools';
import { FrostCosignListener } from '../lib/frostCosignListener';
import type { CosignApprovalHandle } from '../lib/frostCosignListener';
import apiClient from '../api/client';

const EPHEMERAL_STORAGE_KEY = 'cloistr-frost-cosign-ephemeral-sk';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

/**
 * Gets or lazily creates the session-scoped cosign ephemeral keypair.
 * Persisted in sessionStorage so page refreshes don't drop registrations.
 * Cleared on logout via clearCosignEphemeral().
 */
function getOrCreateCosignEphemeral(): { sk: string; pk: string } {
  const stored = sessionStorage.getItem(EPHEMERAL_STORAGE_KEY);
  if (stored) {
    try {
      const skBytes = hexToBytes(stored);
      return { sk: stored, pk: getPublicKey(skBytes) };
    } catch {
      // fall through — regenerate
    }
  }
  const skBytes = generateSecretKey();
  const sk = bytesToHex(skBytes);
  const pk = getPublicKey(skBytes);
  sessionStorage.setItem(EPHEMERAL_STORAGE_KEY, sk);
  return { sk, pk };
}

export function clearCosignEphemeral(): void {
  sessionStorage.removeItem(EPHEMERAL_STORAGE_KEY);
}

interface UseFrostCosignListenerOptions {
  /** Relays to listen on. Typically the union of relays for all of
   *  the user's FROST keys. Empty array disables the listener. */
  relays: string[];
  /** When false (e.g. not logged in), the listener is not started. */
  enabled: boolean;
}

interface UseFrostCosignListenerResult {
  /** All pending approval handles in FIFO order. */
  queue: CosignApprovalHandle[];
  /** Dismiss the head of the queue after user acts on it. */
  dismissHead: () => void;
  /** True while registration + listener start is in flight. */
  starting: boolean;
  /** Non-null if startup failed. */
  error: string | null;
}

export function useFrostCosignListener(
  opts: UseFrostCosignListenerOptions,
): UseFrostCosignListenerResult {
  const [queue, setQueue] = useState<CosignApprovalHandle[]>([]);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const listenerRef = useRef<FrostCosignListener | null>(null);

  const dismissHead = useCallback(() => {
    setQueue((q) => q.slice(1));
  }, []);

  useEffect(() => {
    if (!opts.enabled || opts.relays.length === 0) {
      // Tear down if disabled or no relays.
      if (listenerRef.current) {
        listenerRef.current.stop();
        listenerRef.current = null;
      }
      setQueue([]);
      return;
    }

    let cancelled = false;
    const { sk, pk } = getOrCreateCosignEphemeral();

    setStarting(true);
    setError(null);

    (async () => {
      try {
        // Register our ephemeral pubkey with the signer so it knows
        // where to send cosign requests.
        try {
          await apiClient.frostRegisterCosignListener(pk);
        } catch (registerErr) {
          // Registration endpoint may not exist yet; log but continue —
          // the listener still works if the signer knows the pubkey
          // by other means (e.g. hardcoded during rollout).
          console.warn(
            '[useFrostCosignListener] register failed; listener will still subscribe:',
            registerErr,
          );
        }
        if (cancelled) return;

        const listener = new FrostCosignListener({
          relays: opts.relays,
          sessionSecretKey: sk,
          onRequest: (handle) => {
            setQueue((q) => [...q, handle]);
          },
        });
        await listener.start();
        if (cancelled) {
          listener.stop();
          return;
        }
        listenerRef.current = listener;
        setStarting(false);
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
          setStarting(false);
        }
      }
    })();

    return () => {
      cancelled = true;
      if (listenerRef.current) {
        listenerRef.current.stop();
        listenerRef.current = null;
      }
    };
    // Only re-run when relay set or enabled flag changes; the SK is
    // stable across renders via sessionStorage.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opts.enabled, opts.relays.join('|')]);

  return { queue, dismissHead, starting, error };
}
