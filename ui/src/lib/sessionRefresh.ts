/**
 * "Stay signed in until I sign out" keeps the signer's own JWT alive while the
 * UI is open. The token in localStorage has a fixed expiry; for a sliding
 * sign-in, POST /users/session/refresh hands back a fresh token and expiry. A
 * fixed-lifetime sign-in (session only, 1 day, 30 days) answers 409
 * not_sliding, and the UI stops asking.
 */
import { ApiRequestError } from '../api/client';

export type RefreshOutcome =
  | { kind: 'renewed'; token: string; expiresAt: string }
  | { kind: 'fixed' } // not a sliding sign-in: stop refreshing
  | { kind: 'ended' } // the sign-in is gone (401): stop refreshing
  | { kind: 'retry' }; // network or server trouble: try again next interval

export async function refreshOnce(
  refresh: () => Promise<{ token: string; expires_at: string }>,
): Promise<RefreshOutcome> {
  try {
    const r = await refresh();
    if (!r?.token || !r?.expires_at) return { kind: 'retry' };
    return { kind: 'renewed', token: r.token, expiresAt: r.expires_at };
  } catch (err) {
    if (err instanceof ApiRequestError) {
      if (err.status === 409 && err.code === 'not_sliding') return { kind: 'fixed' };
      if (err.status === 401) return { kind: 'ended' };
    }
    return { kind: 'retry' };
  }
}

export interface RefreshTickDeps {
  refresh: () => Promise<{ token: string; expires_at: string }>;
  /** Persist the renewed token and its expiry (the expiry is what the next page load checks). */
  save: (token: string, expiresAt: string) => void;
  /** Stop the timer: the sign-in is fixed-lifetime or gone. */
  stop: () => void;
}

/** One refresh: renew and save, stop for good, or leave it for the next interval. */
export async function runRefreshTick(deps: RefreshTickDeps): Promise<RefreshOutcome['kind']> {
  const o = await refreshOnce(deps.refresh);
  if (o.kind === 'renewed') deps.save(o.token, o.expiresAt);
  else if (o.kind === 'fixed' || o.kind === 'ended') deps.stop();
  return o.kind;
}
