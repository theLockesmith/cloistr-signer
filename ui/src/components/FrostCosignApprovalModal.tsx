// FROST cosign approval modal (P4e). Renders a pending cosign
// request coming from the FrostCosignListener and lets the user
// approve or deny. Self-contained; parent decides mounting/routing.

import { useState } from 'react';
import type { CosignApprovalHandle } from '../lib/frostCosignListener';

interface Props {
  handle: CosignApprovalHandle;
  onDismiss: () => void;
}

// Human-readable label for common Nostr event kinds. Falls back to
// "kind:N" for unknown values.
const KIND_LABELS: Record<number, string> = {
  0: 'Profile update (kind:0)',
  1: 'Public post (kind:1)',
  3: 'Contact list (kind:3)',
  4: 'DM (kind:4 - NIP-04)',
  6: 'Repost (kind:6)',
  7: 'Reaction (kind:7)',
  1059: 'Gift wrap / NIP-17 DM (kind:1059)',
  10002: 'Relay list (kind:10002)',
  30023: 'Long-form article (kind:30023)',
};

function labelForKind(k: number): string {
  return KIND_LABELS[k] ?? `kind:${k}`;
}

export function FrostCosignApprovalModal({ handle, onDismiss }: Props) {
  const { request } = handle;
  const [busy, setBusy] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const kindLabel = labelForKind(request.eventToSign.kind);
  const contentPreview = request.eventToSign.content.length > 240
    ? request.eventToSign.content.slice(0, 240) + '…'
    : request.eventToSign.content;

  const receivedAt = new Date(request.receivedAt);
  const ageSeconds = Math.floor((Date.now() - request.receivedAt) / 1000);

  async function doApprove() {
    setBusy(true);
    setError(null);
    try {
      await handle.approve();
      onDismiss();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function doDeny(reason: string) {
    setBusy(true);
    setError(null);
    try {
      await handle.deny(reason);
      onDismiss();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-overlay">
      <div className="modal" style={{ maxWidth: 640 }}>
        <div className="modal-content">
          <h2 style={{ marginTop: 0 }}>🛡️ Cosign request</h2>
          <p style={{ color: 'var(--signer-text-muted, #888)', fontSize: 14, marginBottom: 12 }}>
            A signer is asking your device to cosign a Nostr event for FROST key
            <code style={{ marginLeft: 6, wordBreak: 'break-all' }}>{request.keyId}</code>.
          </p>

          <div style={{ background: 'var(--signer-bg)', padding: 12, borderRadius: 8, marginBottom: 12 }}>
            <div style={{ fontSize: 14, marginBottom: 6 }}>
              <strong>{kindLabel}</strong>
            </div>
            <div style={{ fontSize: 13, color: 'var(--signer-text-muted, #888)', marginBottom: 6 }}>
              received {ageSeconds}s ago ({receivedAt.toLocaleTimeString()})
            </div>
            <div
              style={{
                fontSize: 13,
                fontFamily: 'monospace',
                background: 'rgba(0,0,0,0.15)',
                padding: 8,
                borderRadius: 4,
                whiteSpace: 'pre-wrap',
                maxHeight: 200,
                overflow: 'auto',
              }}
            >
              {contentPreview || '(no content)'}
            </div>
            {request.eventToSign.tags.length > 0 && (
              <div style={{ marginTop: 8, fontSize: 12, color: 'var(--signer-text-muted, #888)' }}>
                {request.eventToSign.tags.length} tag{request.eventToSign.tags.length === 1 ? '' : 's'}
              </div>
            )}
          </div>

          <button
            onClick={() => setShowRaw((s) => !s)}
            className="btn btn-secondary"
            style={{ fontSize: 12, padding: '4px 8px', marginBottom: 12 }}
            type="button"
          >
            {showRaw ? '▼ Hide raw event' : '▶ Show raw event'}
          </button>
          {showRaw && (
            <pre
              style={{
                fontSize: 11,
                background: 'rgba(0,0,0,0.2)',
                padding: 12,
                borderRadius: 6,
                overflow: 'auto',
                maxHeight: 200,
                marginBottom: 12,
              }}
            >
              {JSON.stringify(request.eventToSign, null, 2)}
            </pre>
          )}

          {error && (
            <div className="auth-error" style={{ marginBottom: 12 }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => doDeny('user denied')}
              disabled={busy}
            >
              {busy ? '…' : 'Deny'}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={doApprove}
              disabled={busy}
            >
              {busy ? '⏳ Signing…' : 'Approve & sign'}
            </button>
          </div>

          <div style={{ marginTop: 12, fontSize: 11, color: 'var(--signer-text-muted, #888)' }}>
            Session {request.sessionId.slice(0, 12)}… ·
            &nbsp;Event {request.eventId.slice(0, 16)}…
          </div>
        </div>
      </div>
    </div>
  );
}
