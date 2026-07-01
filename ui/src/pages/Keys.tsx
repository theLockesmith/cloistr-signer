import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from '../api/client';
import {
  createFrostKeyWithPhrase,
  generateFrostRecoveryPhrase,
  isValidFrostRecoveryPhrase,
  recoverFrostKey,
  migrateKeyToFrostPathA,
  FrostRecoveryWrongPhraseError,
  type CreatedFrostKey,
} from '../lib/frost';
import { listShareIds, isShareStorageUnlocked } from '../lib/frostStorage';
import type { Key, CreateKeyRequest } from '../types/api';

export function KeysPage() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [keyToDelete, setKeyToDelete] = useState<Key | null>(null);
  const [frostResult, setFrostResult] = useState<{ pubkey: string } | null>(null);
  // FROST creation runs in two stages: generate phrase → user confirms →
  // run DKG with that phrase. frostPhrase is the in-flight phrase shown
  // to the user; null when no creation is in progress.
  const [frostPhrase, setFrostPhrase] = useState<string | null>(null);
  const [frostPhraseError, setFrostPhraseError] = useState<string | null>(null);
  // Recovery flow: which existing FROST key (id + pubkey) the user is
  // trying to recover.
  const [recoveryTarget, setRecoveryTarget] = useState<Key | null>(null);
  // P7 Path A: which existing local key the user is upgrading to FROST.
  const [migrateTarget, setMigrateTarget] = useState<Key | null>(null);

  const { data: keys, isLoading } = useQuery({
    queryKey: ['keys'],
    queryFn: () => apiClient.listKeys(),
  });

  // Which FROST keys have a local share stored on this device? Loaded
  // once and refetched when the keys list changes. Empty Set means no
  // FROST shares stored here (or the user logged in via a path that
  // didn't unlock the KEK).
  const { data: localShareIds } = useQuery({
    queryKey: ['frost-local-shares', keys?.length ?? 0],
    queryFn: async () => new Set(await listShareIds()),
  });

  const storageUnlocked = isShareStorageUnlocked();

  const createMutation = useMutation({
    mutationFn: (data: CreateKeyRequest) => apiClient.createKey(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keys'] });
      setShowCreateModal(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiClient.deleteKey(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keys'] });
      setKeyToDelete(null);
    },
  });

  // FROST 2-of-N creation, stage 1: generate a phrase locally (WASM) and
  // show it to the user. No network traffic yet; the phrase isn't sent
  // anywhere. The user must explicitly confirm they've written it down
  // before stage 2 (the DKG itself) runs.
  const generatePhraseMutation = useMutation({
    mutationFn: () => generateFrostRecoveryPhrase(),
    onSuccess: (phrase) => {
      setFrostPhrase(phrase);
      setFrostPhraseError(null);
    },
    onError: (err) => {
      setFrostPhraseError(err instanceof Error ? err.message : String(err));
    },
  });

  // FROST creation, stage 2: with the phrase the user just confirmed,
  // run the 3-round DKG. Phrase becomes the seed for the deterministic
  // user-side polynomial → the resulting key is recoverable via the
  // same phrase later.
  const frostCreateMutation = useMutation({
    mutationFn: (phrase: string) => createFrostKeyWithPhrase(phrase),
    onSuccess: (result: CreatedFrostKey) => {
      queryClient.invalidateQueries({ queryKey: ['keys'] });
      queryClient.invalidateQueries({ queryKey: ['frost-local-shares'] });
      setFrostResult({ pubkey: result.pubkey });
      setFrostPhrase(null);
    },
  });

  // Recovery: re-derive the user share from a phrase + fetch the
  // signer's stored at-DKG materials, then persist to IndexedDB. Wrong
  // phrase surfaces as FrostRecoveryWrongPhraseError - the modal handles
  // that specifically so the user gets actionable feedback.
  const recoverMutation = useMutation({
    mutationFn: ({ keyId, phrase }: { keyId: string; phrase: string }) =>
      recoverFrostKey(keyId, phrase),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keys'] });
      queryClient.invalidateQueries({ queryKey: ['frost-local-shares'] });
      setRecoveryTarget(null);
    },
  });

  // P7 Path A: server splits the nsec, browser stores its half in
  // IndexedDB. Same pubkey preserved.
  const migrateMutation = useMutation({
    mutationFn: (keyId: string) => migrateKeyToFrostPathA(keyId),
    onSuccess: (result: CreatedFrostKey) => {
      queryClient.invalidateQueries({ queryKey: ['keys'] });
      queryClient.invalidateQueries({ queryKey: ['frost-local-shares'] });
      setFrostResult({ pubkey: result.pubkey });
      setMigrateTarget(null);
    },
  });

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Keys</h1>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className="btn btn-secondary"
            onClick={() => generatePhraseMutation.mutate()}
            disabled={generatePhraseMutation.isPending || frostCreateMutation.isPending}
            title="Create a 2-of-N FROST key. The signer holds one share, this browser holds the other; signing requires both. A 24-word phrase is shown for lost-device recovery."
          >
            {generatePhraseMutation.isPending
              ? '⏳ Generating phrase…'
              : frostCreateMutation.isPending
                ? '⏳ Running DKG…'
                : '🛡️ Create FROST key'}
          </button>
          <button className="btn btn-primary" onClick={() => setShowCreateModal(true)}>
            + Create Key
          </button>
        </div>
      </div>

      {(frostCreateMutation.error || frostPhraseError) && (
        <div className="auth-error" style={{ marginBottom: '16px' }}>
          FROST key creation failed:{' '}
          {frostCreateMutation.error
            ? frostCreateMutation.error instanceof Error
              ? frostCreateMutation.error.message
              : String(frostCreateMutation.error)
            : frostPhraseError}
        </div>
      )}

      {frostResult && (
        <div className="card" style={{ marginBottom: '16px', borderLeft: '3px solid var(--signer-primary)' }}>
          <div style={{ fontWeight: 500, marginBottom: '4px' }}>
            🛡️ FROST key created
          </div>
          <div style={{ fontSize: '12px', color: 'var(--signer-text-muted, #888)', marginBottom: '8px' }}>
            Pubkey:{' '}
            <code style={{ wordBreak: 'break-all' }}>{frostResult.pubkey}</code>
          </div>
          <div style={{ fontSize: '12px', color: 'var(--signer-text-muted, #888)' }}>
            The signer cannot sign with this key without this browser
            participating. Your share is stored in this browser's IndexedDB,
            encrypted under a key derived from your password (PBKDF2 + AES-GCM).
            Lose this device and recovery is via your BIP39 phrase.
          </div>
          <button
            className="btn btn-secondary"
            style={{ marginTop: '12px', padding: '4px 10px' }}
            onClick={() => setFrostResult(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {keys && keys.some((k) => k.key_type === 'frost-user') && !storageUnlocked && (
        <div className="auth-error" style={{ marginBottom: '16px' }}>
          You have FROST keys, but this session can't decrypt their shares.
          Log out and log back in with your password to unlock them.
        </div>
      )}

      {isLoading ? (
        <div className="loading-container">
          <div className="spinner" />
        </div>
      ) : keys && keys.length > 0 ? (
        <div className="key-list">
          {keys.map((key) => (
            <KeyCard
              key={key.id}
              keyData={key}
              hasLocalShare={
                key.key_type === 'frost-user' && (localShareIds?.has(key.id) ?? false)
              }
              onDelete={() => setKeyToDelete(key)}
              onRecover={() => setRecoveryTarget(key)}
              onMigrate={() => setMigrateTarget(key)}
            />
          ))}
        </div>
      ) : (
        <div className="card">
          <div className="empty-state">
            <div className="empty-state-icon">🔑</div>
            <div className="empty-state-title">No Keys Yet</div>
            <p>Create your first signing key to get started.</p>
            <button className="btn btn-primary" onClick={() => setShowCreateModal(true)}>
              Create Key
            </button>
          </div>
        </div>
      )}

      {showCreateModal && (
        <CreateKeyModal
          onClose={() => setShowCreateModal(false)}
          onCreate={(data) => createMutation.mutate(data)}
          loading={createMutation.isPending}
          error={createMutation.error?.message}
        />
      )}

      {keyToDelete && (
        <DeleteKeyModal
          keyData={keyToDelete}
          onCancel={() => {
            if (!deleteMutation.isPending) setKeyToDelete(null);
          }}
          onConfirm={() => deleteMutation.mutate(keyToDelete.id)}
          loading={deleteMutation.isPending}
          error={deleteMutation.error?.message}
        />
      )}

      {frostPhrase && (
        <FrostPhraseModal
          phrase={frostPhrase}
          onCancel={() => {
            if (!frostCreateMutation.isPending) setFrostPhrase(null);
          }}
          onConfirm={() => frostCreateMutation.mutate(frostPhrase)}
          loading={frostCreateMutation.isPending}
        />
      )}

      {migrateTarget && (
        <FrostMigrateModal
          keyData={migrateTarget}
          onCancel={() => {
            if (!migrateMutation.isPending) {
              setMigrateTarget(null);
              migrateMutation.reset();
            }
          }}
          onConfirm={() => migrateMutation.mutate(migrateTarget.id)}
          loading={migrateMutation.isPending}
          error={migrateMutation.error}
        />
      )}

      {recoveryTarget && (
        <FrostRecoveryModal
          keyData={recoveryTarget}
          onCancel={() => {
            if (!recoverMutation.isPending) {
              setRecoveryTarget(null);
              recoverMutation.reset();
            }
          }}
          onRecover={(phrase) =>
            recoverMutation.mutate({ keyId: recoveryTarget.id, phrase })
          }
          loading={recoverMutation.isPending}
          error={recoverMutation.error}
        />
      )}
    </div>
  );
}

function DeleteKeyModal({
  keyData,
  onCancel,
  onConfirm,
  loading,
  error,
}: {
  keyData: Key;
  onCancel: () => void;
  onConfirm: () => void;
  loading: boolean;
  error?: string;
}) {
  const pubkeyShort = `${keyData.pubkey.slice(0, 12)}…${keyData.pubkey.slice(-12)}`;
  return (
    <div
      className="cloistr-modal-backdrop"
      onClick={(e) => e.target === e.currentTarget && !loading && onCancel()}
    >
      <div className="cloistr-modal" style={{ maxWidth: '440px' }}>
        <div className="cloistr-modal-header">
          <h2>Delete Key</h2>
          <button className="cloistr-modal-close" onClick={onCancel} disabled={loading}>×</button>
        </div>
        <div className="cloistr-modal-content">
          {error && <div className="auth-error">{error}</div>}
          <p style={{ marginTop: 0 }}>
            Delete <strong>{keyData.name}</strong>? Any apps connected to this key will stop working,
            and the key material will be permanently removed from the signer. This cannot be undone.
          </p>
          <div style={{
            fontFamily: 'monospace',
            fontSize: '12px',
            color: 'var(--signer-text-muted)',
            background: 'var(--signer-bg)',
            padding: '8px 10px',
            borderRadius: '4px',
            wordBreak: 'break-all',
          }}>
            {pubkeyShort}
          </div>
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', marginTop: '20px' }}>
            <button type="button" className="btn btn-secondary" onClick={onCancel} disabled={loading}>
              Cancel
            </button>
            <button type="button" className="btn btn-danger" onClick={onConfirm} disabled={loading}>
              {loading ? 'Deleting…' : 'Delete Key'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function KeyCard({ keyData, hasLocalShare, onDelete, onRecover, onMigrate }: { keyData: Key; hasLocalShare: boolean; onDelete: () => void; onRecover: () => void; onMigrate: () => void }) {
  const queryClient = useQueryClient();
  const [showBunkerUrl, setShowBunkerUrl] = useState(false);
  const [bunkerUrl, setBunkerUrl] = useState<string | null>(null);
  const [bunkerError, setBunkerError] = useState<string | null>(null);
  const [bunkerLoading, setBunkerLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [disposableError, setDisposableError] = useState<string | null>(null);

  const disposableMutation = useMutation({
    mutationFn: (next: boolean) =>
      apiClient.updateKey(keyData.id, { disposable_mode: next }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keys'] });
      setDisposableError(null);
    },
    onError: (err) => {
      setDisposableError(err instanceof Error ? err.message : 'Failed to update');
    },
  });

  const coverTrafficMutation = useMutation({
    mutationFn: (next: boolean) =>
      apiClient.updateKey(keyData.id, { cover_traffic: next }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keys'] });
    },
  });

  const torEgressMutation = useMutation({
    mutationFn: (next: boolean) =>
      apiClient.updateKey(keyData.id, { tor_egress: next }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keys'] });
    },
  });

  const handleGetBunkerUrl = async () => {
    setBunkerError(null);
    setBunkerLoading(true);
    try {
      const result = await apiClient.getBunkerUrl(keyData.id);
      setBunkerUrl(result.bunker_uri);
      setShowBunkerUrl(true);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to get bunker URL';
      setBunkerError(msg);
      setShowBunkerUrl(true);
    } finally {
      setBunkerLoading(false);
    }
  };

  const copyBunkerUrl = async () => {
    if (!bunkerUrl) return;
    try {
      await navigator.clipboard.writeText(bunkerUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setBunkerError('Failed to copy to clipboard');
    }
  };

  const pubkeyShort = `${keyData.pubkey.slice(0, 12)}...${keyData.pubkey.slice(-12)}`;

  return (
    <div className="key-card">
      <div className="key-header">
        <div>
          <h3 className="key-name">{keyData.name}</h3>
          <div className="key-pubkey">{pubkeyShort}</div>
        </div>
        <div className="key-actions">
          <button className="btn btn-secondary" onClick={handleGetBunkerUrl} disabled={bunkerLoading}>
            {bunkerLoading ? '⏳ Generating…' : '🔗 Connect'}
          </button>
          <button className="btn btn-danger" onClick={onDelete} aria-label="Delete key">
            🗑️
          </button>
        </div>
      </div>

      <div className="key-meta">
        <span>
          {keyData.key_type === 'frost-user'
            ? '🛡️ FROST 2-of-N'
            : keyData.is_proxy
              ? '🔀 Proxy Key'
              : '🔑 Local Key'}
        </span>
        <span>
          {keyData.is_active ? '✅ Active' : '⏸️ Inactive'}
        </span>
        {keyData.nip05 && <span>📧 {keyData.nip05}</span>}
        {keyData.disposable_mode && <span title="Privacy guardrails enforced: refuses identity-linking kinds (0/3/10002), refuses NIP-04 DMs, strips client tags, jitters timing">🛡️ Disposable</span>}
        {keyData.key_type === 'frost-user' && (
          hasLocalShare
            ? <span title="Your FROST share is stored on this device (encrypted in IndexedDB).">✓ share on this device</span>
            : <span title="This FROST key has no share on this device. Sign in on a device that has your share, or recover via your BIP39 phrase.">⚠️ no share on this device</span>
        )}
      </div>
      {keyData.key_type === 'frost-user' && !hasLocalShare && (
        <div style={{ marginTop: '12px' }}>
          <button
            className="btn btn-secondary"
            onClick={onRecover}
            style={{ fontSize: '14px' }}
            title="Recover this FROST share on this device by entering your 24-word phrase."
          >
            🔑 Recover from phrase
          </button>
        </div>
      )}
      {(!keyData.key_type || keyData.key_type === 'local') && !keyData.is_proxy && (
        <div style={{ marginTop: '12px' }}>
          <button
            className="btn btn-secondary"
            onClick={onMigrate}
            style={{ fontSize: '14px' }}
            title="Upgrade this key to FROST 2-of-2. Pubkey is preserved; signer will no longer be able to sign without this browser."
          >
            🛡️ Upgrade to FROST
          </button>
        </div>
      )}

      <div
        style={{
          marginTop: '12px',
          padding: '10px 12px',
          background: 'var(--signer-bg)',
          borderRadius: '6px',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '10px',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 500, marginBottom: '2px' }}>
            🛡️ Disposable mode
          </div>
          <div style={{ fontSize: '12px', color: 'var(--signer-text-muted, #888)' }}>
            Refuses kind:0/3/10002 (profile, contacts, relay list) and NIP-04 DMs.
            Strips client fingerprint tags. Jitters response timing. Cryptography is
            necessary but not sufficient — behavioral hygiene is up to you.
          </div>
          {disposableError && (
            <div className="auth-error" style={{ marginTop: '8px' }}>{disposableError}</div>
          )}
        </div>
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            cursor: disposableMutation.isPending ? 'wait' : 'pointer',
            opacity: disposableMutation.isPending ? 0.6 : 1,
            whiteSpace: 'nowrap',
          }}
        >
          <input
            type="checkbox"
            checked={!!keyData.disposable_mode}
            disabled={disposableMutation.isPending}
            onChange={(e) => disposableMutation.mutate(e.target.checked)}
          />
          <span>{keyData.disposable_mode ? 'On' : 'Off'}</span>
        </label>
      </div>

      <div
        style={{
          marginTop: '8px',
          padding: '10px 12px',
          background: 'var(--signer-bg)',
          borderRadius: '6px',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '10px',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 500, marginBottom: '2px' }}>
            👻 Cover traffic
          </div>
          <div style={{ fontSize: '12px', color: 'var(--signer-text-muted, #888)' }}>
            Signer emits ephemeral NIP-17 gift-wrap decoys to this key's
            relays at randomized intervals so an observer cannot tell whether
            you are online or idle.
          </div>
        </div>
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            cursor: coverTrafficMutation.isPending ? 'wait' : 'pointer',
            opacity: coverTrafficMutation.isPending ? 0.6 : 1,
            whiteSpace: 'nowrap',
          }}
        >
          <input
            type="checkbox"
            checked={!!keyData.cover_traffic}
            disabled={coverTrafficMutation.isPending}
            onChange={(e) => coverTrafficMutation.mutate(e.target.checked)}
          />
          <span>{keyData.cover_traffic ? 'On' : 'Off'}</span>
        </label>
      </div>

      <div
        style={{
          marginTop: '8px',
          padding: '10px 12px',
          background: 'var(--signer-bg)',
          borderRadius: '6px',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '10px',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 500, marginBottom: '2px' }}>
            🧅 Tor egress
          </div>
          <div style={{ fontSize: '12px', color: 'var(--signer-text-muted, #888)' }}>
            Route outbound relay connections for this key through Tor. Flag
            is plumbed end-to-end; runtime relay-client routing is pending
            an upstream go-nostr change.
          </div>
        </div>
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            cursor: torEgressMutation.isPending ? 'wait' : 'pointer',
            opacity: torEgressMutation.isPending ? 0.6 : 1,
            whiteSpace: 'nowrap',
          }}
        >
          <input
            type="checkbox"
            checked={!!keyData.tor_egress}
            disabled={torEgressMutation.isPending}
            onChange={(e) => torEgressMutation.mutate(e.target.checked)}
          />
          <span>{keyData.tor_egress ? 'On' : 'Off'}</span>
        </label>
      </div>

      {showBunkerUrl && bunkerError && (
        <div className="auth-error" style={{ marginTop: '16px' }}>{bunkerError}</div>
      )}

      {showBunkerUrl && bunkerUrl && (
        <div style={{ marginTop: '16px', padding: '12px', background: 'var(--signer-bg)', borderRadius: '6px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontWeight: 500 }}>Bunker URL</span>
            <button className="btn btn-secondary" onClick={copyBunkerUrl} style={{ padding: '4px 8px' }}>
              {copied ? '✓ Copied' : '📋 Copy'}
            </button>
          </div>
          <code style={{ fontSize: '12px', wordBreak: 'break-all', color: 'var(--signer-primary)' }}>
            {bunkerUrl}
          </code>
        </div>
      )}
    </div>
  );
}

function CreateKeyModal({
  onClose,
  onCreate,
  loading,
  error,
}: {
  onClose: () => void;
  onCreate: (data: CreateKeyRequest) => void;
  loading: boolean;
  error?: string;
}) {
  const [name, setName] = useState('');
  const [nip05, setNip05] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onCreate({ name, nip05: nip05 || undefined });
  };

  return (
    <div className="cloistr-modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="cloistr-modal" style={{ maxWidth: '400px' }}>
        <div className="cloistr-modal-header">
          <h2>Create Key</h2>
          <button className="cloistr-modal-close" onClick={onClose}>×</button>
        </div>
        <div className="cloistr-modal-content">
          {error && <div className="auth-error">{error}</div>}

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">Name</label>
              <input
                type="text"
                className="form-input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="My Signing Key"
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">NIP-05 Identifier (optional)</label>
              <input
                type="text"
                className="form-input"
                value={nip05}
                onChange={(e) => setNip05(e.target.value)}
                placeholder="user@domain.com"
              />
            </div>

            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <button type="button" className="btn btn-secondary" onClick={onClose}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Create Key'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

// FrostPhraseModal shows the 24-word BIP39 recovery phrase to the user
// once at FROST key creation. Two gates before the DKG runs:
//   1. "I have written this down" checkbox
//   2. Confirm button (disabled until checkbox is checked)
// We deliberately avoid a "Copy" button on first reveal - encouraging
// the user to write it down on paper rather than store digitally is
// part of the user-controlled-secret threat model. They can still
// select-and-copy; we just don't make it the obvious primary action.
function FrostPhraseModal({
  phrase,
  onCancel,
  onConfirm,
  loading,
}: {
  phrase: string;
  onCancel: () => void;
  onConfirm: () => void;
  loading: boolean;
}) {
  const [confirmed, setConfirmed] = useState(false);
  const words = phrase.trim().split(/\s+/);
  return (
    <div className="modal-overlay">
      <div className="modal" style={{ maxWidth: '600px' }}>
        <div className="modal-content">
          <h2 style={{ marginTop: 0 }}>🛡️ Your FROST recovery phrase</h2>
          <p style={{ fontSize: '14px', color: 'var(--signer-text-muted, #888)', marginBottom: '12px' }}>
            Write down these 24 words in order. They are the ONLY way to
            recover this key on a new device. If you lose this browser AND
            don't have the phrase, the key is gone.
          </p>
          <p style={{ fontSize: '14px', color: 'var(--signer-text-muted, #888)', marginBottom: '16px' }}>
            The phrase never leaves this browser tab. The signer never sees it.
          </p>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: '8px',
              padding: '16px',
              background: 'var(--signer-bg)',
              borderRadius: '8px',
              marginBottom: '16px',
              fontFamily: 'monospace',
            }}
          >
            {words.map((word, i) => (
              <div key={i} style={{ display: 'flex', gap: '6px', alignItems: 'baseline' }}>
                <span style={{ color: 'var(--signer-text-muted, #888)', fontSize: '11px', minWidth: '20px', textAlign: 'right' }}>
                  {i + 1}.
                </span>
                <span style={{ fontSize: '14px' }}>{word}</span>
              </div>
            ))}
          </div>
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', marginBottom: '16px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={confirmed}
              disabled={loading}
              onChange={(e) => setConfirmed(e.target.checked)}
              style={{ marginTop: '3px' }}
            />
            <span style={{ fontSize: '14px' }}>
              I have written this phrase down somewhere safe and offline. I
              understand the signer cannot recover it for me.
            </span>
          </label>
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button type="button" className="btn btn-secondary" onClick={onCancel} disabled={loading}>
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={onConfirm}
              disabled={!confirmed || loading}
            >
              {loading ? '⏳ Running DKG…' : 'Continue → run DKG'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// FrostRecoveryModal collects a 24-word phrase and triggers the
// recoverFrostKey flow against a specific FROST key. The phrase is
// validated locally (WASM is_valid_recovery_phrase) before any network
// roundtrip so typos surface immediately.
function FrostRecoveryModal({
  keyData,
  onCancel,
  onRecover,
  loading,
  error,
}: {
  keyData: Key;
  onCancel: () => void;
  onRecover: (phrase: string) => void;
  loading: boolean;
  error: Error | null;
}) {
  const [phrase, setPhrase] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);
    const trimmed = phrase.trim().replace(/\s+/g, ' ');
    const valid = await isValidFrostRecoveryPhrase(trimmed);
    if (!valid) {
      setValidationError('Phrase is not a valid 24-word BIP39 phrase. Check word count, spelling, and order.');
      return;
    }
    onRecover(trimmed);
  };

  const wrongPhrase = error instanceof FrostRecoveryWrongPhraseError;
  const otherErrorMsg = error && !wrongPhrase
    ? (error instanceof Error ? error.message : String(error))
    : null;

  return (
    <div className="modal-overlay">
      <div className="modal" style={{ maxWidth: '600px' }}>
        <div className="modal-content">
          <h2 style={{ marginTop: 0 }}>🔑 Recover FROST share</h2>
          <p style={{ fontSize: '14px', color: 'var(--signer-text-muted, #888)', marginBottom: '8px' }}>
            For key: <code style={{ wordBreak: 'break-all' }}>{keyData.pubkey}</code>
          </p>
          <p style={{ fontSize: '14px', color: 'var(--signer-text-muted, #888)', marginBottom: '16px' }}>
            Enter the 24-word phrase you wrote down when this FROST key was
            created. The phrase reconstructs your share on this device; the
            signer cannot do this for you.
          </p>
          <form onSubmit={handleSubmit}>
            <textarea
              value={phrase}
              onChange={(e) => setPhrase(e.target.value)}
              disabled={loading}
              rows={4}
              placeholder="word1 word2 word3 …"
              style={{
                width: '100%',
                padding: '10px',
                fontFamily: 'monospace',
                fontSize: '14px',
                borderRadius: '6px',
                border: '1px solid var(--signer-border, #444)',
                background: 'var(--signer-bg)',
                color: 'var(--signer-text, #eee)',
                boxSizing: 'border-box',
                marginBottom: '12px',
              }}
            />
            {validationError && (
              <div className="auth-error" style={{ marginBottom: '12px' }}>
                {validationError}
              </div>
            )}
            {wrongPhrase && (
              <div className="auth-error" style={{ marginBottom: '12px' }}>
                That phrase does not reconstruct the share for this key.
                Double-check the words and try again.
              </div>
            )}
            {otherErrorMsg && (
              <div className="auth-error" style={{ marginBottom: '12px' }}>
                Recovery failed: {otherErrorMsg}
              </div>
            )}
            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <button type="button" className="btn btn-secondary" onClick={onCancel} disabled={loading}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading || !phrase.trim()}>
                {loading ? '⏳ Recovering…' : 'Recover'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

// FrostMigrateModal shows a confirmation gate before Path A migration.
// The user must acknowledge (a) that the pubkey is preserved,
// (b) that signing will require this browser going forward, and
// (c) that they've backed up their FROST recovery phrase somewhere
// safe (Path A doesn't generate a fresh phrase — it inherits the
// existing custody model, so this is more of an informational
// checkbox than a phrase-write-down).
function FrostMigrateModal({
  keyData,
  onCancel,
  onConfirm,
  loading,
  error,
}: {
  keyData: Key;
  onCancel: () => void;
  onConfirm: () => void;
  loading: boolean;
  error: Error | null;
}) {
  const [ack, setAck] = useState(false);
  const errMsg = error ? (error instanceof Error ? error.message : String(error)) : null;
  return (
    <div className="modal-overlay">
      <div className="modal" style={{ maxWidth: '560px' }}>
        <div className="modal-content">
          <h2 style={{ marginTop: 0 }}>🛡️ Upgrade to FROST 2-of-2</h2>
          <p style={{ fontSize: '14px', color: 'var(--signer-text-muted, #888)', marginBottom: '12px' }}>
            Key: <code style={{ wordBreak: 'break-all' }}>{keyData.pubkey}</code>
          </p>
          <div style={{ fontSize: '14px', marginBottom: '16px' }}>
            <p style={{ marginTop: 0 }}>
              This converts your existing key to a FROST 2-of-2 shape:
            </p>
            <ul style={{ paddingLeft: '20px', marginBottom: '12px' }}>
              <li>Your pubkey stays the same — followers, NIP-05, and existing app connections are unaffected.</li>
              <li>The signer will hold one share; your browser will hold the other.</li>
              <li>Signing will require this browser being open and connected. If the tab is closed, sign requests will fail with a clear error.</li>
              <li>The old private-key ciphertext is deleted after migration completes.</li>
            </ul>
            <p style={{ marginBottom: 0 }}>
              This is a one-way operation. If you want to go back, mint a fresh non-FROST key and rotate identities.
            </p>
          </div>
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', marginBottom: '16px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={ack}
              onChange={(e) => setAck(e.target.checked)}
              disabled={loading}
              style={{ marginTop: '3px' }}
            />
            <span style={{ fontSize: '14px' }}>
              I understand that after this upgrade, the signer alone cannot sign for this key. Signing requires my browser cooperating each time.
            </span>
          </label>
          {errMsg && (
            <div className="auth-error" style={{ marginBottom: '12px' }}>
              Upgrade failed: {errMsg}
            </div>
          )}
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button type="button" className="btn btn-secondary" onClick={onCancel} disabled={loading}>
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={onConfirm}
              disabled={!ack || loading}
            >
              {loading ? '⏳ Migrating…' : 'Upgrade to FROST'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
