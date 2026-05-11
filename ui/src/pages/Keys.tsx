import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from '../api/client';
import type { Key, CreateKeyRequest } from '../types/api';

export function KeysPage() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);

  const { data: keys, isLoading } = useQuery({
    queryKey: ['keys'],
    queryFn: () => apiClient.listKeys(),
  });

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
    },
  });

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Keys</h1>
        <button className="btn btn-primary" onClick={() => setShowCreateModal(true)}>
          + Create Key
        </button>
      </div>

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
              onDelete={() => deleteMutation.mutate(key.id)}
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
    </div>
  );
}

function KeyCard({ keyData, onDelete }: { keyData: Key; onDelete: () => void }) {
  const [showBunkerUrl, setShowBunkerUrl] = useState(false);
  const [bunkerUrl, setBunkerUrl] = useState<string | null>(null);

  const handleGetBunkerUrl = async () => {
    try {
      const result = await apiClient.getBunkerUrl(keyData.id);
      setBunkerUrl(result.bunker_url);
      setShowBunkerUrl(true);
    } catch (err) {
      console.error('Failed to get bunker URL:', err);
    }
  };

  const copyBunkerUrl = () => {
    if (bunkerUrl) {
      navigator.clipboard.writeText(bunkerUrl);
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
          <button className="btn btn-secondary" onClick={handleGetBunkerUrl}>
            🔗 Connect
          </button>
          <button className="btn btn-danger" onClick={onDelete}>
            🗑️
          </button>
        </div>
      </div>

      <div className="key-meta">
        <span>
          {keyData.is_proxy ? '🔀 Proxy Key' : '🔑 Local Key'}
        </span>
        <span>
          {keyData.is_active ? '✅ Active' : '⏸️ Inactive'}
        </span>
        {keyData.nip05 && <span>📧 {keyData.nip05}</span>}
      </div>

      {showBunkerUrl && bunkerUrl && (
        <div style={{ marginTop: '16px', padding: '12px', background: 'var(--signer-bg)', borderRadius: '6px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontWeight: 500 }}>Bunker URL</span>
            <button className="btn btn-secondary" onClick={copyBunkerUrl} style={{ padding: '4px 8px' }}>
              📋 Copy
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
