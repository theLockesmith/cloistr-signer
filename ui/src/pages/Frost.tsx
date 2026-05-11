import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from '../api/client';
import type { FrostKey } from '../types/api';

export function FrostPage() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);

  const { data: frostKeys, isLoading } = useQuery({
    queryKey: ['frost-keys'],
    queryFn: () => apiClient.listFrostKeys(),
  });

  const createMutation = useMutation({
    mutationFn: ({ name, threshold, participants }: { name: string; threshold: number; participants: number }) =>
      apiClient.createFrostKey(name, threshold, participants),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['frost-keys'] });
      setShowCreateModal(false);
    },
  });

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">FROST Keys</h1>
        <button className="btn btn-primary" onClick={() => setShowCreateModal(true)}>
          + Create FROST Key
        </button>
      </div>

      <div className="card" style={{ marginBottom: '24px', padding: '16px', background: 'var(--signer-bg-tertiary)' }}>
        <strong>What is FROST?</strong>
        <p style={{ margin: '8px 0 0', color: 'var(--signer-text-muted)' }}>
          FROST (Flexible Round-Optimized Schnorr Threshold) enables threshold signatures where
          t-of-n participants must cooperate to sign. This provides enhanced security for high-value keys.
        </p>
      </div>

      {isLoading ? (
        <div className="loading-container">
          <div className="spinner" />
        </div>
      ) : frostKeys && frostKeys.length > 0 ? (
        <div className="key-list">
          {frostKeys.map((key) => (
            <FrostKeyCard key={key.id} frostKey={key} />
          ))}
        </div>
      ) : (
        <div className="card">
          <div className="empty-state">
            <div className="empty-state-icon">❄️</div>
            <div className="empty-state-title">No FROST Keys</div>
            <p>Create a threshold signing key for enhanced security.</p>
            <button className="btn btn-primary" onClick={() => setShowCreateModal(true)}>
              Create FROST Key
            </button>
          </div>
        </div>
      )}

      {showCreateModal && (
        <CreateFrostModal
          onClose={() => setShowCreateModal(false)}
          onCreate={(data) => createMutation.mutate(data)}
          loading={createMutation.isPending}
          error={createMutation.error?.message}
        />
      )}
    </div>
  );
}

function FrostKeyCard({ frostKey }: { frostKey: FrostKey }) {
  const pubkeyShort = `${frostKey.pubkey.slice(0, 12)}...${frostKey.pubkey.slice(-12)}`;

  return (
    <div className="key-card">
      <div className="key-header">
        <div>
          <h3 className="key-name">{frostKey.name}</h3>
          <div className="key-pubkey">{pubkeyShort}</div>
        </div>
        <span className={`badge ${frostKey.is_complete ? 'badge-success' : 'badge-warning'}`}>
          {frostKey.is_complete ? 'Complete' : 'Pending'}
        </span>
      </div>

      <div className="key-meta">
        <span>❄️ Threshold: {frostKey.threshold} of {frostKey.participants}</span>
        <span>👤 My Index: {frostKey.my_index}</span>
      </div>
    </div>
  );
}

function CreateFrostModal({
  onClose,
  onCreate,
  loading,
  error,
}: {
  onClose: () => void;
  onCreate: (data: { name: string; threshold: number; participants: number }) => void;
  loading: boolean;
  error?: string;
}) {
  const [name, setName] = useState('');
  const [threshold, setThreshold] = useState(2);
  const [participants, setParticipants] = useState(3);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onCreate({ name, threshold, participants });
  };

  return (
    <div className="cloistr-modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="cloistr-modal" style={{ maxWidth: '400px' }}>
        <div className="cloistr-modal-header">
          <h2>Create FROST Key</h2>
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
                placeholder="My FROST Key"
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Participants (n)</label>
              <input
                type="number"
                className="form-input"
                value={participants}
                onChange={(e) => setParticipants(parseInt(e.target.value))}
                min={2}
                max={10}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Threshold (t)</label>
              <input
                type="number"
                className="form-input"
                value={threshold}
                onChange={(e) => setThreshold(parseInt(e.target.value))}
                min={1}
                max={participants}
                required
              />
              <p style={{ fontSize: '12px', color: 'var(--signer-text-muted)', marginTop: '4px' }}>
                {threshold} of {participants} participants must sign
              </p>
            </div>

            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <button type="button" className="btn btn-secondary" onClick={onClose}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Create'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
