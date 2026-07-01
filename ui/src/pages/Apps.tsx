import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from '../api/client';
import type { App } from '../types/api';

export function AppsPage() {
  const queryClient = useQueryClient();

  const { data: apps, isLoading } = useQuery({
    queryKey: ['apps'],
    queryFn: () => apiClient.listApps(),
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => apiClient.revokeApp(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['apps'] }),
  });

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Connected Apps</h1>
      </div>

      <ConnectAppForm />

      {isLoading ? (
        <div className="loading-container">
          <div className="spinner" />
        </div>
      ) : apps && apps.length > 0 ? (
        <div className="card">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Keys</th>
                <th>Permissions</th>
                <th>Last Used</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {apps.map((app) => (
                <AppRow
                  key={app.id}
                  app={app}
                  onRevoke={() => revokeMutation.mutate(app.id)}
                  loading={revokeMutation.isPending}
                />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="card">
          <div className="empty-state">
            <div className="empty-state-icon">📱</div>
            <div className="empty-state-title">No Connected Apps</div>
            <p>When you connect apps to your keys, they will appear here.</p>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Connect-to-App: the signer side of "Login With Cloistr". A logged-in user
 * pastes the nostrconnect:// URI an app shows them, picks a key, and approves —
 * granting that app signing authority over the key (POST /nostrconnect).
 */
function ConnectAppForm() {
  const queryClient = useQueryClient();
  const { data: keys } = useQuery({ queryKey: ['keys'], queryFn: () => apiClient.listKeys() });
  const [uri, setUri] = useState('');
  const [keyId, setKeyId] = useState('');
  const [result, setResult] = useState<string | null>(null);

  const effectiveKeyId = keyId || (keys && keys.length > 0 ? keys[0].id : '');

  const connectMutation = useMutation({
    mutationFn: (vars: { uri: string; key_id: string }) => apiClient.nostrConnect(vars),
    onSuccess: (res) => {
      setResult(`Connected ${res.app_name || 'app'}.`);
      setUri('');
      queryClient.invalidateQueries({ queryKey: ['apps'] });
    },
  });

  const canSubmit =
    uri.trim().startsWith('nostrconnect://') && !!effectiveKeyId && !connectMutation.isPending;

  return (
    <div className="card" style={{ marginBottom: '16px' }}>
      <h2 style={{ marginTop: 0 }}>Connect an App</h2>
      <p style={{ color: 'var(--signer-text-muted)', fontSize: '14px' }}>
        Paste the <code>nostrconnect://</code> link an app shows you (its "Login With Cloistr"
        option), choose a key, and approve to sign it in.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setResult(null);
          connectMutation.mutate({ uri: uri.trim(), key_id: effectiveKeyId });
        }}
        style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}
      >
        <input
          type="text"
          value={uri}
          onChange={(e) => setUri(e.target.value)}
          placeholder="nostrconnect://..."
          style={{ padding: '8px', fontFamily: 'monospace', width: '100%' }}
        />
        <select
          value={effectiveKeyId}
          onChange={(e) => setKeyId(e.target.value)}
          style={{ padding: '8px' }}
        >
          {(keys || []).map((k) => (
            <option key={k.id} value={k.id}>
              {k.name} ({k.pubkey.slice(0, 12)}...)
            </option>
          ))}
        </select>
        {connectMutation.isError && (
          <div style={{ color: 'var(--signer-danger, #c0392b)', fontSize: '13px' }}>
            {(connectMutation.error as Error).message}
          </div>
        )}
        {result && <div className="badge badge-info">{result}</div>}
        <button type="submit" className="btn btn-primary" disabled={!canSubmit}>
          {connectMutation.isPending ? 'Approving...' : 'Approve & Connect'}
        </button>
      </form>
    </div>
  );
}

function AppRow({
  app,
  onRevoke,
  loading,
}: {
  app: App;
  onRevoke: () => void;
  loading: boolean;
}) {
  const lastUsed = app.last_used
    ? new Date(app.last_used).toLocaleDateString()
    : 'Never';

  return (
    <tr>
      <td>
        <div>
          <div style={{ fontWeight: 600 }}>{app.name}</div>
          <div style={{ fontSize: '12px', color: 'var(--signer-text-muted)', fontFamily: 'monospace' }}>
            {app.pubkey.slice(0, 16)}...
          </div>
        </div>
      </td>
      <td>{app.keys.length} key(s)</td>
      <td>
        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
          {app.permissions.map((perm) => (
            <span key={perm} className="badge badge-info" style={{ fontSize: '11px' }}>
              {perm}
            </span>
          ))}
        </div>
      </td>
      <td>{lastUsed}</td>
      <td>
        <button
          className="btn btn-danger"
          onClick={onRevoke}
          disabled={loading}
          style={{ padding: '4px 12px' }}
        >
          Revoke
        </button>
      </td>
    </tr>
  );
}
