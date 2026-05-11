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
