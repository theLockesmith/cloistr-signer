import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import apiClient from '../api/client';
import type { Key, PendingRequest } from '../types/api';

export function DashboardPage() {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['stats'],
    queryFn: () => apiClient.getDashboardStats(),
  });

  const { data: keys } = useQuery({
    queryKey: ['keys'],
    queryFn: () => apiClient.listKeys(),
  });

  const { data: requests } = useQuery({
    queryKey: ['requests'],
    queryFn: () => apiClient.listRequests(),
  });

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Dashboard</h1>
      </div>

      {/* Stats Grid */}
      <div className="stats-grid">
        <StatCard
          value={stats?.total_keys ?? 0}
          label="Total Keys"
          icon="🔑"
          loading={statsLoading}
        />
        <StatCard
          value={stats?.pending_requests ?? 0}
          label="Pending Requests"
          icon="📋"
          loading={statsLoading}
          highlight={stats?.pending_requests ? true : false}
        />
        <StatCard
          value={stats?.total_apps ?? 0}
          label="Connected Apps"
          icon="📱"
          loading={statsLoading}
        />
        <StatCard
          value={stats?.active_sessions ?? 0}
          label="Active Sessions"
          icon="⚡"
          loading={statsLoading}
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        {/* Recent Keys */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Recent Keys</h2>
            <Link to="/keys" className="btn btn-secondary" style={{ fontSize: '13px' }}>
              View All
            </Link>
          </div>

          {keys && keys.length > 0 ? (
            <div className="key-list" style={{ gap: '12px' }}>
              {keys.slice(0, 3).map((key) => (
                <KeyPreview key={key.id} keyData={key} />
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <p>No keys yet</p>
              <Link to="/keys" className="btn btn-primary" style={{ marginTop: '12px' }}>
                Create Your First Key
              </Link>
            </div>
          )}
        </div>

        {/* Pending Requests */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Pending Requests</h2>
            <Link to="/requests" className="btn btn-secondary" style={{ fontSize: '13px' }}>
              View All
            </Link>
          </div>

          {requests && requests.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {requests.slice(0, 3).map((req) => (
                <RequestPreview key={req.id} request={req} />
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <p>No pending requests</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({
  value,
  label,
  icon,
  loading,
  highlight,
}: {
  value: number;
  label: string;
  icon: string;
  loading?: boolean;
  highlight?: boolean;
}) {
  return (
    <div className="stat-card" style={highlight ? { borderColor: 'var(--signer-warning)' } : undefined}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div className="stat-value">{loading ? '-' : value}</div>
          <div className="stat-label">{label}</div>
        </div>
        <span style={{ fontSize: '24px' }}>{icon}</span>
      </div>
    </div>
  );
}

function KeyPreview({ keyData }: { keyData: Key }) {
  const pubkeyShort = `${keyData.pubkey.slice(0, 8)}...${keyData.pubkey.slice(-8)}`;

  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <div>
        <div style={{ fontWeight: 600, color: 'var(--signer-text-heading)' }}>{keyData.name}</div>
        <div style={{ fontSize: '13px', color: 'var(--signer-text-muted)', fontFamily: 'monospace' }}>
          {pubkeyShort}
        </div>
      </div>
      <span className={`badge ${keyData.is_active ? 'badge-success' : 'badge-warning'}`}>
        {keyData.is_active ? 'Active' : 'Inactive'}
      </span>
    </div>
  );
}

function RequestPreview({ request }: { request: PendingRequest }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <div>
        <div style={{ fontWeight: 600, color: 'var(--signer-text-heading)' }}>{request.method}</div>
        <div style={{ fontSize: '13px', color: 'var(--signer-text-muted)' }}>
          {request.key_name} • Kind {request.event_kind ?? 'N/A'}
        </div>
      </div>
      <span className="badge badge-warning">Pending</span>
    </div>
  );
}
