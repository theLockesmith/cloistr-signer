import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from '../api/client';
import type { PendingRequest } from '../types/api';

export function RequestsPage() {
  const queryClient = useQueryClient();

  const { data: requests, isLoading } = useQuery({
    queryKey: ['requests'],
    queryFn: () => apiClient.listRequests(),
    refetchInterval: 5000, // Poll every 5 seconds
  });

  const approveMutation = useMutation({
    mutationFn: (id: string) => apiClient.approveRequest(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['requests'] }),
  });

  const rejectMutation = useMutation({
    mutationFn: (id: string) => apiClient.rejectRequest(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['requests'] }),
  });

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Pending Requests</h1>
      </div>

      {isLoading ? (
        <div className="loading-container">
          <div className="spinner" />
        </div>
      ) : requests && requests.length > 0 ? (
        <div className="card">
          <table className="table">
            <thead>
              <tr>
                <th>Method</th>
                <th>Key</th>
                <th>Kind</th>
                <th>Client</th>
                <th>Expires</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {requests.map((req) => (
                <RequestRow
                  key={req.id}
                  request={req}
                  onApprove={() => approveMutation.mutate(req.id)}
                  onReject={() => rejectMutation.mutate(req.id)}
                  loading={approveMutation.isPending || rejectMutation.isPending}
                />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="card">
          <div className="empty-state">
            <div className="empty-state-icon">📋</div>
            <div className="empty-state-title">No Pending Requests</div>
            <p>When apps request signatures, they will appear here for approval.</p>
          </div>
        </div>
      )}
    </div>
  );
}

function RequestRow({
  request,
  onApprove,
  onReject,
  loading,
}: {
  request: PendingRequest;
  onApprove: () => void;
  onReject: () => void;
  loading: boolean;
}) {
  const clientShort = `${request.client_pubkey.slice(0, 8)}...`;
  const expiresAt = new Date(request.expires_at);
  const expiresIn = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));

  return (
    <tr>
      <td>
        <span className="badge badge-info">{request.method}</span>
      </td>
      <td>{request.key_name}</td>
      <td>{request.event_kind ?? '-'}</td>
      <td style={{ fontFamily: 'monospace', fontSize: '13px' }}>{clientShort}</td>
      <td>{expiresIn}s</td>
      <td>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className="btn btn-primary"
            onClick={onApprove}
            disabled={loading}
            style={{ padding: '4px 12px' }}
          >
            Approve
          </button>
          <button
            className="btn btn-danger"
            onClick={onReject}
            disabled={loading}
            style={{ padding: '4px 12px' }}
          >
            Reject
          </button>
        </div>
      </td>
    </tr>
  );
}
