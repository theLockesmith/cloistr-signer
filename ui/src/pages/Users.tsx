import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from '../api/client';
import { useAuth } from '../hooks/useAuth';
import type { User } from '../types/api';

export function UsersPage() {
  const queryClient = useQueryClient();
  const { user: currentUser } = useAuth();

  const { data: users, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: () => apiClient.listUsers(),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiClient.deleteUser(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  });

  const toggleAdminMutation = useMutation({
    mutationFn: ({ id, isAdmin }: { id: string; isAdmin: boolean }) =>
      apiClient.toggleUserAdmin(id, isAdmin),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  });

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">User Management</h1>
      </div>

      {isLoading ? (
        <div className="loading-container">
          <div className="spinner" />
        </div>
      ) : users && users.length > 0 ? (
        <div className="card">
          <table className="table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th>MFA</th>
                <th>Created</th>
                <th>Last Login</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <UserRow
                  key={user.id}
                  user={user}
                  isCurrentUser={user.id === currentUser?.id}
                  onToggleAdmin={(isAdmin) =>
                    toggleAdminMutation.mutate({ id: user.id, isAdmin })
                  }
                  onDelete={() => deleteMutation.mutate(user.id)}
                  loading={deleteMutation.isPending || toggleAdminMutation.isPending}
                />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="card">
          <div className="empty-state">
            <div className="empty-state-icon">👥</div>
            <div className="empty-state-title">No Users</div>
            <p>User accounts will appear here.</p>
          </div>
        </div>
      )}
    </div>
  );
}

function UserRow({
  user,
  isCurrentUser,
  onToggleAdmin,
  onDelete,
  loading,
}: {
  user: User;
  isCurrentUser: boolean;
  onToggleAdmin: (isAdmin: boolean) => void;
  onDelete: () => void;
  loading: boolean;
}) {
  const createdAt = new Date(user.created_at).toLocaleDateString();
  const lastLogin = user.last_login
    ? new Date(user.last_login).toLocaleDateString()
    : 'Never';

  return (
    <tr>
      <td>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontWeight: 600 }}>{user.username}</span>
          {isCurrentUser && (
            <span className="badge badge-info" style={{ fontSize: '10px' }}>You</span>
          )}
        </div>
      </td>
      <td>
        <span className={`badge ${user.is_admin ? 'badge-success' : 'badge-info'}`}>
          {user.is_admin ? 'Admin' : 'User'}
        </span>
      </td>
      <td>
        <span className={`badge ${user.mfa_enabled ? 'badge-success' : 'badge-warning'}`}>
          {user.mfa_enabled ? 'Enabled' : 'Disabled'}
        </span>
      </td>
      <td>{createdAt}</td>
      <td>{lastLogin}</td>
      <td>
        <div style={{ display: 'flex', gap: '8px' }}>
          {!isCurrentUser && (
            <>
              <button
                className="btn btn-secondary"
                onClick={() => onToggleAdmin(!user.is_admin)}
                disabled={loading}
                style={{ padding: '4px 12px', fontSize: '13px' }}
              >
                {user.is_admin ? 'Remove Admin' : 'Make Admin'}
              </button>
              <button
                className="btn btn-danger"
                onClick={onDelete}
                disabled={loading}
                style={{ padding: '4px 12px', fontSize: '13px' }}
              >
                Delete
              </button>
            </>
          )}
        </div>
      </td>
    </tr>
  );
}
