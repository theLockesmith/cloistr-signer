import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useSignerAuth } from '../hooks/useSignerAuth';
import apiClient from '../api/client';

export function SettingsPage() {
  const { user, logout } = useSignerAuth();

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Settings</h1>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '600px' }}>
        {/* Account Info */}
        <div className="card">
          <h2 className="card-title" style={{ marginBottom: '16px' }}>Account</h2>
          <div style={{ display: 'grid', gap: '12px' }}>
            <div>
              <label style={{ fontSize: '12px', color: 'var(--signer-text-muted)' }}>Username</label>
              <div style={{ fontWeight: 600 }}>{user?.username}</div>
            </div>
            <div>
              <label style={{ fontSize: '12px', color: 'var(--signer-text-muted)' }}>User ID</label>
              <div style={{ fontFamily: 'monospace', fontSize: '13px' }}>{user?.id}</div>
            </div>
            {user?.pubkey && (
              <div>
                <label style={{ fontSize: '12px', color: 'var(--signer-text-muted)' }}>Linked Pubkey</label>
                <div style={{ fontFamily: 'monospace', fontSize: '13px' }}>{user.pubkey}</div>
              </div>
            )}
            <div>
              <label style={{ fontSize: '12px', color: 'var(--signer-text-muted)' }}>MFA</label>
              <span className={`badge ${user?.mfa_enabled ? 'badge-success' : 'badge-warning'}`}>
                {user?.mfa_enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
          </div>
        </div>

        {/* Change Password */}
        <ChangePasswordCard />

        {/* Danger Zone */}
        <div className="card" style={{ borderColor: 'var(--signer-danger)' }}>
          <h2 className="card-title" style={{ color: 'var(--signer-danger)', marginBottom: '16px' }}>
            Danger Zone
          </h2>
          <p style={{ color: 'var(--signer-text-muted)', marginBottom: '16px' }}>
            Logging out will end your session. You'll need to sign in again to access your keys.
          </p>
          <button className="btn btn-danger" onClick={logout}>
            Log Out
          </button>
        </div>
      </div>
    </div>
  );
}

function ChangePasswordCard() {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [localError, setLocalError] = useState('');
  const [success, setSuccess] = useState(false);

  const changeMutation = useMutation({
    mutationFn: () => apiClient.changePassword(currentPassword, newPassword),
    onSuccess: () => {
      setSuccess(true);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => setSuccess(false), 3000);
    },
    onError: (err: Error) => {
      setLocalError(err.message);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError('');

    if (newPassword !== confirmPassword) {
      setLocalError('Passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      setLocalError('Password must be at least 8 characters');
      return;
    }

    changeMutation.mutate();
  };

  return (
    <div className="card">
      <h2 className="card-title" style={{ marginBottom: '16px' }}>Change Password</h2>

      {success && (
        <div style={{ padding: '12px', background: 'rgba(63, 185, 80, 0.1)', borderRadius: '6px', marginBottom: '16px', color: 'var(--signer-success)' }}>
          Password changed successfully!
        </div>
      )}

      {localError && (
        <div className="auth-error">{localError}</div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Current Password</label>
          <input
            type="password"
            className="form-input"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            required
          />
        </div>

        <div className="form-group">
          <label className="form-label">New Password</label>
          <input
            type="password"
            className="form-input"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
          />
        </div>

        <div className="form-group">
          <label className="form-label">Confirm New Password</label>
          <input
            type="password"
            className="form-input"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
        </div>

        <button type="submit" className="btn btn-primary" disabled={changeMutation.isPending}>
          {changeMutation.isPending ? 'Changing...' : 'Change Password'}
        </button>
      </form>
    </div>
  );
}
