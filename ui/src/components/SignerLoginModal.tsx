/**
 * Signer Login Modal
 *
 * Custom login modal for signer.cloistr.xyz that includes:
 * - NIP-07 browser extension login
 * - NIP-46 bunker URL login
 * - Username/password login (for existing users)
 * - Registration (for new users)
 */

import { useState } from 'react';
import { useNostrAuth, useAuthHelpers } from '@cloistr/collab-common';
import { useSignerAuth } from '../hooks/useSignerAuth';

type AuthMode = 'choose' | 'login' | 'register' | 'bunker';

interface SignerLoginModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function SignerLoginModal({ isOpen, onClose }: SignerLoginModalProps) {
  const [mode, setMode] = useState<AuthMode>('choose');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [inviteCode, setInviteCode] = useState('');
  const [bunkerUrl, setBunkerUrl] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  // Nostr auth from SharedAuthProvider
  const { connectNip07, connectNip46, authState: nostrState } = useNostrAuth();
  const { isNip07Available } = useAuthHelpers();

  // Signer backend auth
  const { loginWithPassword, register, error, clearError } = useSignerAuth();

  if (!isOpen) return null;

  const handleBackdropClick = (e: React.MouseEvent) => {
    if (submitting) return;
    if (e.target === e.currentTarget) {
      handleClose();
    }
  };

  const resetForm = () => {
    setUsername('');
    setPassword('');
    setConfirmPassword('');
    setInviteCode('');
    setBunkerUrl('');
    setLocalError(null);
    clearError();
  };

  const handleClose = () => {
    if (submitting) return;
    setMode('choose');
    resetForm();
    onClose();
  };

  const switchMode = (next: AuthMode) => {
    if (submitting) return;
    setLocalError(null);
    clearError();
    setMode(next);
  };

  const handleNip07 = async () => {
    try {
      await connectNip07();
    } catch {
      // Error handled by nostrState.error
    }
  };

  const handleBunkerSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (bunkerUrl.startsWith('bunker://')) {
      try {
        await connectNip46({ bunkerUrl });
      } catch {
        // Error handled by nostrState.error
      }
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    setSubmitting(true);
    try {
      await loginWithPassword({ username, password });
      handleClose();
    } catch {
      // Error surfaced via `error` state from useSignerAuth
    } finally {
      setSubmitting(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);

    if (password !== confirmPassword) {
      setLocalError('Passwords do not match');
      return;
    }
    if (password.length < 8) {
      setLocalError('Password must be at least 8 characters');
      return;
    }

    setSubmitting(true);
    try {
      await register({
        username,
        password,
        invite_code: inviteCode.trim() || undefined,
      });
      handleClose();
    } catch {
      // Error surfaced via `error` state
    } finally {
      setSubmitting(false);
    }
  };

  const displayError = localError || error || nostrState.error;
  const isNostrLoading = nostrState.isConnecting;

  return (
    <div className="modal-backdrop" onClick={handleBackdropClick}>
      <div className="modal" style={{ maxWidth: '400px' }}>
        <div className="modal-header">
          <h2 className="modal-title">
            {mode === 'choose' && 'Sign In to Cloistr'}
            {mode === 'login' && 'Sign In'}
            {mode === 'register' && 'Create Account'}
            {mode === 'bunker' && 'Connect Bunker'}
          </h2>
          <button
            className="modal-close"
            onClick={handleClose}
            disabled={submitting}
            aria-label="Close"
          >
            &times;
          </button>
        </div>

        <div className="modal-body">
          {displayError && (
            <div className="alert alert-error" style={{ marginBottom: '16px' }}>
              {displayError}
            </div>
          )}

          {mode === 'choose' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {isNip07Available && (
                <button
                  className="btn btn-primary"
                  onClick={handleNip07}
                  disabled={isNostrLoading}
                  style={{ width: '100%' }}
                >
                  {isNostrLoading ? 'Connecting…' : 'Use Browser Extension'}
                </button>
              )}

              <button
                className="btn btn-secondary"
                onClick={() => switchMode('bunker')}
                disabled={isNostrLoading}
                style={{ width: '100%' }}
              >
                Use Bunker URL
              </button>

              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                margin: '8px 0',
                color: 'var(--signer-text-muted)'
              }}>
                <div style={{ flex: 1, height: '1px', background: 'var(--signer-border)' }} />
                <span style={{ fontSize: '13px' }}>or</span>
                <div style={{ flex: 1, height: '1px', background: 'var(--signer-border)' }} />
              </div>

              <button
                className="btn btn-secondary"
                onClick={() => switchMode('login')}
                style={{ width: '100%' }}
              >
                Sign In with Password
              </button>

              <p style={{
                textAlign: 'center',
                fontSize: '14px',
                color: 'var(--signer-text-muted)',
                marginTop: '8px'
              }}>
                New to Cloistr?{' '}
                <button
                  onClick={() => switchMode('register')}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--signer-primary)',
                    cursor: 'pointer',
                    padding: 0,
                    textDecoration: 'underline',
                    font: 'inherit',
                  }}
                >
                  Create an account
                </button>
              </p>
            </div>
          )}

          {mode === 'login' && (
            <form onSubmit={handleLogin}>
              <div className="form-group">
                <label htmlFor="login-username">Username</label>
                <input
                  id="login-username"
                  type="text"
                  className="input"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  disabled={submitting}
                  required
                />
              </div>
              <div className="form-group">
                <label htmlFor="login-password">Password</label>
                <input
                  id="login-password"
                  type="password"
                  className="input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  disabled={submitting}
                  required
                />
              </div>
              <div style={{ display: 'flex', gap: '12px', marginTop: '16px' }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => switchMode('choose')}
                  disabled={submitting}
                  style={{ flex: 1 }}
                >
                  Back
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={submitting || !username || !password}
                  style={{ flex: 1 }}
                >
                  {submitting ? 'Signing in…' : 'Sign In'}
                </button>
              </div>
            </form>
          )}

          {mode === 'register' && (
            <form onSubmit={handleRegister}>
              <div className="form-group">
                <label htmlFor="register-username">Username</label>
                <input
                  id="register-username"
                  type="text"
                  className="input"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  minLength={3}
                  disabled={submitting}
                  required
                />
                <small style={{ color: 'var(--signer-text-muted)' }}>
                  At least 3 characters
                </small>
              </div>
              <div className="form-group">
                <label htmlFor="register-password">Password</label>
                <input
                  id="register-password"
                  type="password"
                  className="input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                  minLength={8}
                  disabled={submitting}
                  required
                />
                <small style={{ color: 'var(--signer-text-muted)' }}>
                  At least 8 characters
                </small>
              </div>
              <div className="form-group">
                <label htmlFor="register-confirm-password">Confirm Password</label>
                <input
                  id="register-confirm-password"
                  type="password"
                  className="input"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  autoComplete="new-password"
                  minLength={8}
                  disabled={submitting}
                  required
                />
              </div>
              <div className="form-group">
                <label htmlFor="register-invite-code">Invite Code (optional)</label>
                <input
                  id="register-invite-code"
                  type="text"
                  className="input"
                  value={inviteCode}
                  onChange={(e) => setInviteCode(e.target.value)}
                  placeholder="Enter invite code if you have one"
                  disabled={submitting}
                />
              </div>
              <div style={{ display: 'flex', gap: '12px', marginTop: '16px' }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => switchMode('choose')}
                  disabled={submitting}
                  style={{ flex: 1 }}
                >
                  Back
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={
                    submitting ||
                    !username ||
                    !password ||
                    !confirmPassword ||
                    username.length < 3 ||
                    password.length < 8
                  }
                  style={{ flex: 1 }}
                >
                  {submitting ? 'Creating account…' : 'Create Account'}
                </button>
              </div>
            </form>
          )}

          {mode === 'bunker' && (
            <form onSubmit={handleBunkerSubmit}>
              <div className="form-group">
                <label htmlFor="bunker-url">Bunker URL</label>
                <input
                  id="bunker-url"
                  type="text"
                  className="input"
                  value={bunkerUrl}
                  onChange={(e) => setBunkerUrl(e.target.value)}
                  placeholder="bunker://..."
                  disabled={isNostrLoading}
                  required
                />
                <small style={{ color: 'var(--signer-text-muted)' }}>
                  Paste your bunker:// URL from your signer app
                </small>
              </div>
              <div style={{ display: 'flex', gap: '12px', marginTop: '16px' }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => switchMode('choose')}
                  disabled={isNostrLoading}
                  style={{ flex: 1 }}
                >
                  Back
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={!bunkerUrl.startsWith('bunker://') || isNostrLoading}
                  style={{ flex: 1 }}
                >
                  {isNostrLoading ? 'Connecting…' : 'Connect'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
