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
  const [bunkerUrl, setBunkerUrl] = useState('');

  // Nostr auth from SharedAuthProvider
  const { connectNip07, connectNip46, authState: nostrState } = useNostrAuth();
  const { isNip07Available } = useAuthHelpers();

  // Signer backend auth
  const { loginWithPassword, register, error, clearError } = useSignerAuth();

  if (!isOpen) return null;

  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      handleClose();
    }
  };

  const handleClose = () => {
    setMode('choose');
    setUsername('');
    setPassword('');
    setBunkerUrl('');
    clearError();
    onClose();
  };

  const handleNip07 = async () => {
    try {
      await connectNip07();
      // TODO: Exchange Nostr auth for signer JWT
      // For now, Nostr connection works but user still needs password login
      // to access signer-specific features
    } catch {
      // Error handled by nostrState.error
    }
  };

  const handleBunkerSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (bunkerUrl.startsWith('bunker://')) {
      try {
        await connectNip46({ bunkerUrl });
        // TODO: Exchange Nostr auth for signer JWT
      } catch {
        // Error handled by nostrState.error
      }
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await loginWithPassword({ username, password });
      handleClose();
    } catch {
      // Error handled by error state
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await register({ username, password });
      handleClose();
    } catch {
      // Error handled by error state
    }
  };

  const displayError = error || nostrState.error;
  const isLoading = nostrState.isConnecting;

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
          <button className="modal-close" onClick={handleClose} aria-label="Close">
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
              {/* NIP-07 Extension */}
              {isNip07Available && (
                <button
                  className="btn btn-primary"
                  onClick={handleNip07}
                  disabled={isLoading}
                  style={{ width: '100%' }}
                >
                  {isLoading ? 'Connecting...' : 'Use Browser Extension'}
                </button>
              )}

              {/* Bunker URL */}
              <button
                className="btn btn-secondary"
                onClick={() => setMode('bunker')}
                disabled={isLoading}
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

              {/* Username/Password Login */}
              <button
                className="btn btn-secondary"
                onClick={() => setMode('login')}
                style={{ width: '100%' }}
              >
                Sign In with Password
              </button>

              {/* Register */}
              <p style={{
                textAlign: 'center',
                fontSize: '14px',
                color: 'var(--signer-text-muted)',
                marginTop: '8px'
              }}>
                New to Cloistr?{' '}
                <button
                  onClick={() => setMode('register')}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--signer-primary)',
                    cursor: 'pointer',
                    padding: 0,
                    textDecoration: 'underline',
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
                  required
                />
              </div>
              <div style={{ display: 'flex', gap: '12px', marginTop: '16px' }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setMode('choose')}
                  style={{ flex: 1 }}
                >
                  Back
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  style={{ flex: 1 }}
                >
                  Sign In
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
                  required
                />
                <small style={{ color: 'var(--signer-text-muted)' }}>
                  At least 8 characters
                </small>
              </div>
              <div style={{ display: 'flex', gap: '12px', marginTop: '16px' }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setMode('choose')}
                  style={{ flex: 1 }}
                >
                  Back
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  style={{ flex: 1 }}
                >
                  Create Account
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
                  onClick={() => setMode('choose')}
                  disabled={isLoading}
                  style={{ flex: 1 }}
                >
                  Back
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={!bunkerUrl.startsWith('bunker://') || isLoading}
                  style={{ flex: 1 }}
                >
                  {isLoading ? 'Connecting...' : 'Connect'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
