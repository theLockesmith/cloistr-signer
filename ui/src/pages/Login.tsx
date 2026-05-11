import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export function LoginPage() {
  const navigate = useNavigate();
  const { loginWithPassword, loginWithExtension, extensionAvailable, error, loading, clearError } = useAuth();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await loginWithPassword({ username, password });
      navigate('/dashboard');
    } catch {
      // Error is handled by context
    }
  };

  const handleExtensionLogin = async () => {
    try {
      await loginWithExtension();
      navigate('/dashboard');
    } catch {
      // Error is handled by context
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-header">
          <div className="auth-logo">🔐</div>
          <h1 className="auth-title">Cloistr Signer</h1>
          <p className="auth-subtitle">Secure remote signing for Nostr</p>
        </div>

        {error && (
          <div className="auth-error" onClick={clearError}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username" className="form-label">Username</label>
            <input
              id="username"
              type="text"
              className="form-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter your username"
              autoComplete="username"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="password" className="form-label">Password</label>
            <input
              id="password"
              type="password"
              className="form-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              autoComplete="current-password"
              required
            />
          </div>

          <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <div className="auth-divider">or</div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {extensionAvailable && (
            <button
              type="button"
              className="btn btn-secondary"
              style={{ width: '100%' }}
              onClick={handleExtensionLogin}
              disabled={loading}
            >
              🔗 Sign in with Browser Extension
            </button>
          )}

          <a
            href="https://signer.cloistr.xyz"
            className="btn btn-secondary"
            style={{ width: '100%', textDecoration: 'none' }}
          >
            🪪 Login with Cloistr
          </a>
        </div>

        <div className="auth-footer">
          Don't have an account? <Link to="/register">Create one</Link>
        </div>
      </div>
    </div>
  );
}
