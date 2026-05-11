import { Outlet, Link, useLocation } from 'react-router-dom';
import { Footer } from '@cloistr/ui';
import { useSignerAuth } from '../hooks/useSignerAuth';
import { SignerLoginModal } from './SignerLoginModal';

/**
 * Navigation links for the signer
 */
const NAV_LINKS = [
  { path: '/dashboard', label: 'Dashboard' },
  { path: '/keys', label: 'Keys' },
  { path: '/requests', label: 'Requests' },
  { path: '/apps', label: 'Apps' },
  { path: '/frost', label: 'FROST' },
  { path: '/settings', label: 'Settings' },
];

/**
 * Main application layout with header, navigation, and footer
 */
export function Layout() {
  const location = useLocation();
  const { isAuthenticated, user, logout, showLoginModal, hideLoginModal, loginModalOpen } = useSignerAuth();

  return (
    <div className="app-layout">
      {/* Header */}
      <header className="signer-header">
        <div className="signer-header-left">
          <Link to="/" className="signer-header-logo">
            <svg width="32" height="32" viewBox="0 0 32 32" fill="currentColor">
              <circle cx="16" cy="16" r="14" stroke="currentColor" strokeWidth="2" fill="none" />
              <path d="M12 10l8 6-8 6V10z" fill="currentColor" />
            </svg>
            <span className="signer-header-brand">Cloistr Signer</span>
          </Link>

          {/* Service Menu */}
          <nav className="signer-service-menu">
            <a href="https://docs.cloistr.xyz" className="signer-service-link">Docs</a>
            <a href="https://drive.cloistr.xyz" className="signer-service-link">Drive</a>
            <span className="signer-service-link signer-service-active">Signer</span>
          </nav>
        </div>

        <div className="signer-header-right">
          {isAuthenticated ? (
            <div className="signer-user-menu">
              <span className="signer-username">{user?.username}</span>
              <button className="btn btn-secondary btn-sm" onClick={logout}>
                Sign Out
              </button>
            </div>
          ) : (
            <button className="btn btn-primary" onClick={showLoginModal}>
              Sign In
            </button>
          )}
        </div>
      </header>

      {/* Main Content */}
      <div className="app-main">
        {/* Sidebar - only show when authenticated */}
        {isAuthenticated && (
          <aside className="sidebar">
            <nav className="sidebar-nav">
              {NAV_LINKS.map((link) => (
                <Link
                  key={link.path}
                  to={link.path}
                  className={`sidebar-link ${location.pathname === link.path ? 'active' : ''}`}
                >
                  {link.label}
                </Link>
              ))}
              {user?.is_admin && (
                <Link
                  to="/users"
                  className={`sidebar-link ${location.pathname === '/users' ? 'active' : ''}`}
                >
                  Users
                </Link>
              )}
            </nav>
          </aside>
        )}

        <main className="app-content">
          {isAuthenticated ? (
            <Outlet />
          ) : (
            <div className="welcome-screen">
              <div className="welcome-content">
                <h1>Welcome to Cloistr Signer</h1>
                <p>
                  Secure remote signing for Nostr. Manage your keys, authorize apps,
                  and sign events from any device.
                </p>
                <button className="btn btn-primary btn-lg" onClick={showLoginModal}>
                  Get Started
                </button>
              </div>
            </div>
          )}
        </main>
      </div>

      <Footer />

      {/* Login Modal */}
      <SignerLoginModal isOpen={loginModalOpen} onClose={hideLoginModal} />
    </div>
  );
}
