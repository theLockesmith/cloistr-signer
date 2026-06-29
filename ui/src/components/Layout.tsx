import { Outlet, Link, useLocation } from 'react-router-dom';
import { Header, Footer } from '@cloistr/ui/components';
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
      {/* Shared Cloistr navbar (service menu + Nostr auth) */}
      <Header activeServiceId="signer" />

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
              {/* Signer backend session (JWT) — distinct from the navbar's Nostr auth */}
              <div className="sidebar-account">
                <span className="sidebar-username">{user?.username}</span>
                <button className="btn btn-secondary btn-sm" onClick={logout}>
                  Sign Out
                </button>
              </div>
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
