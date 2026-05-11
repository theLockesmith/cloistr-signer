import { NavLink } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

/**
 * Navigation sidebar
 */
export function Sidebar() {
  const { user } = useAuth();

  return (
    <aside className="sidebar">
      <nav className="sidebar-nav">
        <NavLink to="/dashboard" className={({ isActive }) => isActive ? 'active' : ''}>
          <span className="nav-icon">📊</span>
          <span className="nav-label">Dashboard</span>
        </NavLink>

        <NavLink to="/keys" className={({ isActive }) => isActive ? 'active' : ''}>
          <span className="nav-icon">🔑</span>
          <span className="nav-label">Keys</span>
        </NavLink>

        <NavLink to="/requests" className={({ isActive }) => isActive ? 'active' : ''}>
          <span className="nav-icon">📋</span>
          <span className="nav-label">Requests</span>
        </NavLink>

        <NavLink to="/apps" className={({ isActive }) => isActive ? 'active' : ''}>
          <span className="nav-icon">📱</span>
          <span className="nav-label">Apps</span>
        </NavLink>

        <NavLink to="/frost" className={({ isActive }) => isActive ? 'active' : ''}>
          <span className="nav-icon">❄️</span>
          <span className="nav-label">FROST Keys</span>
        </NavLink>

        <div className="sidebar-divider" />

        <NavLink to="/settings" className={({ isActive }) => isActive ? 'active' : ''}>
          <span className="nav-icon">⚙️</span>
          <span className="nav-label">Settings</span>
        </NavLink>

        {user?.is_admin && (
          <NavLink to="/users" className={({ isActive }) => isActive ? 'active' : ''}>
            <span className="nav-icon">👥</span>
            <span className="nav-label">Users</span>
          </NavLink>
        )}
      </nav>
    </aside>
  );
}
