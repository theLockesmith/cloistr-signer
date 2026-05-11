import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { SharedAuthProvider } from '@cloistr/ui';

// Layout & Pages
import { Layout } from './components/Layout';
import { DashboardPage } from './pages/Dashboard';
import { KeysPage } from './pages/Keys';
import { RequestsPage } from './pages/Requests';
import { AppsPage } from './pages/Apps';
import { FrostPage } from './pages/Frost';
import { SettingsPage } from './pages/Settings';
import { UsersPage } from './pages/Users';

// Auth
import { SignerAuthProvider, useSignerAuth } from './hooks/useSignerAuth';

// Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30 * 1000,
      retry: 1,
    },
  },
});

/**
 * Protected route - requires signer backend auth
 */
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useSignerAuth();

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner" />
      </div>
    );
  }

  if (!isAuthenticated) {
    // Layout will show the login modal
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

/**
 * Admin route wrapper
 */
function AdminRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useSignerAuth();

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner" />
      </div>
    );
  }

  if (!user?.is_admin) {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}

/**
 * App routes
 */
function AppRoutes() {
  return (
    <Routes>
      {/* All routes go through Layout which handles auth state */}
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route
          path="dashboard"
          element={
            <ProtectedRoute>
              <DashboardPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="keys"
          element={
            <ProtectedRoute>
              <KeysPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="requests"
          element={
            <ProtectedRoute>
              <RequestsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="apps"
          element={
            <ProtectedRoute>
              <AppsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="frost"
          element={
            <ProtectedRoute>
              <FrostPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="settings"
          element={
            <ProtectedRoute>
              <SettingsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="users"
          element={
            <ProtectedRoute>
              <AdminRoute>
                <UsersPage />
              </AdminRoute>
            </ProtectedRoute>
          }
        />
      </Route>

      {/* Catch all */}
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

/**
 * Root App component
 */
export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <SharedAuthProvider>
        <SignerAuthProvider>
          <BrowserRouter>
            <AppRoutes />
          </BrowserRouter>
        </SignerAuthProvider>
      </SharedAuthProvider>
    </QueryClientProvider>
  );
}
