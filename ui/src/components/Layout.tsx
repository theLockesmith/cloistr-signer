import { Outlet } from 'react-router-dom';
import { Header, Footer } from '@cloistr/ui';
import { Sidebar } from './Sidebar';

/**
 * Main application layout with header, sidebar, and footer
 */
export function Layout() {
  return (
    <div className="app-layout">
      <Header
        activeServiceId="signer"
        settingsUrl="/settings"
        signerUrl="https://signer.cloistr.xyz"
      />

      <div className="app-main">
        <Sidebar />

        <main className="app-content">
          <Outlet />
        </main>
      </div>

      <Footer />
    </div>
  );
}
