import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    // @cloistr/auth MUST be deduped: @cloistr/ui's SharedAuthProvider and the
    // signer's useSignerAuth both import it, and without dedupe Vite bundles two
    // AuthContext instances (provider populates one, hook reads the other) →
    // "useNostrAuth must be used within an AuthProvider" crash on mount.
    dedupe: ['react', 'react-dom', '@cloistr/collab-common', '@cloistr/auth'],
  },
  build: {
    outDir: path.resolve(__dirname, '../internal/web/dist'),
    emptyDirOnBuild: true,
    sourcemap: true,
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/.well-known': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
});
