/**
 * Signer authentication hook and context
 *
 * Combines:
 * 1. Password-based JWT auth (existing signer flow)
 * 2. Nostr-based auth (NIP-07/NIP-46 via cloistr-ui)
 * 3. Cross-domain SSO (shared session cookies)
 */

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useMemo,
  type ReactNode,
} from 'react';
import { useNostrAuth, useAuthHelpers } from '@cloistr/collab-common';
import apiClient from '../api/client';
import type { User, LoginRequest, RegisterRequest } from '../types/api';

// ============================================
// Types
// ============================================

export interface AuthState {
  user: User | null;
  token: string | null;
  loading: boolean;
  error: string | null;
}

export interface AuthContextValue extends AuthState {
  /** Login with username and password */
  loginWithPassword: (data: LoginRequest) => Promise<void>;
  /** Register new account */
  register: (data: RegisterRequest) => Promise<void>;
  /** Login with NIP-07 browser extension */
  loginWithExtension: () => Promise<void>;
  /** Login with NIP-46 bunker URL */
  loginWithBunker: (bunkerUrl: string) => Promise<void>;
  /** Logout and clear session */
  logout: () => Promise<void>;
  /** Whether user is authenticated */
  isAuthenticated: boolean;
  /** Whether NIP-07 extension is available */
  extensionAvailable: boolean;
  /** Clear error state */
  clearError: () => void;
}

// ============================================
// Context
// ============================================

const AuthContext = createContext<AuthContextValue | null>(null);

// ============================================
// Storage keys
// ============================================

const STORAGE_KEYS = {
  TOKEN: 'signer:token',
  TOKEN_EXPIRY: 'signer:tokenExpiry',
  USER: 'signer:user',
} as const;

// ============================================
// Provider
// ============================================

interface AuthProviderProps {
  children: ReactNode;
}

export function SignerAuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Nostr auth from cloistr-collab-common
  const { connectNip07, connectNip46 } = useNostrAuth();
  const { isNip07Available } = useAuthHelpers();

  // ==========================================
  // Token management
  // ==========================================

  const saveAuthState = useCallback((newToken: string, expiresAt: string, newUser: User) => {
    localStorage.setItem(STORAGE_KEYS.TOKEN, newToken);
    localStorage.setItem(STORAGE_KEYS.TOKEN_EXPIRY, expiresAt);
    localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(newUser));
    setToken(newToken);
    setUser(newUser);
    apiClient.setToken(newToken);
  }, []);

  const clearAuthState = useCallback(() => {
    localStorage.removeItem(STORAGE_KEYS.TOKEN);
    localStorage.removeItem(STORAGE_KEYS.TOKEN_EXPIRY);
    localStorage.removeItem(STORAGE_KEYS.USER);
    setToken(null);
    setUser(null);
    apiClient.setToken(null);
  }, []);

  // ==========================================
  // Auth methods
  // ==========================================

  const loginWithPassword = useCallback(async (data: LoginRequest) => {
    setLoading(true);
    setError(null);

    try {
      const response = await apiClient.login(data);
      saveAuthState(response.token, response.expires_at, response.user);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Login failed';
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [saveAuthState]);

  const register = useCallback(async (data: RegisterRequest) => {
    setLoading(true);
    setError(null);

    try {
      const response = await apiClient.register(data);
      saveAuthState(response.token, response.expires_at, response.user);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Registration failed';
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [saveAuthState]);

  const loginWithExtension = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      // Connect NIP-07
      await connectNip07();

      // TODO: Send signed challenge to backend for JWT
      // For now, just use the Nostr pubkey directly
      // This requires backend support for NIP-98 style auth

      // Placeholder until backend supports challenge-response
      throw new Error('NIP-07 login not yet implemented - use password login');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Extension login failed';
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [connectNip07]);

  const loginWithBunker = useCallback(async (bunkerUrl: string) => {
    setLoading(true);
    setError(null);

    try {
      // Connect NIP-46
      await connectNip46({ bunkerUrl });

      // TODO: Send signed challenge to backend for JWT
      throw new Error('NIP-46 login not yet implemented - use password login');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Bunker login failed';
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [connectNip46]);

  const logout = useCallback(async () => {
    try {
      await apiClient.logout();
    } catch {
      // Ignore logout errors
    }
    clearAuthState();
  }, [clearAuthState]);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  // ==========================================
  // Initialize from storage
  // ==========================================

  useEffect(() => {
    const initAuth = async () => {
      setLoading(true);

      try {
        const storedToken = localStorage.getItem(STORAGE_KEYS.TOKEN);
        const storedExpiry = localStorage.getItem(STORAGE_KEYS.TOKEN_EXPIRY);
        const storedUser = localStorage.getItem(STORAGE_KEYS.USER);

        if (!storedToken || !storedExpiry || !storedUser) {
          clearAuthState();
          return;
        }

        // Check if token is expired
        const expiry = new Date(storedExpiry);
        if (new Date() >= expiry) {
          clearAuthState();
          return;
        }

        // Validate token with server
        apiClient.setToken(storedToken);
        try {
          const currentUser = await apiClient.getMe();
          setToken(storedToken);
          setUser(currentUser);
        } catch {
          // Token invalid
          clearAuthState();
        }
      } finally {
        setLoading(false);
      }
    };

    initAuth();
  }, [clearAuthState]);

  // ==========================================
  // Context value
  // ==========================================

  const value = useMemo<AuthContextValue>(() => ({
    user,
    token,
    loading,
    error,
    loginWithPassword,
    register,
    loginWithExtension,
    loginWithBunker,
    logout,
    isAuthenticated: !!token && !!user,
    extensionAvailable: isNip07Available,
    clearError,
  }), [
    user,
    token,
    loading,
    error,
    loginWithPassword,
    register,
    loginWithExtension,
    loginWithBunker,
    logout,
    isNip07Available,
    clearError,
  ]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// ============================================
// Hook
// ============================================

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within SignerAuthProvider');
  }
  return context;
}
