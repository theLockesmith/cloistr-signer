/**
 * Signer authentication hook
 *
 * Combines:
 * 1. Nostr auth from SharedAuthProvider (NIP-07/NIP-46)
 * 2. Signer backend JWT auth (for API access)
 *
 * Flow:
 * - User authenticates via Nostr OR username/password
 * - Signer backend issues JWT for API access
 * - JWT stored in localStorage
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
import { useNostrAuth } from '@cloistr/collab-common';
import apiClient from '../api/client';
import type { User, LoginRequest, RegisterRequest } from '../types/api';

// ============================================
// Types
// ============================================

export interface SignerAuthState {
  /** Authenticated user from signer backend */
  user: User | null;
  /** JWT token for API access */
  token: string | null;
  /** Loading state */
  loading: boolean;
  /** Error message */
  error: string | null;
}

export interface SignerAuthContextValue extends SignerAuthState {
  /** Login with username and password */
  loginWithPassword: (data: LoginRequest) => Promise<void>;
  /** Register new account with username/password */
  register: (data: RegisterRequest) => Promise<void>;
  /** Logout and clear session */
  logout: () => Promise<void>;
  /** Whether user is authenticated with signer backend */
  isAuthenticated: boolean;
  /** Clear error state */
  clearError: () => void;
  /** Show login modal */
  showLoginModal: () => void;
  /** Hide login modal */
  hideLoginModal: () => void;
  /** Whether login modal is visible */
  loginModalOpen: boolean;
}

// ============================================
// Context
// ============================================

const SignerAuthContext = createContext<SignerAuthContextValue | null>(null);

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

interface SignerAuthProviderProps {
  children: ReactNode;
}

export function SignerAuthProvider({ children }: SignerAuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [loginModalOpen, setLoginModalOpen] = useState(false);

  // Nostr auth from SharedAuthProvider
  const { authState: nostrAuth } = useNostrAuth();

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
    setLoginModalOpen(false);
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

  const showLoginModal = useCallback(() => {
    setLoginModalOpen(true);
  }, []);

  const hideLoginModal = useCallback(() => {
    setLoginModalOpen(false);
    setError(null);
  }, []);

  // ==========================================
  // Sync Nostr auth to signer backend
  // ==========================================

  useEffect(() => {
    // When user connects via Nostr, try to authenticate with signer backend
    if (nostrAuth.isConnected && nostrAuth.pubkey && !token) {
      // TODO: Implement Nostr -> Signer JWT exchange
      // This requires a backend endpoint that:
      // 1. Accepts a signed challenge (NIP-98 style)
      // 2. Creates/finds user by pubkey
      // 3. Returns JWT
      //
      // For now, we still require password login
      // The Nostr connection can be used for key operations
    }
  }, [nostrAuth.isConnected, nostrAuth.pubkey, token]);

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

  const value = useMemo<SignerAuthContextValue>(() => ({
    user,
    token,
    loading,
    error,
    loginWithPassword,
    register,
    logout,
    isAuthenticated: !!token && !!user,
    clearError,
    showLoginModal,
    hideLoginModal,
    loginModalOpen,
  }), [
    user,
    token,
    loading,
    error,
    loginWithPassword,
    register,
    logout,
    clearError,
    showLoginModal,
    hideLoginModal,
    loginModalOpen,
  ]);

  return (
    <SignerAuthContext.Provider value={value}>
      {children}
    </SignerAuthContext.Provider>
  );
}

// ============================================
// Hook
// ============================================

export function useSignerAuth(): SignerAuthContextValue {
  const context = useContext(SignerAuthContext);
  if (!context) {
    throw new Error('useSignerAuth must be used within SignerAuthProvider');
  }
  return context;
}
