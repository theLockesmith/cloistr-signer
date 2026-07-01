/**
 * API client for cloistr-signer
 */

import type {
  User,
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  Key,
  CreateKeyRequest,
  ImportKeyRequest,
  KeyPermissions,
  UpdateKeyRequest,
  PendingRequest,
  App,
  FrostKey,
  DashboardStats,
  ApiError,
  FrostUserDkgRound1Request,
  FrostUserDkgRound1Response,
  FrostUserDkgRound2Request,
  FrostUserDkgRound2Response,
  FrostUserDkgFinalizeRequest,
  FrostUserDkgFinalizeResponse,
  FrostUserDkgRecoveryResponse,
} from '../types/api';

const API_BASE = '/api/v1';

class ApiClient {
  private token: string | null = null;

  setToken(token: string | null) {
    this.token = token;
  }

  private async fetch<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
      credentials: 'include', // Include cookies
    });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({
        error: `HTTP ${response.status}: ${response.statusText}`,
      }));
      throw new Error(error.error);
    }

    // Handle empty responses
    const text = await response.text();
    if (!text) return {} as T;

    return JSON.parse(text);
  }

  // Auth endpoints
  async login(data: LoginRequest): Promise<LoginResponse> {
    return this.fetch('/users/login', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async register(data: RegisterRequest): Promise<LoginResponse> {
    return this.fetch('/users/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async logout(): Promise<void> {
    return this.fetch('/users/logout', { method: 'POST' });
  }

  async getMe(): Promise<User> {
    return this.fetch('/users/me');
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    return this.fetch('/users/password', {
      method: 'PUT',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
  }

  // Key endpoints
  async listKeys(): Promise<Key[]> {
    return this.fetch('/keys');
  }

  async getKey(id: string): Promise<Key> {
    return this.fetch(`/keys/${id}`);
  }

  async createKey(data: CreateKeyRequest): Promise<Key> {
    return this.fetch('/keys', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  /**
   * Approve a client-initiated nostrconnect:// URI ("Login With Cloistr").
   * Grants the app signing authority over the selected key. Requires a session
   * and that the authenticated user owns the key.
   */
  async nostrConnect(data: {
    uri: string;
    key_id: string;
  }): Promise<{ success: boolean; app_name?: string; app_url?: string; client_pubkey: string }> {
    return this.fetch('/nostrconnect', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async importKey(data: ImportKeyRequest): Promise<Key> {
    return this.fetch('/keys/import', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async deleteKey(id: string): Promise<void> {
    return this.fetch(`/keys/${id}`, { method: 'DELETE' });
  }

  async updateKeyPermissions(id: string, permissions: KeyPermissions): Promise<Key> {
    return this.fetch(`/keys/${id}/permissions`, {
      method: 'PUT',
      body: JSON.stringify(permissions),
    });
  }

  async updateKey(id: string, fields: UpdateKeyRequest): Promise<Key> {
    return this.fetch(`/keys/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(fields),
    });
  }

  async getBunkerUrl(id: string): Promise<{ bunker_uri: string; signer_pubkey: string; relays: string[]; secret?: string }> {
    return this.fetch(`/bunker/${id}`);
  }

  // FROST 2-of-N user-cosigner DKG endpoints (docs/frost-2-of-n-design.md §4.2).
  // The orchestrator in ui/src/lib/frost.ts drives all three; consumers
  // typically call createFrostKey() rather than these directly.
  async frostUserDkgRound1(
    body: FrostUserDkgRound1Request,
  ): Promise<FrostUserDkgRound1Response> {
    return this.fetch('/frost/user-dkg/round1', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  async frostUserDkgRound2(
    body: FrostUserDkgRound2Request,
  ): Promise<FrostUserDkgRound2Response> {
    return this.fetch('/frost/user-dkg/round2', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  async frostUserDkgFinalize(
    body: FrostUserDkgFinalizeRequest,
  ): Promise<FrostUserDkgFinalizeResponse> {
    return this.fetch('/frost/user-dkg/finalize', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  /** Fetch recovery materials for a FROST key the authenticated user owns.
   * The server decrypts the at-DKG share via the user's Vault token and
   * returns it plus the verification share. Returns 409 if the key
   * predates recovery support (created before P3e-b), 404 if not owned
   * or not found, 424 if Vault is unavailable. */
  async frostUserDkgRecovery(keyId: string): Promise<FrostUserDkgRecoveryResponse> {
    return this.fetch(`/frost/user-dkg/recovery/${encodeURIComponent(keyId)}`);
  }

  /** Register this browser's ephemeral cosign-listener pubkey with the
   * signer. The signer p-tags kind:24135 cosign requests to this
   * pubkey so the browser can filter for them. */
  async frostRegisterCosignListener(ephemeralPubkey: string): Promise<void> {
    return this.fetch('/frost/cosign-listener/register', {
      method: 'POST',
      body: JSON.stringify({ ephemeral_pubkey: ephemeralPubkey }),
    });
  }


  // Request endpoints
  async listRequests(): Promise<PendingRequest[]> {
    return this.fetch('/requests');
  }

  async approveRequest(id: string): Promise<void> {
    return this.fetch(`/requests/${id}/approve`, { method: 'POST' });
  }

  async rejectRequest(id: string): Promise<void> {
    return this.fetch(`/requests/${id}/reject`, { method: 'POST' });
  }

  // App endpoints
  async listApps(): Promise<App[]> {
    return this.fetch('/apps');
  }

  async revokeApp(id: string): Promise<void> {
    return this.fetch(`/apps/${id}`, { method: 'DELETE' });
  }

  // FROST endpoints
  async listFrostKeys(): Promise<FrostKey[]> {
    return this.fetch('/frost/keys');
  }

  async createFrostKey(name: string, threshold: number, participants: number): Promise<FrostKey> {
    return this.fetch('/frost/keys', {
      method: 'POST',
      body: JSON.stringify({ name, threshold, participants }),
    });
  }

  async joinFrostSession(sessionId: string): Promise<void> {
    return this.fetch(`/frost/sessions/${sessionId}/join`, { method: 'POST' });
  }

  // Stats endpoints
  async getDashboardStats(): Promise<DashboardStats> {
    return this.fetch('/stats');
  }

  // Admin endpoints
  async listUsers(): Promise<User[]> {
    return this.fetch('/admin/users');
  }

  async deleteUser(id: string): Promise<void> {
    return this.fetch(`/admin/users/${id}`, { method: 'DELETE' });
  }

  async toggleUserAdmin(id: string, isAdmin: boolean): Promise<void> {
    return this.fetch(`/admin/users/${id}/admin`, {
      method: 'PUT',
      body: JSON.stringify({ is_admin: isAdmin }),
    });
  }
}

export const apiClient = new ApiClient();
export default apiClient;
