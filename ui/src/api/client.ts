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
  PendingRequest,
  App,
  FrostKey,
  DashboardStats,
  ApiError,
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

  async getBunkerUrl(id: string): Promise<{ bunker_uri: string; signer_pubkey: string; relays: string[]; secret?: string }> {
    return this.fetch(`/bunker/${id}`);
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
