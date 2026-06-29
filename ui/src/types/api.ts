/**
 * API types for cloistr-signer
 */

// User types
export interface User {
  id: string;
  username: string;
  mfa_enabled: boolean;
  is_admin?: boolean;
  pubkey?: string;
  created_at: string;
  last_login?: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  expires_at: string;
  user: User;
}

export interface RegisterRequest {
  username: string;
  password: string;
  invite_code?: string;
}

// Key types
export interface Key {
  id: string;
  user_id: string;
  name: string;
  pubkey: string;
  nip05?: string;
  is_active: boolean;
  is_proxy: boolean;
  proxy_url?: string;
  created_at: string;
  last_used?: string;
  permissions?: KeyPermissions;
  relays?: string[];
  disposable_mode?: boolean;
  cover_traffic?: boolean;
  tor_egress?: boolean;
  /** Key custody type. "frost-user" means the signer holds only a share
   * and signing requires this browser to cosign. See
   * docs/frost-2-of-n-design.md. */
  key_type?: 'local' | 'proxy' | 'frost-user';
}

export interface UpdateKeyRequest {
  name?: string;
  require_approval?: boolean;
  disposable_mode?: boolean;
  cover_traffic?: boolean;
  tor_egress?: boolean;
  relays?: string[];
}

// FROST 2-of-N user-cosigner DKG wire types. Mirror the Go-side
// definitions in internal/frost/user_dkg.go.
export interface FrostUserDkgRound1Request {
  user_commits_hex: string[]; // [A0, A1], compressed-SEC1 hex
}

export interface FrostUserDkgRound1Response {
  session_id: string;
  signer_commits_hex: string[]; // [B0, B1]
}

export interface FrostUserDkgRound2Request {
  session_id: string;
  user_share_for_signer_hex: string; // f(SignerIndex), 32-byte scalar hex
}

export interface FrostUserDkgRound2Response {
  signer_share_for_user_hex: string; // g(UserIndex)
}

export interface FrostUserDkgFinalizeRequest {
  session_id: string;
  confirm_joint_pubkey_hex: string; // A0 + B0, compressed-SEC1 hex
  /** Optional but expected for keys that need lost-device recovery support.
   * The signer stores this verbatim; the recovery flow uses it to verify
   * a share reconstructed from a BIP39 phrase. */
  user_verification_share_hex?: string;
}

export interface FrostUserDkgFinalizeResponse {
  key_id: string;
  pubkey: string; // x-only BIP-340 / Nostr hex (32 bytes / 64 chars)
}

/** GET /api/v1/frost/user-dkg/recovery/{keyId} response.
 * Returned only for keys created post-P3e-b (older rows yield 409 Conflict). */
export interface FrostUserDkgRecoveryResponse {
  key_id: string;
  pubkey: string;
  /** g(UserIndex) from the original DKG, decrypted server-side via the
   * user's Vault token. The client reconstructs the final share by
   * computing f(UserIndex) (from the phrase) + this value. */
  signer_share_for_user_hex: string;
  /** Original final_share·G the user reported at finalize. The
   * orchestrator MUST verify the reconstructed final share against this
   * before accepting recovery; otherwise a wrong phrase silently
   * produces an unusable share. */
  user_verification_share_hex: string;
}

export interface KeyPermissions {
  sign_event: boolean;
  nip04_encrypt: boolean;
  nip04_decrypt: boolean;
  nip44_encrypt: boolean;
  nip44_decrypt: boolean;
  allowed_kinds?: number[];
  blocked_kinds?: number[];
  whitelist_pubkeys?: string[];
  auto_approve?: boolean;
}

export interface CreateKeyRequest {
  name: string;
  nip05?: string;
  relays?: string[];
}

export interface ImportKeyRequest {
  name: string;
  private_key: string;
  nip05?: string;
  relays?: string[];
}

// Request types
export interface PendingRequest {
  id: string;
  key_id: string;
  key_name: string;
  method: string;
  client_pubkey: string;
  event_kind?: number;
  event_content?: string;
  created_at: string;
  expires_at: string;
}

// App types
export interface App {
  id: string;
  name: string;
  pubkey: string;
  keys: string[];
  permissions: string[];
  last_used?: string;
  created_at: string;
}

// FROST types
export interface FrostKey {
  id: string;
  user_id: string;
  name: string;
  pubkey: string;
  threshold: number;
  participants: number;
  my_index: number;
  is_complete: boolean;
  created_at: string;
}

export interface FrostSession {
  id: string;
  frost_key_id: string;
  coordinator_pubkey: string;
  round: number;
  status: string;
  created_at: string;
}

// Stats types
export interface DashboardStats {
  total_keys: number;
  total_requests: number;
  pending_requests: number;
  total_apps: number;
  active_sessions: number;
  total_users?: number;
}

// API error response
export interface ApiError {
  error: string;
  code?: string;
  details?: Record<string, unknown>;
}
