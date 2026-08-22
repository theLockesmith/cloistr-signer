import { useState, useCallback, useEffect, useRef } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useSignerAuth } from '../hooks/useSignerAuth';
import apiClient from '../api/client';
import type { PasskeyRegistrationFinishRequest, LightningKey } from '../types/api';

export function SettingsPage() {
  const { user, logout } = useSignerAuth();

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Settings</h1>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '600px' }}>
        {/* Account Info */}
        <div className="card">
          <h2 className="card-title" style={{ marginBottom: '16px' }}>Account</h2>
          <div style={{ display: 'grid', gap: '12px' }}>
            <div>
              <label style={{ fontSize: '12px', color: 'var(--signer-text-muted)' }}>Username</label>
              <div style={{ fontWeight: 600 }}>{user?.username}</div>
            </div>
            <div>
              <label style={{ fontSize: '12px', color: 'var(--signer-text-muted)' }}>User ID</label>
              <div style={{ fontFamily: 'monospace', fontSize: '13px' }}>{user?.id}</div>
            </div>
            {user?.pubkey && (
              <div>
                <label style={{ fontSize: '12px', color: 'var(--signer-text-muted)' }}>
                  Nostr Identity (Primary Key)
                </label>
                <div style={{ fontFamily: 'monospace', fontSize: '13px', wordBreak: 'break-all' }}>{user.pubkey}</div>
              </div>
            )}
            {user?.linked_pubkey && user.linked_pubkey !== user.pubkey && (
              <div>
                <label style={{ fontSize: '12px', color: 'var(--signer-text-muted)' }}>
                  Platform Pubkey
                  <span
                    title="Internal platform identifier used for cross-service authorization. This is not your Nostr signing identity."
                    style={{ marginLeft: '4px', cursor: 'help', opacity: 0.7 }}
                  >
                    (?)
                  </span>
                </label>
                <div style={{ fontFamily: 'monospace', fontSize: '12px', color: 'var(--signer-text-muted)', wordBreak: 'break-all' }}>
                  {user.linked_pubkey}
                </div>
              </div>
            )}
            <div>
              <label style={{ fontSize: '12px', color: 'var(--signer-text-muted)' }}>MFA</label>
              <span className={`badge ${user?.mfa_enabled ? 'badge-success' : 'badge-warning'}`}>
                {user?.mfa_enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
          </div>
        </div>

        {/* Change Password */}
        <ChangePasswordCard />

        {/* Passkeys */}
        <PasskeysCard />

        {/* Lightning wallet */}
        <LightningCard />

        {/* Danger Zone */}
        <div className="card" style={{ borderColor: 'var(--signer-danger)' }}>
          <h2 className="card-title" style={{ color: 'var(--signer-danger)', marginBottom: '16px' }}>
            Danger Zone
          </h2>
          <p style={{ color: 'var(--signer-text-muted)', marginBottom: '16px' }}>
            Logging out will end your session. You'll need to sign in again to access your keys.
          </p>
          <button className="btn btn-danger" onClick={logout}>
            Log Out
          </button>
        </div>
      </div>
    </div>
  );
}

function ChangePasswordCard() {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [localError, setLocalError] = useState('');
  const [success, setSuccess] = useState(false);

  const changeMutation = useMutation({
    mutationFn: () => apiClient.changePassword(currentPassword, newPassword),
    onSuccess: () => {
      setSuccess(true);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => setSuccess(false), 3000);
    },
    onError: (err: Error) => {
      setLocalError(err.message);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError('');

    if (newPassword !== confirmPassword) {
      setLocalError('Passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      setLocalError('Password must be at least 8 characters');
      return;
    }

    changeMutation.mutate();
  };

  return (
    <div className="card">
      <h2 className="card-title" style={{ marginBottom: '16px' }}>Change Password</h2>

      {success && (
        <div style={{ padding: '12px', background: 'rgba(63, 185, 80, 0.1)', borderRadius: '6px', marginBottom: '16px', color: 'var(--signer-success)' }}>
          Password changed successfully!
        </div>
      )}

      {localError && (
        <div className="auth-error">{localError}</div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Current Password</label>
          <input
            type="password"
            className="form-input"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            required
          />
        </div>

        <div className="form-group">
          <label className="form-label">New Password</label>
          <input
            type="password"
            className="form-input"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
          />
        </div>

        <div className="form-group">
          <label className="form-label">Confirm New Password</label>
          <input
            type="password"
            className="form-input"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
        </div>

        <button type="submit" className="btn btn-primary" disabled={changeMutation.isPending}>
          {changeMutation.isPending ? 'Changing...' : 'Change Password'}
        </button>
      </form>
    </div>
  );
}

// ---------------------------------------------------------------------------
// WebAuthn / Passkey helpers
// ---------------------------------------------------------------------------

function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((b) => { binary += String.fromCharCode(b); });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(base64 + padding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ---------------------------------------------------------------------------
// PasskeysCard
// ---------------------------------------------------------------------------

function PasskeysCard() {
  const [name, setName] = useState('Passkey');
  const [status, setStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState('');

  // Guard: hide the whole card if the browser does not support WebAuthn.
  const webAuthnAvailable =
    typeof window !== 'undefined' && typeof window.PublicKeyCredential !== 'undefined';

  const registerPasskey = useCallback(async () => {
    setStatus('idle');
    setErrorMessage('');

    try {
      // Step 1 – get options from the server.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const options = await apiClient.passkeyRegisterBegin() as any;

      // Step 2 – convert base64url fields to ArrayBuffer as required by
      // the WebAuthn API.
      options.publicKey.challenge = base64UrlToArrayBuffer(
        options.publicKey.challenge as string,
      );
      options.publicKey.user.id = base64UrlToArrayBuffer(
        options.publicKey.user.id as string,
      );
      if (Array.isArray(options.publicKey.excludeCredentials)) {
        options.publicKey.excludeCredentials = (
          options.publicKey.excludeCredentials as Array<{ id: string; [k: string]: unknown }>
        ).map((cred) => ({
          ...cred,
          id: base64UrlToArrayBuffer(cred.id),
        }));
      }

      // Step 3 – ask the authenticator to create a credential.
      const credential = (await navigator.credentials.create({
        publicKey: options.publicKey,
      })) as PublicKeyCredential | null;

      if (!credential) {
        throw new Error('No credential returned from authenticator');
      }

      const attestation = credential.response as AuthenticatorAttestationResponse;

      // Step 4 – serialise and send to the server.
      const body: PasskeyRegistrationFinishRequest = {
        id: credential.id,
        rawId: arrayBufferToBase64Url(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: arrayBufferToBase64Url(attestation.attestationObject),
          clientDataJSON: arrayBufferToBase64Url(attestation.clientDataJSON),
        },
      };

      await apiClient.passkeyRegisterFinish(name.trim() || 'Passkey', body);
      setStatus('success');
    } catch (err) {
      if (err instanceof Error && err.name === 'NotAllowedError') {
        // User cancelled or dismissed the browser prompt — not an error.
        return;
      }
      setErrorMessage(
        err instanceof Error ? err.message : 'Failed to register passkey',
      );
      setStatus('error');
    }
  }, [name]);

  if (!webAuthnAvailable) {
    return null;
  }

  return (
    <div className="card">
      <h2 className="card-title" style={{ marginBottom: '16px' }}>Passkeys</h2>
      <p style={{ color: 'var(--signer-text-muted)', marginBottom: '16px' }}>
        Add a passkey to sign in to any Cloistr app without your password.
        Your device (fingerprint, Face ID, or hardware key) authenticates you.
      </p>

      {status === 'success' && (
        <div
          style={{
            padding: '12px',
            background: 'rgba(63, 185, 80, 0.1)',
            borderRadius: '6px',
            marginBottom: '16px',
            color: 'var(--signer-success)',
          }}
        >
          Passkey registered successfully!
        </div>
      )}

      {status === 'error' && (
        <div className="auth-error" style={{ marginBottom: '16px' }}>
          {errorMessage}
        </div>
      )}

      <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-end' }}>
        <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
          <label className="form-label">Passkey name (optional)</label>
          <input
            type="text"
            className="form-input"
            value={name}
            onChange={(e) => {
              setStatus('idle');
              setName(e.target.value);
            }}
            placeholder="e.g. MacBook Touch ID"
            maxLength={64}
          />
        </div>
        <button
          type="button"
          className="btn btn-primary"
          onClick={registerPasskey}
          style={{ whiteSpace: 'nowrap' }}
        >
          Add a passkey
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// LightningCard
// ---------------------------------------------------------------------------

/** How long (ms) between status polls while a LNURL-auth QR is displayed. */
const LIGHTNING_POLL_INTERVAL_MS = 2000;

function LightningCard() {
  // Linked keys list
  const [keys, setKeys] = useState<LightningKey[]>([]);
  const [loadError, setLoadError] = useState('');
  const [loadingKeys, setLoadingKeys] = useState(true);

  // Link-flow state
  type LinkPhase = 'idle' | 'pending' | 'linked' | 'error';
  const [phase, setPhase] = useState<LinkPhase>('idle');
  const [lnurl, setLnurl] = useState('');
  const [linkError, setLinkError] = useState('');
  const [copied, setCopied] = useState(false);

  // Deleting
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState('');

  // QR canvas ref

  // Poll interval ref — cleared on unmount / success / error
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // -------------------------------------------------------------------------
  // Load linked keys on mount
  // -------------------------------------------------------------------------
  const loadKeys = useCallback(async () => {
    setLoadError('');
    setLoadingKeys(true);
    try {
      const list = await apiClient.lightningListKeys();
      setKeys(list);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Failed to load Lightning keys');
    } finally {
      setLoadingKeys(false);
    }
  }, []);

  useEffect(() => {
    loadKeys();
  }, [loadKeys]);


  // -------------------------------------------------------------------------
  // Cleanup poll on unmount
  // -------------------------------------------------------------------------
  useEffect(() => {
    return () => {
      if (pollRef.current !== null) {
        clearInterval(pollRef.current);
      }
    };
  }, []);

  // -------------------------------------------------------------------------
  // Start a link-challenge flow
  // -------------------------------------------------------------------------
  const startLink = useCallback(async () => {
    setLinkError('');
    setPhase('pending');
    setCopied(false);

    try {
      const challenge = await apiClient.lightningLinkChallenge();
      setLnurl(challenge.lnurl);

      // Begin polling
      pollRef.current = setInterval(async () => {
        try {
          const result = await apiClient.lightningStatus(challenge.session_id);
          if (result.success) {
            clearInterval(pollRef.current!);
            pollRef.current = null;
            setPhase('linked');
            setLnurl('');
            // Refresh the key list to show the newly linked wallet
            loadKeys();
          } else if (result.status === 'expired') {
            clearInterval(pollRef.current!);
            pollRef.current = null;
            setPhase('error');
            setLinkError('QR code expired. Please try again.');
            setLnurl('');
          }
          // status === 'pending': keep polling
        } catch {
          clearInterval(pollRef.current!);
          pollRef.current = null;
          setPhase('error');
          setLinkError('Lost connection while waiting for wallet confirmation.');
          setLnurl('');
        }
      }, LIGHTNING_POLL_INTERVAL_MS);
    } catch (err) {
      setPhase('error');
      setLinkError(err instanceof Error ? err.message : 'Failed to start wallet link');
    }
  }, [loadKeys]);

  const cancelLink = useCallback(() => {
    if (pollRef.current !== null) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    setPhase('idle');
    setLnurl('');
    setLinkError('');
  }, []);

  // -------------------------------------------------------------------------
  // Unlink a key
  // -------------------------------------------------------------------------
  const unlinkKey = useCallback(async (id: string) => {
    setDeleteError('');
    setDeletingId(id);
    try {
      await apiClient.lightningDeleteKey(id);
      setKeys((prev) => prev.filter((k) => k.id !== id));
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Failed to unlink wallet');
    } finally {
      setDeletingId(null);
    }
  }, []);

  // -------------------------------------------------------------------------
  // Copy LNURL to clipboard
  // -------------------------------------------------------------------------
  const copyLnurl = useCallback(() => {
    if (!lnurl) return;
    navigator.clipboard.writeText(lnurl).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [lnurl]);

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------
  return (
    <div className="card">
      <h2 className="card-title" style={{ marginBottom: '16px' }}>Lightning Wallet</h2>
      <p style={{ color: 'var(--signer-text-muted)', marginBottom: '16px' }}>
        Link a Lightning wallet via LNURL-auth to enable Bitcoin payments across
        Cloistr apps. Scan the QR code with any compatible wallet.
      </p>

      {/* Success banner after linking */}
      {phase === 'linked' && (
        <div
          style={{
            padding: '12px',
            background: 'rgba(63, 185, 80, 0.1)',
            borderRadius: '6px',
            marginBottom: '16px',
            color: 'var(--signer-success)',
          }}
        >
          Lightning wallet linked successfully!
        </div>
      )}

      {/* Link-flow error */}
      {phase === 'error' && linkError && (
        <div className="auth-error" style={{ marginBottom: '16px' }}>
          {linkError}
        </div>
      )}

      {/* Unlink error */}
      {deleteError && (
        <div className="auth-error" style={{ marginBottom: '16px' }}>
          {deleteError}
        </div>
      )}

      {/* Existing linked keys */}
      {loadError ? (
        <div className="auth-error" style={{ marginBottom: '16px' }}>{loadError}</div>
      ) : loadingKeys ? (
        <p style={{ color: 'var(--signer-text-muted)', marginBottom: '16px' }}>
          Loading linked wallets…
        </p>
      ) : keys.length > 0 ? (
        <div style={{ marginBottom: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {keys.map((k) => (
            <div
              key={k.id}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '10px 12px',
                background: 'var(--signer-bg)',
                border: '1px solid var(--signer-border)',
                borderRadius: '6px',
              }}
            >
              <div>
                <div style={{ fontWeight: 500 }}>
                  {k.name ?? 'Lightning wallet'}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--signer-text-muted)', marginTop: '2px' }}>
                  Linked {new Date(k.created_at).toLocaleDateString()}
                  {k.last_used_at && (
                    <> · Last used {new Date(k.last_used_at).toLocaleDateString()}</>
                  )}
                </div>
              </div>
              <button
                type="button"
                className="btn btn-danger btn-sm"
                disabled={deletingId === k.id}
                onClick={() => unlinkKey(k.id)}
              >
                {deletingId === k.id ? 'Unlinking…' : 'Unlink'}
              </button>
            </div>
          ))}
        </div>
      ) : null}

      {/* QR / pending flow */}
      {phase === 'pending' && lnurl ? (
        <div style={{ marginTop: '8px' }}>
          <p style={{ color: 'var(--signer-text-muted)', marginBottom: '12px', fontSize: '13px' }}>
            Open the link below in your Lightning wallet, or copy the LNURL code
            and paste it into your wallet. This request expires after a few minutes.
          </p>

          {/* LNURL code (selectable / paste into wallet) */}
          <div style={{ marginBottom: '12px' }}>
            <code
              style={{
                display: 'block',
                wordBreak: 'break-all',
                fontSize: '12px',
                padding: '8px',
                background: 'var(--signer-bg-muted, rgba(0,0,0,0.2))',
                borderRadius: '6px',
              }}
            >
              {lnurl}
            </code>
          </div>

          {/* Deep link */}
          <div style={{ marginBottom: '12px' }}>
            <a
              href={`lightning:${lnurl}`}
              style={{ fontSize: '13px', wordBreak: 'break-all' }}
            >
              Open in wallet app
            </a>
          </div>

          {/* Copy button */}
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={copyLnurl}
            >
              {copied ? 'Copied!' : 'Copy LNURL'}
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={cancelLink}
            >
              Cancel
            </button>
          </div>

          <p style={{ color: 'var(--signer-text-muted)', fontSize: '12px', marginTop: '12px' }}>
            Waiting for wallet confirmation…
          </p>
        </div>
      ) : (
        /* Show "Link a Lightning wallet" button when not in pending/linked flow */
        phase !== 'linked' && (
          <button
            type="button"
            className="btn btn-primary"
            onClick={startLink}
          >
            Link a Lightning wallet
          </button>
        )
      )}

      {/* After success, offer to link another */}
      {phase === 'linked' && (
        <button
          type="button"
          className="btn btn-secondary"
          style={{ marginTop: '8px' }}
          onClick={() => { setPhase('idle'); }}
        >
          Link another wallet
        </button>
      )}
    </div>
  );
}
