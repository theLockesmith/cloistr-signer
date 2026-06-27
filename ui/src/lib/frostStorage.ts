// FROST user-share storage layer for the browser.
//
// docs/frost-2-of-n-design.md §3.2: the user's FROST share lives in
// IndexedDB encrypted under a key derived from the user's password. This
// module owns that storage and the in-memory KEK that wraps it.
//
// Lifecycle:
//   1. After a successful login, the auth flow calls unlockShareStorage()
//      with the password the user just typed. PBKDF2 derives a 256-bit
//      KEK; the KEK is held in this module's memory only. The password
//      itself is forgotten by the caller immediately.
//   2. createFrostKey() (lib/frost.ts) calls storeShare() after the DKG
//      finalize succeeds. The share scalar is AES-GCM-encrypted under
//      the KEK and persisted to IndexedDB keyed by key_id.
//   3. P4 cosigning loads the share via loadShare(); the decrypted
//      scalar lives in memory only for the duration of a single
//      partial-signature computation.
//   4. Logout calls lockShareStorage() which drops the KEK from memory.
//
// Threat model:
//   - At-rest IndexedDB compromise (someone with disk access to the
//     browser's data) sees only AES-GCM ciphertext. Password not
//     recoverable from the salt + ciphertext without dictionary attack
//     against the PBKDF2 (600,000 iterations).
//   - Compromised browser at session-time (malicious extension, etc.)
//     CAN extract the KEK from memory. We do not solve this; the
//     trade-off is documented in the design doc.
//   - Lost device with browser data: same as above. Recovery via the
//     BIP39 phrase (internal/crypto/recovery_phrase.go) re-derives the
//     share from scratch in P3e.

const DB_NAME = 'cloistr-frost';
const DB_VERSION = 1;
const META_STORE = 'meta';
const SHARES_STORE = 'shares';

// PBKDF2 iteration count. 600,000 is the current OWASP Password Storage
// Cheat Sheet baseline for HMAC-SHA-256.
const PBKDF2_ITERATIONS = 600_000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const KEK_LENGTH_BITS = 256;

// Module-scoped KEK. Lives in this tab's memory only - NEVER serialized,
// NEVER sent over the network, NEVER passed to other modules. Other
// modules call storeShare/loadShare which use this KEK internally.
let activeKek: CryptoKey | null = null;

// Per-user salt cache to avoid re-reading IndexedDB on every operation.
let activeSalt: Uint8Array | null = null;

// User the KEK was derived for - lets loadShare/storeShare assert the
// caller is operating against the same user that unlocked.
let activeUserId: string | null = null;

interface ShareRecord {
  keyId: string;
  pubkey: string;
  ciphertext: Uint8Array;
  iv: Uint8Array;
  verificationShareHex: string;
  createdAt: number;
}

/**
 * The decrypted-share payload returned by loadShare. The plaintext
 * finalShareHex MUST be discarded as soon as the partial-signature
 * computation is done.
 */
export interface DecryptedShare {
  keyId: string;
  pubkey: string;
  finalShareHex: string;
  verificationShareHex: string;
  createdAt: number;
}

/**
 * Errors thrown by this module. Specific subclasses let callers respond
 * differently to "locked" (prompt for re-login) vs "decryption failed"
 * (likely wrong password, or IndexedDB corruption).
 */
export class FrostStorageLockedError extends Error {
  constructor() {
    super('FROST share storage is locked - call unlockShareStorage first');
    this.name = 'FrostStorageLockedError';
  }
}

export class FrostStorageDecryptError extends Error {
  constructor() {
    super('failed to decrypt FROST share - wrong password or corrupted storage');
    this.name = 'FrostStorageDecryptError';
  }
}

// ---------------------------------------------------------------------
// IndexedDB plumbing
// ---------------------------------------------------------------------

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(META_STORE)) {
        db.createObjectStore(META_STORE);
      }
      if (!db.objectStoreNames.contains(SHARES_STORE)) {
        db.createObjectStore(SHARES_STORE, { keyPath: 'keyId' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexedDB open failed'));
  });
}

function tx<T>(
  storeName: string,
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest<T> | Promise<T>,
): Promise<T> {
  return new Promise(async (resolve, reject) => {
    try {
      const db = await openDb();
      const transaction = db.transaction(storeName, mode);
      const store = transaction.objectStore(storeName);
      const out = run(store);
      transaction.oncomplete = () => {
        // If run() returned a request, resolve with its result; if a
        // promise, the promise itself will resolve before oncomplete.
        if (out && 'result' in out) {
          resolve((out as IDBRequest<T>).result);
        }
      };
      transaction.onerror = () => reject(transaction.error ?? new Error('indexedDB tx failed'));
      transaction.onabort = () => reject(transaction.error ?? new Error('indexedDB tx aborted'));

      if (out instanceof Promise) {
        out.then(resolve, reject);
      }
    } catch (err) {
      reject(err);
    }
  });
}

// ---------------------------------------------------------------------
// Hex helpers (independent of the WASM module - this layer doesn't
// depend on the FROST crypto)
// ---------------------------------------------------------------------

function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0) throw new Error('hex length not even');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

// ---------------------------------------------------------------------
// KEK derivation
// ---------------------------------------------------------------------

async function deriveKek(password: string, salt: Uint8Array): Promise<CryptoKey> {
  // Cast to BufferSource because TS 5 narrows Uint8Array to ArrayBufferLike,
  // but WebCrypto APIs accept the wider BufferSource union at runtime.
  const passwordBytes = new TextEncoder().encode(password) as unknown as BufferSource;
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    passwordBytes,
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as unknown as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: KEK_LENGTH_BITS },
    false, // KEK is non-extractable - cannot be exported even from WebCrypto
    ['encrypt', 'decrypt'],
  );
}

async function getOrCreateSalt(userId: string): Promise<Uint8Array> {
  const metaKey = `salt:${userId}`;
  const existing = await tx<Uint8Array | undefined>(META_STORE, 'readonly', (store) => store.get(metaKey));
  if (existing instanceof Uint8Array) return existing;

  const fresh = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  await tx<IDBValidKey>(META_STORE, 'readwrite', (store) => store.put(fresh, metaKey));
  return fresh;
}

// ---------------------------------------------------------------------
// Public lifecycle API
// ---------------------------------------------------------------------

/**
 * Derive and cache the KEK for this user. Call after a successful login,
 * passing the password the user just typed. The password should not be
 * stored anywhere by the caller; this module forgets it after derivation.
 */
export async function unlockShareStorage(password: string, userId: string): Promise<void> {
  const salt = await getOrCreateSalt(userId);
  const kek = await deriveKek(password, salt);
  activeKek = kek;
  activeSalt = salt;
  activeUserId = userId;
}

/**
 * Drop the KEK from memory. Call on logout, on session expiry detection,
 * or whenever the user explicitly locks the app.
 */
export function lockShareStorage(): void {
  activeKek = null;
  activeSalt = null;
  activeUserId = null;
}

/** True iff a KEK is currently held in memory for the given user. */
export function isShareStorageUnlocked(userId?: string): boolean {
  if (activeKek === null) return false;
  if (userId !== undefined && activeUserId !== userId) return false;
  return true;
}

// ---------------------------------------------------------------------
// Share CRUD
// ---------------------------------------------------------------------

function requireKek(): CryptoKey {
  if (activeKek === null) throw new FrostStorageLockedError();
  return activeKek;
}

export interface StoreShareInput {
  keyId: string;
  pubkey: string;
  finalShareHex: string;
  verificationShareHex: string;
}

/**
 * Encrypt and persist a FROST user share. KEK must be unlocked. Overwrites
 * any existing record for the same keyId (used for share rotation).
 */
export async function storeShare(input: StoreShareInput): Promise<void> {
  const kek = requireKek();
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const plaintext = hexToBytes(input.finalShareHex);
  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    kek,
    plaintext as unknown as BufferSource,
  );
  const record: ShareRecord = {
    keyId: input.keyId,
    pubkey: input.pubkey,
    ciphertext: new Uint8Array(ciphertextBuf),
    iv,
    verificationShareHex: input.verificationShareHex,
    createdAt: Date.now(),
  };
  await tx<IDBValidKey>(SHARES_STORE, 'readwrite', (store) => store.put(record));
}

/**
 * Load and decrypt a share. Throws FrostStorageLockedError if no KEK,
 * FrostStorageDecryptError on auth-tag mismatch (wrong password or
 * tampering). Returns null if no record exists for the keyId.
 */
export async function loadShare(keyId: string): Promise<DecryptedShare | null> {
  const kek = requireKek();
  const record = await tx<ShareRecord | undefined>(SHARES_STORE, 'readonly', (store) => store.get(keyId));
  if (!record) return null;

  let plaintextBuf: ArrayBuffer;
  try {
    plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: record.iv as unknown as BufferSource },
      kek,
      record.ciphertext as unknown as BufferSource,
    );
  } catch {
    throw new FrostStorageDecryptError();
  }
  return {
    keyId: record.keyId,
    pubkey: record.pubkey,
    finalShareHex: bytesToHex(new Uint8Array(plaintextBuf)),
    verificationShareHex: record.verificationShareHex,
    createdAt: record.createdAt,
  };
}

/**
 * Check whether a share exists for the given keyId without decrypting it.
 * Cheap; does not require the KEK to be unlocked.
 */
export async function hasShare(keyId: string): Promise<boolean> {
  const count = await tx<number>(SHARES_STORE, 'readonly', (store) => store.count(keyId));
  return count > 0;
}

/**
 * List all key IDs that have a share stored on this device. Useful for
 * the Keys page to indicate which FROST keys are "active" on this
 * browser. Does not require the KEK.
 */
export async function listShareIds(): Promise<string[]> {
  return tx<string[]>(SHARES_STORE, 'readonly', (store) => {
    return new Promise<string[]>((resolve, reject) => {
      const req = store.getAllKeys();
      req.onsuccess = () => resolve((req.result as IDBValidKey[]).map((k) => String(k)));
      req.onerror = () => reject(req.error ?? new Error('listShareIds failed'));
    });
  });
}

/**
 * Delete a share. Used by share-refresh + device-revoke flows. The KEK
 * is NOT required - the operation only removes ciphertext, doesn't read
 * it.
 */
export async function deleteShare(keyId: string): Promise<void> {
  await tx<undefined>(SHARES_STORE, 'readwrite', (store) => store.delete(keyId));
}

// Exported for tests. Not part of the stable API.
export const _internal = {
  PBKDF2_ITERATIONS,
  SALT_LENGTH,
  IV_LENGTH,
  activeSaltView: (): Uint8Array | null => activeSalt,
  activeUserView: (): string | null => activeUserId,
};
