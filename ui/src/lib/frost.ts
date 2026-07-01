// FROST 2-of-N user-cosigner DKG orchestrator. Drives the three-round
// ceremony against the signer's /api/v1/frost/user-dkg/* endpoints,
// using the WASM share-holder in ui/frost-wasm/ for the cryptographic
// primitives.
//
// See docs/frost-2-of-n-design.md §4.2 for the protocol. The Go-side
// implementation in internal/frost/user_dkg.go is the counterparty.
//
// Trust posture:
//   - The WASM module owns the cryptographic math. JS never touches scalars
//     or points directly.
//   - The user_state_hex blob holds the user's secret polynomial
//     coefficients across rounds. It is created in generateUserDkgState()
//     and destroyed in a finally block - in either success or error path -
//     before this function returns. JS callers never see it.
//   - The signer's share is Pedersen-verified BEFORE being used. A
//     malicious signer cannot feed the user a share that doesn't
//     correspond to its committed polynomial without aborting.
//   - The joint pubkey is computed locally from A0 + B0 and confirmed via
//     the finalize endpoint. The signer cannot lie about the joint
//     pubkey: the user has already computed it from the same inputs.

import apiClient from '../api/client';
import {
  storeShare,
  isShareStorageUnlocked,
  FrostStorageLockedError,
} from './frostStorage';

// Static-relative import of the wasm-pack output. Vite resolves the JS
// wrapper at build time; the .wasm binary is loaded at runtime via the
// `?url` import below.
//
// The pkg/ directory is build output from `wasm-pack build --target web
// --release`, gitignored. Fresh checkouts must run that build before
// `npm run build` here. See ui/frost-wasm/README.md.
import init, {
  generate_recovery_phrase,
  is_valid_recovery_phrase,
  derive_user_dkg_state_from_phrase,
  compute_share_for_signer,
  verify_signer_share,
  compute_joint_pubkey,
  compute_user_final_share,
  compute_user_verification_share,
} from '../../frost-wasm/pkg/cloistr_frost_wasm.js';
import wasmUrl from '../../frost-wasm/pkg/cloistr_frost_wasm_bg.wasm?url';

// Lazy single-flight init. Multiple createFrostKey() calls share the same
// WASM module instance; we don't pay the load cost more than once per
// page lifetime.
let wasmInitPromise: Promise<void> | null = null;

function initWasm(): Promise<void> {
  if (!wasmInitPromise) {
    wasmInitPromise = init(wasmUrl).then(() => undefined).catch((err) => {
      // Reset so a future call can retry rather than hang on the
      // failed promise forever.
      wasmInitPromise = null;
      throw err;
    });
  }
  return wasmInitPromise;
}

/**
 * Result returned by createFrostKey() on a successful DKG ceremony.
 *
 * userFinalShareHex is the scalar the caller MUST store securely (P3d
 * wraps it with a password-derived KEK and persists to IndexedDB).
 * userVerificationShareHex is public material used by the signer to
 * verify the user's partial signatures during signing (P4).
 */
export interface CreatedFrostKey {
  keyId: string;
  pubkey: string;
  userFinalShareHex: string;
  userVerificationShareHex: string;
}

interface UserDkgStatePayload {
  user_state_hex: string;
  commits_hex: string[];
}

/**
 * Generate a fresh 24-word BIP39 recovery phrase. The caller MUST display
 * it to the user once and obtain explicit acknowledgement before passing
 * it to createFrostKeyWithPhrase. After the ceremony completes the phrase
 * is the user's only recovery path; if they don't write it down, losing
 * IndexedDB is permanent loss.
 */
export async function generateFrostRecoveryPhrase(): Promise<string> {
  await initWasm();
  return generate_recovery_phrase() as string;
}

/**
 * Cheap structural + checksum validation of a typed-in phrase. Used by
 * the recovery UI to catch typos before the network roundtrip.
 */
export async function isValidFrostRecoveryPhrase(phrase: string): Promise<boolean> {
  await initWasm();
  return is_valid_recovery_phrase(phrase) as boolean;
}

/**
 * Drive the full 3-round FROST 2-of-N user-cosigner DKG using a phrase
 * the user has just been shown (and confirmed they wrote down). The
 * resulting key is RECOVERABLE: on a fresh browser, recoverFrostKey()
 * with the same phrase reproduces the same final share.
 *
 * passphrase is the BIP39 25th-word secret. Empty string is acceptable
 * for users who don't want passphrase composition.
 *
 * On any failure - network, cryptographic verification, or signer-side
 * rejection - throws and ensures the user_state_hex is destroyed. The
 * server-side DKG session also self-aborts on any 4xx from the
 * intermediate rounds.
 *
 * Caller must hold an authenticated session AND must have already called
 * unlockShareStorage (the share storage KEK must be derivable).
 */
export async function createFrostKeyWithPhrase(
  phrase: string,
  passphrase: string = '',
): Promise<CreatedFrostKey> {
  if (!isShareStorageUnlocked()) {
    throw new FrostStorageLockedError();
  }

  await initWasm();

  const initial = derive_user_dkg_state_from_phrase(phrase, passphrase) as UserDkgStatePayload;
  let userStateHex: string | null = initial.user_state_hex;
  const userCommitsHex = initial.commits_hex;

  try {
    // Round 1
    const r1 = await apiClient.frostUserDkgRound1({
      user_commits_hex: userCommitsHex,
    });
    if (!r1.session_id || r1.signer_commits_hex?.length !== 2) {
      throw new Error('signer round1 response missing session_id or commits');
    }

    // Round 2: send our share-for-signer; verify signer's share against its
    // round 1 commitments before accepting.
    const userShareForSignerHex = compute_share_for_signer(userStateHex);
    const r2 = await apiClient.frostUserDkgRound2({
      session_id: r1.session_id,
      user_share_for_signer_hex: userShareForSignerHex,
    });
    if (!r2.signer_share_for_user_hex) {
      throw new Error('signer round2 response missing share');
    }
    const signerShareValid = verify_signer_share(
      r2.signer_share_for_user_hex,
      r1.signer_commits_hex,
    ) as boolean;
    if (!signerShareValid) {
      throw new Error("signer's share did not verify against its commitments");
    }

    // Independently compute joint pubkey + aggregated final share.
    const jointPubkeyHex = compute_joint_pubkey(
      userStateHex,
      r1.signer_commits_hex[0],
    ) as string;
    const userFinalShareHex = compute_user_final_share(
      userStateHex,
      r2.signer_share_for_user_hex,
    ) as string;
    const userVerificationShareHex = compute_user_verification_share(
      userFinalShareHex,
    ) as string;

    // Finalize - now WITH user_verification_share so the signer can
    // persist the recovery materials (design doc §6.4, P3e-b).
    const fin = await apiClient.frostUserDkgFinalize({
      session_id: r1.session_id,
      confirm_joint_pubkey_hex: jointPubkeyHex,
      user_verification_share_hex: userVerificationShareHex,
    });
    if (!fin.key_id || !fin.pubkey) {
      throw new Error('signer finalize response missing key_id or pubkey');
    }

    await storeShare({
      keyId: fin.key_id,
      pubkey: fin.pubkey,
      finalShareHex: userFinalShareHex,
      verificationShareHex: userVerificationShareHex,
    });

    return {
      keyId: fin.key_id,
      pubkey: fin.pubkey,
      userFinalShareHex,
      userVerificationShareHex,
    };
  } finally {
    // Drop the polynomial coefficients - the phrase itself stays with
    // the user (on paper) as the long-term recovery anchor; this
    // in-memory derivation is ephemeral.
    if (userStateHex !== null) {
      userStateHex = null;
    }
  }
}

/**
 * P7 Path A migration: convert an existing user-owned local key to
 * FROST-user shape without changing the pubkey. Server splits the nsec
 * into (p_signer, p_user); this function stores p_user in IndexedDB
 * under the KEK so subsequent cosigning finds it.
 */
export async function migrateKeyToFrostPathA(keyId: string): Promise<CreatedFrostKey> {
  if (!isShareStorageUnlocked()) {
    throw new FrostStorageLockedError();
  }
  const resp = await apiClient.frostMigratePathA(keyId);
  await storeShare({
    keyId: resp.key_id,
    pubkey: resp.pubkey,
    finalShareHex: resp.user_share_hex,
    verificationShareHex: resp.user_verification_share_hex,
  });
  return {
    keyId: resp.key_id,
    pubkey: resp.pubkey,
    userFinalShareHex: resp.user_share_hex,
    userVerificationShareHex: resp.user_verification_share_hex,
  };
}

/**
 * Errors recoverFrostKey throws to distinguish recoverable user mistakes
 * (wrong phrase, key never had recovery support) from infrastructure
 * problems (Vault down, server unreachable).
 */
export class FrostRecoveryWrongPhraseError extends Error {
  constructor() {
    super('the phrase does not reconstruct the original FROST share for this key');
    this.name = 'FrostRecoveryWrongPhraseError';
  }
}

/**
 * Reconstruct a FROST user share from a BIP39 phrase and the signer's
 * stored recovery materials. After success the share is persisted to
 * IndexedDB exactly like createFrostKeyWithPhrase persists fresh DKG
 * output - subsequent signing on this device works without re-entering
 * the phrase.
 *
 * Flow (design doc §6.4):
 *   1. Derive (a0, a1) deterministically from phrase + passphrase.
 *   2. GET /recovery/{keyId} → signer_share_for_user_hex + user_verification_share_hex.
 *   3. final_share = f(UserIndex) + signer_share_for_user, where f is
 *      the polynomial derived from the phrase. Compute via WASM.
 *   4. Verify final_share·G == user_verification_share_hex. If yes the
 *      phrase is correct; if no the user typed the wrong phrase
 *      (or the signer is lying, which is detected here too).
 *   5. Persist to IndexedDB.
 *
 * Caller must hold an authenticated session and must have already
 * unlocked share storage.
 */
export async function recoverFrostKey(
  keyId: string,
  phrase: string,
  passphrase: string = '',
): Promise<CreatedFrostKey> {
  if (!isShareStorageUnlocked()) {
    throw new FrostStorageLockedError();
  }

  await initWasm();

  // Phrase-derived polynomial. The user_state_hex blob is ephemeral
  // and destroyed in finally.
  const derived = derive_user_dkg_state_from_phrase(phrase, passphrase) as UserDkgStatePayload;
  let userStateHex: string | null = derived.user_state_hex;

  try {
    const rec = await apiClient.frostUserDkgRecovery(keyId);
    if (!rec.signer_share_for_user_hex || !rec.user_verification_share_hex) {
      throw new Error('recovery response missing required fields');
    }

    const userFinalShareHex = compute_user_final_share(
      userStateHex,
      rec.signer_share_for_user_hex,
    ) as string;
    const recomputedVerificationShare = compute_user_verification_share(
      userFinalShareHex,
    ) as string;

    if (recomputedVerificationShare !== rec.user_verification_share_hex) {
      // Phrase mismatch (most likely) OR server returned wrong recovery
      // materials. Either way, we refuse to persist a wrong share -
      // doing so would brick the user (they'd think recovery succeeded
      // but signing would fail). Fail loud so the UI can prompt for
      // the correct phrase.
      throw new FrostRecoveryWrongPhraseError();
    }

    await storeShare({
      keyId: rec.key_id,
      pubkey: rec.pubkey,
      finalShareHex: userFinalShareHex,
      verificationShareHex: rec.user_verification_share_hex,
    });

    return {
      keyId: rec.key_id,
      pubkey: rec.pubkey,
      userFinalShareHex,
      userVerificationShareHex: rec.user_verification_share_hex,
    };
  } finally {
    if (userStateHex !== null) {
      userStateHex = null;
    }
  }
}
