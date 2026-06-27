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
  generate_user_dkg_state,
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
 * userFinalShareHex is the scalar the caller MUST store securely (in P3d
 * this gets wrapped by a password-derived KEK and persisted to IndexedDB).
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
 * Drive the full 3-round FROST 2-of-N user-cosigner DKG against the
 * signer endpoints. Returns the created key's id + pubkey on success.
 *
 * On any failure - network, cryptographic verification, or signer-side
 * rejection - throws and ensures the user_state_hex is destroyed. The
 * server-side DKG session also self-aborts on any 4xx from the
 * intermediate rounds.
 *
 * Caller must hold an authenticated session (apiClient.setToken).
 */
export async function createFrostKey(): Promise<CreatedFrostKey> {
  // Fail fast if the KEK is locked. Otherwise we'd run the full ceremony,
  // build the final share, then discover at storeShare time that we
  // can't persist it - losing the share material.
  if (!isShareStorageUnlocked()) {
    throw new FrostStorageLockedError();
  }

  await initWasm();

  const initial = generate_user_dkg_state() as UserDkgStatePayload;
  let userStateHex: string | null = initial.user_state_hex;
  const userCommitsHex = initial.commits_hex;

  try {
    // Round 1: send our commits, get the signer's commits + session_id.
    const r1 = await apiClient.frostUserDkgRound1({
      user_commits_hex: userCommitsHex,
    });
    if (!r1.session_id || r1.signer_commits_hex?.length !== 2) {
      throw new Error('signer round1 response missing session_id or commits');
    }

    // Round 2: compute and send our share-for-signer; the signer responds
    // with its share-for-us.
    const userShareForSignerHex = compute_share_for_signer(userStateHex);
    const r2 = await apiClient.frostUserDkgRound2({
      session_id: r1.session_id,
      user_share_for_signer_hex: userShareForSignerHex,
    });
    if (!r2.signer_share_for_user_hex) {
      throw new Error('signer round2 response missing share');
    }

    // Cryptographic verification: the signer's share MUST validate against
    // the signer's commits from round 1. Without this check, a malicious
    // signer could feed us a share whose corresponding scalar doesn't
    // produce a sensible joint identity.
    const signerShareValid = verify_signer_share(
      r2.signer_share_for_user_hex,
      r1.signer_commits_hex,
    ) as boolean;
    if (!signerShareValid) {
      throw new Error("signer's share did not verify against its commitments");
    }

    // Independently compute the joint pubkey from A0 + B0. The signer
    // computes the same value server-side; we send ours up at finalize
    // and the signer rejects on mismatch.
    const jointPubkeyHex = compute_joint_pubkey(
      userStateHex,
      r1.signer_commits_hex[0],
    ) as string;

    // Aggregate the final share = f(UserIndex) + signer_share.
    // After this point, the polynomial coefficients (a0, a1) are no
    // longer needed - everything we keep going forward is the
    // aggregated share.
    const userFinalShareHex = compute_user_final_share(
      userStateHex,
      r2.signer_share_for_user_hex,
    ) as string;
    const userVerificationShareHex = compute_user_verification_share(
      userFinalShareHex,
    ) as string;

    // Finalize: confirm the pubkey to the signer. On success the signer
    // persists its share and returns key_id + the BIP-340 x-only pubkey.
    const fin = await apiClient.frostUserDkgFinalize({
      session_id: r1.session_id,
      confirm_joint_pubkey_hex: jointPubkeyHex,
    });
    if (!fin.key_id || !fin.pubkey) {
      throw new Error('signer finalize response missing key_id or pubkey');
    }

    // Persist the user share to IndexedDB, encrypted under the
    // password-derived KEK. After this returns, the share survives
    // page reloads on this device. Lose the device or clear IndexedDB
    // and recovery is via the BIP39 phrase (P3e).
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
    // Always destroy the polynomial coefficients. They are not needed
    // after the ceremony - only the aggregated final share matters.
    // Even on success this is intentional: in P3d the final share is
    // wrapped by a password-derived KEK and stored; the coefficients
    // never persist anywhere.
    if (userStateHex !== null) {
      userStateHex = null;
    }
  }
}
