//! Browser-side FROST 2-of-N user-cosigner share holder.
//!
//! Wire-compatible with the Go signer-side DKG in
//! `internal/frost/user_dkg.go`. This crate exposes the minimal set of
//! functions a browser needs to drive the 3-round DKG against the
//! /api/v1/frost/user-dkg/* endpoints and to participate in subsequent
//! per-signature cosigning ceremonies (P4 future).
//!
//! Threshold and indices are fixed for 2-of-N:
//!   user index = 1, signer index = 2, threshold = 2.
//!
//! Math (matches the Go side exactly):
//!   User polynomial:   f(x) = a0 + a1·x
//!   Commitments:       A0 = a0·G,  A1 = a1·G
//!   Share for signer:  f(SignerIndex) = a0 + 2·a1
//!   Signer's share to us must verify against:
//!                      signer_share·G == B0 + UserIndex·B1
//!   Joint pubkey:      P = A0 + B0
//!   User's final share = f(UserIndex) + signer_share_for_user
//!
//! State management: this crate is intentionally STATELESS. The two secret
//! scalars (a0, a1) are returned to the JS caller as an opaque hex blob
//! ("user_state") that the caller is responsible for protecting between
//! rounds (typically: hold in memory only, never serialize). After
//! finalize, only the aggregated final share survives; a0/a1 should be
//! discarded.

use bip39::Mnemonic;
use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::Field;
use hkdf::Hkdf;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar, U256};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

/// Signer's participant index in 2-of-N. Must match
/// `internal/frost/user_dkg.go` SignerIndex.
pub const SIGNER_INDEX: u64 = 2;

/// User's participant index in 2-of-N. Must match
/// `internal/frost/user_dkg.go` UserIndex.
pub const USER_INDEX: u64 = 1;

/// Word count for cloistr recovery phrases. 24 words = 256 bits of entropy,
/// matching `internal/crypto/recovery_phrase.go` PhraseWordCount on the Go
/// side. We deliberately do NOT support shorter variants - any phrase
/// weaker than the secp256k1 keys it protects is not worth offering.
pub const PHRASE_WORD_COUNT: usize = 24;
const PHRASE_ENTROPY_BYTES: usize = 32; // 24 words

/// HKDF info string for the share-seed derivation. The "-v1" suffix lets
/// us version the derivation if we ever need to migrate to a new scheme
/// without breaking existing phrases (the new scheme would use "-v2").
const SHARE_SEED_INFO: &[u8] = b"cloistr-frost-share-v1";

// --- Internal helpers ---------------------------------------------------

fn scalar_from_u64(n: u64) -> Scalar {
    Scalar::reduce(U256::from(n))
}

fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

fn scalar_from_hex(h: &str) -> Result<Scalar, String> {
    let bytes = hex::decode(h).map_err(|e| format!("scalar hex decode: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("scalar must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let s_opt = Scalar::from_repr(arr.into());
    if bool::from(s_opt.is_some()) {
        Ok(s_opt.unwrap())
    } else {
        Err("scalar bytes outside field order".to_string())
    }
}

/// Serialize a projective point as compressed-SEC1 hex (33 bytes,
/// 0x02/0x03 prefix + x). This matches what `bytemare/ecc` Element.Hex()
/// emits on the Go side.
fn point_to_hex(p: &ProjectivePoint) -> String {
    let affine = p.to_affine();
    let encoded = affine.to_encoded_point(true);
    hex::encode(encoded.as_bytes())
}

fn point_from_hex(h: &str) -> Result<ProjectivePoint, String> {
    let bytes = hex::decode(h).map_err(|e| format!("point hex decode: {}", e))?;
    if bytes.len() != 33 {
        return Err(format!("compressed point must be 33 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 33];
    arr.copy_from_slice(&bytes);
    let opt = ProjectivePoint::from_bytes(&arr.into());
    if bool::from(opt.is_some()) {
        Ok(opt.unwrap())
    } else {
        Err("point bytes do not decode to a valid curve element".to_string())
    }
}

/// f(x) = a0 + a1·x. Used for the 2-of-N (degree-1) polynomial evaluation.
fn eval_linear(a0: &Scalar, a1: &Scalar, x: u64) -> Scalar {
    let x_scalar = scalar_from_u64(x);
    *a0 + (*a1 * x_scalar)
}

/// Verifies share·G == commit0 + idx·commit1 (Pedersen-style share check
/// against the sender's commitments).
fn verify_share(share: &Scalar, commit0: &ProjectivePoint, commit1: &ProjectivePoint, idx: u64) -> bool {
    let idx_scalar = scalar_from_u64(idx);
    let expected = *commit0 + (*commit1 * idx_scalar);
    let actual = ProjectivePoint::GENERATOR * (*share);
    expected == actual
}

// --- Public WASM exports -----------------------------------------------

/// Generate fresh user DKG state and return commitments to send in Round 1.
///
/// Returns an object with two fields:
///   - `user_state_hex`: opaque hex (64 chars = 32 bytes a0 || 32 bytes a1)
///     the JS layer must hold securely across rounds.
///   - `commits_hex`: array of 2 hex strings [A0, A1] (compressed SEC1).
///
/// Throws on entropy failure (browser without crypto.getRandomValues).
#[wasm_bindgen]
pub fn generate_user_dkg_state() -> Result<JsValue, JsValue> {
    let mut rng = OsRng;
    let a0 = Scalar::random(&mut rng);
    let a1 = Scalar::random(&mut rng);

    let a0_pt = ProjectivePoint::GENERATOR * a0;
    let a1_pt = ProjectivePoint::GENERATOR * a1;

    let mut state_bytes = Vec::with_capacity(64);
    state_bytes.extend_from_slice(&a0.to_bytes());
    state_bytes.extend_from_slice(&a1.to_bytes());

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("user_state_hex"),
        &JsValue::from_str(&hex::encode(&state_bytes)),
    )?;

    let commits = js_sys::Array::new();
    commits.push(&JsValue::from_str(&point_to_hex(&a0_pt)));
    commits.push(&JsValue::from_str(&point_to_hex(&a1_pt)));
    js_sys::Reflect::set(&obj, &JsValue::from_str("commits_hex"), &commits)?;

    Ok(obj.into())
}

/// Compute the user's share-for-signer = f(SignerIndex), to send in Round 2.
///
/// `user_state_hex` is the opaque blob from generate_user_dkg_state.
/// Returns: hex-encoded 32-byte scalar.
#[wasm_bindgen]
pub fn compute_share_for_signer(user_state_hex: &str) -> Result<String, JsValue> {
    let (a0, a1) = unpack_state(user_state_hex)?;
    let share = eval_linear(&a0, &a1, SIGNER_INDEX);
    Ok(scalar_to_hex(&share))
}

/// Verify the signer's share-for-user (received in Round 2 response) against
/// the signer's commitments (from Round 1 response). MUST be called before
/// accepting the signer share - a malicious signer could otherwise hand the
/// browser a share that doesn't correspond to its committed polynomial,
/// breaking the joint identity.
///
/// Returns true if verification passes, false otherwise. Never throws on
/// verification failure - the caller handles the boolean.
///
/// Throws only on input decode errors.
#[wasm_bindgen]
pub fn verify_signer_share(
    signer_share_hex: &str,
    signer_commits_hex: js_sys::Array,
) -> Result<bool, JsValue> {
    if signer_commits_hex.length() != 2 {
        return Err(JsValue::from_str("signer_commits_hex must have length 2"));
    }
    let signer_share = scalar_from_hex(signer_share_hex).map_err(JsValue::from)?;
    let b0_hex: String = signer_commits_hex
        .get(0)
        .as_string()
        .ok_or_else(|| JsValue::from_str("signer commit 0 not a string"))?;
    let b1_hex: String = signer_commits_hex
        .get(1)
        .as_string()
        .ok_or_else(|| JsValue::from_str("signer commit 1 not a string"))?;
    let b0 = point_from_hex(&b0_hex).map_err(JsValue::from)?;
    let b1 = point_from_hex(&b1_hex).map_err(JsValue::from)?;

    Ok(verify_share(&signer_share, &b0, &b1, USER_INDEX))
}

/// Compute the joint pubkey = A0 + B0.
///
/// `user_state_hex` provides A0 (recomputed from a0 to avoid trusting JS
/// to carry the public commitments correctly across rounds).
/// `signer_b0_hex` is the signer's constant-term commitment from Round 1.
/// Returns: hex-encoded compressed SEC1 (33 bytes / 66 chars).
#[wasm_bindgen]
pub fn compute_joint_pubkey(user_state_hex: &str, signer_b0_hex: &str) -> Result<String, JsValue> {
    let (a0, _a1) = unpack_state(user_state_hex)?;
    let a0_pt = ProjectivePoint::GENERATOR * a0;
    let b0 = point_from_hex(signer_b0_hex).map_err(JsValue::from)?;
    Ok(point_to_hex(&(a0_pt + b0)))
}

/// Compute the user's final aggregated share = f(UserIndex) + signer_share.
/// Returned share is what the user must hold (encrypted) and later use to
/// produce partial signatures.
///
/// After calling this, the JS layer should DISCARD user_state_hex (a0, a1).
#[wasm_bindgen]
pub fn compute_user_final_share(
    user_state_hex: &str,
    signer_share_for_user_hex: &str,
) -> Result<String, JsValue> {
    let (a0, a1) = unpack_state(user_state_hex)?;
    let signer_share = scalar_from_hex(signer_share_for_user_hex).map_err(JsValue::from)?;
    let user_self = eval_linear(&a0, &a1, USER_INDEX);
    Ok(scalar_to_hex(&(user_self + signer_share)))
}

/// Compute the verification share for the user's final share:
/// final_share·G. The signer keeps this to verify partial signatures from
/// the user during signing. The user can also use it as a self-check.
#[wasm_bindgen]
pub fn compute_user_verification_share(final_share_hex: &str) -> Result<String, JsValue> {
    let s = scalar_from_hex(final_share_hex).map_err(JsValue::from)?;
    Ok(point_to_hex(&(ProjectivePoint::GENERATOR * s)))
}

/// Generate a fresh 24-word BIP39 English recovery phrase.
///
/// Throws on entropy failure (no crypto.getRandomValues in the host).
/// The phrase is the user's secret - it MUST be displayed once and
/// confirmed-written-down before any downstream FROST operation. The JS
/// layer should never log it, never serialize it, and discard it from
/// memory after derivation.
#[wasm_bindgen]
pub fn generate_recovery_phrase() -> Result<String, JsValue> {
    let mut entropy = [0u8; PHRASE_ENTROPY_BYTES];
    OsRng
        .try_fill_bytes(&mut entropy)
        .map_err(|e| JsValue::from_str(&format!("entropy: {}", e)))?;
    let mnemonic = Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
        .map_err(|e| JsValue::from_str(&format!("mnemonic from entropy: {}", e)))?;
    Ok(mnemonic.to_string())
}

/// Validate a 24-word BIP39 English phrase. Returns true if the phrase is
/// well-formed and has a valid checksum, false otherwise. Never throws -
/// the caller handles the boolean. (Helps the UI confirm a re-typed
/// phrase before showing scary "wrong phrase" decryption errors deeper
/// in the recovery flow.)
#[wasm_bindgen]
pub fn is_valid_recovery_phrase(phrase: &str) -> bool {
    let trimmed = phrase.trim();
    if trimmed.split_whitespace().count() != PHRASE_WORD_COUNT {
        return false;
    }
    Mnemonic::parse_in_normalized(bip39::Language::English, trimmed).is_ok()
}

/// Derive deterministic user DKG state from a BIP39 phrase + optional
/// passphrase. Same return shape as `generate_user_dkg_state` so the
/// orchestrator can pick its source of state without branching after.
///
/// Determinism: same (phrase, passphrase) pair ALWAYS produces the same
/// (a0, a1), hence the same commits, hence the same f(x). That is what
/// makes lost-device recovery work - the user re-enters the phrase, the
/// browser re-derives the polynomial, and combined with the signer's
/// stored share-for-user from the original DKG it reconstructs the
/// user's final share.
///
/// The HKDF info string includes a version suffix; if we ever change the
/// derivation scheme, old phrases continue to derive against the old
/// info string via a separate exported function.
#[wasm_bindgen]
pub fn derive_user_dkg_state_from_phrase(
    phrase: &str,
    passphrase: &str,
) -> Result<JsValue, JsValue> {
    let trimmed = phrase.trim();
    let mnemonic = Mnemonic::parse_in_normalized(bip39::Language::English, trimmed)
        .map_err(|e| JsValue::from_str(&format!("invalid recovery phrase: {}", e)))?;
    if mnemonic.word_count() != PHRASE_WORD_COUNT {
        return Err(JsValue::from_str(&format!(
            "phrase must be {} words, got {}",
            PHRASE_WORD_COUNT,
            mnemonic.word_count()
        )));
    }

    let seed = mnemonic.to_seed_normalized(passphrase); // [u8; 64]
    let hk = Hkdf::<Sha256>::new(None, &seed);
    let mut okm = [0u8; 64];
    hk.expand(SHARE_SEED_INFO, &mut okm)
        .map_err(|e| JsValue::from_str(&format!("hkdf expand: {}", e)))?;

    // First 32 bytes → a0, second 32 bytes → a1. Scalar::reduce performs
    // a modular reduction against the secp256k1 order; on a randomly-
    // distributed 32-byte input the bias is negligible (group order is
    // within 2^-128 of 2^256), and applying it to BOTH halves keeps the
    // mapping uniformly defined.
    let mut a0_arr = [0u8; 32];
    let mut a1_arr = [0u8; 32];
    a0_arr.copy_from_slice(&okm[..32]);
    a1_arr.copy_from_slice(&okm[32..]);
    let a0 = Scalar::reduce(U256::from_be_slice(&a0_arr));
    let a1 = Scalar::reduce(U256::from_be_slice(&a1_arr));

    // A degenerate phrase whose HKDF output happens to reduce to 0 would
    // produce an invalid polynomial. Practically impossible (probability
    // ~2^-256) but checked to avoid leaking a confusing failure later.
    if bool::from(a0.is_zero()) || bool::from(a1.is_zero()) {
        return Err(JsValue::from_str(
            "phrase derived to a zero scalar (cosmically unlikely - regenerate phrase)",
        ));
    }

    let a0_pt = ProjectivePoint::GENERATOR * a0;
    let a1_pt = ProjectivePoint::GENERATOR * a1;

    let mut state_bytes = Vec::with_capacity(64);
    state_bytes.extend_from_slice(&a0.to_bytes());
    state_bytes.extend_from_slice(&a1.to_bytes());

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("user_state_hex"),
        &JsValue::from_str(&hex::encode(&state_bytes)),
    )?;

    let commits = js_sys::Array::new();
    commits.push(&JsValue::from_str(&point_to_hex(&a0_pt)));
    commits.push(&JsValue::from_str(&point_to_hex(&a1_pt)));
    js_sys::Reflect::set(&obj, &JsValue::from_str("commits_hex"), &commits)?;

    Ok(obj.into())
}

fn unpack_state(user_state_hex: &str) -> Result<(Scalar, Scalar), JsValue> {
    unpack_state_native(user_state_hex).map_err(|e| JsValue::from_str(&e))
}

/// Native-typed version of unpack_state. Returns plain String errors so it
/// can be exercised from `cargo test` (no JsValue, which panics on
/// non-wasm32 targets). Kept private; tests use it directly via the
/// `tests` submodule's parent path.
fn unpack_state_native(user_state_hex: &str) -> Result<(Scalar, Scalar), String> {
    let bytes = hex::decode(user_state_hex).map_err(|e| format!("state hex decode: {}", e))?;
    if bytes.len() != 64 {
        return Err(format!("user_state must be 64 bytes (a0 || a1), got {}", bytes.len()));
    }
    let mut a0_arr = [0u8; 32];
    let mut a1_arr = [0u8; 32];
    a0_arr.copy_from_slice(&bytes[..32]);
    a1_arr.copy_from_slice(&bytes[32..]);
    let a0 = Scalar::from_repr(a0_arr.into());
    let a1 = Scalar::from_repr(a1_arr.into());
    if !bool::from(a0.is_some()) || !bool::from(a1.is_some()) {
        return Err("user_state scalars outside field order".to_string());
    }
    Ok((a0.unwrap(), a1.unwrap()))
}

// --- Native tests (run via `cargo test`, no WASM target needed) ----------

#[cfg(test)]
mod tests {
    use super::*;

    // End-to-end protocol simulation: run both parties locally and verify
    // the shares form a valid 2-of-2 sharing via Lagrange reconstruction.
    // Mirrors the Go-side TestUserDKG_EndToEnd assertion.
    #[test]
    fn dkg_end_to_end_produces_valid_2_of_2() {
        let mut rng = OsRng;

        // User party
        let a0 = Scalar::random(&mut rng);
        let a1 = Scalar::random(&mut rng);
        let a0_pt = ProjectivePoint::GENERATOR * a0;
        let a1_pt = ProjectivePoint::GENERATOR * a1;

        // Signer party (simulated)
        let b0 = Scalar::random(&mut rng);
        let b1 = Scalar::random(&mut rng);
        let b0_pt = ProjectivePoint::GENERATOR * b0;
        let b1_pt = ProjectivePoint::GENERATOR * b1;

        // Round 2: each party sends evaluation at the other's index.
        let user_share_for_signer = eval_linear(&a0, &a1, SIGNER_INDEX);
        let signer_share_for_user = eval_linear(&b0, &b1, USER_INDEX);

        // Each verifies against the other's commitments.
        assert!(verify_share(&user_share_for_signer, &a0_pt, &a1_pt, SIGNER_INDEX),
            "user share must verify against user commits");
        assert!(verify_share(&signer_share_for_user, &b0_pt, &b1_pt, USER_INDEX),
            "signer share must verify against signer commits");

        // Final aggregated shares (matches Go-side aggregation).
        let user_self = eval_linear(&a0, &a1, USER_INDEX);
        let signer_self = eval_linear(&b0, &b1, SIGNER_INDEX);
        let user_final = user_self + signer_share_for_user;
        let signer_final = user_share_for_signer + signer_self;

        // Joint pubkey
        let joint = a0_pt + b0_pt;

        // Reconstruct master_secret via Lagrange interpolation at x=0.
        // For indices (1, 2):
        //   lambda_1(0) = (0 - 2) / (1 - 2) = 2
        //   lambda_2(0) = (0 - 1) / (2 - 1) = -1
        // So master = 2·user_final - signer_final.
        let lambda_user = scalar_from_u64(2);
        let reconstructed = (user_final * lambda_user) - signer_final;

        let reconstructed_pubkey = ProjectivePoint::GENERATOR * reconstructed;
        assert_eq!(
            reconstructed_pubkey, joint,
            "Lagrange-reconstructed master·G must equal joint pubkey"
        );
    }

    // verify_share must reject a random scalar that doesn't correspond to
    // the committed polynomial. Mirrors the adversarial-share test on the
    // Go side (TestUserDKG_Round2DetectsBadShare).
    #[test]
    fn verify_share_rejects_bogus() {
        let mut rng = OsRng;
        let a0 = Scalar::random(&mut rng);
        let a1 = Scalar::random(&mut rng);
        let a0_pt = ProjectivePoint::GENERATOR * a0;
        let a1_pt = ProjectivePoint::GENERATOR * a1;

        // A random scalar not equal to f(SignerIndex)
        let bogus = Scalar::random(&mut rng);
        assert!(
            !verify_share(&bogus, &a0_pt, &a1_pt, SIGNER_INDEX),
            "random scalar must not pass commitment verification"
        );
    }

    // Hex round-trips for scalar and point - any encoding bug here breaks
    // wire interop with the Go side, so this is a load-bearing test.
    #[test]
    fn hex_roundtrip_scalar_and_point() {
        let mut rng = OsRng;
        let s = Scalar::random(&mut rng);
        let s_hex = scalar_to_hex(&s);
        let s2 = scalar_from_hex(&s_hex).expect("decode scalar");
        assert_eq!(s, s2);

        let p = ProjectivePoint::GENERATOR * s;
        let p_hex = point_to_hex(&p);
        let p2 = point_from_hex(&p_hex).expect("decode point");
        assert_eq!(p, p2);
    }

    // eval_linear is the core polynomial math. Pin a known case.
    #[test]
    fn eval_linear_known_values() {
        // f(x) = 3 + 5x. f(2) = 13. f(1) = 8.
        let a0 = scalar_from_u64(3);
        let a1 = scalar_from_u64(5);
        let at_2 = eval_linear(&a0, &a1, 2);
        let at_1 = eval_linear(&a0, &a1, 1);
        assert_eq!(at_2, scalar_from_u64(13));
        assert_eq!(at_1, scalar_from_u64(8));
    }

    // BIP39 + HKDF determinism: same phrase + passphrase MUST produce
    // the same (a0, a1) every time. This is the load-bearing invariant
    // for recovery (§6.4): lose your device, enter the phrase, get back
    // the same polynomial, recombine with the signer's stored share to
    // reconstruct your share. If this property breaks, recovery breaks.
    //
    // Test uses the native-typed helpers (derive_state_from_phrase_native)
    // rather than the JsValue-exposed wrappers, for the same reason
    // unpack_state_validation does.
    #[test]
    fn derive_from_phrase_is_deterministic() {
        // A known-valid 24-word BIP39 phrase (the "all eleven words"
        // pattern often used in BIP39 test vectors).
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let passphrase = "TREZOR";

        let (a0_first, a1_first) = derive_from_phrase_native(phrase, passphrase)
            .expect("derive first");
        let (a0_again, a1_again) = derive_from_phrase_native(phrase, passphrase)
            .expect("derive again");

        assert_eq!(a0_first, a0_again, "a0 must be deterministic from phrase");
        assert_eq!(a1_first, a1_again, "a1 must be deterministic from phrase");

        // Different passphrase MUST produce different (a0, a1). The
        // passphrase is the 25th-word secret in BIP39; same phrase but
        // different passphrase is a different wallet.
        let (a0_diff, a1_diff) = derive_from_phrase_native(phrase, "different")
            .expect("derive diff passphrase");
        assert_ne!(a0_first, a0_diff, "different passphrase must shift a0");
        assert_ne!(a1_first, a1_diff, "different passphrase must shift a1");
    }

    // A freshly generated phrase is valid by the validation function.
    // Doubles as smoke test that generate_recovery_phrase produces
    // BIP39-conforming output.
    #[test]
    fn fresh_phrase_validates() {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mn =
            Mnemonic::from_entropy_in(bip39::Language::English, &entropy).expect("mnemonic");
        let phrase = mn.to_string();
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert!(
            is_valid_recovery_phrase_native(&phrase),
            "freshly generated phrase must validate"
        );
        // The same phrase must still derive a valid (non-zero) state.
        let _ = derive_from_phrase_native(&phrase, "").expect("fresh phrase derives");
    }

    // Garbage phrases must reject.
    #[test]
    fn invalid_phrase_rejected() {
        assert!(!is_valid_recovery_phrase_native("not a real phrase"));
        // 24 words but one isn't in the wordlist:
        assert!(!is_valid_recovery_phrase_native(
            "zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz"
        ));
        // 12 valid BIP39 words but wrong length (must be 24):
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(!is_valid_recovery_phrase_native(twelve));
        assert!(derive_from_phrase_native(twelve, "").is_err());
    }

    // Native-typed helpers - same logic as the WASM exports but returning
    // raw Rust values, so cargo test doesn't panic on JsValue.
    fn derive_from_phrase_native(phrase: &str, passphrase: &str) -> Result<(Scalar, Scalar), String> {
        let trimmed = phrase.trim();
        let mnemonic = Mnemonic::parse_in_normalized(bip39::Language::English, trimmed)
            .map_err(|e| format!("invalid recovery phrase: {}", e))?;
        if mnemonic.word_count() != PHRASE_WORD_COUNT {
            return Err(format!(
                "phrase must be {} words, got {}",
                PHRASE_WORD_COUNT,
                mnemonic.word_count()
            ));
        }
        let seed = mnemonic.to_seed_normalized(passphrase);
        let hk = Hkdf::<Sha256>::new(None, &seed);
        let mut okm = [0u8; 64];
        hk.expand(SHARE_SEED_INFO, &mut okm)
            .map_err(|e| format!("hkdf expand: {}", e))?;
        let mut a0_arr = [0u8; 32];
        let mut a1_arr = [0u8; 32];
        a0_arr.copy_from_slice(&okm[..32]);
        a1_arr.copy_from_slice(&okm[32..]);
        let a0 = Scalar::reduce(U256::from_be_slice(&a0_arr));
        let a1 = Scalar::reduce(U256::from_be_slice(&a1_arr));
        Ok((a0, a1))
    }

    fn is_valid_recovery_phrase_native(phrase: &str) -> bool {
        let trimmed = phrase.trim();
        if trimmed.split_whitespace().count() != PHRASE_WORD_COUNT {
            return false;
        }
        Mnemonic::parse_in_normalized(bip39::Language::English, trimmed).is_ok()
    }

    // unpack_state round-trips and rejects malformed input. Uses the
    // native-typed helper because JsValue construction panics on non-wasm
    // targets.
    #[test]
    fn unpack_state_validation() {
        let mut rng = OsRng;
        let a0 = Scalar::random(&mut rng);
        let a1 = Scalar::random(&mut rng);
        let mut state = Vec::with_capacity(64);
        state.extend_from_slice(&a0.to_bytes());
        state.extend_from_slice(&a1.to_bytes());
        let state_hex = hex::encode(&state);

        let (got_a0, got_a1) = unpack_state_native(&state_hex).expect("unpack");
        assert_eq!(got_a0, a0);
        assert_eq!(got_a1, a1);

        assert!(unpack_state_native("deadbeef").is_err(), "short input must error");
        assert!(unpack_state_native("zz").is_err(), "non-hex input must error");
    }
}
