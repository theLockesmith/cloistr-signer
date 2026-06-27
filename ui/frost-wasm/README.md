# cloistr-frost-wasm

Browser-side FROST 2-of-N user-cosigner share holder for cloistr-signer.

Compiles to WebAssembly via `wasm-pack`. The Rust source is the authoritative
client-side implementation of the protocol math defined in
[`docs/frost-2-of-n-design.md`](../../docs/frost-2-of-n-design.md). The Go
signer-side implementation in `internal/frost/user_dkg.go` is the
counterparty; the two are byte-for-byte wire-compatible by design (same
secp256k1 group, same scalar/point encodings, same DKG message shape).

## Why a separate crate, not a workspace

This is a build-time dependency of the React SPA in `ui/`. Vite resolves
the WASM module from `pkg/` after `wasm-pack` emits it. Keeping the crate
self-contained avoids a Cargo workspace at the repo root, which would
complicate the Go-side build paths.

## Why `k256` + manual math, not `frost-secp256k1`

The wire format must match the Go signer side, which uses `bytemare/ecc`
for elliptic-curve operations. ZcashFoundation's `frost-secp256k1` crate
exposes its own DKG message struct layout that does not interop. By
implementing the 2-of-N degree-1 polynomial math directly using
`k256` (RustCrypto), the Rust and Go sides exchange raw hex-encoded
scalars and compressed-SEC1 points - the simplest possible wire format -
and stay independently auditable.

`frost-secp256k1` may still be used for the later signing primitives (P4),
where its FROST signing API (rather than its DKG) covers what we need.

## Build

Requires Rust toolchain (1.91+) and `wasm-pack`.

```
# One-time setup
cargo install wasm-pack --locked

# Build release WASM (run from this directory)
wasm-pack build --target web --release
```

Output lands in `./pkg/`:
- `cloistr_frost_wasm_bg.wasm` (~76 KB optimized)
- `cloistr_frost_wasm.js` - ES module wrapper
- `cloistr_frost_wasm.d.ts` - TypeScript types

## Tests

Native Rust tests (no WASM target needed):
```
cargo test
```

Five tests, including an end-to-end DKG simulation that verifies via
Lagrange reconstruction that the produced shares form a valid 2-of-2
secret sharing - the same correctness anchor the Go-side
`TestUserDKG_EndToEnd` uses.

## Exported API (see `src/lib.rs`)

| Function | Purpose |
|---|---|
| `generate_user_dkg_state()` | Fresh random `(a0, a1)` plus commitments `[A0, A1]` for Round 1 |
| `compute_share_for_signer(state)` | Evaluate `f(SignerIndex)` for Round 2 send |
| `verify_signer_share(share, signer_commits)` | Pedersen-check the share the signer returns in Round 2 |
| `compute_joint_pubkey(state, signer_B0)` | Compute `P = A0 + B0` independently for finalize confirmation |
| `compute_user_final_share(state, signer_share_for_user)` | Aggregate `f(UserIndex) + signer_share` into the user's stored share |
| `compute_user_verification_share(final_share)` | `final_share·G` for the signer's partial-sig verifier (P4 prep) |

State management is intentional: `user_state_hex` (a0 || a1) is returned
to JS, threaded across rounds, and discarded after finalize. Anything
the WASM module forgets is gone.
