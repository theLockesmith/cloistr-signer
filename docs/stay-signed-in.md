# Stay Signed In

At sign-in the user picks how long to stay signed in: **this session only**, **1 day**,
**30 days** or **until I sign out**. For anything but "this session only", restarting or
redeploying the signer does not lock them out: outside NIP-46 apps keep working with no
re-login and no client involvement.

## How it works

Signing keys are wrapped under the user's password (or their Vault token), so a fresh
signer process cannot use them until the user signs in. With stay-signed-in, the signer
**seals** the decrypted key right after sign-in and stores the sealed copy in the database
(`signer_session_seals`) with an expiry. Every replica restores every live seal it can
open at startup and then every 15 seconds, so the key is listening on the relays again
right after a deploy. A request that finds a key locked also tries the seal first.

Each seal is bound to the key's pubkey **and** the sign-in session. The binding is mixed
into the sealing key and used as authenticated data, so a sealed blob copied onto another
account's or another session's row does not open.

**The trust line, stated plainly:** while a seal exists (except in split mode), the signer
can recover that user's key without them. That is what makes it work for outside apps. It
is bounded by the expiry the user chose, enforced server-side, and revocable.

### Lifetimes

| Choice | Sign-in session and seal |
|--------|--------------------------|
| this session only | No seal. The key is locked at the next restart (the behaviour before this feature). |
| 1 day / 30 days | Fixed: the sign-in session, its token and the seal all expire then. |
| until I sign out | Sliding: renewed on use, ends after `SESSION_IDLE_DAYS` idle (default 90). No hard cap unless `SESSION_SEAL_MAX_DAYS` is set. |

`SESSION_SEAL_MAX_DAYS` caps every choice, counted from sign-in.

### Ending a seal

- **Sign-out** deletes all of the user's seals and locks the keys, on this replica at
  once, on the replica the location registry names at once, and on any other replica
  within 15 seconds.
- **Revoke all** (`DELETE /api/v1/users/stay-signed-in`) does the same but keeps the web
  sign-in.
- **Expiry**, or the sign-in session ending any other way (revoked, expired), makes the
  seal unusable; replicas drop the key within 15 seconds and the row is swept.
- Deleting a key or the account deletes its seals.

## Sealers (`SESSION_SEALER`)

| Setting | What it does | A database copy alone… |
|---------|--------------|------------------------|
| `none` (default) | Sealing off. Only "this session only" is offered, unless split is used (below). Today's behaviour. | has nothing to open |
| `keyfile` | Seals under a 32-byte key in `SESSION_SEAL_KEYFILE`, created `0600` if missing. The simple choice for a single host. | cannot unseal. Keep the key file **on a different volume from the database**: DB + key file together can. |
| `vault` | Seals with Vault transit key `SESSION_SEAL_VAULT_KEY` (default `cloistr-signer-session-seal`), using the signer's own token. The sealing key never leaves Vault. | cannot unseal, even with an old backup once the key has rotated (below) |

If the configured sealer cannot be built (no Vault, unreadable key file), the signer logs an
error and runs as `none`; it does not stop.

### Split sealing (`SESSION_SEAL_SPLIT`, default on)

Opt-in per sign-in, in any sealer mode including `none`, and needs no Vault or key file.
The sealing key is split: the server keeps one half in the seal row, the user's browser
keeps the other. **Neither the database nor the server alone can unseal.** After a deploy,
Cloistr apps hand the browser half back and the key is restored; outside NIP-46 apps get no
help until then. That is the price of the stricter guarantee.

Browsers get the half only as an `HttpOnly; Secure; SameSite=Strict` host-only cookie
scoped to `/api/v1/users/session/unseal`, so page scripts never see it. Its lifetime is the
seal's (400 days, the browser maximum, or `SESSION_SEAL_MAX_DAYS` for "until I sign out";
the server-side seal expiry governs either way). Non-browser clients get it once in the
login response.

### Vault setup and key rotation

The signer's token needs this, in addition to its existing policy (the per-user
`transit/keys/cloistr-user-*` grant does not cover it):

```hcl
path "transit/encrypt/cloistr-signer-session-seal" { capabilities = ["update"] }
path "transit/decrypt/cloistr-signer-session-seal" { capabilities = ["update"] }
path "transit/rewrap/cloistr-signer-session-seal"  { capabilities = ["update"] }
path "transit/keys/cloistr-signer-session-seal"    { capabilities = ["read"] }
path "transit/keys/cloistr-signer-session-seal/rotate" { capabilities = ["update"] }
path "transit/keys/cloistr-signer-session-seal/config" { capabilities = ["update"] }
```

Create the key once, derived so the binding is part of the key derivation:

```bash
vault write transit/keys/cloistr-signer-session-seal \
  type=aes256-gcm96 derived=true exportable=false allow_plaintext_backup=false auto_rotate_period=720h
```

Vault rotates the key every `auto_rotate_period`. Each hour the signer re-wraps every
live seal to the newest key version (inside Vault; the key is never decrypted for this)
and only then raises the key's `min_decryption_version`. Live sign-ins, including "until
I sign out", carry on. Any older copy of a seal, such as one in a database backup, stops
decrypting even for someone who can call Vault. A backup taken since the last rotation
still opens until the next one, so the replay window is one rotation period. If any live
seal fails to re-wrap, the minimum is not raised, so nobody is locked out.

## Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSION_SEALER` | `none` | `none`, `keyfile` or `vault` |
| `SESSION_SEAL_KEYFILE` | `data/session-seal.key` | Key file for `keyfile` mode. Use an absolute path on a persistent volume separate from the database. On Kubernetes, mount it from a Secret with `defaultMode: 0400`; a group- or world-readable file is refused. Losing it makes existing seals unopenable (users sign in again). |
| `SESSION_SEAL_VAULT_KEY` | `cloistr-signer-session-seal` | Transit key for `vault` mode |
| `SESSION_SEAL_SPLIT` | `true` | Offer split sealing |
| `SESSION_IDLE_DAYS` | `90` | "Until I sign out" ends after this many idle days |
| `SESSION_SEAL_MAX_DAYS` | `0` | Hard ceiling on any choice, from sign-in; `0` = none |

## API

| Call | Purpose |
|------|---------|
| `GET /api/v1/users/stay-signed-in/options` | No auth. What the sign-in form may offer: `{sealer, choices, split, split_choices, max_days}`. |
| `POST /api/v1/users/login` | New optional fields `stay_signed_in` (`session`, `1d`, `30d`, `until_signout`) and `stay_signed_in_split`. The response's `stay_signed_in` says what was **granted** (may be less than asked), its `mode` and `expires_at`, and, for non-browser split sign-ins only, `split_half`. |
| `POST /api/v1/users/session/unseal` | Split mode: restore this session's keys. Body `{"split_half": "<base64url>"}`, or an empty body with the half cookie. `200 {restored}`, `400 bad_split_half`, `404 no_split_seal` (sign in again), `403 seal_mismatch`. |
| `POST /api/v1/users/session/refresh` | "Until I sign out" sessions: renew and get `{token, expires_at}`. `409 not_sliding` for fixed sessions. `GET /api/v1/users/me` renews too and re-sets the cookie. |
| `GET /api/v1/users/session` | Can this sign-in still sign? `200 {"state":"live","signing_pubkey","expires_at"}`; `200 {"state":"key_locked","signing_pubkey","expires_at","needs_split_half"?}` (sign in again, or unseal with the half when `needs_split_half`); `401 {"code":"session_gone","reason"}` for missing, expired, ended (signed out or revoked) or invalid tokens: sign in again. Branch on `state`/`code` only. The check itself recovers the key where it can (seal, session Vault token, another replica), so it never reports `key_locked` for a key a signing request could have unlocked. Use it instead of waiting on a NIP-46 reply: a request for a locked key gets no reply, because it is encrypted to that key. |
| `GET /api/v1/users/stay-signed-in` | The caller's active seals. |
| `DELETE /api/v1/users/stay-signed-in` | Revoke all (keeps the web sign-in). |
