# Integration Tests

Node.js integration tests for the coldforge-signer NIP-46 implementation.

## Setup

```bash
npm install
```

## Running Tests

```bash
# Test basic NIP-46 methods
node test-nip46.mjs

# Test ping
node test-ping.mjs

# Test get_public_key
node test-getpubkey.mjs

# Test NIP-44 encrypt/decrypt
node test-encrypt-decrypt.mjs

# Test Go signer integration
node test-go-signer.mjs

# Test nostrconnect:// flow
node test-nostrconnect.mjs
node test-nostrconnect-client.mjs

# Full integration test with nostream relay
node test-nostream-nip46.mjs
```

## Configuration

Tests use these defaults (edit scripts to change):
- **Relay:** `wss://relay.coldforge.xyz`
- **Admin key:** `5c300b0008fa7307ca35585aab688eb4aae6ab98250b968c4ebb425be7af98fe`
