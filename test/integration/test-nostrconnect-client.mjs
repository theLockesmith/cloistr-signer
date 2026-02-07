#!/usr/bin/env node
/**
 * Test client for nostrconnect:// flow
 * This simulates what Primal does when you paste a nostrconnect URI
 */

import WebSocket from 'ws';
import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { hkdf } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { randomBytes } from 'crypto';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { concatBytes, utf8ToBytes, bytesToUtf8 } from '@noble/hashes/utils';

// Configuration
const RELAY = process.env.RELAY || 'wss://relay.primal.net';

// Generate ephemeral client keypair
const clientPrivKey = secp256k1.utils.randomPrivateKey();
const clientPubKey = Buffer.from(secp256k1.getPublicKey(clientPrivKey, true).slice(1)).toString('hex');

// Generate random secret
const secret = `sec-${randomBytes(16).toString('hex')}`;

console.log('=== NostrConnect Test Client ===\n');
console.log('Client pubkey:', clientPubKey);
console.log('Secret:', secret);
console.log('Relay:', RELAY);

// Build nostrconnect URI
const nostrconnectURI = `nostrconnect://${clientPubKey}?relay=${encodeURIComponent(RELAY)}&secret=${secret}&name=TestClient`;
console.log('\n--- Copy this URI to the signer ---');
console.log(nostrconnectURI);
console.log('-----------------------------------\n');

// Base64 decode (standard)
function base64Decode(str) {
  return new Uint8Array(Buffer.from(str, 'base64'));
}

// NIP-44 decryption
function nip44Decrypt(payload, conversationKey) {
  const data = base64Decode(payload);

  const version = data[0];
  if (version !== 2) {
    throw new Error(`Unknown NIP-44 version: ${version}`);
  }

  const nonce = data.slice(1, 25);
  const ciphertext = data.slice(25);

  // Derive message keys using HKDF
  const keys = hkdf(sha256, conversationKey, nonce, utf8ToBytes('nip44-v2'), 76);

  const chachaKey = keys.slice(0, 32);
  const chachaNonce = keys.slice(32, 44);
  const hmacKey = keys.slice(44, 76);

  // Decrypt with ChaCha20-Poly1305
  const chacha = chacha20poly1305(chachaKey, chachaNonce);
  const decrypted = chacha.decrypt(ciphertext);

  // Remove padding
  const unpaddedLen = (decrypted[0] << 8) | decrypted[1];
  return bytesToUtf8(decrypted.slice(2, 2 + unpaddedLen));
}

// Generate conversation key for NIP-44
function getConversationKey(privkey, pubkey) {
  const sharedX = secp256k1.getSharedSecret(privkey, '02' + pubkey).slice(1, 33);
  return hkdf(sha256, sharedX, utf8ToBytes('nip44-v2'), null, 32);
}

// Connect to relay and wait for response
const ws = new WebSocket(RELAY);

ws.on('open', () => {
  console.log('Connected to relay');

  // Subscribe for kind 24133 events tagged to our pubkey
  const subId = 'nostrconnect-test';
  const filter = {
    kinds: [24133],
    '#p': [clientPubKey],
    limit: 0
  };

  const req = JSON.stringify(['REQ', subId, filter]);
  console.log('Subscribing:', req);
  ws.send(req);
  console.log('\nWaiting for signer response...\n');
});

ws.on('message', async (data) => {
  const msg = JSON.parse(data.toString());

  if (msg[0] === 'EOSE') {
    console.log('End of stored events, waiting for new events...');
    return;
  }

  if (msg[0] === 'NOTICE') {
    console.log('Relay notice:', msg[1]);
    return;
  }

  if (msg[0] === 'EVENT') {
    const event = msg[2];
    console.log('\n=== Got event! ===');
    console.log('Event ID:', event.id);
    console.log('From (signer pubkey):', event.pubkey);
    console.log('Content (encrypted):', event.content.substring(0, 50) + '...');

    try {
      // Compute conversation key
      const convKey = getConversationKey(clientPrivKey, event.pubkey);
      console.log('Conversation key computed');

      // Decrypt content
      const decrypted = nip44Decrypt(event.content, convKey);
      console.log('\n=== Decrypted response ===');
      console.log(decrypted);

      const response = JSON.parse(decrypted);
      console.log('\nParsed response:');
      console.log('  id:', response.id);
      console.log('  result:', response.result);
      console.log('  error:', response.error);

      // Validate
      console.log('\n=== Validation ===');
      console.log('Expected secret:', secret);
      console.log('Got result:', response.result);
      console.log('Match:', response.result === secret ? 'YES ✓' : 'NO ✗');

      if (response.result === secret) {
        console.log('\n🎉 CONNECTION SUCCESSFUL! 🎉');
        console.log('Signer pubkey:', event.pubkey);
      } else {
        console.log('\n❌ CONNECTION FAILED - secret mismatch');
      }

    } catch (err) {
      console.error('\nDecryption error:', err.message);
      console.error(err.stack);
    }

    ws.close();
    process.exit(0);
  }

  console.log('Other message:', JSON.stringify(msg));
});

ws.on('error', (err) => {
  console.error('WebSocket error:', err.message);
});

ws.on('close', () => {
  console.log('Connection closed');
});

// Timeout after 60 seconds
setTimeout(() => {
  console.log('\nTimeout - no response received');
  ws.close();
  process.exit(1);
}, 60000);
