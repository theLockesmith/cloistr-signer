#!/usr/bin/env node
/**
 * Test using BunkerSigner.fromURI (the nostrconnect flow)
 */
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { BunkerSigner } from 'nostr-tools/nip46';

const SIGNER_API = process.env.SIGNER_API || 'http://localhost:7778';
const RELAY = process.env.RELAY || 'wss://relay.primal.net';
const KEY_ID = process.env.KEY_ID || '89fa1d881f81358a';

// Generate client keypair and secret
const clientSk = generateSecretKey();
const clientPk = getPublicKey(clientSk);
const secret = 'test-' + Math.random().toString(36).slice(2);

const uri = `nostrconnect://${clientPk}?relay=${encodeURIComponent(RELAY)}&secret=${secret}&name=TestClient`;

console.log('=== BunkerSigner.fromURI Test ===');
console.log('Client pubkey:', clientPk);
console.log('Secret:', secret);
console.log('URI:', uri);
console.log('');

// Start the connection (will wait for signer response)
console.log('[1] Starting BunkerSigner.fromURI (waiting for signer)...');
const connectionPromise = BunkerSigner.fromURI(clientSk, uri, {}, 20000);

// Wait a bit for subscription to establish, then call signer API
setTimeout(async () => {
  console.log('[2] Calling signer nostrconnect API...');
  try {
    const resp = await fetch(`${SIGNER_API}/api/v1/nostrconnect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ uri, key_id: KEY_ID })
    });
    const data = await resp.json();
    console.log('[3] Signer API response:', JSON.stringify(data));
  } catch (e) {
    console.error('[3] Signer API error:', e.message);
  }
}, 2000);

try {
  const signer = await connectionPromise;
  console.log('[4] Connected! Signer object created.');

  const pubkey = await signer.getPublicKey();
  console.log('[5] SUCCESS! Signer pubkey:', pubkey);
  process.exit(0);
} catch (e) {
  console.error('[!] FAILED:', e.message);
  process.exit(1);
}
