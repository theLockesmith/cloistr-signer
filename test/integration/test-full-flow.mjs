#!/usr/bin/env node
/**
 * Full nostrconnect test - runs client and triggers signer
 */
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import WebSocket from 'ws';

const SIGNER_API = process.env.SIGNER_API || 'http://localhost:7778';
const RELAY = process.env.RELAY || 'wss://relay.primal.net';
const KEY_ID = process.env.KEY_ID || '89fa1d881f81358a';

// Generate client keypair and secret
const clientSk = generateSecretKey();
const clientPk = getPublicKey(clientSk);
const secret = 'test-' + Math.random().toString(36).slice(2);

const uri = `nostrconnect://${clientPk}?relay=${encodeURIComponent(RELAY)}&secret=${secret}&name=TestClient`;

console.log('=== NostrConnect Full Flow Test ===');
console.log('Client pubkey:', clientPk);
console.log('Secret:', secret);
console.log('Relay:', RELAY);
console.log('URI:', uri);
console.log('');

// Connect to relay and subscribe
const ws = new WebSocket(RELAY);
let resolved = false;

ws.on('open', async () => {
  console.log('[1] Connected to relay');

  // Subscribe for responses
  const filter = { kinds: [24133], '#p': [clientPk] };
  ws.send(JSON.stringify(['REQ', 'test', filter]));
  console.log('[2] Subscribed to kind:24133 #p=' + clientPk.slice(0, 8) + '...');

  // Give subscription time to establish
  await new Promise(r => setTimeout(r, 500));

  // Call signer API
  console.log('[3] Calling signer nostrconnect API...');
  try {
    const resp = await fetch(`${SIGNER_API}/api/v1/nostrconnect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ uri, key_id: KEY_ID })
    });
    const data = await resp.json();
    console.log('[4] Signer API response:', data);
  } catch (e) {
    console.error('[4] Signer API error:', e.message);
  }
});

ws.on('message', (data) => {
  const msg = JSON.parse(data.toString());

  if (msg[0] === 'EOSE') {
    console.log('[*] EOSE received');
    return;
  }

  if (msg[0] === 'EVENT') {
    const event = msg[2];
    console.log('\n[5] === GOT EVENT ===');
    console.log('    Event ID:', event.id);
    console.log('    From:', event.pubkey);
    console.log('    Content:', event.content.substring(0, 60) + '...');

    // Try to decrypt
    try {
      const convKey = nip44.v2.utils.getConversationKey(clientSk, event.pubkey);
      const decrypted = nip44.v2.decrypt(event.content, convKey);

      console.log('\n[6] === DECRYPTED ===');
      console.log('    ', decrypted);

      const response = JSON.parse(decrypted);
      console.log('\n[7] === VALIDATION ===');
      console.log('    Expected:', secret);
      console.log('    Got result:', response.result);
      console.log('    Match:', response.result === secret ? '✅ YES' : '❌ NO');

      if (response.result === secret) {
        console.log('\n🎉 SUCCESS! Connection would work! 🎉\n');
      } else {
        console.log('\n❌ FAILED: Secret mismatch\n');
      }
    } catch (e) {
      console.error('\n[!] Decryption failed:', e.message);
    }

    resolved = true;
    ws.close();
  }
});

ws.on('error', (e) => console.error('WS Error:', e.message));
ws.on('close', () => {
  console.log('[*] Connection closed');
  process.exit(resolved ? 0 : 1);
});

setTimeout(() => {
  if (!resolved) {
    console.log('\n[!] Timeout - no response received');
    ws.close();
  }
}, 15000);
