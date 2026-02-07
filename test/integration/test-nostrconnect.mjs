import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { BunkerSigner, parseBunkerInput } from 'nostr-tools/nip46';

const clientSk = generateSecretKey();
const clientPk = getPublicKey(clientSk);
const secret = 'test-' + Math.random().toString(36).slice(2);
const relay = 'wss://relay.primal.net';

const uri = `nostrconnect://${clientPk}?relay=${encodeURIComponent(relay)}&secret=${secret}&name=TestClient`;
console.log('\n=== URI ===\n' + uri + '\n===========\n');

try {
  const bunkerParams = await parseBunkerInput(uri);
  console.log('Parsed params:', bunkerParams);

  const signer = new BunkerSigner(clientSk, bunkerParams);
  await signer.connect();

  const pubkey = await signer.getPublicKey();
  console.log('SUCCESS! Signer pubkey:', pubkey);
} catch (e) {
  console.error('FAILED:', e.message, e.stack);
}
process.exit(0);
