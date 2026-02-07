// Test the Go signer
import NDK, { NDKPrivateKeySigner, NDKEvent, NDKUser } from '@nostr-dev-kit/ndk';
import crypto from 'crypto';

const TESTKEY_PUBKEY = '1b9a8d756b54ee7f6807ed36ced1f220ee7b7fc159e397f71c195a7a289a17af';
const ADMIN_KEY_HEX = '5c300b0008fa7307ca35585aab688eb4aae6ab98250b968c4ebb425be7af98fe';

async function main() {
  const clientSigner = new NDKPrivateKeySigner(ADMIN_KEY_HEX);
  const clientUser = await clientSigner.user();
  console.log('=== Testing Go Signer ===');
  console.log('Client pubkey:', clientUser.pubkey);

  const ndk = new NDK({
    explicitRelayUrls: ['wss://relay.damus.io'],
    enableOutboxModel: false
  });
  ndk.signer = clientSigner;
  await ndk.connect(10000);
  await new Promise(r => setTimeout(r, 2000));
  console.log('Connected to relay\n');

  // Test 1: Ping
  console.log('--- Test 1: Ping ---');
  const pingResult = await sendRequest(ndk, clientSigner, clientUser, TESTKEY_PUBKEY, 'ping', []);
  console.log('Result:', pingResult, '\n');

  // Test 2: Get Public Key
  console.log('--- Test 2: Get Public Key ---');
  const pubkeyResult = await sendRequest(ndk, clientSigner, clientUser, TESTKEY_PUBKEY, 'get_public_key', []);
  console.log('Result:', pubkeyResult);
  console.log('Match:', pubkeyResult === TESTKEY_PUBKEY ? '✅' : '❌', '\n');

  // Test 3: Sign Event
  console.log('--- Test 3: Sign Event ---');
  const eventToSign = {
    kind: 1,
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
    content: 'Test from Go signer'
  };
  const signResult = await sendRequest(ndk, clientSigner, clientUser, TESTKEY_PUBKEY, 'sign_event', [JSON.stringify(eventToSign)]);
  try {
    const signed = JSON.parse(signResult);
    console.log('Signed event ID:', signed.id?.slice(0, 16) + '...');
    console.log('Has signature:', signed.sig ? '✅' : '❌', '\n');
  } catch (e) {
    console.log('Error parsing signed event:', e.message, '\n');
  }

  console.log('=== Tests Complete ===');
  process.exit(0);
}

async function sendRequest(ndk, clientSigner, clientUser, targetPubkey, method, params) {
  const requestId = crypto.randomBytes(16).toString('hex');
  const request = { id: requestId, method, params };

  const encryptedContent = await clientSigner.encrypt(
    new NDKUser({ pubkey: targetPubkey }),
    JSON.stringify(request)
  );

  const event = new NDKEvent(ndk);
  event.kind = 24133;
  event.content = encryptedContent;
  event.tags = [['p', targetPubkey]];
  await event.sign();

  const relays = await event.publish();
  console.log(`Sent ${method} request (published to ${relays.size} relay(s))`);

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      sub.stop();
      reject(new Error('Timeout'));
    }, 15000);

    const sub = ndk.subscribe({
      kinds: [24133],
      '#p': [clientUser.pubkey],
      since: Math.floor(Date.now() / 1000) - 60
    });

    sub.on('event', async (e) => {
      if (e.pubkey !== targetPubkey) return;
      try {
        const d = await clientSigner.decrypt(new NDKUser({ pubkey: e.pubkey }), e.content);
        const r = JSON.parse(d);
        if (r.id === requestId) {
          clearTimeout(timeout);
          sub.stop();
          if (r.error) {
            reject(new Error(r.error));
          } else {
            resolve(r.result);
          }
        }
      } catch (err) {
        // Ignore decryption errors for other events
      }
    });
  });
}

main().catch(e => {
  console.error('Error:', e.message);
  process.exit(1);
});
