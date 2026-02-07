// Test NIP-46 signing flow with nsecbunker
import NDK, { NDKPrivateKeySigner, NDKEvent, NDKUser } from '@nostr-dev-kit/ndk';
import crypto from 'crypto';

const RELAY_URL = 'wss://relay.coldforge.xyz';
// Use admin key (which has permissions) to sign our requests
const ADMIN_KEY_HEX = '5c300b0008fa7307ca35585aab688eb4aae6ab98250b968c4ebb425be7af98fe';
const clientSigner = new NDKPrivateKeySigner(ADMIN_KEY_HEX);

// The testkey pubkey in nsecbunker
const TESTKEY_PUBKEY = '1b9a8d756b54ee7f6807ed36ced1f220ee7b7fc159e397f71c195a7a289a17af';

async function main() {
  console.log('=== Test NIP-46 Signing Flow ===\n');

  const ndk = new NDK({
    explicitRelayUrls: [RELAY_URL, 'wss://relay.damus.io'],
    enableOutboxModel: false
  });

  ndk.signer = clientSigner;
  const clientUser = await clientSigner.user();
  console.log(`Client pubkey: ${clientUser.pubkey}`);
  console.log(`Testkey pubkey: ${TESTKEY_PUBKEY}`);
  console.log('');

  console.log('Connecting to relays...');
  await ndk.connect(5000);
  console.log('Connected!');
  console.log('');

  // Create a unique request ID
  const requestId = crypto.randomBytes(16).toString('hex');

  // Create a test event to sign
  const testEvent = {
    kind: 1,
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
    content: 'Test event from NIP-46 client'
  };

  // NIP-46 sign_event request
  const request = {
    id: requestId,
    method: 'sign_event',
    params: [JSON.stringify(testEvent)]
  };

  console.log('Creating NIP-46 sign_event request:');
  console.log(`  Request ID: ${requestId}`);
  console.log(`  Event kind: ${testEvent.kind}`);
  console.log(`  Content: ${testEvent.content}`);
  console.log('');

  // Encrypt the request to the testkey pubkey
  const encryptedContent = await clientSigner.encrypt(
    new NDKUser({ pubkey: TESTKEY_PUBKEY }),
    JSON.stringify(request)
  );

  // Create kind 24133 event (NIP-46 request)
  const event = new NDKEvent(ndk);
  event.kind = 24133;
  event.content = encryptedContent;
  event.tags = [
    ['p', TESTKEY_PUBKEY]
  ];

  console.log('Publishing NIP-46 sign_event request...');
  try {
    await event.sign();
    const relays = await event.publish();
    console.log(`Published to ${relays.size} relay(s)`);
    console.log(`Event ID: ${event.id}`);
    console.log('');
  } catch (e) {
    console.error('Failed to publish:', e.message);
    process.exit(1);
  }

  // Subscribe to responses
  console.log('Waiting for response from bunker...');
  const sub = ndk.subscribe({
    kinds: [24133, 24134],
    '#p': [clientUser.pubkey],
    since: Math.floor(Date.now() / 1000) - 60
  });

  const timeout = setTimeout(() => {
    console.log('\nTimeout waiting for response (30s)');
    console.log('The bunker may not have the key loaded or there may be permission issues.');
    process.exit(1);
  }, 30000);

  sub.on('event', async (responseEvent) => {
    // Skip our own event
    if (responseEvent.id === event.id) return;
    if (responseEvent.pubkey !== TESTKEY_PUBKEY) return;

    console.log('\nReceived response!');
    console.log(`  From: ${responseEvent.pubkey.slice(0, 16)}...`);
    console.log(`  Kind: ${responseEvent.kind}`);

    try {
      const decrypted = await clientSigner.decrypt(
        new NDKUser({ pubkey: responseEvent.pubkey }),
        responseEvent.content
      );
      console.log(`  Decrypted: ${decrypted}`);

      const response = JSON.parse(decrypted);
      if (response.id === requestId) {
        clearTimeout(timeout);
        if (response.error) {
          console.log(`\nError: ${response.error}`);
        } else if (response.result) {
          console.log(`\nSuccess! Signed event:`);
          try {
            const signedEvent = JSON.parse(response.result);
            console.log(`  ID: ${signedEvent.id}`);
            console.log(`  Sig: ${signedEvent.sig?.slice(0, 32)}...`);
            console.log(`  Pubkey: ${signedEvent.pubkey}`);
          } catch (e) {
            console.log(`  Result: ${response.result}`);
          }
        }
        process.exit(0);
      }
    } catch (e) {
      console.log(`  Failed to decrypt: ${e.message}`);
    }
  });
}

main().catch(console.error);
