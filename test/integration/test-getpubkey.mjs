// Simple test for get_public_key
import NDK, { NDKPrivateKeySigner, NDKEvent, NDKUser } from '@nostr-dev-kit/ndk';
import crypto from 'crypto';

const RELAY_URL = 'wss://relay.coldforge.xyz';
const TESTKEY_PUBKEY = '1b9a8d756b54ee7f6807ed36ced1f220ee7b7fc159e397f71c195a7a289a17af';
const ADMIN_KEY_HEX = '5c300b0008fa7307ca35585aab688eb4aae6ab98250b968c4ebb425be7af98fe';

async function main() {
  console.log('=== Simple get_public_key Test ===\n');

  const clientSigner = new NDKPrivateKeySigner(ADMIN_KEY_HEX);
  const clientUser = await clientSigner.user();

  const ndk = new NDK({
    explicitRelayUrls: [RELAY_URL, 'wss://relay.damus.io'],
    enableOutboxModel: false
  });
  ndk.signer = clientSigner;

  await ndk.connect(5000);
  console.log('Connected!\n');

  const requestId = crypto.randomBytes(16).toString('hex');
  const request = {
    id: requestId,
    method: 'get_public_key',
    params: []
  };

  console.log(`Request ID: ${requestId}`);
  console.log(`Target: ${TESTKEY_PUBKEY}`);
  console.log(`Method: get_public_key`);
  console.log('');

  const encryptedContent = await clientSigner.encrypt(
    new NDKUser({ pubkey: TESTKEY_PUBKEY }),
    JSON.stringify(request)
  );

  const event = new NDKEvent(ndk);
  event.kind = 24133;
  event.content = encryptedContent;
  event.tags = [['p', TESTKEY_PUBKEY]];

  await event.sign();
  console.log('Sending request...');
  const relays = await event.publish();
  console.log(`Published to ${relays.size} relay(s)`);

  // Subscribe to responses
  const sub = ndk.subscribe({
    kinds: [24133, 24134],
    '#p': [clientUser.pubkey],
    since: Math.floor(Date.now() / 1000) - 60
  });

  sub.on('event', async (responseEvent) => {
    console.log(`\nReceived event from ${responseEvent.pubkey.slice(0, 16)}...`);

    if (responseEvent.pubkey !== TESTKEY_PUBKEY) {
      console.log('  (not from testkey, skipping)');
      return;
    }

    try {
      const decrypted = await clientSigner.decrypt(
        new NDKUser({ pubkey: responseEvent.pubkey }),
        responseEvent.content
      );
      console.log(`Decrypted: ${decrypted}`);

      const response = JSON.parse(decrypted);
      if (response.id === requestId) {
        console.log(`\n✅ Got response for our request!`);
        console.log(`   Result: ${response.result}`);
        console.log(`   Error: ${response.error || 'none'}`);
        process.exit(0);
      }
    } catch (e) {
      console.log(`  Decrypt error: ${e.message}`);
    }
  });

  setTimeout(() => {
    console.log('\n⏱️ Timeout after 20s');
    process.exit(1);
  }, 20000);
}

main().catch(console.error);
