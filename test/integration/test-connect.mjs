// Test NIP-46 connect method
import NDK, { NDKPrivateKeySigner, NDKEvent, NDKUser } from '@nostr-dev-kit/ndk';
import crypto from 'crypto';

const RELAY_URL = 'wss://relay.coldforge.xyz';
const TESTKEY_PUBKEY = '1b9a8d756b54ee7f6807ed36ced1f220ee7b7fc159e397f71c195a7a289a17af';
const ADMIN_KEY_HEX = '5c300b0008fa7307ca35585aab688eb4aae6ab98250b968c4ebb425be7af98fe';

async function sendNip46Request(ndk, clientSigner, targetPubkey, method, params) {
  const requestId = crypto.randomBytes(16).toString('hex');

  const request = {
    id: requestId,
    method: method,
    params: params
  };

  const encryptedContent = await clientSigner.encrypt(
    new NDKUser({ pubkey: targetPubkey }),
    JSON.stringify(request)
  );

  const event = new NDKEvent(ndk);
  event.kind = 24133;
  event.content = encryptedContent;
  event.tags = [['p', targetPubkey]];

  await event.sign();
  await event.publish();

  return requestId;
}

async function waitForNip46Response(ndk, clientSigner, clientPubkey, expectedPubkey, requestId, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      sub.stop();
      reject(new Error('Timeout waiting for NIP-46 response'));
    }, timeoutMs);

    const sub = ndk.subscribe({
      kinds: [24133, 24134],
      '#p': [clientPubkey],
      since: Math.floor(Date.now() / 1000) - 120
    });

    sub.on('event', async (responseEvent) => {
      if (responseEvent.pubkey !== expectedPubkey) return;

      try {
        const decrypted = await clientSigner.decrypt(
          new NDKUser({ pubkey: responseEvent.pubkey }),
          responseEvent.content
        );
        const response = JSON.parse(decrypted);

        if (response.id === requestId) {
          clearTimeout(timeout);
          sub.stop();

          if (response.error) {
            reject(new Error(response.error));
          } else {
            resolve(response.result);
          }
        }
      } catch (e) {
        // Ignore decryption errors for other events
      }
    });
  });
}

async function main() {
  console.log('=== Test NIP-46 Connect ===\n');

  const clientSigner = new NDKPrivateKeySigner(ADMIN_KEY_HEX);
  const clientUser = await clientSigner.user();

  console.log(`Client (admin) pubkey: ${clientUser.pubkey}`);
  console.log(`Testkey pubkey: ${TESTKEY_PUBKEY}`);
  console.log('');

  const ndk = new NDK({
    explicitRelayUrls: [RELAY_URL, 'wss://relay.damus.io'],
    enableOutboxModel: false
  });
  ndk.signer = clientSigner;

  console.log('Connecting to relays...');
  await ndk.connect(5000);
  console.log('Connected!\n');

  // Test 1: Connect request
  console.log('--- Test 1: NIP-46 Connect ---');
  console.log('Sending connect request to nsecbunker...');

  try {
    const connectRequestId = await sendNip46Request(
      ndk,
      clientSigner,
      TESTKEY_PUBKEY,
      'connect',
      [clientUser.pubkey]  // Client's pubkey as param
    );

    const connectResult = await waitForNip46Response(
      ndk,
      clientSigner,
      clientUser.pubkey,
      TESTKEY_PUBKEY,
      connectRequestId
    );

    console.log(`✅ Connect successful!`);
    console.log(`   Result: ${connectResult}`);
    console.log('');

  } catch (e) {
    console.log(`❌ Connect failed: ${e.message}`);
    console.log('');
  }

  // Test 2: Get public key
  console.log('--- Test 2: Get Public Key ---');
  console.log('Requesting public key from nsecbunker...');

  try {
    const getPubkeyRequestId = await sendNip46Request(
      ndk,
      clientSigner,
      TESTKEY_PUBKEY,
      'get_public_key',
      []
    );

    const pubkeyResult = await waitForNip46Response(
      ndk,
      clientSigner,
      clientUser.pubkey,
      TESTKEY_PUBKEY,
      getPubkeyRequestId
    );

    console.log(`✅ Got public key!`);
    console.log(`   Pubkey: ${pubkeyResult}`);
    console.log(`   Match: ${pubkeyResult === TESTKEY_PUBKEY ? '✅ Yes!' : '❌ No'}`);
    console.log('');

  } catch (e) {
    console.log(`❌ Get public key failed: ${e.message}`);
    console.log('');
  }

  // Test 3: Ping
  console.log('--- Test 3: Ping ---');
  console.log('Sending ping to nsecbunker...');

  try {
    const pingRequestId = await sendNip46Request(
      ndk,
      clientSigner,
      TESTKEY_PUBKEY,
      'ping',
      []
    );

    const pingResult = await waitForNip46Response(
      ndk,
      clientSigner,
      clientUser.pubkey,
      TESTKEY_PUBKEY,
      pingRequestId
    );

    console.log(`✅ Pong received!`);
    console.log(`   Result: ${pingResult}`);
    console.log('');

  } catch (e) {
    console.log(`❌ Ping failed: ${e.message}`);
    console.log('');
  }

  // Test 4: Get relays
  console.log('--- Test 4: Get Relays ---');
  console.log('Requesting relay list from nsecbunker...');

  try {
    const getRelaysRequestId = await sendNip46Request(
      ndk,
      clientSigner,
      TESTKEY_PUBKEY,
      'get_relays',
      []
    );

    const relaysResult = await waitForNip46Response(
      ndk,
      clientSigner,
      clientUser.pubkey,
      TESTKEY_PUBKEY,
      getRelaysRequestId
    );

    console.log(`✅ Got relays!`);
    try {
      const relays = JSON.parse(relaysResult);
      console.log(`   Relays: ${JSON.stringify(relays, null, 2)}`);
    } catch {
      console.log(`   Result: ${relaysResult}`);
    }
    console.log('');

  } catch (e) {
    console.log(`ℹ️  Get relays: ${e.message}`);
    console.log('');
  }

  console.log('=== Test Complete ===');
  process.exit(0);
}

main().catch(console.error);
