// Test NIP-46 remote signing with nostream relay
// Flow: Client → nsecbunker (NIP-46 signing) → nostream (NIP-42 auth)
import NDK, { NDKPrivateKeySigner, NDKEvent, NDKUser, NDKRelay } from '@nostr-dev-kit/ndk';
import crypto from 'crypto';
import WebSocket from 'ws';

const RELAY_URL = 'wss://relay.coldforge.xyz';
const TESTKEY_PUBKEY = '1b9a8d756b54ee7f6807ed36ced1f220ee7b7fc159e397f71c195a7a289a17af';

// Admin key has permissions to sign with testkey
const ADMIN_KEY_HEX = '5c300b0008fa7307ca35585aab688eb4aae6ab98250b968c4ebb425be7af98fe';

async function sendNip46Request(ndk, clientSigner, targetPubkey, method, params) {
  const requestId = crypto.randomBytes(16).toString('hex');

  const request = {
    id: requestId,
    method: method,
    params: params
  };

  // Encrypt the request to the target pubkey
  const encryptedContent = await clientSigner.encrypt(
    new NDKUser({ pubkey: targetPubkey }),
    JSON.stringify(request)
  );

  // Create kind 24133 event (NIP-46 request)
  const event = new NDKEvent(ndk);
  event.kind = 24133;
  event.content = encryptedContent;
  event.tags = [['p', targetPubkey]];

  await event.sign();
  await event.publish();

  return requestId;
}

async function waitForNip46Response(ndk, clientSigner, clientPubkey, expectedPubkey, requestId, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      sub.stop();
      reject(new Error('Timeout waiting for NIP-46 response'));
    }, timeoutMs);

    const sub = ndk.subscribe({
      kinds: [24133, 24134],
      '#p': [clientPubkey],
      since: Math.floor(Date.now() / 1000) - 60
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
  console.log('=== Test NIP-46 with Nostream Relay ===\n');

  // Create NDK with admin signer (has permissions to use testkey via NIP-46)
  const clientSigner = new NDKPrivateKeySigner(ADMIN_KEY_HEX);
  const clientUser = await clientSigner.user();

  console.log(`Client pubkey (admin): ${clientUser.pubkey}`);
  console.log(`Testkey pubkey: ${TESTKEY_PUBKEY}`);
  console.log(`Relay: ${RELAY_URL}`);
  console.log('');

  // NDK for NIP-46 communication
  const ndk = new NDK({
    explicitRelayUrls: [RELAY_URL, 'wss://relay.damus.io'],
    enableOutboxModel: false
  });
  ndk.signer = clientSigner;

  console.log('Connecting to relays for NIP-46...');
  await ndk.connect(5000);
  console.log('Connected!\n');

  // Step 1: Test basic NIP-46 signing (we already know this works)
  console.log('--- Step 1: Test NIP-46 Signing ---');

  const testEvent = {
    kind: 1,
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
    content: `NIP-46 test via nostream - ${new Date().toISOString()}`
  };

  console.log('Sending sign_event request to nsecbunker...');
  const signRequestId = await sendNip46Request(
    ndk,
    clientSigner,
    TESTKEY_PUBKEY,
    'sign_event',
    [JSON.stringify(testEvent)]
  );

  try {
    const signedEventJson = await waitForNip46Response(
      ndk,
      clientSigner,
      clientUser.pubkey,
      TESTKEY_PUBKEY,
      signRequestId
    );

    const signedEvent = JSON.parse(signedEventJson);
    console.log(`✅ Event signed by nsecbunker!`);
    console.log(`   ID: ${signedEvent.id}`);
    console.log(`   Pubkey: ${signedEvent.pubkey}`);
    console.log(`   Sig: ${signedEvent.sig.slice(0, 32)}...`);
    console.log('');

    // Step 2: Publish the signed event to nostream
    console.log('--- Step 2: Publish Signed Event to Nostream ---');

    // Create a new NDK event from the signed data
    const publishEvent = new NDKEvent(ndk);
    publishEvent.kind = signedEvent.kind;
    publishEvent.content = signedEvent.content;
    publishEvent.created_at = signedEvent.created_at;
    publishEvent.tags = signedEvent.tags;
    publishEvent.pubkey = signedEvent.pubkey;
    publishEvent.id = signedEvent.id;
    publishEvent.sig = signedEvent.sig;

    console.log('Publishing signed event to relay...');
    try {
      const relays = await publishEvent.publish();
      console.log(`✅ Published to ${relays.size} relay(s)!`);

      // List which relays accepted
      for (const relay of relays) {
        console.log(`   - ${relay.url}`);
      }
    } catch (e) {
      console.log(`❌ Publish failed: ${e.message}`);
    }
    console.log('');

    // Step 3: Verify the event exists on the relay
    console.log('--- Step 3: Verify Event on Relay ---');
    console.log(`Fetching event ${signedEvent.id}...`);

    const fetchedEvents = await ndk.fetchEvents({ ids: [signedEvent.id] });
    if (fetchedEvents.size > 0) {
      const fetched = [...fetchedEvents][0];
      console.log(`✅ Event found on relay!`);
      console.log(`   Content: ${fetched.content}`);
      console.log(`   Author: ${fetched.pubkey}`);
    } else {
      console.log('❌ Event not found on relay (may need NIP-42 auth)');
    }
    console.log('');

    // Step 4: Test NIP-42 AUTH flow (if required)
    console.log('--- Step 4: NIP-42 Authentication Test ---');
    console.log('Testing if relay requires NIP-42 AUTH...');

    // Create a direct WebSocket connection to check for AUTH challenge
    await testNip42Auth(ndk, clientSigner, signedEvent);

  } catch (e) {
    console.error(`❌ Error: ${e.message}`);
  }

  console.log('\n=== Test Complete ===');
  process.exit(0);
}

async function testNip42Auth(ndk, clientSigner, signedEvent) {
  return new Promise((resolve) => {
    const ws = new WebSocket(RELAY_URL);
    let authChallenge = null;

    ws.on('open', () => {
      console.log('Direct WebSocket connected to relay');

      // Try to publish an event - this might trigger AUTH
      const eventMsg = JSON.stringify(['EVENT', signedEvent]);
      ws.send(eventMsg);
    });

    ws.on('message', async (data) => {
      const msg = JSON.parse(data.toString());
      console.log(`Relay message: ${JSON.stringify(msg).slice(0, 100)}...`);

      if (msg[0] === 'AUTH') {
        authChallenge = msg[1];
        console.log(`\n🔐 Received NIP-42 AUTH challenge: ${authChallenge}`);

        // Create AUTH event (kind 22242)
        const authEvent = {
          kind: 22242,
          created_at: Math.floor(Date.now() / 1000),
          tags: [
            ['relay', RELAY_URL],
            ['challenge', authChallenge]
          ],
          content: ''
        };

        console.log('Requesting nsecbunker to sign AUTH event...');

        try {
          const clientUser = await clientSigner.user();
          const authRequestId = await sendNip46Request(
            ndk,
            clientSigner,
            TESTKEY_PUBKEY,
            'sign_event',
            [JSON.stringify(authEvent)]
          );

          const signedAuthJson = await waitForNip46Response(
            ndk,
            clientSigner,
            clientUser.pubkey,
            TESTKEY_PUBKEY,
            authRequestId
          );

          const signedAuth = JSON.parse(signedAuthJson);
          console.log(`✅ AUTH event signed!`);

          // Send signed AUTH to relay
          ws.send(JSON.stringify(['AUTH', signedAuth]));
          console.log('Sent signed AUTH to relay');

        } catch (e) {
          console.log(`❌ Failed to sign AUTH: ${e.message}`);
        }
      } else if (msg[0] === 'OK') {
        const [_, eventId, success, message] = msg;
        if (success) {
          console.log(`✅ Event ${eventId.slice(0, 16)}... accepted by relay`);
        } else {
          console.log(`❌ Event rejected: ${message}`);
        }
      } else if (msg[0] === 'NOTICE') {
        console.log(`📢 Relay notice: ${msg[1]}`);
      }
    });

    ws.on('error', (err) => {
      console.log(`WebSocket error: ${err.message}`);
    });

    ws.on('close', () => {
      console.log('WebSocket closed');
      resolve();
    });

    // Timeout after 15 seconds
    setTimeout(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
      resolve();
    }, 15000);
  });
}

main().catch(console.error);
