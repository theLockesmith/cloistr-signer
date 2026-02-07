// Test NIP-46 encrypt and decrypt methods
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
  console.log('=== Test NIP-46 Encrypt/Decrypt ===\n');

  const clientSigner = new NDKPrivateKeySigner(ADMIN_KEY_HEX);
  const clientUser = await clientSigner.user();

  // Generate a recipient keypair for encryption test
  const recipientSigner = NDKPrivateKeySigner.generate();
  const recipientUser = await recipientSigner.user();

  console.log(`Client (admin) pubkey: ${clientUser.pubkey}`);
  console.log(`Testkey pubkey: ${TESTKEY_PUBKEY}`);
  console.log(`Recipient pubkey: ${recipientUser.pubkey}`);
  console.log('');

  const ndk = new NDK({
    explicitRelayUrls: [RELAY_URL, 'wss://relay.damus.io'],
    enableOutboxModel: false
  });
  ndk.signer = clientSigner;

  console.log('Connecting to relays...');
  await ndk.connect(5000);
  console.log('Connected!\n');

  const plaintext = 'Hello from NIP-46! This is a secret message. 🔐';
  console.log(`Original message: "${plaintext}"`);
  console.log('');

  // Test 1: Encrypt
  console.log('--- Test 1: NIP-46 Encrypt ---');
  console.log(`Requesting nsecbunker to encrypt message to recipient...`);

  try {
    const encryptRequestId = await sendNip46Request(
      ndk,
      clientSigner,
      TESTKEY_PUBKEY,
      'nip04_encrypt',
      [recipientUser.pubkey, plaintext]
    );

    const ciphertext = await waitForNip46Response(
      ndk,
      clientSigner,
      clientUser.pubkey,
      TESTKEY_PUBKEY,
      encryptRequestId
    );

    console.log(`✅ Encrypted!`);
    console.log(`   Ciphertext: ${ciphertext.slice(0, 50)}...`);
    console.log('');

    // Test 2: Decrypt (recipient decrypts message from testkey)
    console.log('--- Test 2: Verify Encryption ---');
    console.log('Recipient decrypting message locally...');

    // The recipient can decrypt using their private key and testkey's pubkey
    const decryptedByRecipient = await recipientSigner.decrypt(
      new NDKUser({ pubkey: TESTKEY_PUBKEY }),
      ciphertext
    );

    console.log(`✅ Recipient decrypted!`);
    console.log(`   Decrypted: "${decryptedByRecipient}"`);
    console.log(`   Match: ${decryptedByRecipient === plaintext ? '✅ Yes!' : '❌ No'}`);
    console.log('');

    // Test 3: NIP-46 Decrypt
    console.log('--- Test 3: NIP-46 Decrypt ---');

    // First, recipient encrypts a message TO testkey
    const replyMessage = 'Reply from recipient! 📨';
    console.log(`Recipient encrypts reply: "${replyMessage}"`);

    const encryptedReply = await recipientSigner.encrypt(
      new NDKUser({ pubkey: TESTKEY_PUBKEY }),
      replyMessage
    );
    console.log(`   Encrypted reply: ${encryptedReply.slice(0, 50)}...`);
    console.log('');

    // Now ask nsecbunker to decrypt it via NIP-46
    console.log('Requesting nsecbunker to decrypt the reply...');

    const decryptRequestId = await sendNip46Request(
      ndk,
      clientSigner,
      TESTKEY_PUBKEY,
      'nip04_decrypt',
      [recipientUser.pubkey, encryptedReply]
    );

    const decryptedByBunker = await waitForNip46Response(
      ndk,
      clientSigner,
      clientUser.pubkey,
      TESTKEY_PUBKEY,
      decryptRequestId
    );

    console.log(`✅ nsecbunker decrypted!`);
    console.log(`   Decrypted: "${decryptedByBunker}"`);
    console.log(`   Match: ${decryptedByBunker === replyMessage ? '✅ Yes!' : '❌ No'}`);
    console.log('');

    // Test 4: NIP-44 encrypt/decrypt (if supported)
    console.log('--- Test 4: NIP-44 Encrypt (if supported) ---');

    try {
      const nip44EncryptRequestId = await sendNip46Request(
        ndk,
        clientSigner,
        TESTKEY_PUBKEY,
        'nip44_encrypt',
        [recipientUser.pubkey, plaintext]
      );

      const nip44Ciphertext = await waitForNip46Response(
        ndk,
        clientSigner,
        clientUser.pubkey,
        TESTKEY_PUBKEY,
        nip44EncryptRequestId
      );

      console.log(`✅ NIP-44 Encrypted!`);
      console.log(`   Ciphertext: ${nip44Ciphertext.slice(0, 50)}...`);

      // Try to decrypt
      const nip44DecryptRequestId = await sendNip46Request(
        ndk,
        clientSigner,
        TESTKEY_PUBKEY,
        'nip44_decrypt',
        [recipientUser.pubkey, nip44Ciphertext]
      );

      const nip44Decrypted = await waitForNip46Response(
        ndk,
        clientSigner,
        clientUser.pubkey,
        TESTKEY_PUBKEY,
        nip44DecryptRequestId
      );

      console.log(`✅ NIP-44 Decrypted!`);
      console.log(`   Decrypted: "${nip44Decrypted}"`);
      console.log(`   Match: ${nip44Decrypted === plaintext ? '✅ Yes!' : '❌ No'}`);

    } catch (e) {
      console.log(`ℹ️  NIP-44 not supported or error: ${e.message}`);
    }

  } catch (e) {
    console.error(`❌ Error: ${e.message}`);
  }

  console.log('\n=== Test Complete ===');
  process.exit(0);
}

main().catch(console.error);
